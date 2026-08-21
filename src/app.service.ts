import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { SignOptions } from 'jsonwebtoken';
import ms from 'ms';
import { PrismaService } from './PrismaService/prisma.service';
import { RedisService } from './redis.service';
import { CasbinService } from './casbin/casbin.service';
// import { PrismaService } from '../prisma/prisma.service';

// ============================================================================
// CONFIG — every tunable value lives here. Change an expiry time or a
// cookie flag once and both the signed token AND the cookie maxAge stay in
// sync (they're derived from the same env var below), instead of being
// hardcoded separately in four different places like the original code.
//
// Override any of these by setting the env var; sensible defaults are used
// otherwise.
// ============================================================================
export const AUTH_CONFIG = {
  jwt: {
    secret: process.env.JWT_SECRET || 'my-secret-key',
    accessTokenExpiresIn: (process.env.JWT_ACCESS_TOKEN_EXPIRES_IN ||
      '1m') as SignOptions['expiresIn'],
    refreshTokenExpiresIn: (process.env.JWT_REFRESH_TOKEN_EXPIRES_IN ||
      '7d') as SignOptions['expiresIn'],
  },
  cookie: {
    // true in production by default, false otherwise, unless set explicitly
    secure: true,
    sameSite:
      (process.env.COOKIE_SAME_SITE as 'lax' | 'strict' | 'none') || 'none',
    accessToken: {
      name: 'access_token',
      path: '/',
      maxAge: ms(
        (process.env.JWT_ACCESS_TOKEN_EXPIRES_IN || '15m') as ms.StringValue,
      ),
    },
    refreshToken: {
      name: 'refresh_token',
      // Only ever sent back to /refresh, not every API call.
      path: '/refresh',
      maxAge: ms(
        (process.env.JWT_REFRESH_TOKEN_EXPIRES_IN || '7d') as ms.StringValue,
      ),
    },
  },
} as const;

// ============================================================================
// TYPES / DTOs
// ============================================================================
export type TokenType = 'access' | 'refresh';

export interface UserTokenDetails {
  nt_id: string;
  userDetails: string;
  role_name?: string;
  short_name?: string;
  is_active: boolean;
}

export interface TokenPayload {
  sub: string;
  username: string;
  userDetails: UserTokenDetails;
  role_id?: string;
  user_role_mapping_id?: string;
  type: TokenType;
}

export class ChangeRoleDto {
  user_role_mapping_id!: string;
  role_id!: string;
}

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

type LoginResult = TokenPair;

// ============================================================================
// SERVICE — all business logic: DB access, token issuing/verification,
// role switching. The controller should never talk to Prisma or JwtService
// directly; it only calls into here.
// ============================================================================
@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly casbinService: CasbinService,
  ) {}

  async login(
    username: string,
    password: string,
  ): Promise<LoginResult> {
    const user = await this.findUserOrThrow(username, password);
    const accessKey = this.getRedisKey('ACCESS', user.nt_id);
    const refreshKey = this.getRedisKey('REFRESH', user.nt_id);
    let existingAccess: string | null = null;
    let existingRefresh: string | null = null;

    try {
      [existingAccess, existingRefresh] = await Promise.all([
        this.redisService.get(accessKey),
        this.redisService.get(refreshKey),
      ]);
      console.log('Redis access key:', accessKey);
      console.log('Redis access value:', existingAccess);
      console.log('Redis refresh key:', refreshKey);
      console.log('Redis refresh value:', existingRefresh);

    } catch {
      throw new HttpException(
        {
          success: false,
          code: 'REDIS_UNAVAILABLE',
          message: 'Redis is unavailable. Please try again later.',
        },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }

    const hasExistingSession =
      existingAccess !== null || existingRefresh !== null;

      console.log(hasExistingSession)

    console.log('Redis check for login => ', {
      accessKey,
      refreshKey,
      existingAccess: existingAccess !== null,
      existingRefresh: existingRefresh !== null,
      accessPreview: existingAccess ? existingAccess.slice(0, 20) : null,
      refreshPreview: existingRefresh ? existingRefresh.slice(0, 20) : null,
      hasExistingSession,
    });
    if (hasExistingSession) {
      throw new HttpException(
        {
          success: false,
          code: 'USER_ALREADY_LOGGED_IN',
          message: 'User already logged in. Please logout before logging in again.',
        },
        HttpStatus.CONFLICT,
      );
    }

    const activeRole = await this.prisma.user_role_mapping.findFirst({
      where: { nt_id: user.nt_id },
      include: { role_master: true },
    });

    const userDetails: UserTokenDetails = {
      nt_id: user.nt_id,
      userDetails: user.username,
      role_name: activeRole?.role_master?.role_name,
      // short_name: activeRole?.role_master?.short_name,
      is_active: user.is_active,
    };

    const tokens = await this.issueTokenPair({
      sub: user.nt_id,
      username: user.username,
      userDetails,
      role_id: activeRole?.role_id?.toString(),
      user_role_mapping_id: activeRole?.user_role_mapping_id?.toString(),
    });
    console.log('Tokens => ', tokens);

    try {
      await this.storeUserTokens(user.nt_id, tokens);
    } catch {
      throw new HttpException(
        {
          success: false,
          code: 'REDIS_UNAVAILABLE',
          message: 'Redis is unavailable. Please try again later.',
        },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }

    return tokens;
  }

  async continueSession(
    username?: string,
    password?: string,
  ): Promise<LoginResult> {
    if (!username) {
      throw new BadRequestException('username is required to continue session');
    }

    const user = await this.findUserOrThrow(username, password || '');
    const accessKey = this.getRedisKey('ACCESS', user.nt_id);
    const refreshKey = this.getRedisKey('REFRESH', user.nt_id);

    await Promise.all([
      this.redisService.delete(accessKey),
      this.redisService.delete(refreshKey),
    ]);

    const activeRole = await this.prisma.user_role_mapping.findFirst({
      where: { nt_id: user.nt_id },
      include: { role_master: true },
    });

    const userDetails: UserTokenDetails = {
      nt_id: user.nt_id,
      userDetails: user.username,
      role_name: activeRole?.role_master?.role_name,
      is_active: user.is_active,
    };

    const tokens = await this.issueTokenPair({
      sub: user.nt_id,
      username: user.username,
      userDetails,
      role_id: activeRole?.role_id?.toString(),
      user_role_mapping_id: activeRole?.user_role_mapping_id?.toString(),
    });

    await this.storeUserTokens(user.nt_id, tokens);

    return tokens;
  }

  async getDashboardData(payload: TokenPayload) {
    const nt_id = payload.userDetails?.nt_id;

    if (!nt_id) {
      throw new UnauthorizedException('Nt_id is not there');
    }

    const roleName = payload.userDetails?.role_name;


    if (!roleName) {
      throw new UnauthorizedException('Role is not available in token');
    }

    const roles = await this.prisma.user_role_mapping.findMany({
      where: { nt_id },
      include: { role_master: true },
    });

    const permissions =
      await this.casbinService.getPermissionsForRole(roleName);

    const menus =
      await this.casbinService.getMenusForRole(roleName);

    const landingPage =
      await this.casbinService.getLandingPagesForRole(roleName);

    return {
      currentRole: this.serializeBigInt(roles),
      user: { id: payload.sub, username: payload.username },
      permissions,
      menus,
      landingPage,
    };
  }

  async refreshTokens(
    refreshToken: string | undefined,
    accessToken: string | undefined,
  ) {
    const refreshPayload = await this.verifyRefreshToken(refreshToken); // confirms the refresh cookie is valid
    // const accessPayload = await this.verifyAccessToken(accessToken);

    const { userDetails, role_id, user_role_mapping_id } = refreshPayload;

    if (!userDetails?.nt_id) {
      throw new UnauthorizedException('User details missing from access token');
    }

    const tokens = await this.issueTokenPair({
      sub: refreshPayload.sub,
      username: refreshPayload.username,
      userDetails,
      role_id,
      user_role_mapping_id,
    });

    await this.storeUserTokens(refreshPayload.sub, tokens);

    return { tokens, userDetails, role_id, user_role_mapping_id };
  }

  async logout(userId: string): Promise<void> {
    await Promise.all([
      this.redisService.delete(this.getRedisKey('ACCESS', userId)),
      this.redisService.delete(this.getRedisKey('REFRESH', userId)),
    ]);
  }

  async switchRole(currentPayload: TokenPayload, dto: ChangeRoleDto) {
    const nt_id = currentPayload.userDetails?.nt_id;

    if (!nt_id) {
      throw new UnauthorizedException('Nt_id is not there');
    }

    const { user_role_mapping_id, role_id } = dto;

    if (!user_role_mapping_id || !role_id) {
      throw new BadRequestException(
        'user_role_mapping_id and role_id are required',
      );
    }

    if (currentPayload.role_id?.toString() === role_id.toString()) {
      throw new BadRequestException('This is already the active user role');
    }

    const requestedRole = await this.prisma.user_role_mapping.findFirst({
      where: {
        user_role_mapping_id: BigInt(user_role_mapping_id),
        role_id: BigInt(role_id),
        nt_id,
        is_active: true,
      },
      include: { role_master: true },
    });

    if (!requestedRole) {
      throw new UnauthorizedException(
        'The requested role is not assigned to this user or is inactive',
      );
    }

    const roleName = requestedRole.role_master.role_name;

    // Get permissions directly from Casbin CSV policies
    const permissions =
      await this.casbinService.getPermissionsForRole(
        roleName,
    );
    const menus =
      await this.casbinService.getMenusForRole(
        roleName,
      );

    const landingPage =
      await this.casbinService.getLandingPagesForRole(
        roleName,
      );
    const newUserDetails: UserTokenDetails = {
      nt_id,
      userDetails: nt_id,
      role_name: requestedRole.role_master.role_name,
      // short_name: requestedRole.role_master.short_name,
      is_active: requestedRole.is_active,
    };

    const tokens = await this.issueTokenPair({
      sub: currentPayload.sub,
      username: currentPayload.username,
      userDetails: newUserDetails,
      role_id: requestedRole.role_id.toString(),
      user_role_mapping_id: requestedRole.user_role_mapping_id.toString(),
    });

    await this.storeUserTokens(currentPayload.sub, tokens);

    return { tokens, currentRole: this.serializeBigInt(requestedRole), permissions, menus, landingPage };
  }

  /** Used directly by the controller before any protected route runs. */
  async verifyAccessToken(token: string | undefined): Promise<TokenPayload> {
    if (!token) {
      throw new UnauthorizedException('Access token missing');
    }

    const payload = await this.verifyOrThrow(
      token,
      'Access token expired or invalid',
    );

    if (payload.type !== 'access') {
      throw new UnauthorizedException('Invalid access token');
    }

    return payload;
  }

  async verifyRefreshToken(token: string | undefined): Promise<TokenPayload> {
    if (!token) {
      throw new UnauthorizedException('Refresh token missing');
    }

    const payload = await this.verifyOrThrow(
      token,
      'Refresh token expired or invalid',
    );

    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Invalid refresh token');
    }

    return payload;
  }

  // --------------------------------------------------------------------
  // Private helpers
  // --------------------------------------------------------------------

  private async verifyOrThrow(
    token: string,
    errorMessage: string,
  ): Promise<TokenPayload> {
    try {
      return await this.jwtService.verifyAsync<TokenPayload>(token, {
        secret: AUTH_CONFIG.jwt.secret,
      });
    } catch {
      throw new UnauthorizedException(errorMessage);
    }
  }

  private async findUserOrThrow(username: string, password: string) {
    // TODO — SECURITY: the original controller looked the user up by
    // username only and never checked the password. Any request with a
    // valid username could log in as that user. Preserved as-is rather
    // than guessed at — the right fix depends on how passwords are
    // hashed/stored (e.g. bcrypt.compare against a stored hash). Wire up
    // a real check before relying on this in production.
    void password;

    const user = await this.prisma.users.findUnique({
      where: { nt_id: username },
    });

    if (!user) {
      throw new UnauthorizedException('Said User does not exist');
    }

    return user;
  }

  private async issueTokenPair(
    payload: Omit<TokenPayload, 'type'>,
  ): Promise<TokenPair> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { ...payload, type: 'access' as const },
        {
          secret: AUTH_CONFIG.jwt.secret,
          expiresIn: AUTH_CONFIG.jwt.accessTokenExpiresIn,
        },
      ),
      this.jwtService.signAsync(
        { ...payload, type: 'refresh' as const },
        {
          secret: AUTH_CONFIG.jwt.secret,
          expiresIn: AUTH_CONFIG.jwt.refreshTokenExpiresIn,
        },
      ),
    ]);

    return { accessToken, refreshToken };
  }

  private async storeUserTokens(userId: string, tokens: TokenPair): Promise<void> {
    const accessKey = this.getRedisKey('ACCESS', userId);
    const refreshKey = this.getRedisKey('REFRESH', userId);

    await Promise.all([
      this.redisService.set(
        accessKey,
        tokens.accessToken,
        this.getTokenTtlSeconds('access'),
      ),
      this.redisService.set(
        refreshKey,
        tokens.refreshToken,
        this.getTokenTtlSeconds('refresh'),
      ),
    ]);

    //checking
      const [storedAccessToken, storedRefreshToken] = await Promise.all([
    this.redisService.get(accessKey),
    this.redisService.get(refreshKey),
  ]);

  // Log the Redis keys and values
  console.log('Redis Access Key:', accessKey);
  console.log('Redis Access Token:', storedAccessToken);

  console.log('Redis Refresh Key:', refreshKey);
  console.log('Redis Refresh Token:', storedRefreshToken);
  }

  public getRedisKey(type: 'ACCESS' | 'REFRESH', userId: string): string {
    return `${type}_${userId}`;
  }

  private getTokenTtlSeconds(type: TokenType): number {
    const expiresIn =
      type === 'access'
        ? AUTH_CONFIG.jwt.accessTokenExpiresIn
        : AUTH_CONFIG.jwt.refreshTokenExpiresIn;

    const parsed =
      typeof expiresIn === 'number'
        ? expiresIn * 1000
        : ms(expiresIn as ms.StringValue);

    return Math.max(1, Math.ceil(parsed / 1000));
  }

  private serializeBigInt<T>(data: T): T {
    return JSON.parse(
      JSON.stringify(data, (_key, value) =>
        typeof value === 'bigint' ? value.toString() : value,
      ),
    );
  }
}
