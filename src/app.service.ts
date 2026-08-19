import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { SignOptions } from 'jsonwebtoken';
import ms from 'ms';
import { PrismaService } from './PrismaService/prisma.service';
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
  user_role_mapping_id: string;
  role_id: string;
}

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

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
  ) {}

  async login(username: string, password: string): Promise<TokenPair> {
    const user = await this.findUserOrThrow(username, password);

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

    return this.issueTokenPair({
      sub: user.nt_id,
      username: user.username,
      userDetails,
      role_id: activeRole?.role_id?.toString(),
      user_role_mapping_id: activeRole?.user_role_mapping_id?.toString(),
    });
  }

  async getDashboardData(payload: TokenPayload) {
    const nt_id = payload.userDetails?.nt_id;

    if (!nt_id) {
      throw new UnauthorizedException('Nt_id is not there');
    }

    const roles = await this.prisma.user_role_mapping.findMany({
      where: { nt_id },
      include: { role_master: true },
    });

    return {
      currentRole: this.serializeBigInt(roles),
      user: { id: payload.sub, username: payload.username },
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

    return { tokens, userDetails, role_id, user_role_mapping_id };
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

    return { tokens, currentRole: this.serializeBigInt(requestedRole) };
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

  private serializeBigInt<T>(data: T): T {
    return JSON.parse(
      JSON.stringify(data, (_key, value) =>
        typeof value === 'bigint' ? value.toString() : value,
      ),
    );
  }
}
