import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import {
  AUTH_CONFIG,
  AuthService,
  ChangeRoleDto,
  TokenPayload,
} from './app.service';
import { Public } from './public.decorator';
import { Logger } from 'nest-common-utilities';

export class LoginDto {
  username!: string;
  password!: string;
}

// ============================================================================
// CONTROLLER — HTTP concerns only: reads the request, calls AuthService,
// sets/clears cookies, shapes the response. No Prisma, no JWT verification,
// and no business rules live here.
// ============================================================================
@Controller('api')
export class AuthController {
  private logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.logger.info('Login request received', {
      methodName: 'login',
      api: 'POST /api/login',
      username: body.username,
      nt_id: 'n/a',
      role_id: 'n/a',
      role_name: 'n/a',
    });

    const result = await this.authService.login(body.username, body.password);

    this.setAuthCookies(response, result);

    const loggedInUser = await this.authService.verifyAccessToken(
      result.accessToken,
    );
    this.logger.info('Login successful', {
      methodName: 'login',
      api: 'POST /api/login',
      username: body.username,
      ...this.getUserLogContext(loggedInUser),
    });

    return {
      success: true,
      code: 'LOGIN_SUCCESS',
      message: 'Login successful',
    };
  }

  @Public()
  @Post('continue-session')
  async continueSession(
    @Req() request: Request,
    @Body() body: Partial<LoginDto>,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.logger.info('Continue-session request received', {
      methodName: 'continueSession',
      api: 'POST /api/continue-session',
      username: body?.username || 'n/a',
      nt_id: 'n/a',
      role_id: 'n/a',
      role_name: 'n/a',
    });

    let username = body?.username;
    let password = body?.password;
    let currentUserFromCookie: TokenPayload | undefined;

    if (!username && request.cookies?.access_token) {
      currentUserFromCookie = await this.authService.verifyAccessToken(
        request.cookies.access_token,
      );
      username = currentUserFromCookie.username;
      password = '';

      this.logger.info('Continue-session using active cookie context', {
        methodName: 'continueSession',
        api: 'POST /api/continue-session',
        username,
        ...this.getUserLogContext(currentUserFromCookie),
      });
    }

    if (!username) {
      throw new BadRequestException(
        'username is required. Send username/password or use the active session cookie.',
      );
    }

    const result = await this.authService.continueSession(username, password);

    this.setAuthCookies(response, result);

    const continuedUser = await this.authService.verifyAccessToken(
      result.accessToken,
    );
    this.logger.info('Continue-session successful', {
      methodName: 'continueSession',
      api: 'POST /api/continue-session',
      username,
      previous_nt_id:
        currentUserFromCookie?.userDetails?.nt_id || currentUserFromCookie?.sub,
      ...this.getUserLogContext(continuedUser),
    });

    return {
      success: true,
      code: 'CONTINUE_SESSION_SUCCESS',
      message: 'Previous session replaced successfully',
    };
  }

  @Get('dashboard')
  async getDashboard(@Req() request: Request & { user?: TokenPayload }) {
    const user = request.user as TokenPayload;
    this.logger.info('Dashboard request received', {
      methodName: 'getDashboard',
      api: 'GET /api/dashboard',
      ...this.getUserLogContext(user),
    });

    const data = await this.authService.getDashboardData(user);

    this.logger.info('Dashboard data fetched successfully', {
      methodName: 'getDashboard',
      api: 'GET /api/dashboard',
      ...this.getUserLogContext(user),
    });

    return {
      message: 'Protected API successful',
      ...data,
      role_id: user.role_id,
    };
  }

  @Public()
  @Post('refresh')
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.logger.info('Refresh token request received', {
      methodName: 'refresh',
      api: 'POST /api/refresh',
      has_access_cookie: Boolean(request.cookies?.access_token),
      has_refresh_cookie: Boolean(request.cookies?.refresh_token),
      nt_id: 'n/a',
      role_id: 'n/a',
      role_name: 'n/a',
    });

    const { tokens, userDetails, role_id, user_role_mapping_id } =
      await this.authService.refreshTokens(
        request.cookies?.refresh_token,
        request.cookies?.access_token,
      );

    this.setAuthCookies(response, tokens);

    this.logger.info('Refresh token successful', {
      methodName: 'refresh',
      api: 'POST /api/refresh',
      nt_id: userDetails?.nt_id || 'n/a',
      role_id: role_id || 'n/a',
      role_name: userDetails?.role_name || 'n/a',
      user_role_mapping_id: user_role_mapping_id || 'n/a',
    });

    return {
      message: 'Token refreshed successfully',
      userDetails,
      role_id,
      user_role_mapping_id,
    };
  }

  @Post('changerole')
  async changeRole(
    @Req() request: Request & { user?: TokenPayload },
    @Body() body: ChangeRoleDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = request.user as TokenPayload;

    this.logger.info('Change-role request received', {
      methodName: 'changeRole',
      api: 'POST /api/changerole',
      nt_id: user.userDetails?.nt_id || user.sub,
      old_role_id: user.role_id || 'n/a',
      old_role_name: user.userDetails?.role_name || 'n/a',
      old_user_role_mapping_id: user.user_role_mapping_id || 'n/a',
      new_role_id: body.role_id,
      new_user_role_mapping_id: body.user_role_mapping_id,
    });

    const { tokens, currentRole } = await this.authService.switchRole(
      user,
      body,
    );
    this.setAuthCookies(response, tokens);

    const newRole = currentRole as Record<string, unknown>;
    const newRoleMaster =
      newRole.role_master && typeof newRole.role_master === 'object'
        ? (newRole.role_master as Record<string, unknown>)
        : undefined;

    this.logger.info('Change-role successful', {
      methodName: 'changeRole',
      api: 'POST /api/changerole',
      nt_id: user.userDetails?.nt_id || user.sub,
      old_role_id: user.role_id || 'n/a',
      old_role_name: user.userDetails?.role_name || 'n/a',
      old_user_role_mapping_id: user.user_role_mapping_id || 'n/a',
      new_role_id: this.toLogString(newRole.role_id) || body.role_id,
      new_role_name: this.toLogString(newRoleMaster?.role_name) || 'n/a',
      new_user_role_mapping_id:
        this.toLogString(newRole.user_role_mapping_id) ||
        body.user_role_mapping_id,
    });

    return {
      message: 'Role changed successfully',
      currentRole,
      user: { id: user.sub, username: user.username },
    };
  }

  @Get('thistoken')
  async getThisToken(@Req() request: Request & { user?: TokenPayload }) {
    const user = request.user as TokenPayload;
    this.logger.info('Current token data requested', {
      methodName: 'getThisToken',
      api: 'GET /api/thistoken',
      ...this.getUserLogContext(user),
    });

    return {
      message: 'Current access token retrieved successfully',
      tokenData: user,
    };
  }

  @Post('logout')
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    this.logger.info('Logout request received', {
      methodName: 'logout',
      api: 'POST /api/logout',
      has_access_cookie: Boolean(request.cookies?.access_token),
      nt_id: 'n/a',
      role_id: 'n/a',
      role_name: 'n/a',
    });

    const accessToken = request.cookies?.access_token;

    if (accessToken) {
      try {
        const user = await this.authService.verifyAccessToken(accessToken);
        this.logger.info('Logout token verified', {
          methodName: 'logout',
          api: 'POST /api/logout',
          ...this.getUserLogContext(user),
        });

        await this.authService.logout(user.sub);

        this.logger.info('Logout successful', {
          methodName: 'logout',
          api: 'POST /api/logout',
          ...this.getUserLogContext(user),
        });
      } catch {
        this.logger.warn('Logout received invalid or expired access token', {
          methodName: 'logout',
          api: 'POST /api/logout',
          has_access_cookie: true,
          nt_id: 'n/a',
          role_id: 'n/a',
          role_name: 'n/a',
        });

        // Ignore invalid tokens during logout and still clear cookies.
      }
    }

    this.clearAuthCookies(response);
    return { message: 'Logout successful' };
  }

  // --------------------------------------------------------------------
  // Private helpers — HTTP-transport concerns only.
  // --------------------------------------------------------------------

  private setAuthCookies(
    response: Response,
    tokens: { accessToken: string; refreshToken: string },
  ) {
    const { cookie } = AUTH_CONFIG;

  
    response.cookie(cookie.accessToken.name, tokens.accessToken, {
      httpOnly: true,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      maxAge: cookie.accessToken.maxAge,
      path: cookie.accessToken.path,
    });

   

    response.cookie(cookie.refreshToken.name, tokens.refreshToken, {
      httpOnly: true,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      maxAge: cookie.refreshToken.maxAge,
      path: cookie.refreshToken.path,
    });
  }

  private clearAuthCookies(response: Response) {
    const { cookie } = AUTH_CONFIG;

    response.clearCookie(cookie.accessToken.name, {
      httpOnly: true,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      path: cookie.accessToken.path,
    });

    response.clearCookie(cookie.refreshToken.name, {
      httpOnly: true,
      secure: true,
      sameSite: cookie.sameSite,
      path: cookie.refreshToken.path,
    });
  }

  private getUserLogContext(payload?: TokenPayload) {
    return {
      nt_id: payload?.userDetails?.nt_id || payload?.sub || 'n/a',
      role_id: payload?.role_id || 'n/a',
      role_name: payload?.userDetails?.role_name || 'n/a',
      user_role_mapping_id: payload?.user_role_mapping_id || 'n/a',
    };
  }

  private toLogString(value: unknown): string | undefined {
    if (value === null || value === undefined) {
      return undefined;
    }

    if (typeof value === 'bigint') {
      return value.toString();
    }

    if (typeof value === 'string') {
      return value;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
      return String(value);
    }

    return undefined;
  }
}
 