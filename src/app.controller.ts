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
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.authService.login(body.username, body.password);

    this.setAuthCookies(response, result);

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
    let username = body?.username;
    let password = body?.password;

    if (!username && request.cookies?.access_token) {
      const currentUser = await this.authService.verifyAccessToken(
        request.cookies.access_token,
      );
      username = currentUser.username;
      password = '';
    }

    if (!username) {
      throw new BadRequestException(
        'username is required. Send username/password or use the active session cookie.',
      );
    }

    const result = await this.authService.continueSession(username, password);

    this.setAuthCookies(response, result);

    return {
      success: true,
      code: 'CONTINUE_SESSION_SUCCESS',
      message: 'Previous session replaced successfully',
    };
  }

  @Get('dashboard')
  async getDashboard(@Req() request: Request & { user?: TokenPayload }) {
    const user = request.user as TokenPayload;
    const data = await this.authService.getDashboardData(user);

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
    const { tokens, userDetails, role_id, user_role_mapping_id } =
      await this.authService.refreshTokens(
        request.cookies?.refresh_token,
        request.cookies?.access_token,
      );

    this.setAuthCookies(response, tokens);

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
    const { tokens, currentRole, permissions, menus, landingPage } = await this.authService.switchRole(
      user,
      body,
    );
    this.setAuthCookies(response, tokens);

    return {
      message: 'Role changed successfully',
      currentRole,
      user: { id: user.sub, username: user.username },
      permissions,
      menus,
      landingPage,
    };
  }

  @Get('thistoken')
  async getThisToken(@Req() request: Request & { user?: TokenPayload }) {
    const user = request.user as TokenPayload;
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
    const accessToken = request.cookies?.access_token;

    if (accessToken) {
      try {
        const user = await this.authService.verifyAccessToken(accessToken);
        await this.authService.logout(user.sub);
      } catch {
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

    console.log('Token => ', tokens);

    response.cookie(cookie.accessToken.name, tokens.accessToken, {
      httpOnly: true,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      maxAge: cookie.accessToken.maxAge,
      path: cookie.accessToken.path,
    });

    console.log('Cookie => ', cookie);

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
}
 