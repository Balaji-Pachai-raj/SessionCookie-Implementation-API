import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import {
  AUTH_CONFIG,
  AuthService,
  ChangeRoleDto,
  TokenPayload,
} from './app.service';

export class LoginDto {
  username: string;
  password: string;
}

// ============================================================================
// CONTROLLER — HTTP concerns only: reads the request, calls AuthService,
// sets/clears cookies, shapes the response. No Prisma, no JWT verification,
// and no business rules live here.
// ============================================================================
@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Body() body: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const tokens = await this.authService.login(body.username, body.password);
    this.setAuthCookies(response, tokens);

    return { message: 'Login successful' };
  }

  @Get('dashboard')
  async getDashboard(@Req() request: Request) {
    const user = await this.requireAccessToken(request);
    const data = await this.authService.getDashboardData(user);

    return {
      message: 'Protected API successful',
      ...data,
      role_id: user.role_id,
    };
  }

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
    @Req() request: Request,
    @Body() body: ChangeRoleDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = await this.requireAccessToken(request);
    const { tokens, currentRole } = await this.authService.switchRole(
      user,
      body,
    );
    this.setAuthCookies(response, tokens);

    return {
      message: 'Role changed successfully',
      currentRole,
      user: { id: user.sub, username: user.username },
    };
  }

  @Get('thistoken')
  async getThisToken(@Req() request: Request) {
    const user = await this.requireAccessToken(request);
    return {
      message: 'Current access token retrieved successfully',
      tokenData: user,
    };
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) response: Response) {
    this.clearAuthCookies(response);
    return { message: 'Logout successful' };
  }

  // --------------------------------------------------------------------
  // Private helpers — HTTP-transport concerns only.
  // --------------------------------------------------------------------

  private requireAccessToken(request: Request): Promise<TokenPayload> {
    const accessToken = request.cookies?.access_token;
    return this.authService.verifyAccessToken(accessToken); // throws 401 if invalid/missing
  }

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
