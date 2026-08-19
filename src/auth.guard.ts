import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { AuthService, TokenPayload } from './app.service';
import { RedisService } from './redis.service';
import { IS_PUBLIC_KEY } from './public.decorator';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authService: AuthService,
    private readonly redisService: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

     console.log('first AuthGuard: Checking access token and session in Redis...');
    if (isPublic) {
      return true;
    }

    console.log('AuthGuard: Checking access token and session in Redis...');

    const request = context
      .switchToHttp()
      .getRequest<Request & { user?: TokenPayload }>();

    const accessToken = request.cookies?.access_token;

    if (!accessToken) {
      throw new UnauthorizedException('Access token missing');
    }

    const payload = await this.authService.verifyAccessToken(accessToken);
    const userId = payload.userDetails?.nt_id || payload.sub;
    const redisKey = this.authService.getRedisKey('ACCESS', userId);
    const storedToken = await this.redisService.get(redisKey);

    if (!storedToken || storedToken !== accessToken) {
      throw new HttpException(
        {
          success: false,
          code: 'SESSION_EXPIRED',
          message: 'Session is no longer active',
        },
        HttpStatus.GONE,
      );
    }

    request.user = payload;
    return true;
  }
}
