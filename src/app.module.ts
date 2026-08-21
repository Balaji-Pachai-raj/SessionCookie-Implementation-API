import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './app.controller';
import { AuthService } from './app.service';
import { PrismaModule } from './PrismaService/prismaservice.module';
import { RedisService } from './redis.service';
import { AuthGuard } from './auth.guard';
import { TraceIdMiddleware } from 'nest-common-utilities';
import { CasbinModule } from './casbin/casbin.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    PrismaModule,
    JwtModule.register({}),
    CasbinModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    RedisService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
})
export class AppModule implements NestModule {
  /**
   * Configures middleware for the application.
   *
   * @param {MiddlewareConsumer} consumer - Provides
   * methods to apply middleware
   * to controllers or routes.
   */
  configure(consumer: MiddlewareConsumer) {
    // Apply the logger middleware globally (to all routes)
    consumer.apply(TraceIdMiddleware).forRoutes('*');
  }
}
