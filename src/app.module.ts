import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './app.controller';
import { AuthService } from './app.service';
import { PrismaModule } from './PrismaService/prismaservice.module';
import { RedisService } from './redis.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    PrismaModule,
    JwtModule.register({}),
  ],
  controllers: [AuthController],
  providers: [AuthService, RedisService],
})
export class AppModule {}
