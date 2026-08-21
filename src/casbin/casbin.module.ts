import { Global, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CasbinService } from './casbin.service';
import { CasbinGuard } from './casbin.guard';
import { PrismaModule } from '../PrismaService/prismaservice.module';

@Global()
@Module({
  imports: [PrismaModule],
  providers: [
    CasbinService,
    // Register CasbinGuard globally so every route is checked automatically.
    // It only enforces routes decorated with @CheckPolicy; others pass through.
    {
      provide: APP_GUARD,
      useClass: CasbinGuard,
    },
  ],
  exports: [CasbinService],
})
export class CasbinModule {}
