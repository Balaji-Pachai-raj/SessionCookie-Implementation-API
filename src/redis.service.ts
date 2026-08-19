import {
    Injectable,
    Logger,
    OnModuleDestroy,
    OnModuleInit,
  } from '@nestjs/common';
  import { createClient, RedisClientType } from 'redis';
  
  @Injectable()
  export class RedisService implements OnModuleInit, OnModuleDestroy {
    private client!: RedisClientType;
  
    private readonly logger = new Logger(RedisService.name);
  
    async onModuleInit() {
      const url = process.env.REDIS_URL || 'redis://localhost:6379';
  
      this.client = createClient({
        url,
      });
  
      this.client.on('error', (error) => {
        this.logger.error('Redis Client Error', error);
      });
  
      await this.client.connect();
  
      this.logger.log(`Connected to Redis: ${url}`);
    }
  
    async onModuleDestroy() {
      if (!this.client) {
        return;
      }
  
      try {
        await this.client.quit();
      } catch {
        // Ignore shutdown errors
      }
    }
  
    async get(key: string): Promise<string | null> {
      return this.client.get(key);
    }
  
    async set(
      key: string,
      value: string,
      ttlSeconds?: number,
    ): Promise<void> {
      if (ttlSeconds !== undefined) {
        await this.client.set(key, value, {
          EX: ttlSeconds,
        });
        return;
      }
  
      await this.client.set(key, value);
    }
  
    async delete(key: string): Promise<void> {
      await this.client.del(key);
    }
  }