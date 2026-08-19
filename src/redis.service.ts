import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { createClient, RedisClientType } from 'redis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private client: RedisClientType | null = null;
  private isReady = false;
  private readonly logger = new Logger(RedisService.name);

  async onModuleInit() {
    const url = process.env.REDIS_URL || 'redis://localhost:6379';

    this.client = createClient({ url }); // no legacyMode

    this.client.on('connect', () => {
      this.isReady = true;
      this.logger.log(`Redis client connected to ${url}`);
    });
    this.client.on('ready', () => {
      this.isReady = true;
      this.logger.log(`Connected to Redis: ${url}`);
    });
    this.client.on('end', () => {
      this.isReady = false;
      this.logger.warn(`Redis connection closed for ${url}`);
    });
    this.client.on('reconnecting', () => {
      this.isReady = false;
      this.logger.warn(`Redis reconnecting to ${url}...`);
    });
    this.client.on('error', (error) => {
      this.isReady = false;
      this.logger.error('Redis Client Error', error);
    });

    try {
      await this.client.connect();
      this.isReady = true;
      this.logger.log(`Connected to Redis: ${url}`);
      try {
        await this.clearSessionKeys();
      } catch (error) {
        this.logger.warn(
          `Failed to clear stale Redis session keys: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    } catch (error) {
      this.isReady = false;
      this.logger.warn(
        `Redis is not available at ${url}. Continuing without Redis. ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      if (this.client) {
        try { await this.client.quit(); } catch { /* ignore */ }
      }
      this.client = null;
    }
  }

  async onModuleDestroy() {
    if (!this.client) return;
    try { await this.client.quit(); } catch { /* ignore */ }
  }

  private async getClient(): Promise<RedisClientType> {
    if (!this.client) throw new Error('Redis is not available');

    if (!this.isReady || !this.client.isOpen) {
      try {
        await this.client.connect();
        this.isReady = true;
      } catch {
        this.isReady = false;
        throw new Error('Redis is not available');
      }
    }
    return this.client;
  }

  async clearSessionKeys(): Promise<void> {
    if (!this.client || !this.isReady) return;

    const accessKeys = await this.client.keys('ACCESS_*');
    const refreshKeys = await this.client.keys('REFRESH_*');
    const allKeys = [...accessKeys, ...refreshKeys];

    if (allKeys.length === 0) return;

    await this.client.del(allKeys);
    this.logger.log(`Cleared ${allKeys.length} Redis session keys.`);
  }

  async get(key: string): Promise<string | null> {
    const client = await this.getClient();
    const value = await client.get(key);
    return value ?? null;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    const client = await this.getClient();

    if (ttlSeconds !== undefined) {
      await client.set(key, value, { EX: ttlSeconds }); // v4 native option object
    } else {
      await client.set(key, value);
    }
  }

  async delete(key: string): Promise<void> {
    const client = await this.getClient();
    await client.del(key);
  }
}