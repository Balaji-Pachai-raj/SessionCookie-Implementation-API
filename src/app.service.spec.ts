import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from './app.service';

describe('AuthService', () => {
  let prisma: any;
  let jwtService: any;
  let redis: any;
  let service: AuthService;

  beforeEach(() => {
    prisma = {
      users: {
        findUnique: jest.fn(),
      },
      user_role_mapping: {
        findFirst: jest.fn(),
      },
    };

    jwtService = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
    };

    redis = {
      get: jest.fn(),
      set: jest.fn(),
      delete: jest.fn(),
    };

    service = new AuthService(prisma, jwtService, redis);
  });

  it('should reject login when an access token already exists for the user', async () => {
    prisma.users.findUnique.mockResolvedValue({
      nt_id: 'U001',
      username: 'user1',
      is_active: true,
    });

    prisma.user_role_mapping.findFirst.mockResolvedValue({
      role_id: 10n,
      user_role_mapping_id: 20n,
      role_master: { role_name: 'Admin' },
    });

    redis.get.mockImplementation((key: string) =>
      Promise.resolve(key === 'ACCESS_U001' ? 'existing-access-token' : null),
    );

    await expect(service.login('U001', 'secret')).rejects.toThrow(
      UnauthorizedException,
    );
    expect(redis.get).toHaveBeenCalledWith('ACCESS_U001');
  });
});
