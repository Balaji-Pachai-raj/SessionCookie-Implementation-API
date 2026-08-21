import { SetMetadata } from '@nestjs/common';

export const CHECK_POLICY_KEY = 'check_policy';

export interface PolicyRequirement {
  lob: string;
  page: string;
  mod: string;
  sec: string;
  access: string;
}

/**
 * Decorate a route with the full Casbin policy dimensions.
 * Example: @CheckPolicy('hcp', 'userManagement', 'search', 'searchList', 'edit')
 */
export const CheckPolicy = (
  lob: string,
  page: string,
  mod: string,
  sec: string,
  access: string,
) =>
  SetMetadata(CHECK_POLICY_KEY, { lob, page, mod, sec, access } satisfies PolicyRequirement);
