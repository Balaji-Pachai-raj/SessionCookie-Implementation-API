import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  newEnforcer,
  Enforcer,
  newModelFromString,
} from 'casbin';
import * as path from 'path';
import * as fs from 'fs';

@Injectable()
export class CasbinService implements OnModuleInit {
  private enforcer!: Enforcer;

  private readonly logger = new Logger(CasbinService.name);

  async onModuleInit(): Promise<void> {
    try {
      this.logger.log('Initializing Casbin...');

      // Load model from src/casbin/model/rbac.conf (always relative to project root)
      const modelPath = path.join(process.cwd(), 'src', 'casbin', 'model', 'rbac.conf');
      const model = newModelFromString(fs.readFileSync(modelPath, 'utf-8'));

      // No database / Prisma adapter.
      this.enforcer = await newEnforcer(model);

      this.logger.log('Casbin enforcer created');

      // CSV → Casbin
      await this.loadPoliciesFromCsv();

      this.logger.log(
        'Casbin initialized successfully',
      );
    } catch (error) {
      this.logger.error(
        'Failed to initialize Casbin',
        error instanceof Error ? error.stack : String(error),
      );

      throw error;
    }
  }

  /**
   * Load all CSV files from the policies directory
   * directly into the Casbin enforcer.
   */
  private async loadPoliciesFromCsv(): Promise<void> {
    // process.cwd() is always the project root regardless of dist layout.
    const policyDir = path.join(process.cwd(), 'src', 'casbin', 'policies');

    this.logger.log(
      `Looking for policies at: ${policyDir}`,
    );

    if (!fs.existsSync(policyDir)) {
      throw new Error(
        `Policy directory not found: ${policyDir}`,
      );
    }

    const csvFiles = fs
      .readdirSync(policyDir)
      .filter((file) =>
        file.toLowerCase().endsWith('.csv'),
      );

    if (csvFiles.length === 0) {
      throw new Error(
        `No policy CSV files found in ${policyDir}`,
      );
    }

    this.logger.log(
      `Found ${csvFiles.length} policy CSV file(s)`,
    );

    for (const file of csvFiles) {
      await this.loadCsvFile(
        path.join(policyDir, file),
        file,
      );
    }

    const policies = await this.enforcer.getPolicy();
    const groupingPolicies =
      await this.enforcer.getGroupingPolicy();

    const g2Policies =
      await this.enforcer.getNamedGroupingPolicy('g2');

    this.logger.log(
      `Loaded ${policies.length} p policies`,
    );

    this.logger.log(
      `Loaded ${groupingPolicies.length} g policies`,
    );

    this.logger.log(
      `Loaded ${g2Policies.length} g2 policies`,
    );
  }

  /**
   * Load one CSV file into Casbin.
   */
  private async loadCsvFile(
    filePath: string,
    fileName: string,
  ): Promise<void> {
    this.logger.log(
      `Loading policy file: ${fileName}`,
    );

    const content = fs.readFileSync(
      filePath,
      'utf-8',
    );

    const lines = content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .filter((line) => !line.startsWith('#'));

    for (const [index, line] of lines.entries()) {
      try {
        const values = this.parseCsvLine(line);

        if (values.length === 0) {
          continue;
        }

        const [ptype, ...policyValues] = values;

        switch (ptype) {
          case 'p':
            await this.enforcer.addPolicy(
              ...policyValues,
            );
            break;

          case 'g':
            await this.enforcer.addGroupingPolicy(
              ...policyValues,
            );
            break;

          case 'g2':
            await this.enforcer.addNamedGroupingPolicy(
              'g2',
              ...policyValues,
            );
            break;

          default:
            this.logger.warn(
              `Unknown policy type "${ptype}" in ${fileName}:${index + 1}`,
            );
        }
      } catch (error) {
        this.logger.error(
          `Failed to load ${fileName}:${index + 1}`,
          error instanceof Error
            ? error.message
            : String(error),
        );
      }
    }

    this.logger.log(
      `Finished loading ${fileName}`,
    );
  }

  /**
   * Simple CSV parser.
   *
   * Example:
   *
   * p, userManagement-search-searchList,
   * hcp, userManagement, search,
   * searchList, edit
   */
  private parseCsvLine(line: string): string[] {
    return line
      .split(',')
      .map((value) => value.trim());
  }

  /**
   * Check whether a role is allowed to perform
   * an action on a specific resource.
   */
  async enforce(
    sub: string,
    lob: string,
    page: string,
    mod: string,
    sec: string,
    access: string,
  ): Promise<boolean> {
    return this.enforcer.enforce(
      sub,
      lob,
      page,
      mod,
      sec,
      access,
    );
  }

  /**
   * Get all g2 mappings for a role.
   */
  async getLandingPagesForRole(
    roleName: string,
  ): Promise<string[][]> {
    return this.enforcer.getFilteredNamedGroupingPolicy(
      'g2',
      0,
      roleName,
    );
  }

  /**
   * Expose the Casbin enforcer.
   */
  getEnforcer(): Enforcer {
    return this.enforcer;
  }

  async getPermissionsForRole(roleName: string) {
    const groupingPolicies = await this.enforcer.getFilteredGroupingPolicy(
        0,
        roleName,
      );

    const permissions: Array<{
      permission: string;
      lob: string;
      page: string;
      module: string;
      section: string;
      access: string;
    }> = [];

    for (const grouping of groupingPolicies) {
      const permissionName = grouping[1];

      const policies = await this.enforcer.getFilteredPolicy(
          0,
          permissionName,
        );

      for (const policy of policies) {
        permissions.push({
          permission: policy[0],
          lob: policy[1],
          page: policy[2],
          module: policy[3],
          section: policy[4],
          access: policy[5],
        });
      }
    }

    return permissions;
}


  async getMenusForRole(roleName: string): Promise<string[]> {
    const groupingPolicies =
      await this.enforcer.getFilteredGroupingPolicy(
        0,
        roleName,
      );

    const menus: string[] = [];

    for (const grouping of groupingPolicies) {
      const target = grouping[1];

      const policies =
        await this.enforcer.getFilteredPolicy(
          0,
          target,
        );

      // If no p policy exists for this target,
      // treat it as a menu mapping.
      if (policies.length === 0) {
        menus.push(target);
      }
    }

    return menus;
  }
}