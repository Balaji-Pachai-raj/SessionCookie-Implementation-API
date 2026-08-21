import { Helper, Model } from 'casbin';
import { PrismaService } from '../PrismaService/prisma.service';

type CasbinRuleRecord = {
  ptype: string;
  v0?: string | null;
  v1?: string | null;
  v2?: string | null;
  v3?: string | null;
  v4?: string | null;
  v5?: string | null;
};

const RULE_FIELDS = ['v0', 'v1', 'v2', 'v3', 'v4', 'v5'] as const;

/**
 * Custom Casbin adapter for this project's casbin_rule table.
 * casbin-prisma-adapter cannot be used directly because it calls
 * prisma.casbinRule (camelCase) but this schema generates prisma.casbin_rule.
 */
export class PrismaCasbinAdapter {
  constructor(private readonly prisma: PrismaService) {}

  async loadPolicy(model: Model): Promise<void> {
    const rules = await this.prisma.casbin_rule.findMany();
    for (const rule of rules) {
      const parts = [rule.ptype, rule.v0, rule.v1, rule.v2, rule.v3, rule.v4, rule.v5].filter(
        (v): v is string => v !== null && v !== undefined && v !== '',
      );
      Helper.loadPolicyLine(parts.join(', '), model);
    }
  }

  async savePolicy(model: Model): Promise<boolean> {
    await this.prisma.casbin_rule.deleteMany();

    const records: CasbinRuleRecord[] = [];

    for (const section of ['p', 'g']) {
      const sectionMap = model.model.get(section);
      if (!sectionMap) continue;
      for (const [ptype, assertion] of sectionMap) {
        for (const rule of assertion.policy) {
          records.push(this.buildRecord(ptype, rule));
        }
      }
    }

    if (records.length > 0) {
      await this.prisma.casbin_rule.createMany({ data: records });
    }

    return true;
  }

  async addPolicy(_sec: string, ptype: string, rule: string[]): Promise<void> {
    await this.prisma.casbin_rule.create({ data: this.buildRecord(ptype, rule) });
  }

  async addPolicies(_sec: string, ptype: string, rules: string[][]): Promise<void> {
    await this.prisma.casbin_rule.createMany({
      data: rules.map((r) => this.buildRecord(ptype, r)),
    });
  }

  async removePolicy(_sec: string, ptype: string, rule: string[]): Promise<void> {
    await this.prisma.casbin_rule.deleteMany({ where: this.buildRecord(ptype, rule) });
  }

  async removePolicies(_sec: string, ptype: string, rules: string[][]): Promise<void> {
    for (const rule of rules) {
      await this.prisma.casbin_rule.deleteMany({ where: this.buildRecord(ptype, rule) });
    }
  }

  async removeFilteredPolicy(
    _sec: string,
    ptype: string,
    fieldIndex: number,
    ...fieldValues: string[]
  ): Promise<void> {
    const where: Record<string, string> = { ptype };
    for (let i = 0; i < fieldValues.length; i++) {
      if (fieldValues[i] !== '') {
        where[RULE_FIELDS[fieldIndex + i]] = fieldValues[i];
      }
    }
    await this.prisma.casbin_rule.deleteMany({ where });
  }

  private buildRecord(ptype: string, rule: string[]): CasbinRuleRecord {
    const record: CasbinRuleRecord = { ptype };
    for (let i = 0; i < rule.length && i < RULE_FIELDS.length; i++) {
      record[RULE_FIELDS[i]] = rule[i];
    }
    return record;
  }
}
