import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { PolicyValidationError, validatePolicy } from '../src/index.js';
import { ROOT, loadFixtures } from './helpers/fixtures.js';

const schema = JSON.parse(
  readFileSync(join(ROOT, 'schema/disclosure-policy-v1.schema.json'), 'utf8'),
) as object;
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

function accepts(policy: unknown): boolean {
  try {
    validatePolicy(policy);
    return true;
  } catch (error) {
    if (error instanceof PolicyValidationError) return false;
    throw error;
  }
}

describe('JSON Schema', () => {
  it('accepts every policy the validator accepts', () => {
    const policies: unknown[] = readdirSync(join(ROOT, 'fixtures/policies'))
      .filter((name) => name.endsWith('.json'))
      .map(
        (name) =>
          JSON.parse(readFileSync(join(ROOT, 'fixtures/policies', name), 'utf8')) as unknown,
      );
    for (const fixture of loadFixtures())
      if (typeof fixture.policy === 'object') policies.push(fixture.policy);
    for (const dir of ['age-verification', 'pid-onboarding', 'mdoc-retention']) {
      policies.push(
        JSON.parse(readFileSync(join(ROOT, 'examples', dir, 'policy.json'), 'utf8')) as unknown,
      );
    }
    for (const policy of policies) {
      expect(accepts(policy)).toBe(true);
      expect(validate(policy), JSON.stringify(validate.errors)).toBe(true);
    }
  });

  it('rejects structural errors the validator rejects', () => {
    const base = JSON.parse(
      readFileSync(join(ROOT, 'fixtures/policies/age-gate.json'), 'utf8'),
    ) as Record<string, unknown>;
    const broken: unknown[] = [
      { ...base, schemaVersion: '2.0' },
      { ...base, extra: true },
      { ...base, policyId: '' },
      {
        ...base,
        credentials: [
          {
            id: 'x',
            format: 'dc+sd-jwt',
            credentialType: { kind: 'vct', value: 'v' },
            allowClaims: [{ path: [], matching: 'exact' }],
          },
        ],
      },
      { ...base, defaults: { ...(base['defaults'] as object), unknownClaim: 'allow' } },
    ];
    for (const policy of broken) {
      expect(accepts(policy)).toBe(false);
      expect(validate(policy)).toBe(false);
    }
  });
});
