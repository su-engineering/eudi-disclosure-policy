/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment */
import { describe, expect, it } from 'vitest';
import { PolicyValidationError, validatePolicy } from '../src/index.js';
import { loadPolicy } from './helpers/fixtures.js';

const base = loadPolicy('age-gate');
// Tests edit policies as loose JSON on purpose.
type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const clone = (): Json => structuredClone(base);

function issues(policy: unknown): string[] {
  try {
    validatePolicy(policy);
  } catch (error) {
    expect(error).toBeInstanceOf(PolicyValidationError);
    expect((error as PolicyValidationError).code).toBe('POLICY_INVALID');
    return (error as PolicyValidationError).issues.map((i) => `${i.pointer}: ${i.message}`);
  }
  return [];
}

describe('validatePolicy', () => {
  it('accepts every shipped policy', () => {
    for (const name of [
      'age-gate',
      'pid-onboarding',
      'pid-onboarding-registered',
      'mdoc-retention',
    ]) {
      expect(issues(loadPolicy(name))).toEqual([]);
    }
  });

  it('rejects a non-object', () => {
    expect(issues('policy')).toEqual([': must be an object']);
    expect(issues([])).toEqual([': must be an object']);
  });

  it('rejects unsupported schema versions', () => {
    expect(issues({ ...clone(), schemaVersion: '2.0' })).toContain(
      '/schemaVersion: unsupported schema version; expected "1.0"',
    );
  });

  it('rejects unknown keys at every level', () => {
    const p = clone();
    p['extra'] = 1;
    p['credentials'][0]['allowClaims'][0]['note'] = 'x';
    p['defaults']['strict'] = true;
    expect(issues(p)).toEqual([
      '/extra: unknown key',
      '/credentials/0/allowClaims/0/note: unknown key',
      '/defaults/strict: unknown key',
    ]);
  });

  it('rejects prototype-polluting keys', () => {
    const p = JSON.parse(
      JSON.stringify(base).replace('"policyId"', '"__proto__":{"polluted":true},"policyId"'),
    ) as unknown;
    expect(issues(p)).toContain('/__proto__: forbidden key');
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('reports missing required fields', () => {
    const p = clone();
    delete p['purposeId'];
    delete p['defaults']['unknownClaim'];
    expect(issues(p)).toEqual(['/purposeId: is required', '/defaults/unknownClaim: is required']);
  });

  it('requires the type kind to match the format', () => {
    const p = clone();
    p['credentials'][0]['credentialType']['kind'] = 'doctype';
    expect(issues(p)).toEqual([
      '/credentials/0/credentialType/kind: must be "vct" for format dc+sd-jwt',
    ]);
  });

  it('validates claim path segments', () => {
    const p = clone();
    p['credentials'][0]['allowClaims'][0]['path'] = ['a', -1, 1.5, true];
    p['credentials'][0]['denyClaims'][0]['path'] = [];
    expect(issues(p)).toEqual([
      '/credentials/0/allowClaims/0/path/1: must be a string, a non-negative integer, or null',
      '/credentials/0/allowClaims/0/path/2: must be a string, a non-negative integer, or null',
      '/credentials/0/allowClaims/0/path/3: must be a string, a non-negative integer, or null',
      '/credentials/0/denyClaims/0/path: must not be empty',
    ]);
  });

  it('enforces mdoc path shapes', () => {
    const p: Json = loadPolicy('mdoc-retention');
    p['credentials'][0]['allowClaims'].push({ path: ['org.example.mdl.1'], matching: 'exact' });
    p['credentials'][0]['allowClaims'].push({
      path: ['org.example.mdl.1', null],
      matching: 'exact',
    });
    p['credentials'][0]['denyClaims'].push({ path: ['org.example.mdl.1'], matching: 'subtree' });
    expect(issues(p)).toEqual([
      '/credentials/0/allowClaims/1/path: mso_mdoc exact paths must be [namespace, element] strings',
      '/credentials/0/allowClaims/2/path: mso_mdoc exact paths must be [namespace, element] strings',
    ]);
  });

  it('rejects duplicate and contradictory rules', () => {
    const p = clone();
    p['credentials'][0]['allowClaims'].push({ path: ['age_over_18'], matching: 'exact' });
    p['credentials'][0]['denyClaims'].push({ path: ['age_over_18'], matching: 'exact' });
    expect(issues(p)).toEqual([
      '/credentials/0/allowClaims/1: duplicates allow rule 0',
      '/credentials/0/denyClaims/3: contradicts allowClaims/0: the same path cannot be both allowed and denied',
      '/credentials/0/denyClaims/3: contradicts allowClaims/1: the same path cannot be both allowed and denied',
    ]);
  });

  it('allows the same path with different matching in allow and deny lists', () => {
    const p = clone();
    p['credentials'][0]['allowClaims'].push({ path: ['name'], matching: 'subtree' });
    p['credentials'][0]['denyClaims'].push({ path: ['name'], matching: 'exact' });
    expect(issues(p)).toEqual([]);
  });

  it('rejects duplicate rule ids and types', () => {
    const p = clone();
    p['credentials'].push(structuredClone(p['credentials'][0]));
    expect(issues(p)).toEqual([
      '/credentials/1/id: duplicates the id of /credentials/0',
      '/credentials/1/credentialType: duplicates the format and type of /credentials/0',
    ]);
  });

  it('restricts allowRetention to mdoc allow rules', () => {
    const p = clone();
    p['credentials'][0]['allowClaims'][0]['allowRetention'] = true;
    p['credentials'][0]['denyClaims'][0]['allowRetention'] = true;
    expect(issues(p)).toEqual([
      '/credentials/0/allowClaims/0/allowRetention: applies only to mso_mdoc credential rules',
      '/credentials/0/denyClaims/0/allowRetention: unknown key',
    ]);
  });

  it('rejects knownMandatoryPaths with mode unknown', () => {
    const p = clone();
    p['credentials'][0]['disclosureProfile']['mode'] = 'unknown';
    expect(issues(p)).toEqual([
      '/credentials/0/disclosureProfile/knownMandatoryPaths: contradicts mode "unknown"',
    ]);
  });

  it('validates enumerations and limits in defaults', () => {
    const p = clone();
    p['defaults']['unknownClaim'] = 'allow';
    p['defaults']['maxClaimQueries'] = 0;
    p['defaults']['permitValueConstraints'] = 'no';
    expect(issues(p)).toEqual([
      '/defaults/unknownClaim: must be one of "indeterminate", "deny"',
      '/defaults/permitValueConstraints: must be a boolean',
      '/defaults/maxClaimQueries: must be a positive integer',
    ]);
  });

  it('summarizes the first issue in the error message', () => {
    expect(() => validatePolicy({ ...clone(), schemaVersion: '2.0', policyId: '' })).toThrow(
      'Invalid policy at /schemaVersion: unsupported schema version; expected "1.0" (and 1 more)',
    );
  });

  it('rejects class instances and non-plain objects', () => {
    expect(issues(Object.assign(Object.create({ inherited: true }) as object, clone()))).toEqual([
      ': must be a plain JSON object',
    ]);
  });
});
