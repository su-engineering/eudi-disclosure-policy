/**
 * DisclosurePolicyV1 validation. Policies are trusted configuration, but they
 * are still parsed strictly: unknown keys, contradictory rules, and paths that
 * cannot apply to the declared format are errors rather than silent no-ops.
 */
import { PolicyValidationError, type PolicyIssue } from '../errors.js';
import { pathsEqual } from '../dcql/path.js';
import { appendPointer } from '../pointer.js';
import type {
  ClaimRule,
  CredentialRule,
  DcqlPath,
  DisclosurePolicyV1,
  PolicyDefaults,
} from '../types.js';

const TOXIC_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_RULES = 1024;
const MAX_CLAIM_RULES = 4096;
const MAX_PATH_LENGTH = 64;
const MAX_STRING = 2048;

export const SUPPORTED_FORMATS = ['dc+sd-jwt', 'mso_mdoc'] as const;

/** Policy defaults after applying documented fallbacks for optional fields. */
export interface EffectiveDefaults extends Required<
  Omit<PolicyDefaults, 'maxCredentialQueries' | 'maxClaimQueries'>
> {
  readonly maxCredentialQueries?: number;
  readonly maxClaimQueries?: number;
}

class Checker {
  readonly issues: PolicyIssue[] = [];

  issue(pointer: string, message: string): void {
    if (this.issues.length < 100) this.issues.push({ pointer, message });
  }

  object(
    value: unknown,
    pointer: string,
    required: readonly string[],
    optional: readonly string[],
  ): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      this.issue(pointer, 'must be an object');
      return false;
    }
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      this.issue(pointer, 'must be a plain JSON object');
      return false;
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
      if (TOXIC_KEYS.has(key)) this.issue(appendPointer(pointer, key), 'forbidden key');
      else if (!allowed.has(key)) this.issue(appendPointer(pointer, key), 'unknown key');
    }
    for (const key of required) {
      if (!Object.hasOwn(value, key)) this.issue(appendPointer(pointer, key), 'is required');
    }
    return true;
  }

  string(record: Record<string, unknown>, key: string, pointer: string): string | undefined {
    if (!Object.hasOwn(record, key)) return undefined;
    const value = record[key];
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_STRING) {
      this.issue(
        appendPointer(pointer, key),
        `must be a non-empty string of at most ${MAX_STRING} characters`,
      );
      return undefined;
    }
    return value;
  }

  boolean(record: Record<string, unknown>, key: string, pointer: string): void {
    if (Object.hasOwn(record, key) && typeof record[key] !== 'boolean') {
      this.issue(appendPointer(pointer, key), 'must be a boolean');
    }
  }

  oneOf(
    record: Record<string, unknown>,
    key: string,
    pointer: string,
    values: readonly string[],
  ): void {
    if (Object.hasOwn(record, key) && !values.includes(record[key] as string)) {
      this.issue(
        appendPointer(pointer, key),
        `must be one of ${values.map((v) => `"${v}"`).join(', ')}`,
      );
    }
  }

  positiveInteger(record: Record<string, unknown>, key: string, pointer: string): void {
    if (!Object.hasOwn(record, key)) return;
    const value = record[key];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
      this.issue(appendPointer(pointer, key), 'must be a positive integer');
    }
  }

  array(value: unknown, pointer: string, max: number, nonEmpty = false): value is unknown[] {
    if (!Array.isArray(value)) {
      this.issue(pointer, 'must be an array');
      return false;
    }
    if (nonEmpty && value.length === 0) {
      this.issue(pointer, 'must not be empty');
      return false;
    }
    if (value.length > max) {
      this.issue(pointer, `must have at most ${max} entries`);
      return false;
    }
    return true;
  }

  path(
    value: unknown,
    pointer: string,
    format: string | undefined,
    matching: unknown,
  ): value is DcqlPath {
    if (!this.array(value, pointer, MAX_PATH_LENGTH, true)) return false;
    let ok = true;
    for (const [i, segment] of value.entries()) {
      const valid =
        typeof segment === 'string' ||
        segment === null ||
        (typeof segment === 'number' && Number.isSafeInteger(segment) && segment >= 0);
      if (!valid) {
        this.issue(appendPointer(pointer, i), 'must be a string, a non-negative integer, or null');
        ok = false;
      }
    }
    if (ok && format === 'mso_mdoc') {
      const strings = value.every((segment) => typeof segment === 'string');
      const lengthOk =
        matching === 'subtree' ? value.length === 1 || value.length === 2 : value.length === 2;
      if (!strings || !lengthOk) {
        this.issue(
          pointer,
          matching === 'subtree'
            ? 'mso_mdoc subtree paths must be [namespace] or [namespace, element] strings'
            : 'mso_mdoc exact paths must be [namespace, element] strings',
        );
        ok = false;
      }
    }
    return ok;
  }
}

function checkClaimRules(
  c: Checker,
  value: unknown,
  pointer: string,
  format: string | undefined,
  kind: 'allow' | 'deny',
): ClaimRule[] {
  if (!c.array(value, pointer, MAX_CLAIM_RULES)) return [];
  const rules: ClaimRule[] = [];
  value.forEach((entry, i) => {
    const p = appendPointer(pointer, i);
    const optional =
      kind === 'allow'
        ? ['reason', 'classification', 'allowRetention']
        : ['reason', 'classification'];
    if (!c.object(entry, p, ['path', 'matching'], optional)) return;
    c.oneOf(entry, 'matching', p, ['exact', 'subtree']);
    c.string(entry, 'reason', p);
    c.oneOf(entry, 'classification', p, ['ordinary', 'sensitive', 'highly-sensitive']);
    c.boolean(entry, 'allowRetention', p);
    if (kind === 'allow' && entry['allowRetention'] === true && format !== 'mso_mdoc') {
      c.issue(appendPointer(p, 'allowRetention'), 'applies only to mso_mdoc credential rules');
    }
    if (c.path(entry['path'], appendPointer(p, 'path'), format, entry['matching'])) {
      rules.push(entry as unknown as ClaimRule);
    }
  });
  rules.forEach((rule, i) => {
    for (let j = 0; j < i; j++) {
      const other = rules[j]!;
      if (pathsEqual(other.path, rule.path) && other.matching === rule.matching) {
        c.issue(appendPointer(pointer, i), `duplicates ${kind} rule ${j}`);
      }
    }
  });
  return rules;
}

function checkCredentialRule(c: Checker, value: unknown, pointer: string): void {
  if (
    !c.object(
      value,
      pointer,
      ['id', 'format', 'credentialType', 'allowClaims'],
      ['denyClaims', 'disclosureProfile'],
    )
  ) {
    return;
  }
  c.string(value, 'id', pointer);
  const format = c.string(value, 'format', pointer);
  const typePointer = appendPointer(pointer, 'credentialType');
  const type = value['credentialType'];
  if (c.object(type, typePointer, ['kind', 'value'], [])) {
    c.oneOf(type, 'kind', typePointer, ['vct', 'doctype']);
    c.string(type, 'value', typePointer);
    const expected = format === 'dc+sd-jwt' ? 'vct' : format === 'mso_mdoc' ? 'doctype' : undefined;
    if (expected && type['kind'] !== expected) {
      c.issue(appendPointer(typePointer, 'kind'), `must be "${expected}" for format ${format}`);
    }
  }
  const allow = checkClaimRules(
    c,
    value['allowClaims'],
    appendPointer(pointer, 'allowClaims'),
    format,
    'allow',
  );
  const deny = Object.hasOwn(value, 'denyClaims')
    ? checkClaimRules(c, value['denyClaims'], appendPointer(pointer, 'denyClaims'), format, 'deny')
    : [];
  deny.forEach((denyRule, i) => {
    allow.forEach((allowRule, j) => {
      if (pathsEqual(denyRule.path, allowRule.path) && denyRule.matching === allowRule.matching) {
        c.issue(
          appendPointer(pointer, 'denyClaims', i),
          `contradicts allowClaims/${j}: the same path cannot be both allowed and denied`,
        );
      }
    });
  });

  if (Object.hasOwn(value, 'disclosureProfile')) {
    const p = appendPointer(pointer, 'disclosureProfile');
    const profile = value['disclosureProfile'];
    if (c.object(profile, p, ['mode'], ['knownMandatoryPaths', 'schemaId', 'schemaVersion'])) {
      c.oneOf(profile, 'mode', p, ['selective', 'non-selective', 'mixed', 'unknown']);
      c.string(profile, 'schemaId', p);
      c.string(profile, 'schemaVersion', p);
      const paths = profile['knownMandatoryPaths'];
      if (
        paths !== undefined &&
        c.array(paths, appendPointer(p, 'knownMandatoryPaths'), MAX_CLAIM_RULES)
      ) {
        paths.forEach((path, i) => {
          c.path(path, appendPointer(p, 'knownMandatoryPaths', i), format, 'exact');
        });
      }
      if (profile['mode'] === 'unknown' && paths !== undefined) {
        c.issue(appendPointer(p, 'knownMandatoryPaths'), 'contradicts mode "unknown"');
      }
    }
  }
}

function checkDefaults(c: Checker, value: unknown, pointer: string): void {
  const required = [
    'unknownCredential',
    'unknownClaim',
    'unknownDisclosure',
    'registrationEvidenceRequired',
    'permitValueConstraints',
    'permitHolderBindingDisabled',
    'permitMultipleCredentials',
  ];
  const optional = [
    'maxCredentialQueries',
    'maxClaimQueries',
    'broadSelector',
    'retentionIntent',
    'unknownExtension',
    'invalidRegistrationEvidence',
  ];
  if (!c.object(value, pointer, required, optional)) return;
  c.oneOf(value, 'unknownCredential', pointer, ['indeterminate', 'deny']);
  c.oneOf(value, 'unknownClaim', pointer, ['indeterminate', 'deny']);
  c.oneOf(value, 'unknownDisclosure', pointer, ['indeterminate', 'warn']);
  c.oneOf(value, 'broadSelector', pointer, ['indeterminate', 'deny']);
  c.oneOf(value, 'retentionIntent', pointer, ['deny', 'warn']);
  c.oneOf(value, 'unknownExtension', pointer, ['indeterminate', 'warn']);
  c.oneOf(value, 'invalidRegistrationEvidence', pointer, ['indeterminate', 'deny']);
  for (const key of [
    'registrationEvidenceRequired',
    'permitValueConstraints',
    'permitHolderBindingDisabled',
    'permitMultipleCredentials',
  ]) {
    c.boolean(value, key, pointer);
  }
  c.positiveInteger(value, 'maxCredentialQueries', pointer);
  c.positiveInteger(value, 'maxClaimQueries', pointer);
}

/**
 * Validate a policy document and return it typed. Throws
 * `PolicyValidationError` listing every issue found (up to 100).
 */
export function validatePolicy(input: unknown): DisclosurePolicyV1 {
  const c = new Checker();
  if (
    c.object(
      input,
      '',
      ['schemaVersion', 'policyId', 'policyVersion', 'purposeId', 'credentials', 'defaults'],
      ['description', 'reviewedExtensions'],
    )
  ) {
    if (Object.hasOwn(input, 'schemaVersion') && input['schemaVersion'] !== '1.0') {
      c.issue('/schemaVersion', 'unsupported schema version; expected "1.0"');
    }
    c.string(input, 'policyId', '');
    c.string(input, 'policyVersion', '');
    c.string(input, 'purposeId', '');
    c.string(input, 'description', '');
    const credentials = input['credentials'];
    if (c.array(credentials, '/credentials', MAX_RULES)) {
      credentials.forEach((rule, i) => {
        checkCredentialRule(c, rule, appendPointer('/credentials', i));
      });
      const seenIds = new Map<string, number>();
      const seenTypes = new Map<string, number>();
      credentials.forEach((rule, i) => {
        if (typeof rule !== 'object' || rule === null) return;
        const r = rule as Partial<CredentialRule>;
        if (typeof r.id === 'string') {
          const prior = seenIds.get(r.id);
          if (prior !== undefined)
            c.issue(`/credentials/${i}/id`, `duplicates the id of /credentials/${prior}`);
          else seenIds.set(r.id, i);
        }
        const typeKey = JSON.stringify([r.format, r.credentialType?.kind, r.credentialType?.value]);
        const priorType = seenTypes.get(typeKey);
        if (priorType !== undefined) {
          c.issue(
            `/credentials/${i}/credentialType`,
            `duplicates the format and type of /credentials/${priorType}`,
          );
        } else {
          seenTypes.set(typeKey, i);
        }
      });
    }
    checkDefaults(c, input['defaults'], '/defaults');
    if (Object.hasOwn(input, 'reviewedExtensions')) {
      const extensions = input['reviewedExtensions'];
      if (c.array(extensions, '/reviewedExtensions', 256)) {
        extensions.forEach((name, i) => {
          if (typeof name !== 'string' || name.length === 0)
            c.issue(`/reviewedExtensions/${i}`, 'must be a non-empty string');
        });
      }
    }
  }
  if (c.issues.length > 0) throw new PolicyValidationError(c.issues);
  return input as DisclosurePolicyV1;
}

export function effectiveDefaults(policy: DisclosurePolicyV1): EffectiveDefaults {
  const d = policy.defaults;
  return {
    ...d,
    broadSelector: d.broadSelector ?? 'indeterminate',
    retentionIntent: d.retentionIntent ?? 'deny',
    unknownExtension: d.unknownExtension ?? 'indeterminate',
    invalidRegistrationEvidence: d.invalidRegistrationEvidence ?? 'indeterminate',
  };
}
