/**
 * Registered-scope gate. Evidence is caller-asserted: this module never
 * verifies signatures, certificates, or registries. It only decides whether
 * asserted evidence is complete, fresh, and applicable enough to compare
 * against, and fails closed otherwise.
 */
import { canonicalJson } from '../canonical.js';
import { InputValidationError } from '../errors.js';
import { ruleCovers } from '../dcql/path.js';
import { sha256Hex } from '../sha256.js';
import type { EffectiveDefaults } from '../policy/validate.js';
import type {
  DcqlPath,
  InputEvidenceState,
  RegistrationScopeEvidence,
  RelyingPartyContext,
} from '../types.js';
import type { FindingCollector } from './findings.js';

const UTC_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?Z$/;

/** Parse a strict UTC timestamp to epoch milliseconds, or undefined. */
export function parseUtc(value: unknown): number | undefined {
  if (typeof value !== 'string') return undefined;
  const match = UTC_TIMESTAMP.exec(value);
  if (!match) return undefined;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  const check = new Date(ms);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return undefined;
  }
  const fraction = match[7] ? Number(match[7].slice(1, 4).padEnd(3, '0')) : 0;
  return ms + fraction;
}

const TOXIC = new Set(['__proto__', 'constructor', 'prototype']);

function fail(message: string): never {
  throw new InputValidationError('registration', `Invalid registration evidence: ${message}`);
}

function plainObject(
  value: unknown,
  where: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    fail(`${where} must be an object`);
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail(`${where} must be a plain object`);
  for (const key of Object.keys(value)) {
    if (TOXIC.has(key) || !allowed.includes(key)) fail(`${where} has an unsupported key`);
  }
  return value as Record<string, unknown>;
}

function isPath(value: unknown): value is DcqlPath {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 64 &&
    value.every(
      (s) =>
        typeof s === 'string' ||
        s === null ||
        (typeof s === 'number' && Number.isSafeInteger(s) && s >= 0),
    )
  );
}

/** Validate the shape of caller-supplied evidence. Shape says nothing about trust. */
export function validateRegistrationEvidence(value: unknown): RegistrationScopeEvidence {
  const evidence = plainObject(value, 'evidence', [
    'state',
    'provenance',
    'rpId',
    'serviceId',
    'intendedUseId',
    'allowed',
  ]);
  if (!['verified', 'unverified', 'absent'].includes(evidence['state'] as string)) {
    fail('state must be "verified", "unverified", or "absent"');
  }
  for (const key of ['rpId', 'serviceId', 'intendedUseId']) {
    if (evidence[key] !== undefined && typeof evidence[key] !== 'string')
      fail(`${key} must be a string`);
  }
  if (evidence['provenance'] !== undefined) {
    const provenance = plainObject(evidence['provenance'], 'provenance', [
      'source',
      'profile',
      'verifier',
      'verifiedAt',
      'expiresAt',
      'digest',
    ]);
    for (const [key, item] of Object.entries(provenance)) {
      if (typeof item !== 'string') fail(`provenance.${key} must be a string`);
    }
  }
  const allowed = evidence['allowed'];
  if (!Array.isArray(allowed) || allowed.length > 1024)
    fail('allowed must be an array of at most 1024 entries');
  allowed.forEach((entry, i) => {
    const e = plainObject(entry, `allowed[${i}]`, ['format', 'credentialType', 'claimPaths']);
    if (typeof e['format'] !== 'string') fail(`allowed[${i}].format must be a string`);
    const type = plainObject(e['credentialType'], `allowed[${i}].credentialType`, [
      'kind',
      'value',
    ]);
    if (
      (type['kind'] !== 'vct' && type['kind'] !== 'doctype') ||
      typeof type['value'] !== 'string'
    ) {
      fail(`allowed[${i}].credentialType must have kind "vct" or "doctype" and a string value`);
    }
    const paths = e['claimPaths'];
    if (!Array.isArray(paths) || paths.length > 4096 || !paths.every(isPath)) {
      fail(`allowed[${i}].claimPaths must be an array of claims path pointers`);
    }
  });
  return evidence as unknown as RegistrationScopeEvidence;
}

export interface RegistrationGate {
  readonly state: InputEvidenceState;
  /** Present only when evidence is usable for comparison. */
  readonly scope: RegistrationScopeEvidence['allowed'] | undefined;
  readonly evidenceIds: readonly string[] | undefined;
}

export function evaluateRegistrationGate(
  evidence: RegistrationScopeEvidence | undefined,
  relyingParty: RelyingPartyContext | undefined,
  evaluationTimeMs: number,
  defaults: EffectiveDefaults,
  out: FindingCollector,
): RegistrationGate {
  const active = defaults.registrationEvidenceRequired || evidence !== undefined;
  if (!active) return { state: 'absent', scope: undefined, evidenceIds: undefined };
  const evidenceIds = evidence
    ? [`registration-evidence:sha-256:${sha256Hex(canonicalJson(evidence))}`]
    : undefined;

  if (!evidence || evidence.state === 'absent') {
    if (defaults.registrationEvidenceRequired) {
      out.add('REGISTRATION_EVIDENCE_MISSING', 'INDETERMINATE', {
        pointer: '',
        message:
          'The policy requires a registered-scope comparison, but no registration evidence was supplied. The request is not treated as registered.',
        evidenceIds,
      });
    }
    return { state: 'absent', scope: undefined, evidenceIds };
  }

  if (evidence.state === 'unverified') {
    out.add('REGISTRATION_EVIDENCE_UNVERIFIED', 'INDETERMINATE', {
      pointer: '',
      message:
        'Registration evidence is marked unverified, so its scope is not used for comparison.',
      evidenceIds,
    });
    return { state: 'unverified', scope: undefined, evidenceIds };
  }

  const reasons: string[] = [];
  const p = evidence.provenance;
  const verifiedAt = parseUtc(p?.verifiedAt);
  const expiresAt = p?.expiresAt === undefined ? undefined : parseUtc(p.expiresAt);
  if (
    !p ||
    !p.source ||
    !p.profile ||
    !p.verifier ||
    !p.digest ||
    verifiedAt === undefined ||
    (p.expiresAt !== undefined && expiresAt === undefined)
  ) {
    reasons.push('provenance-incomplete');
  }
  if (verifiedAt !== undefined && verifiedAt > evaluationTimeMs)
    reasons.push('verified-after-evaluation-time');
  if (expiresAt !== undefined && expiresAt <= evaluationTimeMs) reasons.push('expired');
  if (!relyingParty) {
    reasons.push('relying-party-context-missing');
  } else {
    if (evidence.rpId !== relyingParty.rpId) reasons.push('rp-mismatch');
    if (evidence.serviceId !== undefined || relyingParty.serviceId !== undefined) {
      if (evidence.serviceId !== relyingParty.serviceId) reasons.push('service-mismatch');
    }
    if (evidence.intendedUseId !== undefined || relyingParty.intendedUseId !== undefined) {
      if (evidence.intendedUseId !== relyingParty.intendedUseId)
        reasons.push('intended-use-mismatch');
    }
  }

  if (reasons.length > 0) {
    out.add(
      'REGISTRATION_EVIDENCE_INVALID_OR_STALE',
      defaults.invalidRegistrationEvidence === 'deny' ? 'DENY' : 'INDETERMINATE',
      {
        pointer: '',
        message: `Registration evidence asserted as verified cannot be used: ${reasons.join(', ')}.`,
        evidenceIds,
        details: { reasons },
      },
    );
    return { state: 'unverified', scope: undefined, evidenceIds };
  }
  return { state: 'verified', scope: evidence.allowed, evidenceIds };
}

export function registeredEntry(
  scope: RegistrationScopeEvidence['allowed'],
  format: string,
  kind: 'vct' | 'doctype',
  value: string,
): RegistrationScopeEvidence['allowed'][number] | undefined {
  return scope.find(
    (e) =>
      e.format === format && e.credentialType.kind === kind && e.credentialType.value === value,
  );
}

/** A request for a registered claim, or for part of it, is within registered scope. */
export function registeredCovers(
  entry: RegistrationScopeEvidence['allowed'][number],
  path: DcqlPath,
): boolean {
  return entry.claimPaths.some((registered) =>
    ruleCovers({ path: registered, matching: 'subtree' }, path),
  );
}
