import { canonicalJson } from './canonical.js';
import { countBranches } from './dcql/branch-model.js';
import { normalizeQuery } from './dcql/normalize.js';
import { parseDcql } from './dcql/parse.js';
import { analyze } from './engine/analyze.js';
import { FindingCollector, sortFindings, worst } from './engine/findings.js';
import {
  evaluateRegistrationGate,
  parseUtc,
  validateRegistrationEvidence,
} from './engine/registration.js';
import { InputValidationError, UnsupportedProfileError } from './errors.js';
import { DEFAULT_MAX_BRANCHES, resolveLimits } from './limits.js';
import { effectiveDefaults, validatePolicy } from './policy/validate.js';
import { sha256Hex } from './sha256.js';
import { PACKAGE_NAME, RULES_VERSION, VERSION } from './version.js';
import type {
  Coverage,
  EvaluateRequestInput,
  EvaluationResult,
  Finding,
  InputEvidenceState,
  RelyingPartyContext,
} from './types.js';

function validateRelyingParty(value: unknown): RelyingPartyContext | undefined {
  if (value === undefined) return undefined;
  const fail = (): never => {
    throw new InputValidationError(
      'relyingParty',
      'relyingParty must have a string rpId and optional string serviceId and intendedUseId',
    );
  };
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((k) => !['rpId', 'serviceId', 'intendedUseId'].includes(k))) fail();
  if (typeof record['rpId'] !== 'string' || record['rpId'].length === 0) fail();
  for (const key of ['serviceId', 'intendedUseId']) {
    if (record[key] !== undefined && typeof record[key] !== 'string') fail();
  }
  return record as unknown as RelyingPartyContext;
}

function summarize(findings: readonly Finding[]): EvaluationResult['summary'] {
  return {
    errors: findings.filter((f) => f.verdict === 'DENY').length,
    warnings: findings.filter((f) => f.verdict === 'WARN').length,
    indeterminate: findings.filter((f) => f.verdict === 'INDETERMINATE').length,
    info: findings.filter((f) => f.verdict === 'ALLOW').length,
  };
}

/**
 * Evaluate a DCQL request against a disclosure policy.
 *
 * Pure and synchronous: no network, file system, clock, randomness, or
 * environment access. The same input always yields the same result.
 *
 * Throws `PolicyValidationError`, `InputValidationError`,
 * `UnsupportedProfileError`, or `ResourceLimitError`. An invalid DCQL query
 * is not an exception: it yields a `DENY` result with `DCQL_INVALID`.
 *
 * `ALLOW` means the request satisfies the evaluated, configured rules. It is
 * not a statement about lawful processing, relying-party trust, or what a
 * wallet will disclose.
 */
export function evaluateRequest(input: EvaluateRequestInput): EvaluationResult {
  if ((input as { profile?: unknown }).profile !== 'openid4vp-1.0')
    throw new UnsupportedProfileError();
  const evaluationTimeMs = parseUtc(input.evaluationTime);
  if (evaluationTimeMs === undefined) {
    throw new InputValidationError(
      'evaluationTime',
      'evaluationTime must be a UTC timestamp like 2026-11-05T16:00:00Z',
    );
  }
  const maxBranches = input.options?.maxBranches ?? DEFAULT_MAX_BRANCHES;
  if (!Number.isSafeInteger(maxBranches) || maxBranches < 1 || maxBranches > 1_000_000) {
    throw new InputValidationError(
      'options.maxBranches',
      'options.maxBranches must be an integer from 1 to 1000000',
    );
  }
  const limits = resolveLimits(input.options?.limits);
  const policy = validatePolicy(input.policy);
  const registration =
    input.registration === undefined ? undefined : validateRegistrationEvidence(input.registration);
  const relyingParty = validateRelyingParty(input.relyingParty);
  const defaults = effectiveDefaults(policy);
  const debug = input.options?.debug;

  const out = new FindingCollector(
    debug &&
      ((finding) => {
        debug({ stage: 'finding', data: finding });
      }),
  );
  let coverage: Coverage;
  let registrationState: InputEvidenceState =
    registration?.state === 'absent' || !registration ? 'absent' : 'unverified';
  let branchCount = 0;

  const parsed = parseDcql(input.dcql, limits);
  if (!parsed.ok) {
    for (const problem of parsed.problems) {
      out.add('DCQL_INVALID', 'DENY', {
        pointer: problem.pointer,
        message: problem.message,
        details: { code: problem.code },
      });
    }
    coverage = 'unsupported';
  } else {
    const query = normalizeQuery(parsed.query);
    debug?.({ stage: 'normalized', data: query });
    const gate = evaluateRegistrationGate(
      registration,
      relyingParty,
      evaluationTimeMs,
      defaults,
      out,
    );
    registrationState = gate.state;
    const summary = analyze({ query, policy, defaults, gate, out });

    branchCount = countBranches(query, maxBranches);
    debug?.({ stage: 'branches', data: { branchCount, maxBranches } });
    if (branchCount > maxBranches) {
      out.add('BRANCH_LIMIT_REACHED', 'INDETERMINATE', {
        pointer: '',
        message: `The request has more than ${maxBranches} credential and claim set combinations; branch-level outcomes were not enumerated.`,
        details: { maxBranches },
      });
    }
    const findings = out.findings;
    coverage =
      summary.supportedSelectableCredentials === 0
        ? 'unsupported'
        : findings.some((f) => f.verdict === 'INDETERMINATE')
          ? 'partial'
          : 'complete';
  }

  const findings = sortFindings(out.findings);
  const withinBudget = parsed.ok && branchCount <= maxBranches;
  return {
    apiVersion: '1.0',
    verdict: worst(findings.map((f) => f.verdict)),
    coverage,
    evaluatedAt: input.evaluationTime,
    profile: 'openid4vp-1.0',
    engine: { name: PACKAGE_NAME, version: VERSION, rulesVersion: RULES_VERSION },
    policy: {
      id: policy.policyId,
      version: policy.policyVersion,
      purposeId: policy.purposeId,
      digest: `sha-256:${sha256Hex(canonicalJson(policy))}`,
    },
    registrationEvidence: registrationState,
    summary: summarize(findings),
    findings,
    branchCount,
    analyzedBranches: withinBudget ? branchCount : 0,
    skippedBranches: withinBudget ? 0 : branchCount,
    maxBranches,
  };
}
