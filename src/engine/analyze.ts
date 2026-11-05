/**
 * Policy analysis of a normalized DCQL query. See docs/concepts.md for the
 * evaluation model and docs/rule-reference.md for every rule.
 */
import { reachability, credentialOptionLabel, claimOptionLabel } from '../dcql/branch-model.js';
import {
  denyRuleHits,
  formatPath,
  isBroaderThan,
  pathHasWildcard,
  pathsEqual,
  ruleCovers,
} from '../dcql/path.js';
import { appendPointer } from '../pointer.js';
import type { EffectiveDefaults } from '../policy/validate.js';
import type {
  NormalizedClaim,
  NormalizedCredential,
  NormalizedQuery,
  CredentialTypeRef,
} from '../dcql/normalize.js';
import type { CredentialRule, DisclosurePolicyV1, Finding, Verdict } from '../types.js';
import { display, worst, type FindingCollector } from './findings.js';
import { registeredCovers, registeredEntry, type RegistrationGate } from './registration.js';

interface Context {
  readonly query: NormalizedQuery;
  readonly policy: DisclosurePolicyV1;
  readonly defaults: EffectiveDefaults;
  readonly gate: RegistrationGate;
  readonly out: FindingCollector;
}

const join = (...labels: (string | undefined)[]): string | undefined => {
  const present = labels.filter((l): l is string => l !== undefined);
  return present.length > 0 ? present.join('+') : undefined;
};

const within = (finding: Finding, base: string): boolean =>
  finding.jsonPointer === base || finding.jsonPointer.startsWith(base + '/');

function findRule(
  policy: DisclosurePolicyV1,
  format: string,
  type: CredentialTypeRef,
): CredentialRule | undefined {
  return policy.credentials.find(
    (r) =>
      r.format === format &&
      r.credentialType.kind === type.kind &&
      r.credentialType.value === type.value,
  );
}

function typeLabel(type: CredentialTypeRef): string {
  return `${type.kind} ${display(type.value)}`;
}

/** Evaluate one claim against one matched credential rule. Returns the outcome verdict. */
function evaluateClaim(
  ctx: Context,
  credential: NormalizedCredential,
  type: CredentialTypeRef,
  rule: CredentialRule,
  claim: NormalizedClaim,
  branchId: string | undefined,
): Verdict {
  const { out, defaults } = ctx;
  const pathPointer = appendPointer(claim.pointer, 'path');
  const path = formatPath(claim.path);
  const common = { queryId: credential.id, branchId, policyRuleId: rule.id };
  const verdicts: Verdict[] = [];

  const denyIndex = (rule.denyClaims ?? []).findIndex((d) => denyRuleHits(d, claim.path));
  const allowRule = rule.allowClaims.find((a) => ruleCovers(a, claim.path));
  if (denyIndex >= 0) {
    const denied = rule.denyClaims![denyIndex]!;
    out.add('CLAIM_EXPLICITLY_DENIED', 'DENY', {
      ...common,
      pointer: pathPointer,
      message: pathsEqual(denied.path, claim.path)
        ? `Credential query '${credential.id}' requests ${path}, denied by policy rule '${rule.id}' for ${typeLabel(type)}.`
        : `Credential query '${credential.id}' requests ${path}, which may disclose ${formatPath(denied.path)}, denied by policy rule '${rule.id}' for ${typeLabel(type)}.`,
      details: {
        path: claim.path,
        denyRule: denyIndex,
        ...(denied.classification && { classification: denied.classification }),
      },
    });
    verdicts.push('DENY');
  } else if (!allowRule) {
    if (rule.allowClaims.some((a) => isBroaderThan(a, claim.path))) {
      const verdict: Verdict = defaults.broadSelector === 'deny' ? 'DENY' : 'INDETERMINATE';
      out.add('BROAD_CLAIM_SELECTOR', verdict, {
        ...common,
        pointer: pathPointer,
        message: `Credential query '${credential.id}' requests ${path}, which ${pathHasWildcard(claim.path) ? 'uses a wildcard' : 'selects a parent object'} broader than the paths policy rule '${rule.id}' allows.`,
        details: { path: claim.path },
      });
      verdicts.push(verdict);
    } else {
      const verdict: Verdict = defaults.unknownClaim === 'deny' ? 'DENY' : 'INDETERMINATE';
      out.add('CLAIM_NOT_ALLOWED_FOR_PURPOSE', verdict, {
        ...common,
        pointer: pathPointer,
        message: `Credential query '${credential.id}' requests ${path}, outside the purpose '${ctx.policy.purposeId}' allowlist for ${typeLabel(type)}.`,
        details: { path: claim.path },
      });
      verdicts.push(verdict);
    }
  }

  if (claim.intentToRetain) {
    if (allowRule?.allowRetention === true && denyIndex < 0) {
      out.add('MDOC_RETENTION_REQUESTED', 'ALLOW', {
        ...common,
        pointer: claim.intentToRetain.pointer,
        message: `Credential query '${credential.id}' declares intent to retain ${path}; policy rule '${rule.id}' permits retention.`,
      });
    } else {
      const verdict: Verdict = defaults.retentionIntent === 'warn' ? 'WARN' : 'DENY';
      out.add('MDOC_RETENTION_REQUESTED', verdict, {
        ...common,
        pointer: claim.intentToRetain.pointer,
        message: `Credential query '${credential.id}' declares intent to retain ${path}, which the policy does not permit.`,
      });
      verdicts.push(verdict);
    }
  }

  if (ctx.gate.scope) {
    const entry = registeredEntry(ctx.gate.scope, credential.format, type.kind, type.value);
    if (entry && !registeredCovers(entry, claim.path)) {
      out.add('CLAIM_NOT_IN_REGISTERED_SCOPE', 'DENY', {
        ...common,
        pointer: pathPointer,
        evidenceIds: ctx.gate.evidenceIds,
        message: `Credential query '${credential.id}' requests ${path}, which the registration evidence does not list for ${typeLabel(type)}.`,
        details: { path: claim.path },
      });
      verdicts.push('DENY');
    }
  }
  return worst(verdicts);
}

/** Disclosure-profile checks for one matched type. Returns the outcome verdict. */
function evaluateDisclosure(
  ctx: Context,
  credential: NormalizedCredential,
  type: CredentialTypeRef,
  rule: CredentialRule,
): Verdict {
  const profile = rule.disclosureProfile;
  const common = { queryId: credential.id, policyRuleId: rule.id };
  if (!profile || profile.mode === 'unknown' || profile.knownMandatoryPaths === undefined) {
    const verdict: Verdict = ctx.defaults.unknownDisclosure === 'warn' ? 'WARN' : 'INDETERMINATE';
    const fullCredential = profile?.mode === 'non-selective' && !credential.claims;
    ctx.out.add('UNKNOWN_DISCLOSURE_PROFILE', verdict, {
      ...common,
      pointer: type.pointer,
      message: fullCredential
        ? `Credential query '${credential.id}' requests a non-selectively disclosable ${typeLabel(type)} without claims, so the full credential is presented, and policy rule '${rule.id}' does not describe its content.`
        : `Policy rule '${rule.id}' does not describe what presenting ${typeLabel(type)} discloses beyond the requested claims, so minimal disclosure cannot be established.`,
      details: { mode: profile?.mode ?? 'absent' },
    });
    return verdict;
  }
  const verdicts: Verdict[] = [];
  for (const mandatory of profile.knownMandatoryPaths) {
    const denied = (rule.denyClaims ?? []).some((d) => denyRuleHits(d, mandatory));
    const allowed = rule.allowClaims.some((a) => ruleCovers(a, mandatory));
    if (denied || !allowed) {
      ctx.out.add('MANDATORY_DISCLOSURE_EXCEEDS_POLICY', 'DENY', {
        ...common,
        pointer: type.pointer,
        message: `Presenting ${typeLabel(type)} always discloses ${formatPath(mandatory)}, which policy rule '${rule.id}' ${denied ? 'denies' : 'does not allow'}.`,
        details: { path: mandatory, reason: denied ? 'denied' : 'not-allowed' },
      });
      verdicts.push('DENY');
    }
  }
  return worst(verdicts);
}

function evaluateCredential(
  ctx: Context,
  credential: NormalizedCredential,
  labels: readonly string[] | undefined,
  claimReach: ReadonlyMap<number, readonly string[] | undefined>,
): void {
  const { out, defaults } = ctx;
  const credentialBranch = labels?.[0];
  const common = { queryId: credential.id, branchId: credentialBranch };

  if (credential.multiple) {
    out.add(
      'MULTIPLE_CREDENTIALS_REQUESTED',
      defaults.permitMultipleCredentials ? 'WARN' : 'DENY',
      {
        ...common,
        pointer: credential.multiple.pointer,
        message: `Credential query '${credential.id}' sets multiple: true, allowing several credentials to be returned.`,
      },
    );
  }
  if (credential.holderBindingDisabled) {
    out.add('HOLDER_BINDING_DISABLED', defaults.permitHolderBindingDisabled ? 'WARN' : 'DENY', {
      ...common,
      pointer: credential.holderBindingDisabled.pointer,
      message: `Credential query '${credential.id}' accepts a presentation without cryptographic holder binding.`,
    });
  }
  if (!credential.supported) {
    out.add('UNSUPPORTED_CREDENTIAL_FORMAT', 'INDETERMINATE', {
      ...common,
      pointer: appendPointer(credential.pointer, 'format'),
      message: `Credential query '${credential.id}' uses format ${display(credential.format)}, which no format adapter supports; its claims were not interpreted.`,
      details: { supportedFormats: ['dc+sd-jwt', 'mso_mdoc'] },
    });
    return;
  }

  for (const claim of credential.claims ?? []) {
    if (claim.values && claimReach.has(claim.index)) {
      out.add('VALUE_FILTER_PROBING_RISK', defaults.permitValueConstraints ? 'WARN' : 'DENY', {
        queryId: credential.id,
        branchId: join(credentialBranch, claimReach.get(claim.index)?.[0]),
        pointer: claim.values.pointer,
        message: `Credential query '${credential.id}' filters ${formatPath(claim.path)} by value; a match or non-match can reveal attribute information, and value matching is not a security control.`,
        details: { valueConstraintsCount: claim.values.count, valueTypes: claim.values.types },
      });
    }
  }
  if (credential.claims && credential.claimSets) {
    for (const claim of credential.claims) {
      if (!claimReach.has(claim.index)) {
        out.add('UNREFERENCED_QUERY', 'ALLOW', {
          queryId: credential.id,
          pointer: claim.pointer,
          message: `Claims query ${claim.index} of '${credential.id}' is not in any claim_sets option, so it is never requested.`,
        });
      }
    }
  }

  const typeOutcomes: Verdict[] = [];
  for (const type of credential.types) {
    const outcomes: Verdict[] = [];
    if (
      ctx.gate.scope &&
      !registeredEntry(ctx.gate.scope, credential.format, type.kind, type.value)
    ) {
      out.add('CLAIM_NOT_IN_REGISTERED_SCOPE', 'DENY', {
        ...common,
        pointer: type.pointer,
        evidenceIds: ctx.gate.evidenceIds,
        message: `Credential query '${credential.id}' accepts ${typeLabel(type)}, which the registration evidence does not list.`,
      });
      outcomes.push('DENY');
    }
    const rule = findRule(ctx.policy, credential.format, type);
    if (!rule) {
      const verdict: Verdict = defaults.unknownCredential === 'deny' ? 'DENY' : 'INDETERMINATE';
      out.add('CREDENTIAL_TYPE_NOT_ALLOWED', verdict, {
        ...common,
        pointer: type.pointer,
        message: `Credential query '${credential.id}' accepts ${credential.format} ${typeLabel(type)}, which no credential rule in the policy allows.`,
      });
      outcomes.push(verdict);
    } else {
      outcomes.push(evaluateDisclosure(ctx, credential, type, rule));
      for (const claim of credential.claims ?? []) {
        if (!claimReach.has(claim.index)) continue;
        outcomes.push(
          evaluateClaim(
            ctx,
            credential,
            type,
            rule,
            claim,
            join(credentialBranch, claimReach.get(claim.index)?.[0]),
          ),
        );
      }
    }
    typeOutcomes.push(worst(outcomes));
  }
  if (new Set(typeOutcomes).size > 1) {
    out.add('CREDENTIAL_TYPE_AMBIGUOUS', 'INDETERMINATE', {
      ...common,
      pointer: appendPointer(credential.pointer, 'meta', 'vct_values'),
      message: `Credential query '${credential.id}' accepts ${credential.types.length} types whose policy outcomes differ; the wallet chooses which type to present.`,
      details: { typeCount: credential.types.length },
    });
  }
}

const complies = (verdict: Verdict): boolean => verdict === 'ALLOW' || verdict === 'WARN';

const isStrictSubset = (a: readonly number[], b: readonly number[]): boolean =>
  a.length < b.length && a.every((x) => b.includes(x));

/** Compare alternatives within each credential set and claim set. */
function evaluateAlternatives(ctx: Context, findings: readonly Finding[]): void {
  const { query, out } = ctx;
  const worstWithin = (base: string): Verdict =>
    worst(findings.filter((f) => within(f, base)).map((f) => f.verdict));

  for (const set of query.credentialSets ?? []) {
    const optionWorst = set.options.map((option) =>
      worst(option.map((i) => worstWithin(query.credentials[i]!.pointer))),
    );
    if (!set.required) {
      out.add('OPTIONAL_CREDENTIAL_SET', 'ALLOW', {
        pointer: appendPointer(set.pointer, 'required'),
        message: `Credential set ${set.index} is optional, but it is still requested and was evaluated in full.`,
      });
    }
    set.options.forEach((option, j) => {
      const label = credentialOptionLabel(set.index, j);
      const ids = option.map((i) => query.credentials[i]!.id);
      const compliant = set.options.flatMap((_, m) =>
        m !== j && complies(optionWorst[m]!) ? [credentialOptionLabel(set.index, m)] : [],
      );
      if (optionWorst[j] === 'DENY' && compliant.length > 0) {
        out.add('CREDENTIAL_SET_EXCESSIVE_OPTION', 'DENY', {
          branchId: label,
          pointer: appendPointer(set.pointer, 'options', j),
          message: `Option ${j} of credential set ${set.index} (${ids.map((id) => `'${id}'`).join(', ')}) violates the policy, while ${compliant.join(', ')} complies. The wallet may present any option.`,
          details: { compliantAlternatives: compliant },
        });
      } else if (optionWorst[j] !== 'DENY') {
        const smaller = set.options.flatMap((other, m) =>
          m !== j && isStrictSubset(other, option) ? [credentialOptionLabel(set.index, m)] : [],
        );
        if (smaller.length > 0) {
          out.add('CREDENTIAL_SET_EXCESSIVE_OPTION', 'WARN', {
            branchId: label,
            pointer: appendPointer(set.pointer, 'options', j),
            message: `Option ${j} of credential set ${set.index} requests every credential of ${smaller.join(', ')} and more.`,
            details: { smallerAlternatives: smaller },
          });
        }
      }
    });
  }

  for (const credential of query.credentials) {
    if (
      !credential.claimSets ||
      credential.claimSets.length < 2 ||
      !credential.claims ||
      !credential.supported
    )
      continue;
    const claimWorst = (i: number): Verdict => worstWithin(credential.claims![i]!.pointer);
    const optionWorst = credential.claimSets.map((option) => worst(option.map(claimWorst)));
    credential.claimSets.forEach((option, k) => {
      const label = claimOptionLabel(credential.id, k);
      const pointer = appendPointer(credential.pointer, 'claim_sets', k);
      const compliant = credential.claimSets!.flatMap((_, m) =>
        m !== k && complies(optionWorst[m]!) ? [claimOptionLabel(credential.id, m)] : [],
      );
      if (optionWorst[k] === 'DENY' && compliant.length > 0) {
        out.add('CLAIM_SET_NONMINIMAL', 'DENY', {
          queryId: credential.id,
          branchId: label,
          pointer,
          message: `Claim set option ${k} of '${credential.id}' violates the policy, while ${compliant.join(', ')} complies. Option order is only a preference.`,
          details: { compliantAlternatives: compliant },
        });
      } else if (optionWorst[k] !== 'DENY') {
        const smaller = credential.claimSets!.flatMap((other, m) =>
          m !== k && isStrictSubset(other, option) ? [m] : [],
        );
        if (smaller.length > 0) {
          const preferred = smaller.some((m) => m > k);
          out.add('CLAIM_SET_NONMINIMAL', 'WARN', {
            queryId: credential.id,
            branchId: label,
            pointer,
            message: `Claim set option ${k} of '${credential.id}' requests every claim of option ${smaller.join(', ')} and more${preferred ? ', and is preferred over it' : ''}.`,
            details: {
              smallerAlternatives: smaller.map((m) => claimOptionLabel(credential.id, m)),
            },
          });
        }
      }
    });
  }
}

export interface AnalysisSummary {
  readonly selectableCredentials: number;
  readonly supportedSelectableCredentials: number;
}

export function analyze(ctx: Context): AnalysisSummary {
  const { query, policy, defaults, out } = ctx;
  const reach = reachability(query);

  if (
    defaults.maxCredentialQueries !== undefined &&
    query.credentials.length > defaults.maxCredentialQueries
  ) {
    out.add('REQUEST_SIZE_EXCEEDS_POLICY', 'DENY', {
      pointer: '/credentials',
      message: `The request has ${query.credentials.length} credential queries; policy '${policy.policyId}' allows at most ${defaults.maxCredentialQueries}.`,
      details: { count: query.credentials.length, max: defaults.maxCredentialQueries },
    });
  }
  const claimCount = query.credentials.reduce((n, c) => n + (c.claims?.length ?? 0), 0);
  if (defaults.maxClaimQueries !== undefined && claimCount > defaults.maxClaimQueries) {
    out.add('REQUEST_SIZE_EXCEEDS_POLICY', 'DENY', {
      pointer: '/credentials',
      message: `The request has ${claimCount} claims queries; policy '${policy.policyId}' allows at most ${defaults.maxClaimQueries}.`,
      details: { count: claimCount, max: defaults.maxClaimQueries },
    });
  }

  for (const credential of query.credentials) {
    if (!reach.credentials.has(credential.index)) {
      out.add('UNREFERENCED_QUERY', 'ALLOW', {
        queryId: credential.id,
        pointer: credential.pointer,
        message: `Credential query '${credential.id}' is not in any credential_sets option, so it is never requested.`,
      });
      continue;
    }
    evaluateCredential(
      ctx,
      credential,
      reach.credentials.get(credential.index),
      reach.claims.get(credential.index)!,
    );
  }

  // Extensions inside never-requested queries cannot affect disclosure.
  const unreferenced = query.credentials.flatMap((c) => {
    if (!reach.credentials.has(c.index)) return [c.pointer];
    const claimReach = reach.claims.get(c.index)!;
    return (c.claims ?? [])
      .filter((claim) => !claimReach.has(claim.index))
      .map((claim) => claim.pointer);
  });
  const reviewed = new Set(policy.reviewedExtensions ?? []);
  for (const extension of query.extensions) {
    if (unreferenced.some((base) => extension.pointer.startsWith(base + '/'))) continue;
    const verdict: Verdict = reviewed.has(extension.name)
      ? 'ALLOW'
      : defaults.unknownExtension === 'warn'
        ? 'WARN'
        : 'INDETERMINATE';
    out.add('UNKNOWN_EXTENSION_REVIEW', verdict, {
      pointer: extension.pointer,
      message:
        verdict === 'ALLOW'
          ? `Extension property ${display(extension.name)} was reviewed by the policy owner.`
          : `Property ${display(extension.name)} is not defined by OpenID4VP 1.0 at this position; a wallet that understands it may disclose differently.`,
      details: { name: extension.name },
    });
  }

  evaluateAlternatives(ctx, out.findings);

  const selectable = [...reach.credentials.keys()].map((i) => query.credentials[i]!);
  return {
    selectableCredentials: selectable.length,
    supportedSelectableCredentials: selectable.filter((c) => c.supported).length,
  };
}
