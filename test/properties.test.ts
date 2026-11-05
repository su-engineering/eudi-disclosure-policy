import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  evaluateRequest,
  type DisclosurePolicyV1,
  type EvaluationResult,
  type Verdict,
} from '../src/index.js';
import { enumerateBranches } from '../src/dcql/branch-model.js';
import { normalizeQuery } from '../src/dcql/normalize.js';
import { dcqlArb, propertyPolicy, ALLOWED_TYPE, VALUE_PREFIX } from './helpers/arbitraries.js';

const RANK: Record<Verdict, number> = { ALLOW: 0, WARN: 1, INDETERMINATE: 2, DENY: 3 };
const T = '2026-11-05T16:00:00Z';
const RUNS = { numRuns: 400 };

function evaluate(
  dcql: unknown,
  policy: DisclosurePolicyV1 = propertyPolicy,
  extra: object = {},
): EvaluationResult {
  return evaluateRequest({ profile: 'openid4vp-1.0', evaluationTime: T, dcql, policy, ...extra });
}

/** Rules that compare alternatives or describe the request as a whole, rather than one element. */
const STRUCTURAL = new Set([
  'CREDENTIAL_SET_EXCESSIVE_OPTION',
  'CLAIM_SET_NONMINIMAL',
  'OPTIONAL_CREDENTIAL_SET',
  'UNREFERENCED_QUERY',
  'BRANCH_LIMIT_REACHED',
]);

function elementVerdict(result: EvaluationResult): Verdict {
  let verdict: Verdict = 'ALLOW';
  for (const f of result.findings)
    if (!STRUCTURAL.has(f.ruleId) && RANK[f.verdict] > RANK[verdict]) verdict = f.verdict;
  return verdict;
}

function resolvePointer(root: unknown, pointer: string): boolean {
  if (pointer === '') return true;
  let node: unknown = root;
  for (const raw of pointer.slice(1).split('/')) {
    const key = raw.replaceAll('~1', '/').replaceAll('~0', '~');
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node, key)) return false;
    node = (node as Record<string, unknown>)[key];
  }
  return true;
}

describe('properties', () => {
  it('per-element analysis equals the worst verdict over every explicitly enumerated branch', () => {
    fc.assert(
      fc.property(dcqlArb, (dcql) => {
        const result = evaluate(dcql);
        const query = normalizeQuery(dcql);
        const { branches, complete } = enumerateBranches(query, 4096);
        expect(complete).toBe(true);
        const raw = dcql['credentials'] as Record<string, unknown>[];
        let worstBranch: Verdict = 'ALLOW';
        for (const branch of branches) {
          // Rebuild the branch as a request with no alternatives left.
          const credentials = branch.selection.map(({ credential, claims }) => {
            const { claims: allClaims, ...rest } = raw[credential]!;
            delete rest['claim_sets'];
            const picked = claims?.map((i) => (allClaims as unknown[])[i]);
            return picked && picked.length > 0 ? { ...rest, claims: picked } : rest;
          });
          if (credentials.length === 0) continue;
          const verdict = elementVerdict(evaluate({ credentials }));
          if (RANK[verdict] > RANK[worstBranch]) worstBranch = verdict;
        }
        expect(elementVerdict(result)).toBe(worstBranch);
      }),
      RUNS,
    );
  });

  it('reordering credential queries does not change the verdict', () => {
    fc.assert(
      fc.property(dcqlArb, fc.integer(), (dcql, seed) => {
        const credentials = [...(dcql['credentials'] as unknown[])];
        const shuffled = credentials
          .map((c, i) => ({ c, k: Math.imul(seed ^ (i + 1), 2654435761) >>> 0 }))
          .sort((a, b) => a.k - b.k)
          .map(({ c }) => c);
        expect(evaluate({ ...dcql, credentials: shuffled }).verdict).toBe(evaluate(dcql).verdict);
      }),
      RUNS,
    );
  });

  it('adding a selectable forbidden alternative never improves the verdict', () => {
    fc.assert(
      fc.property(dcqlArb, (dcql) => {
        const before = evaluate(dcql);
        const forbidden = {
          id: 'forbidden',
          format: 'dc+sd-jwt',
          meta: { vct_values: [ALLOWED_TYPE] },
          claims: [{ path: ['birth_date'] }],
        };
        const sets = dcql['credential_sets'] as { options: string[][] }[] | undefined;
        const after = evaluate({
          credentials: [...(dcql['credentials'] as unknown[]), forbidden],
          ...(sets && {
            credential_sets: [
              { ...sets[0]!, options: [...sets[0]!.options, ['forbidden']] },
              ...sets.slice(1),
            ],
          }),
        });
        expect(after.verdict).toBe('DENY');
        expect(RANK[after.verdict]).toBeGreaterThanOrEqual(RANK[before.verdict]);
      }),
      RUNS,
    );
  });

  it('adding a deny rule never improves the verdict', () => {
    fc.assert(
      fc.property(
        dcqlArb,
        fc.constantFrom(['age_over_18'], ['address'], ['nationalities'], ['family_name']),
        (dcql, path) => {
          const stricter: DisclosurePolicyV1 = {
            ...propertyPolicy,
            credentials: propertyPolicy.credentials.map((rule) => ({
              ...rule,
              allowClaims: rule.allowClaims,
              denyClaims: [
                ...(rule.denyClaims ?? []),
                { path, matching: 'subtree' as const },
              ].filter(
                (d) =>
                  !rule.allowClaims.some(
                    (a) =>
                      JSON.stringify(a.path) === JSON.stringify(d.path) &&
                      a.matching === d.matching,
                  ),
              ),
            })),
          };
          expect(RANK[evaluate(dcql, stricter).verdict]).toBeGreaterThanOrEqual(
            RANK[evaluate(dcql).verdict],
          );
        },
      ),
      RUNS,
    );
  });

  it('verified registration evidence never improves the verdict', () => {
    fc.assert(
      fc.property(
        dcqlArb,
        fc.subarray([['age_over_18'], ['family_name'], ['address']]),
        (dcql, claimPaths) => {
          const registration = {
            state: 'verified' as const,
            provenance: {
              source: 's',
              profile: 'p',
              verifier: 'v',
              verifiedAt: '2026-01-01T00:00:00Z',
              digest: 'd',
            },
            rpId: 'rp',
            allowed: [
              {
                format: 'dc+sd-jwt',
                credentialType: { kind: 'vct' as const, value: ALLOWED_TYPE },
                claimPaths,
              },
            ],
          };
          const withEvidence = evaluate(dcql, propertyPolicy, {
            registration,
            relyingParty: { rpId: 'rp' },
          });
          expect(RANK[withEvidence.verdict]).toBeGreaterThanOrEqual(RANK[evaluate(dcql).verdict]);
        },
      ),
      RUNS,
    );
  });

  it('missing disclosure knowledge never yields ALLOW', () => {
    const unprofiled: DisclosurePolicyV1 = {
      ...propertyPolicy,
      credentials: propertyPolicy.credentials.map((rule) => {
        const copy = { ...rule };
        delete copy.disclosureProfile;
        return copy;
      }),
    };
    fc.assert(
      fc.property(dcqlArb, (dcql) => {
        expect(evaluate(dcql, unprofiled).verdict).not.toBe('ALLOW');
      }),
      RUNS,
    );
  });

  it('every finding pointer resolves against the original input', () => {
    fc.assert(
      fc.property(dcqlArb, (dcql) => {
        for (const finding of evaluate(dcql).findings)
          expect(resolvePointer(dcql, finding.jsonPointer)).toBe(true);
      }),
      RUNS,
    );
  });

  it('claim values never appear in results', () => {
    fc.assert(
      fc.property(dcqlArb, (dcql) => {
        expect(canonicalJson(evaluate(dcql))).not.toContain(VALUE_PREFIX);
      }),
      RUNS,
    );
  });

  it('evaluation is deterministic', () => {
    fc.assert(
      fc.property(dcqlArb, (dcql) => {
        expect(canonicalJson(evaluate(structuredClone(dcql)))).toBe(canonicalJson(evaluate(dcql)));
      }),
      { numRuns: 100 },
    );
  });
});
