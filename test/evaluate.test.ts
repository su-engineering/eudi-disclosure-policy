import { describe, expect, it, vi } from 'vitest';
import {
  InputValidationError,
  PolicyValidationError,
  ResourceLimitError,
  UnsupportedProfileError,
  VERSION,
  canonicalJson,
  evaluateRequest,
  type EvaluateRequestInput,
} from '../src/index.js';
import { fixtureInput, loadFixtures, loadPolicy } from './helpers/fixtures.js';

const policy = loadPolicy('age-gate');
const age = {
  id: 'age',
  format: 'dc+sd-jwt',
  meta: { vct_values: ['urn:example:proof-of-age:v1'] },
  claims: [{ path: ['age_over_18'] }],
};
const input = (overrides: Partial<EvaluateRequestInput> = {}): EvaluateRequestInput => ({
  profile: 'openid4vp-1.0',
  evaluationTime: '2026-11-05T16:00:00Z',
  dcql: { credentials: [age] },
  policy,
  ...overrides,
});

describe('evaluateRequest result', () => {
  it('describes the evaluation', () => {
    const result = evaluateRequest(input());
    expect(result).toMatchObject({
      apiVersion: '1.0',
      verdict: 'ALLOW',
      coverage: 'complete',
      evaluatedAt: '2026-11-05T16:00:00Z',
      profile: 'openid4vp-1.0',
      engine: {
        name: '@su-engineering/eudi-disclosure-policy',
        version: VERSION,
        rulesVersion: '1.0.0',
      },
      policy: { id: 'example.age-gate', version: '1.0.0', purposeId: 'age-verification-over-18' },
      registrationEvidence: 'absent',
      summary: { errors: 0, warnings: 0, indeterminate: 0, info: 0 },
      findings: [],
      branchCount: 1,
      analyzedBranches: 1,
      skippedBranches: 0,
      maxBranches: 2048,
    });
    expect(result.policy.digest).toMatch(/^sha-256:[0-9a-f]{64}$/);
  });

  it('accepts DCQL as JSON text', () => {
    expect(evaluateRequest(input({ dcql: JSON.stringify({ credentials: [age] }) })).verdict).toBe(
      'ALLOW',
    );
  });

  it('fills every finding field the contract promises', () => {
    const result = evaluateRequest(
      input({ dcql: { credentials: [{ ...age, claims: [{ path: ['birth_date'] }] }] } }),
    );
    expect(result.findings[0]).toEqual({
      ruleId: 'CLAIM_EXPLICITLY_DENIED',
      category: 'A',
      severity: 'error',
      verdict: 'DENY',
      message:
        'Credential query \'age\' requests ["birth_date"], denied by policy rule \'proof-of-age\' for vct "urn:example:proof-of-age:v1".',
      jsonPointer: '/credentials/0/claims/0/path',
      queryId: 'age',
      policyRuleId: 'proof-of-age',
      remediation:
        'Remove the claim from the request. Deny rules exist to block data the purpose must never collect.',
      standardRefs: ['OpenID4VP 1.0 §7'],
      details: { path: ['birth_date'], denyRule: 0, classification: 'sensitive' },
    });
  });

  it('changes the policy digest when the policy changes', () => {
    const a = evaluateRequest(input()).policy.digest;
    const b = evaluateRequest(input({ policy: { ...policy, policyVersion: '1.0.1' } })).policy
      .digest;
    expect(a).not.toBe(b);
  });

  it('honors a lower maxBranches budget', () => {
    const dcql = {
      credentials: [age, { ...age, id: 'age2' }],
      credential_sets: [
        { required: false, options: [['age']] },
        { required: false, options: [['age2']] },
      ],
    };
    const result = evaluateRequest(input({ dcql, options: { maxBranches: 3 } }));
    expect(result).toMatchObject({
      verdict: 'INDETERMINATE',
      coverage: 'partial',
      branchCount: 4,
      analyzedBranches: 0,
      skippedBranches: 4,
      maxBranches: 3,
    });
    expect(evaluateRequest(input({ dcql, options: { maxBranches: 4 } })).verdict).toBe('ALLOW');
  });

  it('still reports denials when the branch budget is exceeded', () => {
    const dcql = {
      credentials: [age, { ...age, id: 'bd', claims: [{ path: ['birth_date'] }] }],
      credential_sets: [
        { required: false, options: [['age']] },
        { required: false, options: [['bd']] },
      ],
    };
    const result = evaluateRequest(input({ dcql, options: { maxBranches: 1 } }));
    expect(result.verdict).toBe('DENY');
    expect(result.findings.map((f) => f.ruleId)).toContain('BRANCH_LIMIT_REACHED');
  });
});

describe('invocation errors', () => {
  it('rejects unsupported profiles', () => {
    expect(() => evaluateRequest(input({ profile: 'openid4vp-1.1' as 'openid4vp-1.0' }))).toThrow(
      UnsupportedProfileError,
    );
  });

  it.each(['2026-11-05T16:00:00', '2026-11-05T17:00:00+01:00', 'now', ''])(
    'rejects evaluationTime %j',
    (evaluationTime) => {
      expect(() => evaluateRequest(input({ evaluationTime }))).toThrow(InputValidationError);
    },
  );

  it.each([0, -1, 1.5, 2_000_000])('rejects maxBranches %j', (maxBranches) => {
    expect(() => evaluateRequest(input({ options: { maxBranches } }))).toThrow(
      InputValidationError,
    );
  });

  it('rejects invalid resource limits', () => {
    expect(() => evaluateRequest(input({ options: { limits: { maxDepth: 0 } } }))).toThrow(
      InputValidationError,
    );
  });

  it('rejects invalid policies before looking at the request', () => {
    expect(() =>
      evaluateRequest(
        input({ policy: { ...policy, schemaVersion: '2.0' as '1.0' }, dcql: 'not json' }),
      ),
    ).toThrow(PolicyValidationError);
  });

  it.each([
    [{ state: 'trusted', allowed: [] }],
    [{ state: 'verified' }],
    [
      {
        state: 'verified',
        allowed: [
          { format: 'dc+sd-jwt', credentialType: { kind: 'vct', value: 'x' }, claimPaths: [[]] },
        ],
      },
    ],
    [{ state: 'verified', allowed: [], extra: true }],
    [{ state: 'verified', allowed: [], provenance: { source: 1 } }],
    [{ state: 'verified', allowed: [], rpId: 7 }],
    [[]],
  ])('rejects malformed registration evidence %j', (registration) => {
    expect(() => evaluateRequest(input({ registration: registration as never }))).toThrow(
      InputValidationError,
    );
  });

  it.each([
    [{}],
    [{ rpId: '' }],
    [{ rpId: 'rp', serviceId: 1 }],
    [{ rpId: 'rp', extra: 'x' }],
    ['rp'],
  ])('rejects malformed relyingParty %j', (relyingParty) => {
    expect(() => evaluateRequest(input({ relyingParty: relyingParty as never }))).toThrow(
      InputValidationError,
    );
  });
});

describe('resource limits', () => {
  it('rejects deep nesting without recursion', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < 100_000; i++) deep = { x: deep };
    let error: unknown;
    try {
      evaluateRequest(input({ dcql: { credentials: [age], x_deep: deep } }));
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(ResourceLimitError);
    expect(error).toMatchObject({ code: 'RESOURCE_LIMIT_EXCEEDED', limit: 'maxDepth', max: 32 });
  });

  it('rejects cyclic objects', () => {
    const cyclic: Record<string, unknown> = { credentials: [age] };
    cyclic['self'] = cyclic;
    expect(() => evaluateRequest(input({ dcql: cyclic }))).toThrow(ResourceLimitError);
  });

  it('rejects oversized JSON text before parsing it', () => {
    const parse = vi.spyOn(JSON, 'parse');
    expect(() => evaluateRequest(input({ dcql: ' '.repeat(256 * 1024 + 1) }))).toThrow(
      /maxInputBytes/,
    );
    expect(parse).not.toHaveBeenCalled();
    parse.mockRestore();
  });

  it('rejects oversized objects', () => {
    const big = { credentials: [age], x_pad: 'p'.repeat(300_000) };
    expect(() => evaluateRequest(input({ dcql: big }))).toThrow(/maxInputBytes/);
  });

  it.each([
    [
      'maxCredentialQueries',
      { credentials: Array.from({ length: 33 }, (_, i) => ({ ...age, id: `a${i}` })) },
    ],
    [
      'maxClaimQueries',
      {
        credentials: [
          { ...age, claims: Array.from({ length: 257 }, (_, i) => ({ path: [`c${i}`] })) },
        ],
      },
    ],
    [
      'maxPathSegments',
      {
        credentials: Array.from({ length: 2 }, (_, i) => ({
          ...age,
          id: `a${i}`,
          claims: Array.from({ length: 30 }, (_, j) => ({
            path: Array.from({ length: 20 }, (_, k) => `s${j}-${k}`),
          })),
        })),
      },
    ],
    [
      'maxSetOptions',
      {
        credentials: [age],
        credential_sets: Array.from({ length: 257 }, () => ({ options: [['age']] })),
      },
    ],
  ])('enforces %s', (limit, dcql) => {
    expect(() => evaluateRequest(input({ dcql }))).toThrow(
      expect.objectContaining({ limit }) as Error,
    );
  });

  it('allows callers to lower limits', () => {
    expect(() =>
      evaluateRequest(
        input({
          options: { limits: { maxCredentialQueries: 0 + 1 } },
          dcql: { credentials: [age, { ...age, id: 'b' }] },
        }),
      ),
    ).toThrow(/maxCredentialQueries/);
  });

  it('reports non-JSON values as invalid DCQL', () => {
    const result = evaluateRequest(input({ dcql: { credentials: [age], x_fn: () => 1 } }));
    expect(result.findings.map((f) => [f.ruleId, f.jsonPointer])).toEqual([
      ['DCQL_INVALID', '/x_fn'],
    ]);
  });

  it('never includes input in error messages', () => {
    const secret = 'SYNTH-SECRET-0042';
    try {
      evaluateRequest(
        input({ dcql: JSON.stringify({ credentials: [age], x: secret.repeat(20_000) }) }),
      );
      expect.fail('expected a resource error');
    } catch (error) {
      expect((error as Error).message).not.toContain(secret);
      expect(String((error as Error).stack)).not.toContain(secret);
    }
  });
});

describe('determinism and isolation', () => {
  it('produces byte-identical canonical output across 100 runs', () => {
    for (const fixture of loadFixtures()) {
      const first = canonicalJson(evaluateRequest(fixtureInput(fixture)));
      for (let i = 0; i < 100; i++)
        expect(canonicalJson(evaluateRequest(fixtureInput(fixture)))).toBe(first);
    }
  }, 60_000); // 7,000 evaluations; slow under coverage on shared CI runners.

  it('differs only in evaluatedAt when only the evaluation time changes', () => {
    const a = evaluateRequest(input()) as unknown as Record<string, unknown>;
    const b = evaluateRequest(
      input({ evaluationTime: '2030-01-01T00:00:00Z' }),
    ) as unknown as Record<string, unknown>;
    expect({ ...a, evaluatedAt: undefined }).toEqual({ ...b, evaluatedAt: undefined });
  });

  it('works with network, clock, and randomness unavailable', () => {
    const trap = (name: string) => () => {
      throw new Error(`core used ${name}`);
    };
    const stubs = ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource'] as const;
    for (const name of stubs) vi.stubGlobal(name, trap(name));
    const now = vi.spyOn(Date, 'now').mockImplementation(trap('Date.now'));
    const random = vi.spyOn(Math, 'random').mockImplementation(trap('Math.random'));
    try {
      for (const fixture of loadFixtures()) evaluateRequest(fixtureInput(fixture));
    } finally {
      vi.unstubAllGlobals();
      now.mockRestore();
      random.mockRestore();
    }
  });

  it('does not mutate its inputs', () => {
    for (const fixture of loadFixtures()) {
      const evaluation = fixtureInput(fixture);
      const before = JSON.stringify(evaluation);
      evaluateRequest(evaluation);
      expect(JSON.stringify(evaluation)).toBe(before);
    }
  });

  it('emits debug events only when asked', () => {
    const events: string[] = [];
    evaluateRequest(
      input({
        dcql: { credentials: [{ ...age, claims: [{ path: ['email'] }] }] },
        options: { debug: (e) => events.push(e.stage) },
      }),
    );
    expect(events).toEqual(['normalized', 'finding', 'branches']);
  });
});
