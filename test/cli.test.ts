import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { EXIT, run, type CliIO } from '../src/cli/run.js';
import { RULE_IDS, VERSION } from '../src/index.js';
import { ROOT } from './helpers/fixtures.js';

const policy = join(ROOT, 'fixtures/policies/age-gate.json');
const T = ['--evaluation-time', '2026-11-05T16:00:00Z'];
const tmp = mkdtempSync(join(tmpdir(), 'eudi-disclosure-cli-'));

function file(name: string, content: unknown): string {
  const path = join(tmp, name);
  writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
  return path;
}

const age = {
  id: 'age',
  format: 'dc+sd-jwt',
  meta: { vct_values: ['urn:example:proof-of-age:v1'] },
  claims: [{ path: ['age_over_18'] }],
};
const allowQuery = file('allow.json', { credentials: [age] });
const denyQuery = file('deny.json', {
  credentials: [age, { ...age, id: 'bd', claims: [{ path: ['birth_date'] }] }],
  credential_sets: [{ options: [['age'], ['bd']] }],
});
const warnQuery = file('warn.json', {
  credentials: [{ ...age, require_cryptographic_holder_binding: false }],
});
const permissive = file('permissive.json', {
  ...(JSON.parse(readFileSync(policy, 'utf8')) as Record<string, unknown>),
  defaults: {
    unknownCredential: 'indeterminate',
    unknownClaim: 'deny',
    unknownDisclosure: 'indeterminate',
    registrationEvidenceRequired: false,
    permitValueConstraints: false,
    permitHolderBindingDisabled: true,
    permitMultipleCredentials: false,
  },
});
const indeterminateQuery = file('indeterminate.json', {
  credentials: [{ id: 'vc', format: 'ldp_vc', meta: {} }],
});

async function cli(
  args: string[],
  stdin = '',
): Promise<{ code: number; stdout: string; stderr: string }> {
  let stdout = '';
  let stderr = '';
  const io: CliIO = {
    stdout: (t) => (stdout += t),
    stderr: (t) => (stderr += t),
    // eslint-disable-next-line @typescript-eslint/require-await
    stdin: async function* () {
      yield stdin;
    },
    now: () => new Date('2026-11-05T12:00:00Z'),
  };
  const code = await run(args, io);
  return { code, stdout, stderr };
}

describe('lint', () => {
  it('exits 0 for ALLOW', async () => {
    expect((await cli(['lint', '--query', allowQuery, '--policy', policy, ...T])).code).toBe(
      EXIT.ok,
    );
  });

  it('exits 1 for DENY', async () => {
    expect((await cli(['lint', '--query', denyQuery, '--policy', policy, ...T])).code).toBe(
      EXIT.deny,
    );
  });

  it('exits 0 for WARN, or 1 with --strict', async () => {
    expect((await cli(['lint', '--query', warnQuery, '--policy', permissive, ...T])).code).toBe(
      EXIT.ok,
    );
    expect(
      (await cli(['lint', '--query', warnQuery, '--policy', permissive, ...T, '--strict'])).code,
    ).toBe(EXIT.deny);
  });

  it('exits 3 for INDETERMINATE', async () => {
    expect(
      (await cli(['lint', '--query', indeterminateQuery, '--policy', policy, ...T])).code,
    ).toBe(EXIT.indeterminate);
  });

  it('reads the query from stdin', async () => {
    const result = await cli(
      ['lint', '--query', '-', '--policy', policy, ...T, '--format', 'json'],
      JSON.stringify({ credentials: [age] }),
    );
    expect(result.code).toBe(EXIT.ok);
    expect(JSON.parse(result.stdout)).toMatchObject({ verdict: 'ALLOW' });
  });

  it('prints canonical JSON only on stdout', async () => {
    const result = await cli([
      'lint',
      '--query',
      denyQuery,
      '--policy',
      policy,
      ...T,
      '--format',
      'json',
    ]);
    expect(result.stderr).toBe('');
    expect(result.stdout.endsWith('\n')).toBe(true);
    expect(result.stdout.trimEnd().includes('\n')).toBe(false);
    await expect(result.stdout).toMatchFileSnapshot('__snapshots__/lint-deny.json');
  });

  it('prints stable human output', async () => {
    const result = await cli(['lint', '--query', denyQuery, '--policy', policy, ...T]);
    await expect(result.stdout).toMatchFileSnapshot('__snapshots__/lint-deny.txt');
  });

  it('uses the injected clock when --evaluation-time is omitted', async () => {
    const result = await cli([
      'lint',
      '--query',
      allowQuery,
      '--policy',
      policy,
      '--format',
      'json',
    ]);
    expect(JSON.parse(result.stdout)).toMatchObject({ evaluatedAt: '2026-11-05T12:00:00.000Z' });
  });

  it('treats an invalid query as DCQL_INVALID without echoing it', async () => {
    const query = file('broken.json', '{"credentials": SYNTH-SECRET-0042');
    const result = await cli(['lint', '--query', query, '--policy', policy, ...T]);
    expect(result.code).toBe(EXIT.deny);
    expect(result.stdout).toContain('DCQL_INVALID');
    expect(result.stdout + result.stderr).not.toContain('SYNTH-SECRET');
  });

  it('reports policy JSON errors without content or paths', async () => {
    const broken = file('policy-broken.json', '{"policyId": "SYNTH-SECRET-0042"');
    const result = await cli(['lint', '--query', allowQuery, '--policy', broken, ...T]);
    expect(result).toMatchObject({ code: EXIT.usage, stdout: '' });
    expect(result.stderr).toBe('eudi-disclosure: The policy file is not valid JSON.\n');
  });

  it('shows file paths only with --no-redact', async () => {
    const missing = join(tmp, 'missing.json');
    expect((await cli(['lint', '--query', missing, '--policy', policy, ...T])).stderr).toBe(
      'eudi-disclosure: Cannot read the query file.\n',
    );
    expect(
      (await cli(['lint', '--query', missing, '--policy', policy, ...T, '--no-redact'])).stderr,
    ).toContain(missing);
  });

  it('exits 2 for invalid policies', async () => {
    const invalid = file('policy-invalid.json', { schemaVersion: '9' });
    const result = await cli(['lint', '--query', allowQuery, '--policy', invalid, ...T]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toMatch(/^eudi-disclosure: POLICY_INVALID: Invalid policy at/);
  });

  it('exits 3 for resource limits and unsupported profiles', async () => {
    const big = file('big.json', `{"credentials":[],"pad":"${'x'.repeat(300_000)}"}`);
    expect((await cli(['lint', '--query', big, '--policy', policy, ...T])).code).toBe(
      EXIT.indeterminate,
    );
    expect(
      (await cli(['lint', '--query', '-', '--policy', policy, ...T], 'x'.repeat(300_000))).code,
    ).toBe(EXIT.indeterminate);
    expect(
      (
        await cli([
          'lint',
          '--query',
          allowQuery,
          '--policy',
          policy,
          ...T,
          '--profile',
          'openid4vp-1.1',
        ])
      ).code,
    ).toBe(EXIT.indeterminate);
  });

  it.each([
    [['lint', '--policy', policy]],
    [['lint', '--query', allowQuery, '--policy', policy, '--format', 'xml']],
    [['lint', '--query', allowQuery, '--policy', policy, '--max-branches', 'many']],
    [['lint', '--query', allowQuery, '--policy', policy, '--unknown']],
    [['lint', '--query', allowQuery, '--policy', policy, '--service-id', 's']],
    [['lint', '--query', allowQuery, '--policy', policy, 'extra']],
    [['lint', '--query', allowQuery, '--policy', policy, '--evaluation-time', 'yesterday']],
    [['frobnicate']],
  ])('exits 2 for usage errors: %j', async (args) => {
    expect((await cli(args)).code).toBe(EXIT.usage);
  });

  it('passes relying-party context and registration evidence', async () => {
    const registration = file('registration.json', {
      state: 'verified',
      provenance: {
        source: 's',
        profile: 'p',
        verifier: 'v',
        verifiedAt: '2026-01-01T00:00:00Z',
        digest: 'd',
      },
      rpId: 'rp',
      serviceId: 'svc',
      allowed: [
        {
          format: 'dc+sd-jwt',
          credentialType: { kind: 'vct', value: 'urn:example:proof-of-age:v1' },
          claimPaths: [['age_over_18']],
        },
      ],
    });
    const ok = await cli([
      'lint',
      '--query',
      allowQuery,
      '--policy',
      policy,
      ...T,
      '--registration',
      registration,
      '--rp-id',
      'rp',
      '--service-id',
      'svc',
      '--format',
      'json',
    ]);
    expect(JSON.parse(ok.stdout)).toMatchObject({
      verdict: 'ALLOW',
      registrationEvidence: 'verified',
    });
    const other = await cli([
      'lint',
      '--query',
      allowQuery,
      '--policy',
      policy,
      ...T,
      '--registration',
      registration,
      '--rp-id',
      'rp',
      '--service-id',
      'other',
    ]);
    expect(other.code).toBe(EXIT.indeterminate);
  });

  it('honors --max-branches', async () => {
    const result = await cli([
      'lint',
      '--query',
      allowQuery,
      '--policy',
      policy,
      ...T,
      '--max-branches',
      '1',
      '--format',
      'json',
    ]);
    expect(JSON.parse(result.stdout)).toMatchObject({ maxBranches: 1, verdict: 'ALLOW' });
  });
});

describe('other commands', () => {
  it('validates policies', async () => {
    expect(await cli(['policy', 'validate', policy])).toMatchObject({
      code: EXIT.ok,
      stdout: expect.stringContaining('Policy example.age-gate@1.0.0 is valid.') as string,
    });
    const json = await cli(['policy', 'validate', policy, '--format', 'json']);
    expect(JSON.parse(json.stdout)).toMatchObject({
      valid: true,
      policy: { id: 'example.age-gate' },
    });
    const invalid = file('invalid-policy.json', { schemaVersion: '1.0' });
    const bad = await cli(['policy', 'validate', invalid]);
    expect(bad.code).toBe(EXIT.usage);
    expect(bad.stdout).toContain('/policyId: is required');
    expect(
      JSON.parse((await cli(['policy', 'validate', invalid, '--format', 'json'])).stdout),
    ).toMatchObject({ valid: false });
    expect((await cli(['policy', 'check', policy])).code).toBe(EXIT.usage);
  });

  it('explains every rule', async () => {
    for (const id of RULE_IDS) {
      const result = await cli(['explain', id]);
      expect(result.code).toBe(EXIT.ok);
      expect(result.stdout.startsWith(`${id} — `)).toBe(true);
    }
    expect((await cli(['lint', '--explain', 'DCQL_INVALID'])).code).toBe(EXIT.ok);
    expect((await cli(['explain', 'NOPE'])).code).toBe(EXIT.usage);
  });

  it('lists rules', async () => {
    expect((await cli(['rules'])).stdout.split('\n').filter(Boolean)).toHaveLength(RULE_IDS.length);
    expect(JSON.parse((await cli(['rules', '--format', 'json'])).stdout)).toHaveLength(
      RULE_IDS.length,
    );
  });

  it('prints version and help', async () => {
    expect((await cli(['--version'])).stdout).toBe(`${VERSION}\n`);
    expect((await cli(['--help'])).stdout).toContain('Exit codes:');
    expect((await cli(['lint', '--help'])).code).toBe(EXIT.ok);
    expect((await cli([])).code).toBe(EXIT.usage);
  });
});

describe.runIf(existsSync(join(ROOT, 'dist/cli.js')))('built executable', () => {
  it('runs with stdin and returns documented exit codes', () => {
    const bin = join(ROOT, 'dist/cli.js');
    const ok = spawnSync(
      process.execPath,
      [bin, 'lint', '--query', '-', '--policy', policy, ...T],
      { input: JSON.stringify({ credentials: [age] }) },
    );
    expect(ok.status).toBe(EXIT.ok);
    const deny = spawnSync(process.execPath, [
      bin,
      'lint',
      '--query',
      denyQuery,
      '--policy',
      policy,
      ...T,
      '--format',
      'json',
    ]);
    expect(deny.status).toBe(EXIT.deny);
    expect(JSON.parse(deny.stdout.toString())).toMatchObject({ verdict: 'DENY' });
  });
});

describe('documentation', () => {
  it('README shows the real CLI output for the age-verification PID alternative', async () => {
    const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
    const block =
      /```text\n\$ npx eudi-disclosure lint --query request\.json --policy policy\.json\n([\s\S]*?)```/.exec(
        readme,
      );
    expect(block).not.toBeNull();
    const example = join(ROOT, 'examples/age-verification');
    const result = await cli([
      'lint',
      '--query',
      join(example, 'requests/pid-alternative.json'),
      '--policy',
      join(example, 'policy.json'),
      ...T,
    ]);
    expect(result.code).toBe(EXIT.deny);
    expect(result.stdout).toBe(block![1]);
  });
});
