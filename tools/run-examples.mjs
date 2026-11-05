/**
 * Run every documented example against the built CLI and API. Each example
 * directory has an expected.json listing requests, extra CLI arguments, the
 * expected verdict, and the exact set of rule IDs in the result.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const cli = join(root, 'dist', 'cli.js');
assert.ok(existsSync(cli), 'Build first: pnpm build');
const EXIT = { ALLOW: 0, WARN: 0, DENY: 1, INDETERMINATE: 3 };
let count = 0;

for (const name of readdirSync(join(root, 'examples')).sort()) {
  const dir = join(root, 'examples', name);
  const manifest = join(dir, 'expected.json');
  if (!existsSync(manifest)) continue;
  const { policy, runs } = JSON.parse(readFileSync(manifest, 'utf8'));
  for (const run of runs) {
    const args = [
      cli,
      'lint',
      '--query',
      run.request,
      '--policy',
      run.policy ?? policy,
      ...(run.args ?? []),
      '--evaluation-time',
      '2026-11-05T16:00:00Z',
      '--format',
      'json',
    ];
    const child = spawnSync(process.execPath, args, { cwd: dir, encoding: 'utf8' });
    const label = `${name}/${run.request}${run.policy ? ` with ${run.policy}` : ''}`;
    assert.equal(child.stderr, '', `${label}: unexpected stderr`);
    const result = JSON.parse(child.stdout);
    assert.equal(result.verdict, run.verdict, `${label}: verdict`);
    assert.equal(child.status, EXIT[run.verdict], `${label}: exit code`);
    assert.deepEqual(
      [...new Set(result.findings.map((f) => f.ruleId))].sort(),
      [...run.ruleIds].sort(),
      `${label}: rule IDs`,
    );
    console.log(`ok ${label}: ${result.verdict}`);
    count++;
  }
}

const api = spawnSync(process.execPath, [join(root, 'examples', 'node-api', 'preflight.mjs')], {
  cwd: root,
  encoding: 'utf8',
});
assert.equal(api.status, 0, `node-api example failed:\n${api.stderr}`);
process.stdout.write(api.stdout.replace(/^/gm, 'ok node-api: '));
console.log(`${count} CLI example runs and the API example passed.`);
