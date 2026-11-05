/**
 * Validate the built package: declared targets exist, the core bundles for
 * browsers without Node.js built-ins, and the bundle evaluates a request in a
 * bare ECMAScript realm with no network, timers, process, or module loader.
 */
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import vm from 'node:vm';
import { build } from 'esbuild';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const targets = new Set([pkg.main, pkg.types, ...Object.values(pkg.bin)]);
const collect = (value) =>
  typeof value === 'string' ? targets.add(value) : Object.values(value).forEach(collect);
collect(pkg.exports);
for (const target of targets)
  assert.ok(existsSync(target), `Missing declared package target: ${target}`);
assert.ok(
  readFileSync(pkg.bin['eudi-disclosure'], 'utf8').startsWith('#!/usr/bin/env node\n'),
  'CLI needs a shebang',
);

const core = readFileSync(pkg.main, 'utf8');
for (const forbidden of [
  /from\s+["']node:/,
  /\brequire\(/,
  /\bprocess\./,
  /\bfetch\(/,
  /\bDate\.now\(/,
  /\bMath\.random\(/,
]) {
  assert.ok(!forbidden.test(core), `Core bundle contains ${forbidden}`);
}

const self = await import('../dist/index.js');
assert.equal(typeof self.evaluateRequest, 'function');
assert.equal(self.VERSION, pkg.version, 'VERSION must match package.json');

// Bundle the public entry exactly as a browser application would.
const bundle = await build({
  stdin: { contents: `export * from '${pkg.name}';`, resolveDir: process.cwd() },
  bundle: true,
  format: 'iife',
  globalName: 'EudiDisclosurePolicy',
  platform: 'browser',
  write: false,
  logLevel: 'silent',
});
const realm = vm.createContext({});
vm.runInContext(bundle.outputFiles[0].text, realm);
const policy = JSON.parse(readFileSync('examples/age-verification/policy.json', 'utf8'));
const dcql = JSON.parse(readFileSync('examples/age-verification/requests/minimal.json', 'utf8'));
realm.input = JSON.stringify({
  profile: 'openid4vp-1.0',
  evaluationTime: '2026-11-05T16:00:00Z',
  dcql,
  policy,
});
const verdict = vm.runInContext(
  'EudiDisclosurePolicy.evaluateRequest(JSON.parse(input)).verdict',
  realm,
);
assert.equal(verdict, 'ALLOW');
const kib = (bundle.outputFiles[0].contents.length / 1024).toFixed(1);
console.log(
  `Verified ${targets.size} package targets and a ${kib} KiB browser bundle in a bare realm.`,
);
