/** Publish with npm's OIDC trusted publishing from GitHub Actions. */
import { appendFileSync, readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const endpoint = `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/${encodeURIComponent(pkg.version)}`;
const response = await fetch(endpoint, { signal: AbortSignal.timeout(30_000) });
if (response.ok) {
  console.log(`${pkg.name}@${pkg.version} is already published; no release needed.`);
  process.exit(0);
}
if (response.status !== 404) {
  throw new Error(`Registry check failed with HTTP ${response.status}; refusing to publish.`);
}
const tag = `v${pkg.version}`;
if (spawnSync('git', ['rev-parse', '--verify', `refs/tags/${tag}`]).status === 0) {
  throw new Error(
    `${tag} already exists but the registry version is missing; investigate before publishing.`,
  );
}
if (process.argv.includes('--dry-run')) {
  console.log(`Would publish ${pkg.name}@${pkg.version} with provenance, then create ${tag}.`);
  process.exit(0);
}
if (!process.env.CI || !process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
  throw new Error(
    'Automated releases require GitHub Actions OIDC. See docs/releasing.md for manual releases.',
  );
}
// changesets/action v2 sets this; without it the tag and release would be lost.
if (!process.env.CHANGESETS_OUTPUT) {
  throw new Error('CHANGESETS_OUTPUT is unset; run this script from changesets/action v2.');
}
// Every release goes to "latest". npm set "latest" on the first publish and it
// cannot be removed, so a separate preview tag would leave plain installs stale.
const result = spawnSync(
  'npm',
  ['publish', '--access', 'public', '--provenance', '--tag', 'latest'],
  { stdio: 'inherit' },
);
if (result.status !== 0) process.exit(result.status ?? 1);
execFileSync('git', ['tag', tag]);
// changesets/action v2 pushes the tag and creates the GitHub release only for
// events written to this file. It ignores the "New tag:" log line used by v1.
appendFileSync(
  process.env.CHANGESETS_OUTPUT,
  `${JSON.stringify({ type: 'git-tag', tag, packageName: pkg.name })}\n`,
);
console.log(`New tag: ${tag}`);
