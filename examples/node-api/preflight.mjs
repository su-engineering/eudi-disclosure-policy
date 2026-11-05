// Backend preflight: evaluate a DCQL request before signing it into an
// OpenID4VP authorization request. Run from the repository after a build:
//   pnpm build && node examples/node-api/preflight.mjs
import { readFileSync } from 'node:fs';
import { evaluateRequest } from '@su-engineering/eudi-disclosure-policy';

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));

// Load and validate policies once at startup; they are trusted configuration.
const policy = read('../age-verification/policy.json');

/**
 * Returns the DCQL query if it passes preflight, or throws with safe
 * diagnostics (rule IDs and JSON pointers, never claim values).
 */
export function preflight(dcql, now = new Date()) {
  const result = evaluateRequest({
    profile: 'openid4vp-1.0',
    evaluationTime: now.toISOString(),
    dcql,
    policy,
  });
  if (result.verdict === 'DENY' || result.verdict === 'INDETERMINATE') {
    const reasons = result.findings
      .filter((f) => f.verdict === 'DENY' || f.verdict === 'INDETERMINATE')
      .map((f) => `${f.ruleId} at ${f.jsonPointer || '/'}`);
    throw Object.assign(new Error(`DCQL preflight ${result.verdict}: ${reasons.join('; ')}`), {
      result,
    });
  }
  return dcql;
}

const minimal = read('../age-verification/requests/minimal.json');
const risky = read('../age-verification/requests/pid-alternative.json');

preflight(minimal);
console.log('minimal request: accepted');
try {
  preflight(risky);
  throw new Error('expected the PID alternative to be rejected');
} catch (error) {
  if (!error.result) throw error;
  console.log(`pid alternative: rejected (${error.result.verdict})`);
}
