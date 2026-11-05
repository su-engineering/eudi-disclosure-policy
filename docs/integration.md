# Integration

Run the preflight where your service builds a DCQL query, before the query is signed into an OpenID4VP authorization request. Block on `DENY` and `INDETERMINATE`. Treat `WARN` as a review signal according to your own policy.

## Node.js backend

Load and validate policies once at startup. They are trusted configuration; a broken policy should stop the deployment, not a single request.

```ts
import { readFileSync } from 'node:fs';
import {
  evaluateRequest,
  validatePolicy,
  type EvaluationResult,
} from '@su-engineering/eudi-disclosure-policy';

const agePolicy = validatePolicy(
  JSON.parse(readFileSync('policies/age-verification.json', 'utf8')),
);

export class PreflightRejected extends Error {
  constructor(readonly result: EvaluationResult) {
    super(`DCQL preflight ${result.verdict}`);
  }
}

export function preflight(dcql: unknown): void {
  const result = evaluateRequest({
    profile: 'openid4vp-1.0',
    evaluationTime: new Date().toISOString(),
    dcql,
    policy: agePolicy,
  });
  if (result.verdict === 'DENY' || result.verdict === 'INDETERMINATE')
    throw new PreflightRejected(result);
  // Findings are safe to log: rule IDs, pointers, and paths, never claim values.
  for (const f of result.findings) if (f.verdict === 'WARN') console.warn(f.ruleId, f.jsonPointer);
}
```

A runnable version is in [examples/node-api](../examples/node-api/preflight.mjs).

### With registration evidence

Pass evidence only after verifying the registration yourself; see [trust boundaries](trust-boundaries.md#registration-evidence-is-caller-asserted).

```ts
const result = evaluateRequest({
  profile: 'openid4vp-1.0',
  evaluationTime: new Date().toISOString(),
  dcql,
  policy: onboardingPolicy, // defaults.registrationEvidenceRequired: true
  registration: await loadVerifiedRegistration(), // Your code: fetch, verify signature and status, then build evidence
  relyingParty: { rpId: config.rpId, serviceId: config.onboardingServiceId },
});
```

## Next.js route handler

```ts
// app/api/presentation-request/route.ts
import { evaluateRequest, validatePolicy } from '@su-engineering/eudi-disclosure-policy';
import policyJson from '@/policies/age-verification.json';
import { buildAgeQuery, createAuthorizationRequest } from '@/lib/openid4vp';

const policy = validatePolicy(policyJson); // Throws at module load if the policy is invalid.

export async function POST() {
  const dcql = buildAgeQuery();
  const result = evaluateRequest({
    profile: 'openid4vp-1.0',
    evaluationTime: new Date().toISOString(),
    dcql,
    policy,
  });
  if (result.verdict === 'DENY' || result.verdict === 'INDETERMINATE') {
    return Response.json(
      { error: 'request_blocked_by_policy', findings: result.findings },
      { status: 500 },
    );
  }
  return Response.json(await createAuthorizationRequest(dcql));
}
```

A blocked request here is a bug in your service's query construction, not a user error, hence the 500.

## Browser and edge runtimes

The core has no Node.js dependencies and runs in browsers, workers, and edge runtimes. Preflight in the browser is useful for developer tooling and request builders. Do not rely on a client-side check for enforcement: run it on the server that signs the request.

## Continuous integration

Check the queries your service can send, in CI, as policy-as-code. Keep the queries as JSON files or generate them in a build step.

```yaml
# .github/workflows/dcql-preflight.yml
name: DCQL preflight
on: [pull_request]
permissions:
  contents: read
jobs:
  preflight:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install --no-save @su-engineering/eudi-disclosure-policy@0.1.0
      - name: Validate policies
        run: for p in policies/*.json; do npx eudi-disclosure policy validate "$p"; done
      - name: Lint requests
        run: |
          npx eudi-disclosure lint --query requests/age.json --policy policies/age-verification.json \
            --evaluation-time 2026-01-01T00:00:00Z --strict
```

Pin the package version: rule changes are versioned (`RULES_VERSION`), and an upgrade should be a reviewed change. A fixed `--evaluation-time` keeps CI runs reproducible; use the current time when registration evidence with an expiry is involved.

Exit codes: `0` pass, `1` deny (or warn with `--strict`), `2` usage or policy error, `3` indeterminate or resource limit, `4` internal error. `--format json` prints one line of canonical JSON on stdout for tools.

## Existing OpenID4VP stacks

- **Keycloak.** In [keycloak-oid4vp](https://github.com/su-engineering/keycloak-oid4vp) or another provider, evaluate the configured DCQL query when the identity provider is saved or deployed, and before each authorization request is signed if queries are built dynamically. Keep Keycloak's own presentation validation unchanged; this check only concerns what is asked.
- **OpenKYC and other RP platforms.** Use the preflight to ensure an age-verification flow cannot fall back to identity attributes. It does not make the platform issue portable credentials or enforce deletion of data received.
- **Wallets.** Not supported yet. Wallet-side evaluation needs authenticated relying-party identity, verified registration, and issuer embedded disclosure policies, and will be a separate module.
