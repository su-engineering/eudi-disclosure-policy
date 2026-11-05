# EUDI Disclosure Policy

**Check an OpenID4VP DCQL request against your data-minimization policy before it reaches an EUDI Wallet.**

[![CI](https://github.com/su-engineering/eudi-disclosure-policy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/su-engineering/eudi-disclosure-policy/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A relying party (verifier) asks a European Digital Identity (EUDI) Wallet for credentials with an OpenID4VP DCQL query. A query can offer alternatives: several credential sets, optional sets, several claim sets, several accepted types. The wallet may answer with any of them. This library evaluates **every alternative** against a versioned, local policy for one purpose, and reports what is allowed, what is not, and what it cannot determine, with a JSON pointer to the exact query branch responsible.

- **Every branch counts:** a compliant first option never hides a non-compliant second one. Optional credential sets are requests too.
- **Fails closed:** unknown types, unknown disclosure behavior, unverified registration evidence, and unreviewed extensions are `INDETERMINATE`, never `ALLOW`.
- **Format-aware:** exact SD-JWT VC (`dc+sd-jwt`) and mdoc (`mso_mdoc`) path semantics, including namespaces, wildcards, and strict index types.
- **Explains itself:** stable rule IDs, categories, remediation, standards references, and deterministic output for CI.
- **Safe to run anywhere:** a pure, synchronous core with no network, clock, file system, or environment access. Claim values never appear in results.

Built for verifier engineers, SDK maintainers, and privacy reviewers in the eIDAS 2.0 ecosystem: run it in your backend before you sign an authorization request, or in CI as policy-as-code.

Maintained by [su.engineering](https://su.engineering) · [Apache-2.0](LICENSE) · Node.js 22+ and browsers · OpenID4VP 1.0 Final

> [!IMPORTANT]
> **Preview (0.x).** `ALLOW` means the request satisfies the rules you configured. It is not a legal assessment, not proof of relying-party registration, not a statement about what a wallet will disclose, and not EUDI certification. Read [trust boundaries](docs/trust-boundaries.md) before relying on a result.

[Concepts](docs/concepts.md) · [Policy format](docs/policy-format.md) · [Rule reference](docs/rule-reference.md) · [API](docs/api.md) · [Integration](docs/integration.md) · [Trust boundaries](docs/trust-boundaries.md) · [Threat model](docs/threat-model.md) · [Standards lock](docs/standards-lock.md)

## Why a parser is not enough

This request is valid DCQL. A parser accepts it, and a check of the first option passes:

```json
{
  "credentials": [
    {
      "id": "proof",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:example:proof-of-age:v1"] },
      "claims": [{ "path": ["age_over_18"] }]
    },
    {
      "id": "pid",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:example:pid"] },
      "claims": [{ "path": ["birth_date"] }, { "path": ["family_name"] }]
    }
  ],
  "credential_sets": [{ "options": [["proof"], ["pid"]] }]
}
```

Option order is only a preference. A wallet holding a PID but no proof-of-age credential may present the PID, disclosing a birth date and family name to a service that only needed to know the user is an adult. An age-verification policy has to reject the request, not the preferred branch.

## Install

```sh
npm install @su-engineering/eudi-disclosure-policy
```

The package is ESM with TypeScript declarations. The core runs in Node.js 22+, browsers, and edge runtimes; the `eudi-disclosure` command needs Node.js.

## Quick start

```ts
import { evaluateRequest } from '@su-engineering/eudi-disclosure-policy';

const result = evaluateRequest({
  profile: 'openid4vp-1.0',
  evaluationTime: new Date().toISOString(), // Supplied by you: the core never reads the clock.
  dcql, // The query you are about to send.
  policy: ageVerificationPolicy, // Your approved policy for this purpose.
});

if (result.verdict === 'DENY' || result.verdict === 'INDETERMINATE') {
  // Block the request. Findings carry rule IDs and JSON pointers, never claim values.
  throw new Error(result.findings.map((f) => `${f.ruleId} ${f.jsonPointer}`).join('\n'));
}
```

For the request above and the [age-verification example policy](examples/age-verification/policy.json):

```text
$ npx eudi-disclosure lint --query request.json --policy policy.json
EUDI DISCLOSURE POLICY / REQUEST PREFLIGHT
Policy: example.age-verification@1.0.0 (age-verification-over-18)
Profile: openid4vp-1.0
Evaluated at: 2026-11-05T16:00:00Z
Registration evidence: absent
Verdict: DENY
Coverage: complete

DENY   CREDENTIAL_SET_EXCESSIVE_OPTION
       /credential_sets/0/options/1  [branch cs0.o1]
       Option 1 of credential set 0 ('pid') violates the policy, while
       cs0.o0 complies. The wallet may present any option.
       Fix: Remove the excessive option. A compliant alternative does not
       make a non-compliant one acceptable.

DENY   CREDENTIAL_TYPE_NOT_ALLOWED
       /credentials/1/meta/vct_values/0  [branch cs0.o1]
       Credential query 'pid' accepts dc+sd-jwt vct "urn:example:pid", which
       no credential rule in the policy allows.
       Fix: Remove the type from the query, or have the policy owner add a
       credential rule for exactly this format and type.

2 denials | 0 warnings | 0 indeterminate checks | 0 notes
```

The exit code is `1`. Use `--format json` for canonical machine output in CI.

## Write a policy

A policy states which credential types and claims one purpose may request. Claim rules match exactly unless you choose `subtree`; deny rules override allow rules.

```json
{
  "schemaVersion": "1.0",
  "policyId": "example.age-verification",
  "policyVersion": "1.0.0",
  "purposeId": "age-verification-over-18",
  "credentials": [
    {
      "id": "proof-of-age",
      "format": "dc+sd-jwt",
      "credentialType": { "kind": "vct", "value": "urn:example:proof-of-age:v1" },
      "allowClaims": [{ "path": ["age_over_18"], "matching": "exact" }],
      "denyClaims": [{ "path": ["birth_date"], "matching": "exact" }],
      "disclosureProfile": { "mode": "selective", "knownMandatoryPaths": [] }
    }
  ],
  "defaults": {
    "unknownCredential": "deny",
    "unknownClaim": "deny",
    "unknownDisclosure": "indeterminate",
    "registrationEvidenceRequired": false,
    "permitValueConstraints": false,
    "permitHolderBindingDisabled": false,
    "permitMultipleCredentials": false
  }
}
```

Validate it with `npx eudi-disclosure policy validate policy.json`, or in editors with the bundled [JSON Schema](schema/disclosure-policy-v1.schema.json) (`@su-engineering/eudi-disclosure-policy/policy.schema.json`). The [policy format](docs/policy-format.md) documents every field. Type identifiers in this repository are fictional `urn:example:` values, not real EUDI schemas.

## What it checks

| Concern                                     | Rules                                                                                                                                                                                   |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Request validity (OpenID4VP 1.0 §6–7)       | `DCQL_INVALID`                                                                                                                                                                          |
| Purpose allowlist and deny list             | `CREDENTIAL_TYPE_NOT_ALLOWED`, `CLAIM_NOT_ALLOWED_FOR_PURPOSE`, `CLAIM_EXPLICITLY_DENIED`, `BROAD_CLAIM_SELECTOR`, `MANDATORY_DISCLOSURE_EXCEEDS_POLICY`, `REQUEST_SIZE_EXCEEDS_POLICY` |
| Alternatives                                | `CREDENTIAL_SET_EXCESSIVE_OPTION`, `CLAIM_SET_NONMINIMAL`, `OPTIONAL_CREDENTIAL_SET`, `CREDENTIAL_TYPE_AMBIGUOUS`, `UNREFERENCED_QUERY`                                                 |
| Registered scope (caller-asserted evidence) | `CLAIM_NOT_IN_REGISTERED_SCOPE`, `REGISTRATION_EVIDENCE_MISSING`, `REGISTRATION_EVIDENCE_UNVERIFIED`, `REGISTRATION_EVIDENCE_INVALID_OR_STALE`                                          |
| Privacy risk                                | `VALUE_FILTER_PROBING_RISK`, `HOLDER_BINDING_DISABLED`, `MULTIPLE_CREDENTIALS_REQUESTED`, `MDOC_RETENTION_REQUESTED`                                                                    |
| What the engine cannot know                 | `UNKNOWN_DISCLOSURE_PROFILE`, `UNSUPPORTED_CREDENTIAL_FORMAT`, `UNKNOWN_EXTENSION_REVIEW`, `BRANCH_LIMIT_REACHED`                                                                       |

The aggregate verdict is the most severe finding: `DENY` > `INDETERMINATE` > `WARN` > `ALLOW`. A separate `coverage` field (`complete`, `partial`, `unsupported`) tells an explicit violation apart from incomplete analysis. See the [rule reference](docs/rule-reference.md).

## Command line

```sh
npx eudi-disclosure lint --query request.json --policy policy.json [--format json] [--strict]
cat request.json | npx eudi-disclosure lint --query - --policy policy.json
npx eudi-disclosure policy validate policy.json
npx eudi-disclosure explain VALUE_FILTER_PROBING_RISK
```

| Exit code | Meaning                                                 |
| --------- | ------------------------------------------------------- |
| `0`       | `ALLOW`, or `WARN` without `--strict`                   |
| `1`       | `DENY`, or `WARN` with `--strict`                       |
| `2`       | Usage, input, or policy error                           |
| `3`       | `INDETERMINATE`, unsupported profile, or resource limit |
| `4`       | Unexpected internal error                               |

The CLI reads local files or stdin only; it never follows a `request_uri`. Diagnostics never print input content. See [integration](docs/integration.md) for a GitHub Actions job.

## Scope

**In scope:** verifier-side preflight of OpenID4VP 1.0 Final DCQL queries for `dc+sd-jwt` and `mso_mdoc`; local purpose policies; comparison with registration scope that you verified elsewhere; privacy risk indicators; CLI and CI output.

**Not in scope:** verifying relying-party identity, access or registration certificates, trust lists, or status lists; fetching registries; wallet-side decisions or embedded disclosure policies (planned as a separate module); consent; generating or rewriting requests; legal compliance. A verifier's `ALLOW` never authorizes a wallet to disclose: wallet security, issuer policy, and user approval remain independent controls.

## Roadmap

Planned work is tracked as [GitHub issues grouped by milestone](https://github.com/su-engineering/eudi-disclosure-policy/milestones): SARIF output and interop fixtures next, then a verifier integration and more credential formats. 1.0 needs external review, a stable API, and a compatibility policy ([releasing](docs/releasing.md#before-10)).

## Examples

Three fictional scenarios with policies, requests, and expected outcomes run in CI:

- [Age verification](examples/age-verification): minimal request, a PID alternative, an optional address set, a value filter, an unprofiled type.
- [PID onboarding](examples/pid-onboarding): names only, an added portrait, verified registration scope, missing evidence, an unknown type variant.
- [mdoc retention](examples/mdoc-retention): exact namespaced element, `intent_to_retain`, a similar element in another namespace, unknown mandatory disclosure.
- [Node.js preflight](examples/node-api/preflight.mjs): the API in a backend request path.

## Development

```sh
git clone https://github.com/su-engineering/eudi-disclosure-policy.git
cd eudi-disclosure-policy
corepack enable
pnpm install --frozen-lockfile
pnpm check   # lint, typecheck, tests, build, package check, examples
```

Use Node.js 22 or newer. Read [CONTRIBUTING.md](.github/CONTRIBUTING.md) before opening a pull request. Changes to rule behavior need a fixture and a [changeset](.changeset/README.md).

## FAQ

**What is DCQL?** The Digital Credentials Query Language, defined in OpenID for Verifiable Presentations (OpenID4VP) 1.0 §6. A verifier uses it to tell a wallet which credentials and claims it wants, including alternatives through `credential_sets` and `claim_sets`.

**Why check a request before sending it?** Every alternative in a DCQL query is a request the wallet may fulfil. Data minimization means asking only for what a purpose needs, so the check has to cover the least favorable alternative, not the preferred one.

**Does it validate relying-party registration or access certificates?** No. It compares the request with registration evidence that your code verified and asserts. Under Implementing Regulation (EU) 2024/2982 (Annex II, WRP-OVERASKING), wallets compare requests with the registration certificate themselves; this library helps you never trigger that warning. See [trust boundaries](docs/trust-boundaries.md).

**Does it support SD-JWT VC and ISO mdoc?** Yes: `dc+sd-jwt` with JSON claim paths, and `mso_mdoc` with `[namespace, element]` paths and `intent_to_retain`. Other formats are reported as unsupported rather than guessed.

**Is it a GDPR or eIDAS compliance tool?** No. It enforces the policy you approve for a purpose and explains its decisions. Whether a purpose is lawful, necessary, and proportionate is decided outside the library.

**Does it work in the browser?** Yes. The core is pure ECMAScript with one small dependency and no network, clock, or Node.js APIs. Enforce on the server that signs requests.

**Does it handle wallet-side embedded disclosure policies?** Not yet. Wallet-side evaluation under Implementing Regulation (EU) 2024/2979 Article 10 is planned as a separate module.

## Security

Report vulnerabilities privately to **[security@su.engineering](mailto:security@su.engineering)**. See [SECURITY.md](SECURITY.md) for scope and the data-handling contract.

## License

[Apache License 2.0](LICENSE). Third-party attribution is in [NOTICE](NOTICE).
