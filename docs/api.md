# API reference

```ts
import {
  evaluateRequest,
  validatePolicy,
  canonicalJson,
  RULES,
  RULE_IDS,
  VERSION,
  RULES_VERSION,
  DEFAULT_LIMITS,
  DEFAULT_MAX_BRANCHES,
  EudiDisclosureError,
  PolicyValidationError,
  InputValidationError,
  UnsupportedProfileError,
  ResourceLimitError,
} from '@su-engineering/eudi-disclosure-policy';
```

The package is ESM only, with TypeScript declarations. Every type below is exported. The core has no runtime dependency other than [`@openeudi/dcql`](decisions/0003-dcql-parser.md), and uses only ECMAScript built-ins: no Node.js modules, DOM, network, timers, clock, or randomness.

## `evaluateRequest(input): EvaluationResult`

Evaluates a DCQL query against a policy. Synchronous, pure, and deterministic.

```ts
interface EvaluateRequestInput {
  dcql: unknown; // Parsed JSON or JSON text
  policy: DisclosurePolicyV1;
  registration?: RegistrationScopeEvidence;
  relyingParty?: { rpId: string; serviceId?: string; intendedUseId?: string };
  evaluationTime: string; // UTC, e.g. "2026-11-05T16:00:00Z"
  profile: 'openid4vp-1.0';
  options?: {
    maxBranches?: number; // Default 2048, at most 1,000,000
    limits?: ResourceLimits; // See below
    debug?: (event: DebugEvent) => void; // Sensitive; see trust boundaries
  };
}
```

**Invalid DCQL is a result, not an exception.** Invalid JSON text or a structurally invalid query returns `verdict: 'DENY'`, `coverage: 'unsupported'`, and `DCQL_INVALID` findings pointing at the problem.

**Exceptions** (all extend `EudiDisclosureError`, with a `code`):

| Error                     | `code`                    | When                                                                                               |
| ------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------- |
| `UnsupportedProfileError` | `PROFILE_UNSUPPORTED`     | `profile` is not `openid4vp-1.0`.                                                                  |
| `InputValidationError`    | `INPUT_INVALID`           | Bad `evaluationTime`, `options`, `registration`, or `relyingParty` shape. `field` names the input. |
| `PolicyValidationError`   | `POLICY_INVALID`          | The policy is invalid. `issues` lists `{ pointer, message }`.                                      |
| `ResourceLimitError`      | `RESOURCE_LIMIT_EXCEEDED` | The query exceeds a budget. `limit` and `max` name it. No partial result exists.                   |

Messages contain codes, pointers, and limit names only, never input content.

### Resource limits

Defaults can be lowered, or raised explicitly, per call with `options.limits`:

| Limit                  | Default | Measured                                                                          |
| ---------------------- | ------- | --------------------------------------------------------------------------------- |
| `maxInputBytes`        | 262,144 | UTF-8 bytes of JSON text, before parsing; approximate serialized size for objects |
| `maxDepth`             | 32      | JSON nesting depth, measured iteratively                                          |
| `maxCredentialQueries` | 32      | Entries in `credentials`                                                          |
| `maxClaimQueries`      | 256     | Claims queries across all credential queries                                      |
| `maxPathSegments`      | 1,024   | Segments across all claims path pointers                                          |
| `maxSetOptions`        | 256     | Options across all `credential_sets` and `claim_sets`                             |

Cyclic objects are caught by the depth limit. Values that are not plain JSON (functions, class instances, sparse arrays, non-finite numbers) are `DCQL_INVALID`.

## `EvaluationResult`

```ts
interface EvaluationResult {
  apiVersion: '1.0';
  verdict: 'ALLOW' | 'WARN' | 'DENY' | 'INDETERMINATE';
  coverage: 'complete' | 'partial' | 'unsupported';
  evaluatedAt: string; // Your evaluationTime, verbatim
  profile: 'openid4vp-1.0';
  engine: { name: string; version: string; rulesVersion: string };
  policy: { id: string; version: string; purposeId: string; digest: string }; // digest: "sha-256:<hex>" of canonical JSON
  registrationEvidence: 'verified' | 'unverified' | 'absent';
  summary: { errors: number; warnings: number; indeterminate: number; info: number };
  findings: Finding[];
  branchCount: number; // Exact up to maxBranches; maxBranches + 1 means "more"
  analyzedBranches: number;
  skippedBranches: number;
  maxBranches: number;
}

interface Finding {
  ruleId: RuleId;
  category: 'N' | 'A' | 'P' | 'U' | 'O';
  severity: 'error' | 'warning' | 'info'; // DENY and INDETERMINATE → error, WARN → warning, ALLOW → info
  verdict: Verdict;
  message: string;
  jsonPointer: string; // RFC 6901 into your DCQL input; "" for the whole request
  queryId?: string; // Credential query id
  branchId?: string; // e.g. "cs0.o1+pid.cl0"
  policyRuleId?: string; // Credential rule id
  evidenceIds?: string[]; // "registration-evidence:sha-256:<hex>"
  remediation?: string;
  standardRefs?: string[];
  details?: Record<string, unknown>; // Derived indicators only, never claim values
}
```

`registrationEvidence` is `verified` only when evidence was asserted as verified **and** passed the provenance, freshness, and applicability checks. Otherwise it is `unverified` (supplied but unusable) or `absent`.

The same inputs and package version produce byte-identical `canonicalJson(result)`, except for `evaluatedAt`. See [concepts](concepts.md#results) for verdict, coverage, and category semantics.

## `validatePolicy(json): DisclosurePolicyV1`

Validates a policy and returns it typed. Throws `PolicyValidationError` with up to 100 `issues`. `evaluateRequest` calls it internally; call it yourself to fail fast at startup.

## `canonicalJson(value): string`

Serializes JSON with sorted keys and no whitespace. For results this matches RFC 8785 (JCS). Use it to store, diff, or hash results.

## `RULES`, `RULE_IDS`

The rule catalog: `id`, `category`, `title`, `outcome`, `description`, `remediation`, and `standardRefs` for every rule. [Rule reference](rule-reference.md) is generated from it.

## Versions

- `VERSION`: the package version.
- `RULES_VERSION`: the rule catalog version, recorded in every result. It changes whenever a rule's trigger, default verdict, or category changes.
- `apiVersion` in results: the result shape version.

## JSON Schema

`@su-engineering/eudi-disclosure-policy/policy.schema.json` is the JSON Schema (draft 2020-12) of `DisclosurePolicyV1`.
