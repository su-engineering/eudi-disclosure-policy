# Policy format

A policy is a JSON document, `schemaVersion` `"1.0"`, describing what one purpose may request. It is project configuration, not an EUDI rulebook or schema encoding. Validate it with:

```sh
npx eudi-disclosure policy validate policy.json
```

or in code with `validatePolicy(json)`, which throws `PolicyValidationError` listing every issue with a JSON pointer. Editors can use the bundled JSON Schema, exported as `@su-engineering/eudi-disclosure-policy/policy.schema.json`. The schema checks structure only; `validatePolicy` also checks the cross-field rules marked **(validator)** below.

Validation is strict: unknown keys are errors at every level, and `__proto__`, `constructor`, and `prototype` are rejected.

## Top level

| Field                | Required | Description                                                                                       |
| -------------------- | -------- | ------------------------------------------------------------------------------------------------- |
| `schemaVersion`      | yes      | `"1.0"`. Other versions are rejected.                                                             |
| `policyId`           | yes      | Stable identifier, reported in results.                                                           |
| `policyVersion`      | yes      | Your version of this policy. Results also carry a SHA-256 digest of the canonical policy.         |
| `purposeId`          | yes      | The purpose this policy approves. Used in messages; never interpreted.                            |
| `description`        | no       | Free text. Not a secret store.                                                                    |
| `credentials`        | yes      | Credential rules. May be empty, which allows nothing.                                             |
| `defaults`           | yes      | Behavior for uncertain cases and opt-in permissions.                                              |
| `reviewedExtensions` | no       | Names of DCQL extension properties the policy owner reviewed and judged not to change disclosure. |

## Credential rules

| Field               | Required | Description                                                                                                                                                                                     |
| ------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                | yes      | Unique within the policy **(validator)**. Reported as `policyRuleId`.                                                                                                                           |
| `format`            | yes      | `dc+sd-jwt` or `mso_mdoc`. Other formats are accepted in the policy, but requests using them are `UNSUPPORTED_CREDENTIAL_FORMAT`.                                                               |
| `credentialType`    | yes      | `{ "kind": "vct", "value": … }` for `dc+sd-jwt`, `{ "kind": "doctype", "value": … }` for `mso_mdoc` **(validator)**. Compared exactly. Format and type are unique across rules **(validator)**. |
| `allowClaims`       | yes      | Claim rules the purpose may request.                                                                                                                                                            |
| `denyClaims`        | no       | Claim rules the purpose must never request. They override allow rules.                                                                                                                          |
| `disclosureProfile` | no       | What presenting this type discloses beyond the requested claims. Without it, requests yield `UNKNOWN_DISCLOSURE_PROFILE`.                                                                       |

## Claim rules

| Field            | Required | Description                                                                                                                             |
| ---------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `path`           | yes      | A claims path pointer: non-empty array of strings, non-negative integers, and `null`.                                                   |
| `matching`       | yes      | `exact` (only this path) or `subtree` (this path and every descendant). There is no default: broad rules are always an explicit choice. |
| `reason`         | no       | Why the rule exists.                                                                                                                    |
| `classification` | no       | `ordinary`, `sensitive`, or `highly-sensitive`. Your label, reported in deny findings; not a legal classification.                      |
| `allowRetention` | no       | Allow rules of `mso_mdoc` credentials only **(validator)**: permit `intent_to_retain: true`.                                            |

Path rules **(validator)**:

- For `mso_mdoc`, `exact` paths are `[namespace, element]`; `subtree` paths are `[namespace]` or `[namespace, element]`. No `null`.
- The same path with the same `matching` cannot appear twice in a list, or in both the allow and deny lists. The same path with different `matching` is allowed: an `exact` deny of `["name"]` with a `subtree` allow of `["name"]` permits children of `name` but not the whole object.

How rules match requests is described in [concepts](concepts.md#matching). In short: `exact` never covers a parent or child; `null` in a rule covers any index; a request broader than every allow rule that intersects it is `BROAD_CLAIM_SELECTOR`.

## Disclosure profile

| Field                       | Required | Description                                                                                                                                                                         |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mode`                      | yes      | `selective`, `non-selective`, `mixed`, or `unknown`.                                                                                                                                |
| `knownMandatoryPaths`       | no       | Paths always disclosed when presenting this type. For `non-selective`, the complete content. Omit when unknown; use `[]` for none. Not allowed with mode `unknown` **(validator)**. |
| `schemaId`, `schemaVersion` | no       | The schema you took this from, for audit.                                                                                                                                           |

Every known mandatory path must be covered by an allow rule and not hit by a deny rule. For SD-JWT VC, consider claims that are always disclosed in your profile, such as `iss` and `vct`, and allow them explicitly. Example: [PID onboarding](../examples/pid-onboarding/policy.json).

## Defaults

| Field                          | Required | Values                            | Effect                                                                                                     |
| ------------------------------ | -------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `unknownCredential`            | yes      | `indeterminate`, `deny`           | Outcome of `CREDENTIAL_TYPE_NOT_ALLOWED`.                                                                  |
| `unknownClaim`                 | yes      | `indeterminate`, `deny`           | Outcome of `CLAIM_NOT_ALLOWED_FOR_PURPOSE`.                                                                |
| `unknownDisclosure`            | yes      | `indeterminate`, `warn`           | Outcome of `UNKNOWN_DISCLOSURE_PROFILE`. Use `warn` only if you do not require assured minimal disclosure. |
| `registrationEvidenceRequired` | yes      | boolean                           | Require registration evidence. Missing evidence is `REGISTRATION_EVIDENCE_MISSING`.                        |
| `permitValueConstraints`       | yes      | boolean                           | `values` filters become `WARN` instead of `DENY`. Still reported.                                          |
| `permitHolderBindingDisabled`  | yes      | boolean                           | `require_cryptographic_holder_binding: false` becomes `WARN` instead of `DENY`.                            |
| `permitMultipleCredentials`    | yes      | boolean                           | `multiple: true` becomes `WARN` instead of `DENY`.                                                         |
| `maxCredentialQueries`         | no       | positive integer                  | More credential queries is `REQUEST_SIZE_EXCEEDS_POLICY`.                                                  |
| `maxClaimQueries`              | no       | positive integer                  | More claims queries (declared, across all credential queries) is `REQUEST_SIZE_EXCEEDS_POLICY`.            |
| `broadSelector`                | no       | `indeterminate` (default), `deny` | Outcome of `BROAD_CLAIM_SELECTOR`.                                                                         |
| `retentionIntent`              | no       | `deny` (default), `warn`          | Outcome of `MDOC_RETENTION_REQUESTED` without `allowRetention`.                                            |
| `unknownExtension`             | no       | `indeterminate` (default), `warn` | Outcome of `UNKNOWN_EXTENSION_REVIEW` for names not in `reviewedExtensions`.                               |
| `invalidRegistrationEvidence`  | no       | `indeterminate` (default), `deny` | Outcome of `REGISTRATION_EVIDENCE_INVALID_OR_STALE`.                                                       |

The optional fields were added to the original specification's shape during API review; see [ADR 0002](decisions/0002-public-api.md). Their defaults keep the behavior conservative.

## One policy per evaluation

Version 1 evaluates exactly one policy. There is no inheritance or merging. If composition is added later, it will be a deterministic compilation step: deny overrides allow, the most restrictive default wins, version conflicts are errors, and results record the merged policy's digest.

## Versioning

`schemaVersion` changes only for incompatible format changes, with a migration guide. New optional fields with conservative defaults can be added within `1.0`. Bump your own `policyVersion` whenever you change a policy; the result's `policy.digest` changes with any edit regardless.
