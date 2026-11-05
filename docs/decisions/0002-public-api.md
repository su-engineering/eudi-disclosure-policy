# 0002: Public API

**Status:** accepted, 2026-11-05

## Context

The specification proposes types for `evaluateRequest()`, the policy, evidence, and results, and asks for an API review before v0.1. It also asks that behavior and trust semantics stay as specified.

## Decision

The specified shapes are kept. Changes are additive or remove ambiguity:

| Change                                                                                                          | Reason                                                                                                                                                                     |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Finding.category` (`N`, `A`, `P`, `U`, `O`)                                                                    | Required by the specification's §8 but missing from its type sketch.                                                                                                       |
| `EvaluationResult.engine` (`name`, `version`, `rulesVersion`)                                                   | "Rule versions and the evaluation profile are recorded so the same inputs yield the same results."                                                                         |
| `EvaluationResult.policy.purposeId`, `summary.info`, `branchCount`, `maxBranches`                               | Make results self-describing; `maxBranches` "must be surfaced in result metadata".                                                                                         |
| `EvaluateRequestInput.relyingParty`                                                                             | Needed to detect evidence issued for another relying party or service (TC-REG-05). Without it, applicability cannot be established and evidence is not used.               |
| `dcql` may be JSON text                                                                                         | Lets the core enforce the byte budget before parsing and report invalid JSON without exposing platform parser messages, which can quote input.                             |
| `options.limits`, `options.debug`                                                                               | Resource budgets (§10.1) are configurable per call; the opt-in debug callback is required by §6.5.                                                                         |
| Optional policy defaults: `broadSelector`, `retentionIntent`, `unknownExtension`, `invalidRegistrationEvidence` | The specification describes these outcomes as "INDETERMINATE or DENY (configured)" and "warn or deny as configured" without a field. Defaults are the conservative choice. |
| `ClaimRule.allowRetention`, `DisclosurePolicyV1.reviewedExtensions`                                             | Explicit, reviewable permissions for mdoc retention and for extensions that do not affect disclosure.                                                                      |
| `options.strict` removed from the core                                                                          | See [ADR 0005](0005-strictness.md).                                                                                                                                        |
| `riskRules` not supported                                                                                       | The specification names the field without defining it. Unknown keys are rejected, so it can be added later without ambiguity.                                              |
| Rules `OPTIONAL_CREDENTIAL_SET`, `UNREFERENCED_QUERY`, `REQUEST_SIZE_EXCEEDS_POLICY`                            | Informational and policy findings the specification asks for (§7.2, §7.6) without naming a rule ID.                                                                        |

Exceptions are typed (`PolicyValidationError`, `InputValidationError`, `UnsupportedProfileError`, `ResourceLimitError`, all with a `code`). Invalid DCQL is a `DENY` result, as §7.1 requires.

## Consequences

- `apiVersion: '1.0'` describes this shape. Additive fields keep it; removals or meaning changes need `2.0`.
- `RULES_VERSION` changes independently when rule behavior changes.
