# Conformance matrix

How each normative behavior is implemented and where it is tested. "Fixture" IDs refer to files under [`fixtures/`](../fixtures); each fixture states its expected verdict, coverage, and exact findings. Clauses refer to OpenID4VP 1.0 Final unless noted.

## DCQL semantics

| Clause | Behavior                                                                                                   | Implementation                                                                   | Tests                                             |
| ------ | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------- |
| §6     | `credentials` required and non-empty; unknown properties ignored by wallets, so preserved and flagged here | `dcql/parse.ts`, `dcql/normalize.ts`                                             | `TC-BASE-02*`, `TC-BASE-03`, `TC-EXT-02`          |
| §6.1   | Credential `id` pattern and uniqueness                                                                     | Parser                                                                           | `TC-BASE-02a`, `TC-BASE-02b`                      |
| §6.1   | Same claim not requested twice in one query                                                                | Supplemental check                                                               | `TC-BASE-02d`                                     |
| §6.1   | `multiple` defaults to `false`                                                                             | `MULTIPLE_CREDENTIALS_REQUESTED` only when `true`                                | `TC-MULTIPLE-01`                                  |
| §6.1   | `require_cryptographic_holder_binding` defaults to `true`                                                  | `HOLDER_BINDING_DISABLED` only when `false`                                      | `TC-BINDING-01`, `TC-BINDING-02`                  |
| §6.2   | Options are non-empty conjunctions of credential ids; `required` defaults to `true`                        | Supplemental check; `dcql/branch-model.ts`                                       | `TC-BASE-02c`, `TC-ALT-04`                        |
| §6.3   | `values` are strings, integers, or booleans                                                                | Parser plus supplemental integer check                                           | `TC-VALUES-03`                                    |
| §6.4.1 | `claims` absent: only mandatory-to-present data                                                            | Disclosure profile analysis; no full-credential assumption for selective formats | `TC-SELECT-01`, `TC-SELECT-02`                    |
| §6.4.1 | `claims` without `claim_sets`: all requested                                                               | `selectableClaims`                                                               | `TC-BASE-01`, `US-02`                             |
| §6.4.1 | `claim_sets`: one option; order is preference                                                              | Every option evaluated                                                           | `TC-ALT-05`, `TC-CLAIMSET-01`                     |
| §6.4.1 | `claim_sets` not allowed without `claims`                                                                  | Parser                                                                           | `TC-BASE-02e`                                     |
| §6.4.1 | `values` matching is best effort, never a security control                                                 | `VALUE_FILTER_PROBING_RISK`, never authorization evidence                        | `TC-VALUES-01`, `TC-VALUES-02`, `TC-REDACTION-01` |
| §6.4.1 | Non-selective formats without claims present the full credential                                           | `UNKNOWN_DISCLOSURE_PROFILE` unless content is described                         | `TC-SELECT-02`                                    |
| §6.4   | Presentations may contain more than selected claims (mandatory fields, duplicate queries)                  | Disclosure profiles; `MANDATORY_DISCLOSURE_EXCEEDS_POLICY`                       | `TC-SELECT-03`                                    |
| §6.4.2 | `credential_sets` absent: all credentials requested                                                        | `reachability`                                                                   | `TC-ALT-03`                                       |
| §6.4.2 | Required sets and optional sets                                                                            | Optional sets evaluated in full                                                  | `TC-ALT-02`, `TC-ALT-OK-03`                       |
| §6.4.2 | Credentials outside every option are not requested                                                         | `UNREFERENCED_QUERY`, not evaluated as disclosed                                 | `TC-ALT-09`                                       |
| §7     | Path: non-empty array of strings, non-negative integers, `null`                                            | Parser; strict-type comparison                                                   | `TC-PATH-04`, `TC-PATH-04a`                       |
| §7.1   | `null` selects all array elements                                                                          | Wildcard coverage and intersection rules                                         | `TC-PATH-03`, `TC-PATH-03b`, `TC-PATH-05`         |
| §7.2   | mdoc path is exactly `[namespace, element]`                                                                | Parser; namespaces never collapsed                                               | `TC-PATH-01`, `TC-PATH-07`, `SCN-C-03`            |
| B.2.3  | mdoc `doctype_value`                                                                                       | Exact `doctype` matching                                                         | `TC-PATH-01`                                      |
| B.2.4  | mdoc `intent_to_retain`                                                                                    | `MDOC_RETENTION_REQUESTED`; on other formats an extension                        | `TC-PATH-02`, `SCN-C-01`, `TC-EXT-03`             |
| B.3.5  | SD-JWT VC `vct_values` is a union of types                                                                 | Every type evaluated; no inheritance                                             | `TC-ALT-07`, `TC-ALT-07b`                         |

## Project requirements

| Requirement                                                                                  | Tests                                                                                  |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| All branches and optional sets evaluated                                                     | Property: per-element analysis equals explicit enumeration; `TC-ALT-*`                 |
| No false pass on unknown facts                                                               | Property: missing disclosure knowledge never yields `ALLOW`; `indeterminate/` fixtures |
| Registration gate distinguishes absent, unverified, stale, mismatched, and verified evidence | `TC-REG-01` to `TC-REG-09`, `TC-TIME-01`, `TC-REG-OK-01`                               |
| Monotonicity: forbidden branches, deny rules, and evidence never improve a verdict           | `test/properties.test.ts`                                                              |
| Pointers resolve in the original input                                                       | Property test                                                                          |
| Redaction of values                                                                          | Property test, `TC-REDACTION-01`, every fixture, CLI tests                             |
| Determinism                                                                                  | 100 runs per fixture; property test; Node.js 22 and 24 in CI                           |
| No network, clock, or randomness                                                             | `evaluate.test.ts`, lint rules, `tools/check-package.mjs`                              |
| Resource limits                                                                              | `evaluate.test.ts`                                                                     |
| Browser-compatible core                                                                      | `tools/check-package.mjs` bare-realm bundle test                                       |
| CLI exit codes and output                                                                    | `test/cli.test.ts`, snapshots, README doc test                                         |

## Not implemented

| Area                                                                             | Status                                                      |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Formats other than `dc+sd-jwt` and `mso_mdoc` (`jwt_vc_json`, `ldp_vc`, …)       | `UNSUPPORTED_CREDENTIAL_FORMAT`                             |
| `trusted_authorities` evaluation                                                 | Accepted and preserved; not part of the disclosure decision |
| Registration evidence verification (TS05)                                        | Caller-asserted only                                        |
| Embedded disclosure policies (Regulation 2024/2979 Annex III, ETSI TS 119 472-3) | Planned wallet-side module                                  |
| SARIF output                                                                     | Planned                                                     |
