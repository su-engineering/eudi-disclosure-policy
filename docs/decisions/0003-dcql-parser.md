# 0003: DCQL parser

**Status:** accepted, 2026-11-05

## Context

The specification asks to reuse and audit an existing DCQL 1.0 parser rather than write one, and to keep OpenID4VP-specific parsing behind an adapter.

## Audit of @openeudi/dcql 0.3.0

| Criterion       | Finding                                                                                                                                                                                                                                                                                                                 |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| License         | Apache-2.0, compatible.                                                                                                                                                                                                                                                                                                 |
| Maintenance     | Four releases in 2026 (0.1.0 in April to 0.3.0 on 2026-10-21); 0.3.0 carries an SLSA provenance attestation on npm.                                                                                                                                                                                                     |
| Dependencies    | None at runtime.                                                                                                                                                                                                                                                                                                        |
| Portability     | ESM and CJS; no Node.js built-ins; runs in the bare-realm browser test.                                                                                                                                                                                                                                                 |
| Conformance     | Interop-tested against OpenWallet Foundation vectors (upstream claim). Enforces id patterns and uniqueness, required `meta` with `vct_values` / `doctype_value`, non-empty arrays, mdoc paths of exactly two strings, `claim_sets` references and its dependency on `claims`, credential set references, boolean types. |
| Error reporting | Typed `DcqlValidationError` with a code and a JSON pointer. Messages may include claim ids; the adapter replaces them with its own messages per code.                                                                                                                                                                   |

Gaps found by probing:

1. Empty credential set options (`"options": [[]]`) are accepted. §6.2 requires non-empty options.
2. Duplicate claim paths in one credential query are accepted. §6.1: verifiers MUST NOT point to the same claim more than once.
3. Non-integer numbers in `values` are accepted. §6.3 allows strings, integers, and booleans.
4. Unknown top-level properties are dropped from the returned object. Properties at other levels are kept.
5. No size or depth limits.

## Decision

Depend on `@openeudi/dcql` at exactly `0.3.0`. The adapter (`src/dcql/parse.ts`):

- enforces resource limits before calling the parser;
- calls `validateQuery` only as a validator, and discards its return value;
- runs supplemental checks for gaps 1–3;
- normalizes from the **original input**, which closes gap 4 and preserves exact pointers.

Fixtures `TC-BASE-02c`, `TC-BASE-02d`, `TC-VALUES-03`, and `TC-EXT-02` cover the gaps. They are candidates for upstream issues.

## Consequences

- One small, audited runtime dependency. Upgrades are deliberate: a new parser version is a reviewed change and follows the [standards update rule](../standards-lock.md#update-rule).
- If upstream fixes the gaps, the supplemental checks stay as defense in depth.
