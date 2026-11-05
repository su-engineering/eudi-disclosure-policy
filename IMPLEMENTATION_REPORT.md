# Implementation report

Milestones M0 and M1 of the _EUDI Disclosure Policy implementation specification_ (version 1.0, 5 November 2026), prepared for the 0.1.0 preview. Updated 2026-11-05.

## Implemented

| Spec item                                                                                        | Status                                                                                             | Where                                                                                           |
| ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| M0-01 Repository, Apache-2.0, strict TypeScript, ESLint, Prettier, Vitest, CI matrix, Dependabot | Done                                                                                               | Root configuration, `.github/`                                                                  |
| M0-02 Standards re-check and lock                                                                | Done                                                                                               | [docs/standards-lock.md](docs/standards-lock.md)                                                |
| M0-03 Parser audit and choice                                                                    | Done: @openeudi/dcql 0.3.0 behind an adapter, five gaps found and covered                          | [ADR 0003](docs/decisions/0003-dcql-parser.md)                                                  |
| M0-04 Policy, input, result types; rule catalog; schema validation; canonical JSON               | Done                                                                                               | `src/types.ts`, `src/rules/catalog.ts`, `src/policy/validate.ts`, `src/canonical.ts`, `schema/` |
| M0-05 Baseline fixtures                                                                          | Done: 70 fixtures                                                                                  | `fixtures/`                                                                                     |
| M0-06 Privacy-safe errors, redaction tests                                                       | Done                                                                                               | `src/errors.ts`, redaction tests                                                                |
| M1-01 Normalizer with pointers and alternative edges                                             | Done                                                                                               | `src/dcql/normalize.ts`                                                                         |
| M1-02 Type matching and exact/subtree paths                                                      | Done                                                                                               | `src/dcql/path.ts`, `src/engine/analyze.ts`                                                     |
| M1-03 Purpose allow and deny rules                                                               | Done                                                                                               | `src/engine/analyze.ts`                                                                         |
| M1-04 credential_sets and claim_sets, optional branches, branch budget                           | Done                                                                                               | `src/dcql/branch-model.ts`, [ADR 0004](docs/decisions/0004-branch-analysis.md)                  |
| M1-05 Registration gates, no cryptographic pretense                                              | Done                                                                                               | `src/engine/registration.ts`                                                                    |
| M1-06 Privacy risk rules                                                                         | Done: values, multiple, holder binding, retention, unknown disclosure, broad selectors, extensions | `src/engine/analyze.ts`                                                                         |
| M1-07 Deterministic aggregation, provenance, redaction                                           | Done                                                                                               | `src/engine/findings.ts`, `src/evaluate.ts`                                                     |
| M1-08 CLI `lint`, `policy validate`, `explain`, exit codes                                       | Done                                                                                               | `src/cli/`                                                                                      |
| M1-09 Three documented examples and CI recipe                                                    | Done, plus a Node.js API example                                                                   | `examples/`, [docs/integration.md](docs/integration.md)                                         |
| M1-10 Security and resource tests                                                                | Done                                                                                               | `test/evaluate.test.ts`, `test/properties.test.ts`                                              |
| M2-01 JSON Schema for policies (pulled forward)                                                  | Done                                                                                               | `schema/disclosure-policy-v1.schema.json`                                                       |

## Commands executed

On Linux (Node.js 24.15.0, pnpm 11.2.2), from a clean `dist/`:

| Command                                                                              | Result                                                                                           |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `pnpm install --frozen-lockfile`                                                     | Pass                                                                                             |
| `pnpm lint` (ESLint strict-type-checked, Prettier check)                             | Pass, 0 problems                                                                                 |
| `pnpm typecheck` and `tsc -p tsconfig.core.json` (core with no Node.js or DOM types) | Pass                                                                                             |
| `pnpm build`                                                                         | Pass                                                                                             |
| `pnpm test`                                                                          | Pass: 227 tests in 9 files                                                                       |
| `pnpm test:coverage`                                                                 | Pass: 96.9% statements, 91.88% branches, 98.92% functions, 98.09% lines (thresholds 90/85/90/90) |
| `pnpm test:package`                                                                  | Pass: 5 package targets; 97.7 KiB browser bundle evaluated in a bare `vm` realm                  |
| `pnpm examples`                                                                      | Pass: 15 CLI runs (verdict, exit code, exact rule IDs) and the API example                       |
| `node tools/gen-rule-reference.mjs --check`                                          | Pass                                                                                             |
| `pnpm audit`                                                                         | No known vulnerabilities (after overriding a dev-only minimatch advisory, GHSA-g3hv-75wg-m249)   |
| `pnpm pack` and install into a clean project                                         | Pass: CLI, ESM import, and TypeScript `nodenext` types                                           |

The macOS and Node.js 22 legs of the CI matrix have not run yet; they run on the first push.

## Test inventory

- **70 fixtures** (`fixtures/valid`, `invalid`, `indeterminate`, `regression`), each with expected verdict, coverage, and the exact ordered list of findings. Every fixture is also checked for leaked `values` literals.
- **Property tests** (fast-check, 400 runs each): per-element analysis equals explicit branch enumeration; reordering credential queries does not change the verdict; adding a forbidden alternative, a deny rule, or verified evidence never improves a verdict; missing disclosure knowledge never yields `ALLOW`; every pointer resolves; values never appear; determinism. A deliberate mutation (skipping optional sets) made three properties fail, confirming they detect real regressions.
- **Unit tests**: path relations, policy validation, SHA-256 against `node:crypto`, canonical JSON, timestamps, input errors, every resource limit, no-network/clock/randomness isolation, input immutability, 100-run byte determinism per fixture.
- **CLI tests**: every exit code, stdin, redaction of input and paths, snapshots of human and JSON output, the built executable, and a test that the README transcript equals real output.
- **Catalog test**: every rule is triggered by at least one fixture and absent from at least one.

## Deviations from the specification

All recorded in ADRs or the standards lock:

1. **Single package** instead of a three-package workspace, with boundaries enforced by compiler settings, lint rules, and a bundle test ([ADR 0001](docs/decisions/0001-core-separation.md)).
2. **API additions**: `category`, `engine`, `relyingParty`, JSON text input, resource limits, optional policy defaults for uncertain cases, `allowRetention`, `reviewedExtensions`, three additional rule IDs. `options.strict` moved to the CLI; undefined `riskRules` not supported ([ADR 0002](docs/decisions/0002-public-api.md), [ADR 0005](docs/decisions/0005-strictness.md)).
3. **mdoc wildcard paths** are `DCQL_INVALID` (`DENY`), not `INDETERMINATE`, because OpenID4VP 1.0 §7.2 makes them invalid.
4. **Specification §7.2 example** is `INDETERMINATE` under the sample policy (which sets `unknownCredential: "indeterminate"`) and `DENY` with `"deny"`. Never `ALLOW`.
5. **Default branch** is `main`; the npm package publishes 0.x under the `next` dist-tag.

## Known limitations

- Registration evidence is caller-asserted. There is no TS05 parser or signature verification.
- Only `dc+sd-jwt` and `mso_mdoc` are interpreted. `trusted_authorities` is preserved but not evaluated.
- SD-JWT VC type inheritance is not resolved.
- Disclosure profiles are policy-author statements; no schema registry is consulted.
- Regulation texts on EUR-Lex were not machine-retrieved (bot protection); their references are carried over from the specification and must be checked manually.
- No independent security review has taken place.

## Minimal usage

```ts
import { evaluateRequest } from '@su-engineering/eudi-disclosure-policy';

const { verdict, findings } = evaluateRequest({
  profile: 'openid4vp-1.0',
  evaluationTime: new Date().toISOString(),
  dcql,
  policy,
});
if (verdict === 'DENY' || verdict === 'INDETERMINATE')
  throw new Error(findings.map((f) => f.ruleId).join(', '));
```

## Next steps (M2)

1. First npm publish and trusted-publisher setup ([docs/releasing.md](docs/releasing.md)).
2. SARIF output for code-scanning tools (M2-02).
3. Interoperability fixtures from OpenID4VP examples and public wallet/verifier test suites, with source and license per fixture (M2-05).
4. Report the parser gaps upstream to openeudi/dcql.
5. A format-adapter interface with contract tests (M2-04), then `jwt_vc_json`.
6. Integration with one open-source verifier, such as keycloak-oid4vp (M2-06).
7. External reviews from at least two implementers (M2-08).
