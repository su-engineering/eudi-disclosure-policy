# Contributing

Thank you for helping. Bug reports with a reproducing query, new fixtures for real-world request shapes, and clearer documentation are especially welcome.

## Local development

Use Node.js 22 or newer and pnpm (version pinned in `package.json`; `corepack enable` selects it).

```sh
git clone https://github.com/su-engineering/eudi-disclosure-policy.git
cd eudi-disclosure-policy
corepack enable
pnpm install --frozen-lockfile
pnpm check
```

`pnpm check` runs lint, typecheck, tests, build, the package check, and the examples. Individual scripts: `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm test:coverage`, `pnpm build`, `pnpm test:package`, `pnpm examples`.

## Repository map

| Path                   | Responsibility                                                                   |
| ---------------------- | -------------------------------------------------------------------------------- |
| `src/dcql/`            | Parser adapter, supplemental checks, normalization, branch model, path relations |
| `src/policy/`          | Policy validation                                                                |
| `src/engine/`          | Registration gate, analysis, findings                                            |
| `src/rules/catalog.ts` | Rule IDs, categories, outcomes, and texts (source of `docs/rule-reference.md`)   |
| `src/cli/`             | The `eudi-disclosure` command; the only code with I/O                            |
| `fixtures/`            | Conformance-style fixtures with exact expected findings                          |
| `test/`                | Unit, property, fixture, CLI, and determinism tests                              |
| `examples/`            | Documented scenarios, executed by `pnpm examples`                                |
| `schema/`              | JSON Schema for policies                                                         |
| `docs/`                | Documentation and architecture decision records                                  |

## Rules for changes

- **Fail closed.** If a change could turn an uncertain case into `ALLOW`, it needs an ADR.
- **Core purity.** No network, file system, clock, randomness, environment, or `node:` imports outside `src/cli/`. Lint and `tsconfig.core.json` enforce this.
- **No values in output.** Findings, messages, and errors must not include claim values or other request content beyond identifiers and paths.
- **Rule changes are versioned.** Changing a rule's trigger, default verdict, or category bumps `RULES_VERSION` in `src/version.ts`. Never rename or reuse a rule ID.
- **Standards first.** Behavior that implements a clause cites it in the fixture's `standardRefs`. Do not adopt draft specifications; see the [update rule](../docs/standards-lock.md#update-rule).

## Adding a fixture

1. Add a JSON file under `fixtures/valid`, `invalid`, `indeterminate`, or `regression` with `id`, `title`, `reason`, `standardRefs`, `policy` (a name in `fixtures/policies` or an inline policy), `evaluationTime`, `dcql`, and `expected.verdict` and `expected.coverage`.
2. Run `UPDATE_FIXTURES=1 pnpm vitest run test/fixtures.test.ts` to record `expected.findings`.
3. **Read every recorded line** and check it against the fixture's `reason`. The recording is a snapshot, not a proof.

Fixtures use synthetic data and `urn:example:` identifiers only.

## Rule reference

`docs/rule-reference.md` is generated. After changing `src/rules/catalog.ts`, run `pnpm build && node tools/gen-rule-reference.mjs`. A test fails if it is stale.

## Pull requests

1. Branch from `main`.
2. Describe the observable problem and the behavior after your change.
3. Add tests: a fixture for behavior changes, a unit test for helpers.
4. Run `pnpm check`.
5. Add a changeset for package changes: `pnpm exec changeset`.

Contributions are licensed under Apache-2.0. Do not commit personal data, real credentials, or files you may not redistribute.

## Community

Read the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).

## Releases

Releases use Changesets and npm trusted publishing; see [docs/releasing.md](../docs/releasing.md).
