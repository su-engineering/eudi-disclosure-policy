# 0001: One package with a portable core and a Node.js CLI shell

**Status:** accepted, 2026-11-05

## Context

The specification proposes a pnpm workspace with three packages: core, a DCQL parser adapter, and a CLI. It allows simplification "if separate publishing causes friction", provided the architectural boundaries remain. The core must run in browsers and must not use `node:` modules, network APIs, environment variables, or clocks.

## Decision

Publish one package, `@su-engineering/eudi-disclosure-policy`, with:

- `dist/index.js`: the core, built with `platform: 'neutral'`.
- `dist/cli.js`: the `eudi-disclosure` executable, the only code that touches files, streams, or the clock.
- The parser adapter as a module (`src/dcql/parse.ts`) rather than a package. It is the only file that imports the parser.

The boundaries are enforced mechanically rather than by package splits:

- `tsconfig.core.json` compiles `src/` (excluding `src/cli/`) with no ambient types, so `process`, `Buffer`, `TextEncoder`, or DOM use fails to compile.
- ESLint forbids `fetch`, `process`, `Buffer`, `Date.now()`, `new Date()`, `Math.random()`, and `node:` imports in the core.
- `tools/check-package.mjs` bundles the public entry for browsers and runs it in a bare `vm` realm without timers, network, or a module loader.

## Consequences

- One version, one changelog, one install. Users of the API do not pay for the CLI: it is a separate entry point and is not imported by the core.
- Splitting later (for example, a wallet-side module) remains possible because the module boundaries already exist.
