# 0005: Unknown means indeterminate; strictness lives in policy and CLI

**Status:** accepted, 2026-11-05

## Context

The specification's highest product risk is false assurance. It requires that unknown scope, disclosure metadata, or path semantics never produce `ALLOW`. It also mentions a `strict` option in several places with different meanings: blocking `INDETERMINATE` in CI, and escalating some uncertain cases to `DENY`.

## Decision

- **Uncertainty is `INDETERMINATE` by default** for unknown types, claims (configurable), disclosure profiles, broad selectors, extensions, formats, and evidence problems. Never `ALLOW`.
- **Escalation to `DENY` is a policy decision**, expressed per case in `defaults` (`unknownCredential`, `unknownClaim`, `broadSelector`, `invalidRegistrationEvidence`). The policy owner decides; the result is reproducible from the policy alone.
- **Relaxation to `WARN` is also explicit** (`unknownDisclosure`, `unknownExtension`, `retentionIntent`, and the `permit*` flags) and the finding is still reported.
- **Blocking is the caller's mapping.** The core has no `strict` flag. The CLI blocks `DENY` and `INDETERMINATE` by default and adds `WARN` with `--strict`.

## Consequences

- One policy file fully determines verdicts, which makes policies reviewable as code.
- Integrators who want a softer gate must say so in the policy, where reviewers see it.
