# Security policy

This library decides whether a request for personal data may be sent. A wrong `ALLOW`, a leak of claim values into output, or a way to make it hang on hostile input are security bugs. Reports are welcome.

## Report a vulnerability

Email **[security@su.engineering](mailto:security@su.engineering)** with `eudi-disclosure-policy` in the subject. Do not open a public issue or pull request for anything that looks exploitable until a fix is released.

Include:

- The package version and how you call it (API or CLI, options).
- A minimal DCQL query and policy that reproduce the problem, using synthetic data and `urn:example:` identifiers.
- The result you got and the result you expected, with the OpenID4VP clause if relevant.

Never send real credentials, presentations, personal data, or registration certificates. If a report needs sensitive material, contact us first to agree on a transfer method.

We will acknowledge the report, coordinate a fix and disclosure date with you, and credit you if you wish. There is no bug bounty or response-time SLA.

## What counts

- A request that yields `ALLOW` or `WARN` although a selectable element violates the policy, or although required information is missing.
- Registration evidence used for comparison although it is unverified, stale, incomplete, or for another relying party.
- Claim values, or other request content beyond identifiers and paths, appearing in results, error messages, or CLI output.
- Input that crashes the process, recurses without bound, or takes disproportionate time or memory within the default limits.
- Prototype pollution or code execution through policies, evidence, or queries.

Disagreements about what a policy should allow are not vulnerabilities; open an issue.

## Data-handling contract

- The core makes no network requests, reads no files or environment variables, reads no clock, and collects no telemetry.
- Results contain rule IDs, JSON pointers, claim paths, credential query IDs, type identifiers, extension property names, and counts. They never contain `values` entries.
- Error messages contain error codes, pointers, and limit names only.
- The CLI reads only the files you name and stdin, writes only to stdout and stderr, and shows file paths only with `--no-redact`.
- The opt-in `debug` callback is not covered by this contract.

See the [threat model](docs/threat-model.md) and [trust boundaries](docs/trust-boundaries.md).

## Supported versions

| Version       | Supported                 |
| ------------- | ------------------------- |
| 0.x (preview) | Latest minor release only |

Security fixes are released as a new version. Older 0.x releases do not receive backports.
