# Changelog

## 0.1.1

### Patch Changes

- 949f6b9: Publish every release under the npm `latest` dist-tag, so `npm install` gets the newest version. Document the trusted publisher settings, and fail the package check when `npm publish` would rewrite `package.json`.

## 0.1.0

### Minor Changes

- 834511a: Initial preview release. `evaluateRequest()` checks every selectable credential and claim alternative of an OpenID4VP 1.0 DCQL query against a versioned local data-minimization policy, with caller-asserted registration scope, disclosure profiles, and privacy risk rules. The `eudi-disclosure` command lints queries and validates policies with documented exit codes. Includes a JSON Schema for policies, 70 conformance-style fixtures, and three example scenarios.
