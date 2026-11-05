# Trust boundaries

**Do not use this library as a relying-party verifier, a registration checker, or a compliance certificate.** It evaluates a request against configuration you trust. It verifies no signature, certificate, registry, or trust list, and it makes no network requests.

## What the library trusts

| Input                 | Trusted?                                                 | Why                                                                                                                                       |
| --------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| The policy            | **Yes.**                                                 | It is your organization's approved configuration, maintained by an administrator. It is still validated strictly.                         |
| The DCQL query        | **No.**                                                  | It may come from application code influenced by users or other systems. It is parsed with resource limits and never executed or followed. |
| Registration evidence | **Only its `state`, and only as asserted by your code.** | See below.                                                                                                                                |
| Relying-party context | **Yes.**                                                 | It names the deployment being evaluated and comes from your configuration.                                                                |
| Evaluation time       | **Yes.**                                                 | Supply it from a trusted clock. Evidence freshness depends on it.                                                                         |

## Registration evidence is caller-asserted

`RegistrationScopeEvidence` has a `state` of `verified`, `unverified`, or `absent`. The library cannot check that claim. A JSON object with `state: "verified"` is not proof of anything: it is a statement by the code that built it.

Construct `verified` evidence only in trusted server code, and only after you have:

1. Obtained the relying-party registration data from the authoritative source for your Member State and profile (for example, a registration certificate or a registrar API defined by EUDI TS05/TS06).
2. Verified its signature or certificate chain against the applicable trust anchors.
3. Checked its validity period and revocation status.
4. Confirmed that it names your relying party and the service being evaluated.

Then record where it came from in `provenance`: `source`, `profile`, `verifier`, `verifiedAt`, optional `expiresAt`, and the `digest` of the verified record.

**Never** derive the `state`, or any part of the evidence, from an HTTP request, a query parameter, a user upload, or the DCQL query.

Even for evidence asserted as verified, the engine fails closed when:

- provenance is missing or incomplete, or a timestamp is not strict UTC;
- `verifiedAt` is after the evaluation time;
- `expiresAt` is at or before the evaluation time;
- no `relyingParty` context was supplied, or `rpId`, `serviceId`, or `intendedUseId` differ from the evidence.

These yield `REGISTRATION_EVIDENCE_INVALID_OR_STALE` (`INDETERMINATE`, or `DENY` by policy). The evidence content is then ignored; there is no fallback. `unverified` evidence yields `REGISTRATION_EVIDENCE_UNVERIFIED` and is never compared.

`result.registrationEvidence` is `verified` only when the evidence was used. Even then it means "asserted as verified by the caller, complete, fresh, and applicable", not "cryptographically verified by this library".

## What a result does and does not mean

| A result of…    | means                                                                                                         | does not mean                                                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLOW`         | Every selectable element satisfies the configured rules, with the disclosure information the policy provided. | The request is lawful, necessary, proportionate, registered, or certified. The wallet will disclose only the named claims. The relying party is trusted. |
| `DENY`          | A selectable element violates a configured rule.                                                              | The request is illegal. The relying party is malicious.                                                                                                  |
| `INDETERMINATE` | The engine could not decide with the information given.                                                       | The request is unsafe. It is a request for more information or review.                                                                                   |

The library has no badge, seal, or "certified" output, by design.

## Where it fits

```text
Your service builds a DCQL query
        │
        ▼
evaluateRequest(query, policy, verified-evidence?)   ◀── this library (verifier side)
        │ ALLOW / WARN
        ▼
Sign and send the OpenID4VP authorization request
        │
        ▼
Wallet: authenticate RP → check registration → evaluate EDP → ask the user
        │
        ▼
Presentation returned → your verifier validates it cryptographically
```

The library sits entirely before the request is sent. It does not replace any wallet-side check or the cryptographic validation of the presentation you receive.

## Diagnostics and logging

Results contain rule IDs, JSON pointers, claim paths, credential query IDs, and type identifiers. They never contain `values` entries, credential data, keys, or tokens. Value filters are described by count and JSON type only.

The opt-in `options.debug` callback receives internal structures: the normalized query (identifiers, claim paths, type identifiers, extension names) and each finding as it is produced. Value filters are reduced to count and type there too, but the event format is not a stable redaction contract and may carry more request content in future versions. Treat debug output as sensitive and do not wire it to production logs.

Policy files are not secret stores. Do not put secrets in descriptions or reasons.
