# mdoc retention

A verifier reads one namespaced element from a fictional mdoc doctype and must not retain it. The [policy](policy.json) allows exactly `["org.example.mdl.1", "age_over_18"]` and leaves retention at its default, `deny`. A second doctype has no disclosure profile.

All identifiers are fictional. Run the commands from this directory with the package installed. In a clone of this repository, run `pnpm build` and use `node ../../dist/cli.js` in place of `npx eudi-disclosure`.

| Command                                                                               | Verdict         | Rules                           | Why                                                                                           |
| ------------------------------------------------------------------------------------- | --------------- | ------------------------------- | --------------------------------------------------------------------------------------------- |
| `npx eudi-disclosure lint --query requests/exact-element.json --policy policy.json`   | `ALLOW`         | —                               | Exact namespace and element, no retention.                                                    |
| `npx eudi-disclosure lint --query requests/retain.json --policy policy.json`          | `DENY`          | `MDOC_RETENTION_REQUESTED`      | Same element with intent_to_retain: true.                                                     |
| `npx eudi-disclosure lint --query requests/other-namespace.json --policy policy.json` | `DENY`          | `CLAIM_NOT_ALLOWED_FOR_PURPOSE` | A similar element in another namespace is not authorized.                                     |
| `npx eudi-disclosure lint --query requests/wildcard.json --policy policy.json`        | `DENY`          | `DCQL_INVALID`                  | mdoc paths are exactly [namespace, element]; a wildcard is invalid DCQL (OpenID4VP 1.0 §7.2). |
| `npx eudi-disclosure lint --query requests/unprofiled.json --policy policy.json`      | `INDETERMINATE` | `UNKNOWN_DISCLOSURE_PROFILE`    | The mandatory disclosure of this doctype is unknown.                                          |

`expected.json` holds the same table; `pnpm examples` checks every row against the built CLI, including exit codes.
