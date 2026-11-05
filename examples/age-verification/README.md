# Age verification

A service needs to know that the user is over 18, and nothing else. The [policy](policy.json) allows `age_over_18` from a fictional proof-of-age type, denies identity attributes, and denies unconfigured credential types (`unknownCredential: "deny"`). A second type, `urn:example:age-unprofiled:v1`, has no disclosure profile to show what happens when the engine cannot establish minimal disclosure.

All identifiers are fictional. Run the commands from this directory with the package installed. In a clone of this repository, run `pnpm build` and use `node ../../dist/cli.js` in place of `npx eudi-disclosure`.

| Command                                                                                | Verdict         | Rules                                                            | Why                                                                                                              |
| -------------------------------------------------------------------------------------- | --------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `npx eudi-disclosure lint --query requests/minimal.json --policy policy.json`          | `ALLOW`         | —                                                                | Only the age threshold is requested from a type with a known disclosure profile.                                 |
| `npx eudi-disclosure lint --query requests/pid-alternative.json --policy policy.json`  | `DENY`          | `CREDENTIAL_SET_EXCESSIVE_OPTION`, `CREDENTIAL_TYPE_NOT_ALLOWED` | The PID alternative stays selectable even though the proof-of-age option is preferred (specification §7.2).      |
| `npx eudi-disclosure lint --query requests/optional-address.json --policy policy.json` | `DENY`          | `CLAIM_EXPLICITLY_DENIED`, `OPTIONAL_CREDENTIAL_SET`             | An optional credential set is still a request for the address.                                                   |
| `npx eudi-disclosure lint --query requests/value-filter.json --policy policy.json`     | `DENY`          | `VALUE_FILTER_PROBING_RISK`                                      | values: [true] is a probing risk and the policy does not permit value filters. It proves nothing about the user. |
| `npx eudi-disclosure lint --query requests/unprofiled-type.json --policy policy.json`  | `INDETERMINATE` | `UNKNOWN_DISCLOSURE_PROFILE`                                     | The type has no disclosure profile, so minimal disclosure cannot be established.                                 |

`expected.json` holds the same table; `pnpm examples` checks every row against the built CLI, including exit codes.
