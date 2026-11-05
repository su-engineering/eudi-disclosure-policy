# Concepts

This page explains what the library decides, from which inputs, and with which semantics. The [rule reference](rule-reference.md) lists every individual rule.

## Four separate controls

An EUDI presentation passes several independent checks. This library implements one of them and must not be mistaken for the others.

| Control                              | Who decides                                        | Question                                                                                                                                                | This library                                                  |
| ------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| **Purpose policy**                   | The verifier's own policy owner                    | Should our service ask for this, for this purpose?                                                                                                      | **Yes.** The `DisclosurePolicyV1` document.                   |
| **Registered scope**                 | The relying-party registrar; checked by the wallet | Did the relying party register to request these attributes? (EUDI ARF 3.0.0 §6.6.3.3; Implementing Regulation (EU) 2024/2982, Annex II, WRP-OVERASKING) | **Comparison only**, against evidence you verified elsewhere. |
| **Embedded disclosure policy (EDP)** | The credential issuer; enforced by the wallet      | May this attestation be shown to this relying party at all? (ARF §6.6.2.8, §6.6.3.4)                                                                    | **No.** Planned as a separate wallet-side module.             |
| **User approval**                    | The user, in the wallet                            | Do I agree to present these attributes? (ARF §6.6.3.5)                                                                                                  | **No.**                                                       |

A verifier-side `ALLOW` never authorizes a wallet to disclose. The wallet still authenticates the relying party, checks registration, evaluates any EDP, and asks the user.

The library also deliberately applies a stricter rule than the wallet framework requires. Under Implementing Regulation (EU) 2024/2982, Annex II (WRP-OVERASKING-01 to -03), a wallet that sees a request exceeding the registration certificate warns the user and asks for explicit approval; the wallet provider decides whether to continue, disclose only the registered subset, or reject. Wallet validation of registration certificates applies only from 11 August 2028 (Implementing Regulation (EU) 2026/1731, recital 27). A verifier preflight with this library blocks the request before it is sent. That is an organizational choice, not a claim that regulation always requires a hard denial.

## Inputs

- **The DCQL query** you are about to send: the `dcql_query` of an OpenID4VP 1.0 authorization request, as parsed JSON or JSON text.
- **A policy** for one purpose: allowed and denied claims per credential type, plus defaults for uncertain cases. See [policy format](policy-format.md).
- **Registration evidence** (optional): the registered scope of your relying-party service, asserted by your code as verified or not. See [trust boundaries](trust-boundaries.md).
- **Relying-party context** (needed with evidence): the `rpId`, and optionally `serviceId` and `intendedUseId`, being evaluated.
- **Evaluation time**: a UTC timestamp you supply. The core never reads the clock, so results are reproducible.

## What a wallet may return

OpenID4VP 1.0 §6.4 defines how a query selects credentials and claims. The engine follows it exactly.

**Credentials.** Without `credential_sets`, every credential query is requested. With `credential_sets`, the wallet satisfies every set whose `required` is `true` or omitted, and may also satisfy optional sets. Each set is satisfied by exactly one of its `options`, and an option is a conjunction: `["age", "name"]` means both credentials together. Option order expresses preference only.

**Claims.** Without `claims`, no selectively disclosable claim is requested; only data that is mandatory to present is returned. With `claims` but no `claim_sets`, every listed claim is requested. With `claim_sets`, the wallet returns one option, again with order as preference only.

A **branch** is one complete answer: one option per required set, zero or one option per optional set, and one claim set option per selected credential query. A credential query or claims query that no option references is never requested. The engine reports it as `UNREFERENCED_QUERY` and does not treat it as disclosed.

### Every branch is evaluated

Claim authorization, value filters, retention, holder binding, and type checks depend only on the element itself. So a request is as bad as its worst **selectable** element, and the engine evaluates each element once instead of expanding the Cartesian product of branches. Every option of every set appears in at least one branch, which makes this equivalent to evaluating every branch. A property test checks the equivalence against explicit enumeration on random queries.

Comparisons between alternatives are separate findings: an option that violates the policy while a sibling complies (`CREDENTIAL_SET_EXCESSIVE_OPTION`, `CLAIM_SET_NONMINIMAL` as `DENY`), and an option that requests a strict superset of a sibling (`WARN`).

Branch-level outcomes are enumerated up to `maxBranches` (default 2048). Above that, the request is `INDETERMINATE` with `BRANCH_LIMIT_REACHED`. Element findings, including denials, are still complete and still reported.

## Matching

**Credential types.** A policy credential rule matches a credential query only when the format and the type identifier (`vct` for `dc+sd-jwt`, `doctype` for `mso_mdoc`) are exactly equal. There is no substring matching, case folding, Unicode normalization, or URI equivalence. A query listing several `vct_values` is a union: each type is evaluated, and an allowed type never approves another. SD-JWT VC type inheritance is not resolved; a subtype needs its own rule.

**Claims path pointers** (OpenID4VP 1.0 §7). A path selects a node and everything below it. Segments compare with strict types: the string `"0"` is not the index `0`. A `null` segment selects every array element.

- An `exact` allow rule covers only the identical path. A `null` in the rule covers any index or wildcard in that position.
- A `subtree` allow rule also covers every descendant.
- Requesting a parent of an allowed path (`["address"]` when only `["address", "locality"]` is allowed) or a wildcard where the rule names an index is **broader** than the allowlist: `BROAD_CLAIM_SELECTOR`.
- A deny rule is hit by any request that may disclose the denied node: the node, an ancestor, or an intersecting wildcard. A `subtree` deny rule is also hit by descendants. Deny rules always take precedence.
- mdoc paths are exactly `[namespace, element]`. A similar element name in another namespace is a different claim. mdoc wildcards are invalid DCQL.

## What a presentation discloses beyond the request

A presentation can disclose more than the named claims: fields that are always present, data from non-selectively disclosable formats, or claims selected by another query for the same credential (OpenID4VP 1.0 §6.4). The engine cannot know a credential's content. The policy describes it with a **disclosure profile** per credential rule:

- `knownMandatoryPaths` lists fields always disclosed. Each must be allowed and not denied, or `MANDATORY_DISCLOSURE_EXCEEDS_POLICY` denies the request. Use `[]` to state that there are none.
- For `non-selective` credentials, list the complete content.
- Without a profile, with mode `unknown`, or without `knownMandatoryPaths`, the engine reports `UNKNOWN_DISCLOSURE_PROFILE` (`INDETERMINATE`, or `WARN` if `unknownDisclosure` is `"warn"`).

Profiles are statements by the policy author about a schema they trust. They are not fetched or verified.

## Results

### Verdict

| Verdict         | Meaning                                                                                             |
| --------------- | --------------------------------------------------------------------------------------------------- |
| `ALLOW`         | Every applicable rule is satisfied with the information required. Informational findings may exist. |
| `WARN`          | No violation, but a risk or review condition exists. Not a statement that presenting is safe.       |
| `DENY`          | At least one configured rule is violated by a selectable element.                                   |
| `INDETERMINATE` | No violation was proven, but information, semantics, trust, or analysis coverage is insufficient.   |

The aggregate verdict is the most severe finding verdict: `DENY` > `INDETERMINATE` > `WARN` > `ALLOW`. Strict CI should block on `DENY` and `INDETERMINATE`, as the CLI does by default.

### Coverage

| Coverage      | Meaning                                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------------------- |
| `complete`    | Every selectable element was analyzed with sufficient information.                                                |
| `partial`     | At least one finding is `INDETERMINATE`.                                                                          |
| `unsupported` | Nothing could be analyzed: the query is invalid, or every selectable credential query uses an unsupported format. |

### Finding categories

| Category | Meaning                                                                             |
| -------- | ----------------------------------------------------------------------------------- |
| `N`      | Protocol invalidity: the request violates OpenID4VP 1.0.                            |
| `A`      | Authorization: the request violates the policy or verified registered scope.        |
| `P`      | Privacy or security risk: a query feature that increases disclosure or linkability. |
| `U`      | Uncertainty: information or semantics are missing.                                  |
| `O`      | Operational: an analysis limit was reached.                                         |

Findings are sorted by verdict, then JSON pointer (array indices numerically), then rule ID, then branch. Branch IDs are stable labels such as `cs0.o1` (credential set 0, option 1) and `pid.cl2` (claim set option 2 of credential query `pid`), joined with `+`.

## What the engine does not infer

- **No semantic equivalence.** `birth_date` does not satisfy an `age_over_18` purpose, and `age_over_18` is not derived from `birth_date`. Only explicit policy rules count.
- **No lawful-purpose inference.** Classification labels in a policy are the author's labels, not legal classifications.
- **No value-based reasoning.** A `values` filter is reported as a probing risk (OpenID4VP 1.0 §6.4.1, §15.4.1). It is never evidence about the user or a reason to allow.
- **No request rewriting.** The engine explains what should change; it never mutates a query.
