# 0004: Branch analysis

**Status:** accepted, 2026-11-05

## Context

A DCQL query describes alternatives through `credential_sets` (with optional sets) and `claim_sets`. Every alternative the wallet may choose must be evaluated, not only the preferred one. Explicit enumeration is exponential: twelve optional sets already give 4,096 branches. The specification allows symbolic evaluation if its soundness is proven by tests, and requires a branch budget (default 2,048) that never yields `ALLOW` when exceeded.

## Decision

1. **Per-element analysis.** Rules about a claim, a credential query, or a type depend only on that element. The engine computes which elements are selectable (reachable through some option of some set) and evaluates each once. A branch's verdict is the worst verdict of its elements; every option of every set appears in at least one branch (sets are independent, and options reference existing queries); so the worst branch equals the worst selectable element.
2. **Proof by test.** `test/properties.test.ts` generates random queries, enumerates every branch explicitly, rebuilds each branch as a request with no alternatives, and checks that the worst branch verdict equals the element verdict of the full request.
3. **Set-level comparisons** run per set, not per branch: an option that violates the policy while a sibling complies, and an option that is a strict superset of a sibling.
4. **Bounded enumeration.** Branches are counted by lazy enumeration that stops at `maxBranches`. Beyond it, the result is `INDETERMINATE` with `BRANCH_LIMIT_REACHED` and `coverage: partial`, while element findings, including denials, remain complete. The number of set options is budgeted (`maxSetOptions`, default 256), which also bounds recursion depth.
5. **No unique-data arithmetic.** Several credential queries can be answered by the same credential, so the engine never sums claim counts into a "disclosure volume".

## Consequences

- Analysis cost is linear in request size; only counting is bounded by the budget.
- A request above the budget is never allowed, even though its element analysis is complete. This matches the specification and keeps wallet choice spaces reviewable.
