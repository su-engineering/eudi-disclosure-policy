# Architecture decision records

| ADR                             | Decision                                                              | Status   |
| ------------------------------- | --------------------------------------------------------------------- | -------- |
| [0001](0001-core-separation.md) | One package with a portable core and a Node.js CLI shell              | Accepted |
| [0002](0002-public-api.md)      | Public API and deviations from the original specification             | Accepted |
| [0003](0003-dcql-parser.md)     | Use @openeudi/dcql 0.3.0 behind an adapter, with supplemental checks  | Accepted |
| [0004](0004-branch-analysis.md) | Per-element analysis instead of branch expansion; bounded enumeration | Accepted |
| [0005](0005-strictness.md)      | Unknown means indeterminate; strictness lives in policy and CLI       | Accepted |

New ADRs use the next number and the same sections: context, decision, consequences.
