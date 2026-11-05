import { RULES } from '../rules/catalog.js';
import type { Finding, RuleId, Severity, Verdict } from '../types.js';

export interface FindingInput {
  readonly pointer: string;
  readonly message: string;
  readonly queryId?: string | undefined;
  readonly branchId?: string | undefined;
  readonly policyRuleId?: string | undefined;
  readonly evidenceIds?: readonly string[] | undefined;
  readonly remediation?: string | undefined;
  readonly details?: Readonly<Record<string, unknown>> | undefined;
}

const SEVERITY: Readonly<Record<Verdict, Severity>> = {
  DENY: 'error',
  INDETERMINATE: 'error',
  WARN: 'warning',
  ALLOW: 'info',
};

export const VERDICT_RANK: Readonly<Record<Verdict, number>> = {
  DENY: 3,
  INDETERMINATE: 2,
  WARN: 1,
  ALLOW: 0,
};

export function worst(verdicts: Iterable<Verdict>): Verdict {
  let result: Verdict = 'ALLOW';
  for (const verdict of verdicts)
    if (VERDICT_RANK[verdict] > VERDICT_RANK[result]) result = verdict;
  return result;
}

/** Display an untrusted identifier safely: JSON-escaped and length-bounded. */
export function display(value: string): string {
  const quoted = JSON.stringify(value);
  return quoted.length > 122 ? `${quoted.slice(0, 118)}…"` : quoted;
}

export class FindingCollector {
  private readonly byKey = new Map<string, Finding>();
  private readonly onEmit: ((finding: Finding) => void) | undefined;

  constructor(onEmit?: (finding: Finding) => void) {
    this.onEmit = onEmit;
  }

  add(ruleId: RuleId, verdict: Verdict, input: FindingInput): Finding {
    const rule = RULES[ruleId];
    const finding: Finding = {
      ruleId,
      category: rule.category,
      severity: SEVERITY[verdict],
      verdict,
      message: input.message,
      jsonPointer: input.pointer,
      ...(input.queryId !== undefined && { queryId: input.queryId }),
      ...(input.branchId !== undefined && { branchId: input.branchId }),
      ...(input.policyRuleId !== undefined && { policyRuleId: input.policyRuleId }),
      ...(input.evidenceIds !== undefined && { evidenceIds: input.evidenceIds }),
      remediation: input.remediation ?? rule.remediation,
      ...(rule.standardRefs.length > 0 && { standardRefs: rule.standardRefs }),
      ...(input.details !== undefined && { details: input.details }),
    };
    // The same element can be reached through several types or rules; keep one
    // finding per location and outcome.
    const key = JSON.stringify([
      ruleId,
      verdict,
      finding.jsonPointer,
      finding.branchId,
      finding.policyRuleId,
      finding.message,
    ]);
    if (!this.byKey.has(key)) {
      this.byKey.set(key, finding);
      this.onEmit?.(finding);
    }
    return finding;
  }

  get findings(): Finding[] {
    return [...this.byKey.values()];
  }
}

const compare = (a: string | undefined, b: string | undefined): number => {
  const x = a ?? '';
  const y = b ?? '';
  return x < y ? -1 : x > y ? 1 : 0;
};

/** Order pointers segment by segment, with array indices compared numerically. */
export function comparePointers(a: string, b: string): number {
  const x = a.split('/');
  const y = b.split('/');
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const p = x[i]!;
    const q = y[i]!;
    if (p === q) continue;
    const numeric = /^\d+$/;
    if (numeric.test(p) && numeric.test(q)) return Number(p) - Number(q);
    return compare(p, q);
  }
  return x.length - y.length;
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict] ||
      comparePointers(a.jsonPointer, b.jsonPointer) ||
      compare(a.ruleId, b.ruleId) ||
      compare(a.branchId, b.branchId) ||
      compare(a.policyRuleId, b.policyRuleId) ||
      compare(a.message, b.message),
  );
}
