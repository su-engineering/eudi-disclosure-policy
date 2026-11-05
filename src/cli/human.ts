import type { RuleDefinition } from '../rules/catalog.js';
import type { EvaluationResult, Verdict } from '../types.js';

const WIDTH = 76;
const INDENT = '       ';
const LABEL: Record<Verdict, string> = {
  DENY: 'DENY',
  INDETERMINATE: 'INDET',
  WARN: 'WARN',
  ALLOW: 'INFO',
};

/** Wrap at a fixed width: output never depends on the terminal. */
function wrap(text: string, indent: string): string {
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (line && indent.length + line.length + 1 + word.length > WIDTH) {
      lines.push(indent + line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(indent + line);
  return lines.join('\n');
}

/** Replace control characters so that untrusted identifiers cannot drive the terminal. */
function safe(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, '�');
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

export function formatHuman(result: EvaluationResult): string {
  const out: string[] = [
    'EUDI DISCLOSURE POLICY / REQUEST PREFLIGHT',
    `Policy: ${safe(result.policy.id)}@${safe(result.policy.version)} (${safe(result.policy.purposeId)})`,
    `Profile: ${result.profile}`,
    `Evaluated at: ${result.evaluatedAt}`,
    `Registration evidence: ${result.registrationEvidence}`,
    `Verdict: ${result.verdict}`,
    `Coverage: ${result.coverage}`,
    '',
  ];
  for (const f of result.findings) {
    out.push(`${LABEL[f.verdict].padEnd(INDENT.length)}${f.ruleId}`);
    out.push(
      `${INDENT}${safe(f.jsonPointer || '(whole request)')}${f.branchId ? `  [branch ${safe(f.branchId)}]` : ''}`,
    );
    out.push(wrap(safe(f.message), INDENT));
    if (f.verdict !== 'ALLOW' && f.remediation) out.push(wrap(`Fix: ${f.remediation}`, INDENT));
    out.push('');
  }
  const s = result.summary;
  out.push(
    [
      plural(s.errors, 'denial', 'denials'),
      plural(s.warnings, 'warning', 'warnings'),
      plural(s.indeterminate, 'indeterminate check', 'indeterminate checks'),
      plural(s.info, 'note', 'notes'),
    ].join(' | '),
  );
  if (result.verdict === 'ALLOW' || result.verdict === 'WARN') {
    out.push(
      wrap(
        'ALLOW and WARN mean the request satisfies the configured rules. They are not a legal, trust, or certification statement.',
        '',
      ),
    );
  }
  return out.join('\n') + '\n';
}

export function formatExplain(rule: RuleDefinition): string {
  const out = [
    `${rule.id} — ${rule.title}`,
    `Category: ${rule.category}`,
    '',
    wrap(`Outcome: ${rule.outcome}`, ''),
    '',
    wrap(rule.description, ''),
    '',
    wrap(`Fix: ${rule.remediation}`, ''),
  ];
  if (rule.standardRefs.length > 0) out.push('', `References: ${rule.standardRefs.join('; ')}`);
  return out.join('\n') + '\n';
}
