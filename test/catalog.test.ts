import { describe, expect, it } from 'vitest';
import { RULES, RULE_IDS } from '../src/index.js';
import { loadFixtures } from './helpers/fixtures.js';

const INFORMATIONAL = new Set(['OPTIONAL_CREDENTIAL_SET', 'UNREFERENCED_QUERY']);

describe('rule catalog', () => {
  it('documents every rule completely', () => {
    for (const id of RULE_IDS) {
      const rule = RULES[id];
      expect(rule.id).toBe(id);
      expect(rule.title.length).toBeGreaterThan(5);
      expect(rule.description.length).toBeGreaterThan(40);
      expect(rule.remediation.length).toBeGreaterThan(10);
      expect(rule.outcome.length).toBeGreaterThan(3);
    }
  });

  it('has a fixture that triggers every rule, and one that does not', () => {
    const fixtures = loadFixtures();
    const lines = fixtures.flatMap((f) => f.expected.findings ?? []);
    for (const id of RULE_IDS) {
      const triggering = lines.filter((l) => l.split(' ')[1] === id);
      const verdicts = new Set(triggering.map((l) => l.split(' ')[0]));
      if (INFORMATIONAL.has(id)) expect(verdicts, id).toEqual(new Set(['ALLOW']));
      else
        expect(
          [...verdicts].some((v) => v !== 'ALLOW'),
          id,
        ).toBe(true);
      expect(
        fixtures.some((f) => !(f.expected.findings ?? []).some((l) => l.split(' ')[1] === id)),
        id,
      ).toBe(true);
    }
  });
});
