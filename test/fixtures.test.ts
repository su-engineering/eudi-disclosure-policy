import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { canonicalJson, evaluateRequest } from '../src/index.js';
import {
  ROOT,
  findingLine,
  fixtureInput,
  loadFixtures,
  valueLiterals,
} from './helpers/fixtures.js';

// UPDATE_FIXTURES=1 records the current findings into fixtures that lack them.
// Review every recorded line against the fixture's reason before committing.
const update = process.env['UPDATE_FIXTURES'] === '1';

describe('fixtures', () => {
  const fixtures = loadFixtures();

  it('has unique ids', () => {
    const ids = fixtures.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  for (const fixture of fixtures) {
    it(`${fixture.id} ${fixture.file}: ${fixture.title}`, () => {
      const result = evaluateRequest(fixtureInput(fixture));
      const lines = result.findings.map(findingLine);

      expect(result.verdict, fixture.reason).toBe(fixture.expected.verdict);
      expect(result.coverage).toBe(fixture.expected.coverage);

      // Directory names state the expected class of outcome.
      const dir = fixture.file.split('/')[0];
      if (dir === 'valid') expect(['ALLOW', 'WARN']).toContain(result.verdict);
      if (dir === 'invalid') expect(result.verdict).toBe('DENY');
      if (dir === 'indeterminate') expect(result.verdict).toBe('INDETERMINATE');

      // Values from the request never appear in the result.
      const serialized = canonicalJson(result);
      for (const literal of valueLiterals(fixture.dcql)) {
        if (literal.length >= 4) expect(serialized).not.toContain(literal);
      }
      if (typeof fixture.dcql === 'string') expect(serialized).not.toContain('SYNTH-SECRET');

      if (fixture.expected.findings) {
        expect(lines).toEqual(fixture.expected.findings);
      } else if (update) {
        const path = join(ROOT, 'fixtures', fixture.file);
        const raw = JSON.parse(readFileSync(path, 'utf8')) as { expected: Record<string, unknown> };
        raw.expected['findings'] = lines;
        writeFileSync(path, JSON.stringify(raw, null, 2) + '\n');
      } else {
        expect.fail(`Fixture ${fixture.file} has no expected findings`);
      }
    });
  }
});
