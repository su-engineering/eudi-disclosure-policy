import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type {
  DisclosurePolicyV1,
  EvaluateRequestInput,
  EvaluationResult,
} from '../../src/index.js';

export const ROOT = join(import.meta.dirname, '..', '..');

export interface Fixture {
  readonly file: string;
  readonly id: string;
  readonly title: string;
  readonly reason: string;
  readonly policy: string | DisclosurePolicyV1;
  readonly dcql: unknown;
  readonly evaluationTime: string;
  readonly registration?: EvaluateRequestInput['registration'];
  readonly relyingParty?: EvaluateRequestInput['relyingParty'];
  readonly expected: {
    readonly verdict: EvaluationResult['verdict'];
    readonly coverage: EvaluationResult['coverage'];
    readonly findings?: readonly string[];
  };
}

export function loadPolicy(name: string): DisclosurePolicyV1 {
  return JSON.parse(
    readFileSync(join(ROOT, 'fixtures', 'policies', `${name}.json`), 'utf8'),
  ) as DisclosurePolicyV1;
}

export function loadFixtures(): Fixture[] {
  const fixtures: Fixture[] = [];
  for (const dir of ['valid', 'invalid', 'indeterminate', 'regression']) {
    for (const name of readdirSync(join(ROOT, 'fixtures', dir)).sort()) {
      if (!name.endsWith('.json')) continue;
      const file = `${dir}/${name}`;
      fixtures.push({
        file,
        ...(JSON.parse(readFileSync(join(ROOT, 'fixtures', file), 'utf8')) as Omit<
          Fixture,
          'file'
        >),
      });
    }
  }
  return fixtures;
}

export function fixtureInput(fixture: Fixture): EvaluateRequestInput {
  return {
    profile: 'openid4vp-1.0',
    evaluationTime: fixture.evaluationTime,
    dcql: fixture.dcql,
    policy: typeof fixture.policy === 'string' ? loadPolicy(fixture.policy) : fixture.policy,
    ...(fixture.registration && { registration: fixture.registration }),
    ...(fixture.relyingParty && { relyingParty: fixture.relyingParty }),
  };
}

/** Compact, reviewable form of a finding: verdict, rule, pointer, and branch. */
export function findingLine(f: EvaluationResult['findings'][number]): string {
  return `${f.verdict} ${f.ruleId} ${f.jsonPointer || '(request)'}${f.branchId ? ` [${f.branchId}]` : ''}`;
}

/** Every string and number literal inside `values` arrays of the request. */
export function valueLiterals(dcql: unknown): string[] {
  const out: string[] = [];
  const walk = (node: unknown, inValues: boolean): void => {
    if (Array.isArray(node))
      node.forEach((n) => {
        walk(n, inValues);
      });
    else if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) walk(v, k === 'values');
    } else if (inValues && (typeof node === 'string' || typeof node === 'number'))
      out.push(String(node));
  };
  walk(typeof dcql === 'string' ? safeParse(dcql) : dcql, false);
  return out;
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
