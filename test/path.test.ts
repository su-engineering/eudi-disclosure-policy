import { describe, expect, it } from 'vitest';
import { denyRuleHits, isBroaderThan, ruleCovers } from '../src/dcql/path.js';
import type { ClaimRule, DcqlPath } from '../src/index.js';

const exact = (...path: DcqlPath): ClaimRule => ({ path, matching: 'exact' });
const subtree = (...path: DcqlPath): ClaimRule => ({ path, matching: 'subtree' });

describe('ruleCovers', () => {
  it.each<[string, ClaimRule, DcqlPath, boolean]>([
    ['identical exact path', exact('age_over_18'), ['age_over_18'], true],
    ['different name', exact('age_over_18'), ['age_over_21'], false],
    ['child of an exact rule', exact('address'), ['address', 'locality'], false],
    ['parent of an exact rule', exact('address', 'locality'), ['address'], false],
    ['descendant of a subtree rule', subtree('address'), ['address', 'locality'], true],
    ['subtree root itself', subtree('address'), ['address'], true],
    ['sibling of a subtree rule', subtree('address'), ['addresses'], false],
    ['index under a wildcard rule', exact('degrees', null, 'type'), ['degrees', 3, 'type'], true],
    [
      'wildcard under a wildcard rule',
      exact('degrees', null, 'type'),
      ['degrees', null, 'type'],
      true,
    ],
    ['wildcard under an index rule', exact('degrees', 0, 'type'), ['degrees', null, 'type'], false],
    ['string "0" under index 0', exact('degrees', 0), ['degrees', '0'], false],
    ['index 0 under string "0"', exact('degrees', '0'), ['degrees', 0], false],
    ['key under a wildcard rule', exact('degrees', null), ['degrees', 'type'], false],
    ['no case folding', exact('Age_Over_18'), ['age_over_18'], false],
    [
      'mdoc exact',
      exact('org.example.mdl.1', 'age_over_18'),
      ['org.example.mdl.1', 'age_over_18'],
      true,
    ],
    [
      'mdoc other namespace',
      exact('org.example.mdl.1', 'age_over_18'),
      ['org.example.other.1', 'age_over_18'],
      false,
    ],
    [
      'mdoc namespace subtree',
      subtree('org.example.mdl.1'),
      ['org.example.mdl.1', 'portrait'],
      true,
    ],
  ])('%s', (_, rule, request, expected) => {
    expect(ruleCovers(rule, request)).toBe(expected);
  });
});

describe('denyRuleHits', () => {
  it.each<[string, ClaimRule, DcqlPath, boolean]>([
    ['the denied node', exact('birth_date'), ['birth_date'], true],
    ['an ancestor of the denied node', exact('name', 'family_name'), ['name'], true],
    ['a child of an exact deny', exact('address'), ['address', 'locality'], false],
    ['a child of a subtree deny', subtree('address'), ['address', 'locality'], true],
    ['a sibling', exact('name', 'family_name'), ['name', 'given_name'], false],
    ['a wildcard including a denied index', exact('degrees', 0), ['degrees', null], true],
    ['an index under a denied wildcard', exact('degrees', null), ['degrees', 4], true],
    ['a different index', exact('degrees', 0), ['degrees', 1], false],
    ['string "0" vs index 0', exact('degrees', 0), ['degrees', '0'], false],
  ])('%s', (_, rule, request, expected) => {
    expect(denyRuleHits(rule, request)).toBe(expected);
  });
});

describe('isBroaderThan', () => {
  it.each<[string, ClaimRule, DcqlPath, boolean]>([
    ['parent of an allowed child', exact('address', 'locality'), ['address'], true],
    ['wildcard over an allowed index', exact('nationalities', 0), ['nationalities', null], true],
    ['covered request', exact('address', 'locality'), ['address', 'locality'], false],
    ['unrelated request', exact('address', 'locality'), ['email'], false],
    ['child of an exact rule', exact('address'), ['address', 'locality'], false],
  ])('%s', (_, rule, request, expected) => {
    expect(isBroaderThan(rule, request)).toBe(expected);
  });
});
