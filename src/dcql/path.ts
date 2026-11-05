/**
 * Claims path pointer relations (OpenID4VP 1.0 §7).
 *
 * A path selects a node and everything below it. Segments compare with strict
 * type equality: the string "0" and the index 0 are different segments, and no
 * Unicode or case normalization is applied. A `null` segment selects every
 * element of an array, so it can only correspond to an index or another `null`.
 *
 * These relations are conservative by construction. When it cannot be proven
 * that a request stays inside an allowed path, the request is not covered.
 */
import type { ClaimRule, DcqlPath } from '../types.js';

type Segment = string | number | null;

const isArrayPosition = (segment: Segment): boolean =>
  segment === null || typeof segment === 'number';

/** `rule` matches every value `request` can select at this position. */
function segmentCovers(rule: Segment, request: Segment): boolean {
  if (rule === null) return isArrayPosition(request);
  return rule === request;
}

/** Some value could be selected by both segments. */
function segmentsIntersect(a: Segment, b: Segment): boolean {
  if (a === null) return isArrayPosition(b);
  if (b === null) return isArrayPosition(a);
  return a === b;
}

function prefixIntersects(a: DcqlPath, b: DcqlPath): boolean {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (!segmentsIntersect(a[i] as Segment, b[i] as Segment)) return false;
  }
  return true;
}

export function pathHasWildcard(path: DcqlPath): boolean {
  return path.includes(null);
}

/** Every node the request selects is inside the rule's approved scope. */
export function ruleCovers(rule: ClaimRule, request: DcqlPath): boolean {
  if (
    rule.matching === 'exact'
      ? request.length !== rule.path.length
      : request.length < rule.path.length
  ) {
    return false;
  }
  for (let i = 0; i < rule.path.length; i++) {
    if (!segmentCovers(rule.path[i] as Segment, request[i] as Segment)) return false;
  }
  return true;
}

/**
 * Disclosing `request` may disclose data the deny rule forbids.
 *
 * An `exact` deny forbids the node itself, so it is hit when the request selects
 * that node or one of its ancestors. A `subtree` deny also forbids every
 * descendant, so it is hit by any request on the same branch.
 */
export function denyRuleHits(rule: ClaimRule, request: DcqlPath): boolean {
  if (rule.matching === 'exact' && request.length > rule.path.length) return false;
  return prefixIntersects(rule.path, request);
}

/**
 * The request is broader than the allow rule: it selects an ancestor of the
 * allowed node, or uses a wildcard where the rule names a specific index. The
 * request includes allowed data, but may include more.
 */
export function isBroaderThan(rule: ClaimRule, request: DcqlPath): boolean {
  if (!prefixIntersects(rule.path, request) || ruleCovers(rule, request)) return false;
  if (request.length < rule.path.length) return true;
  const length = Math.min(rule.path.length, request.length);
  for (let i = 0; i < length; i++) {
    if (request[i] === null && typeof rule.path[i] === 'number') return true;
  }
  return false;
}

export function pathsEqual(a: DcqlPath, b: DcqlPath): boolean {
  return a.length === b.length && a.every((segment, i) => segment === b[i]);
}

/** Stable display form, e.g. `["address","locality"]`. Paths are identifiers, not values. */
export function formatPath(path: DcqlPath): string {
  return JSON.stringify(path);
}
