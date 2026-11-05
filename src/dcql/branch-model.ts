/**
 * Request alternatives (OpenID4VP 1.0 §6.4).
 *
 * A branch is one way a wallet may answer: one option per required credential
 * set, zero or one option per optional set, and one claim set option per
 * selected credential query. Without credential_sets every credential query is
 * selected; without claim_sets every listed claim is.
 *
 * Element rules (claim authorization, values, retention, holder binding) only
 * depend on the element itself, so a request is as bad as its worst
 * selectable element. Every option of every set appears in at least one
 * branch, which makes the per-element analysis equivalent to evaluating every
 * branch, without the Cartesian product. test/branch-equivalence.test.ts checks
 * this against explicit enumeration.
 */
import type { NormalizedCredential, NormalizedQuery } from './normalize.js';

export interface Reachability {
  /** Credential index -> labels of the credential set options that select it (`undefined`: no credential_sets). */
  readonly credentials: ReadonlyMap<number, readonly string[] | undefined>;
  /** Credential index -> claim index -> labels of claim set options that select it (`undefined`: no claim_sets). */
  readonly claims: ReadonlyMap<number, ReadonlyMap<number, readonly string[] | undefined>>;
}

export const credentialOptionLabel = (set: number, option: number): string => `cs${set}.o${option}`;
export const claimOptionLabel = (credentialId: string, option: number): string =>
  `${credentialId}.cl${option}`;

/** Claim indices requested by a credential query, across every claim set option. */
export function selectableClaims(
  credential: NormalizedCredential,
): ReadonlyMap<number, readonly string[] | undefined> {
  const result = new Map<number, string[] | undefined>();
  if (!credential.claims) return result;
  if (!credential.claimSets) {
    for (const claim of credential.claims) result.set(claim.index, undefined);
    return result;
  }
  credential.claimSets.forEach((option, k) => {
    for (const claimIndex of option) {
      const labels = result.get(claimIndex) ?? [];
      labels.push(claimOptionLabel(credential.id, k));
      result.set(claimIndex, labels);
    }
  });
  return result;
}

export function reachability(query: NormalizedQuery): Reachability {
  const credentials = new Map<number, string[] | undefined>();
  if (!query.credentialSets) {
    for (const credential of query.credentials) credentials.set(credential.index, undefined);
  } else {
    for (const set of query.credentialSets) {
      set.options.forEach((option, j) => {
        for (const credentialIndex of option) {
          const labels = credentials.get(credentialIndex) ?? [];
          labels.push(credentialOptionLabel(set.index, j));
          credentials.set(credentialIndex, labels);
        }
      });
    }
  }
  const claims = new Map<number, ReadonlyMap<number, readonly string[] | undefined>>();
  for (const index of credentials.keys())
    claims.set(index, selectableClaims(query.credentials[index]!));
  return { credentials, claims };
}

export interface Branch {
  readonly id: string;
  /** Selected credential indices with the selected claim indices (`undefined` when claims is absent). */
  readonly selection: readonly {
    readonly credential: number;
    readonly claims: readonly number[] | undefined;
  }[];
}

function credentialChoices(
  query: NormalizedQuery,
): { label: string; credentials: readonly number[] }[][] {
  if (!query.credentialSets) {
    return [[{ label: 'all', credentials: query.credentials.map((c) => c.index) }]];
  }
  return query.credentialSets.map((set) => {
    const choices = set.options.map((option, j) => ({
      label: credentialOptionLabel(set.index, j),
      credentials: option,
    }));
    if (!set.required) choices.push({ label: `cs${set.index}.skip`, credentials: [] });
    return choices;
  });
}

function claimChoices(
  credential: NormalizedCredential,
): { label: string | undefined; claims: readonly number[] | undefined }[] {
  if (!credential.claims) return [{ label: undefined, claims: undefined }];
  if (!credential.claimSets)
    return [{ label: undefined, claims: credential.claims.map((c) => c.index) }];
  return credential.claimSets.map((option, k) => ({
    label: claimOptionLabel(credential.id, k),
    claims: option,
  }));
}

/**
 * Enumerate branches lazily, stopping once `limit` branches were produced.
 * Returns the branches and whether enumeration was complete.
 */
export function enumerateBranches(
  query: NormalizedQuery,
  limit: number,
): { branches: Branch[]; complete: boolean } {
  const branches: Branch[] = [];
  const sets = credentialChoices(query);
  // Shared across the recursive walks; a plain object keeps the flow analysis honest.
  const state = { complete: true };
  const stopped = (): boolean => !state.complete;

  const walkClaims = (
    credentialIndices: number[],
    prefix: string[],
    picked: Branch['selection'][number][],
    i: number,
  ): void => {
    if (stopped()) return;
    if (i === credentialIndices.length) {
      if (branches.length === limit) {
        state.complete = false;
        return;
      }
      branches.push({ id: prefix.join('+') || 'all', selection: [...picked] });
      return;
    }
    const credential = query.credentials[credentialIndices[i]!]!;
    for (const choice of claimChoices(credential)) {
      picked.push({ credential: credential.index, claims: choice.claims });
      walkClaims(
        credentialIndices,
        choice.label ? [...prefix, choice.label] : prefix,
        picked,
        i + 1,
      );
      picked.pop();
      if (stopped()) return;
    }
  };

  const walkSets = (i: number, labels: string[], selected: Set<number>): void => {
    if (stopped()) return;
    if (i === sets.length) {
      walkClaims(
        [...selected].sort((a, b) => a - b),
        labels.filter((l) => l !== 'all'),
        [],
        0,
      );
      return;
    }
    for (const choice of sets[i]!) {
      const next = new Set(selected);
      for (const credential of choice.credentials) next.add(credential);
      walkSets(i + 1, [...labels, choice.label], next);
      if (stopped()) return;
    }
  };

  walkSets(0, [], new Set());
  return { branches, complete: state.complete };
}

/** Branch count, saturated at `limit + 1`. Work is bounded by `limit`. */
export function countBranches(query: NormalizedQuery, limit: number): number {
  const { branches, complete } = enumerateBranches(query, limit);
  return complete ? branches.length : limit + 1;
}
