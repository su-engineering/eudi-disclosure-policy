/**
 * Normalized, immutable view of a validated DCQL query. Every node keeps the
 * JSON pointer of its origin, every alternative edge is preserved, and
 * properties OpenID4VP 1.0 does not define are recorded as extensions.
 */
import { pointer, appendPointer } from '../pointer.js';
import type { DcqlPath } from '../types.js';

export const SUPPORTED_FORMATS: ReadonlySet<string> = new Set(['dc+sd-jwt', 'mso_mdoc']);

export interface Extension {
  readonly name: string;
  readonly pointer: string;
}

export interface NormalizedClaim {
  readonly index: number;
  readonly id: string | undefined;
  readonly path: DcqlPath;
  readonly pointer: string;
  /** Count and JSON types of the values filter. The values themselves are never copied. */
  readonly values:
    | { readonly count: number; readonly types: readonly string[]; readonly pointer: string }
    | undefined;
  readonly intentToRetain: { readonly pointer: string } | undefined;
}

export interface CredentialTypeRef {
  readonly kind: 'vct' | 'doctype';
  readonly value: string;
  readonly pointer: string;
}

export interface NormalizedCredential {
  readonly index: number;
  readonly id: string;
  readonly format: string;
  readonly supported: boolean;
  readonly pointer: string;
  readonly types: readonly CredentialTypeRef[];
  readonly multiple: { readonly pointer: string } | undefined;
  readonly holderBindingDisabled: { readonly pointer: string } | undefined;
  /** Undefined when `claims` is absent: no selectively disclosable claim is requested. */
  readonly claims: readonly NormalizedClaim[] | undefined;
  /** Claim set options as indices into `claims`. Undefined when `claim_sets` is absent. */
  readonly claimSets: readonly (readonly number[])[] | undefined;
}

export interface NormalizedCredentialSet {
  readonly index: number;
  readonly required: boolean;
  readonly pointer: string;
  /** Options as indices into `credentials`. */
  readonly options: readonly (readonly number[])[];
}

export interface NormalizedQuery {
  readonly credentials: readonly NormalizedCredential[];
  /** Undefined when `credential_sets` is absent: every credential query is requested. */
  readonly credentialSets: readonly NormalizedCredentialSet[] | undefined;
  readonly extensions: readonly Extension[];
}

type JsonRecord = Record<string, unknown>;

const TOP_KEYS = new Set(['credentials', 'credential_sets']);
const CREDENTIAL_KEYS = new Set([
  'id',
  'format',
  'multiple',
  'meta',
  'trusted_authorities',
  'require_cryptographic_holder_binding',
  'claims',
  'claim_sets',
]);
const CREDENTIAL_SET_KEYS = new Set(['options', 'required']);
const TRUSTED_AUTHORITY_KEYS = new Set(['type', 'values']);
const META_KEYS: Readonly<Record<string, ReadonlySet<string>>> = {
  'dc+sd-jwt': new Set(['vct_values']),
  mso_mdoc: new Set(['doctype_value']),
};
const CLAIM_KEYS: Readonly<Record<string, ReadonlySet<string>>> = {
  'dc+sd-jwt': new Set(['id', 'path', 'values']),
  mso_mdoc: new Set(['id', 'path', 'values', 'intent_to_retain']),
};

function collectExtensions(
  record: JsonRecord,
  known: ReadonlySet<string>,
  base: string,
  out: Extension[],
): void {
  for (const key of Object.keys(record).sort()) {
    if (!known.has(key)) out.push({ name: key, pointer: appendPointer(base, key) });
  }
}

function jsonType(value: unknown): string {
  if (typeof value === 'number') return 'integer';
  return typeof value;
}

/** Normalize a query that already passed structural validation. */
export function normalizeQuery(query: JsonRecord): NormalizedQuery {
  const extensions: Extension[] = [];
  collectExtensions(query, TOP_KEYS, '', extensions);

  const rawCredentials = query['credentials'] as JsonRecord[];
  const idToIndex = new Map<string, number>();
  const credentials = rawCredentials.map((raw, index): NormalizedCredential => {
    const base = pointer('credentials', index);
    const id = raw['id'] as string;
    const format = raw['format'] as string;
    const supported = SUPPORTED_FORMATS.has(format);
    idToIndex.set(id, index);

    const types: CredentialTypeRef[] = [];
    const meta = (raw['meta'] ?? {}) as JsonRecord;
    if (format === 'dc+sd-jwt') {
      (meta['vct_values'] as string[]).forEach((value, i) => {
        types.push({ kind: 'vct', value, pointer: appendPointer(base, 'meta', 'vct_values', i) });
      });
    } else if (format === 'mso_mdoc') {
      types.push({
        kind: 'doctype',
        value: meta['doctype_value'] as string,
        pointer: appendPointer(base, 'meta', 'doctype_value'),
      });
    }

    if (supported) {
      collectExtensions(raw, CREDENTIAL_KEYS, base, extensions);
      collectExtensions(meta, META_KEYS[format]!, appendPointer(base, 'meta'), extensions);
      ((raw['trusted_authorities'] ?? []) as JsonRecord[]).forEach((authority, i) => {
        collectExtensions(
          authority,
          TRUSTED_AUTHORITY_KEYS,
          appendPointer(base, 'trusted_authorities', i),
          extensions,
        );
      });
    }

    let claims: NormalizedClaim[] | undefined;
    let claimSets: number[][] | undefined;
    if (Array.isArray(raw['claims'])) {
      const claimIdToIndex = new Map<string, number>();
      claims = (raw['claims'] as JsonRecord[]).map((claim, i): NormalizedClaim => {
        const claimPointer = appendPointer(base, 'claims', i);
        const claimId = typeof claim['id'] === 'string' ? claim['id'] : undefined;
        if (claimId !== undefined) claimIdToIndex.set(claimId, i);
        if (supported) collectExtensions(claim, CLAIM_KEYS[format]!, claimPointer, extensions);
        const values = Array.isArray(claim['values']) ? (claim['values'] as unknown[]) : undefined;
        return {
          index: i,
          id: claimId,
          path: Object.freeze([...(claim['path'] as (string | number | null)[])]),
          pointer: claimPointer,
          values: values && {
            count: values.length,
            types: [...new Set(values.map(jsonType))].sort(),
            pointer: appendPointer(claimPointer, 'values'),
          },
          intentToRetain:
            format === 'mso_mdoc' && claim['intent_to_retain'] === true
              ? { pointer: appendPointer(claimPointer, 'intent_to_retain') }
              : undefined,
        };
      });
      if (Array.isArray(raw['claim_sets'])) {
        claimSets = (raw['claim_sets'] as string[][]).map((option) =>
          [...new Set(option.map((claimId) => claimIdToIndex.get(claimId)!))].sort((a, b) => a - b),
        );
      }
    }

    return {
      index,
      id,
      format,
      supported,
      pointer: base,
      types,
      multiple: raw['multiple'] === true ? { pointer: appendPointer(base, 'multiple') } : undefined,
      holderBindingDisabled:
        raw['require_cryptographic_holder_binding'] === false
          ? { pointer: appendPointer(base, 'require_cryptographic_holder_binding') }
          : undefined,
      claims,
      claimSets,
    };
  });

  let credentialSets: NormalizedCredentialSet[] | undefined;
  if (Array.isArray(query['credential_sets'])) {
    credentialSets = (query['credential_sets'] as JsonRecord[]).map((raw, index) => {
      const base = pointer('credential_sets', index);
      collectExtensions(raw, CREDENTIAL_SET_KEYS, base, extensions);
      return {
        index,
        required: raw['required'] !== false,
        pointer: base,
        options: (raw['options'] as string[][]).map((option) =>
          [...new Set(option.map((credentialId) => idToIndex.get(credentialId)!))].sort(
            (a, b) => a - b,
          ),
        ),
      };
    });
  }

  return { credentials, credentialSets, extensions };
}
