import fc from 'fast-check';
import type { DisclosurePolicyV1 } from '../../src/index.js';

export const ALLOWED_TYPE = 'urn:example:proof-of-age:v1';
export const OTHER_TYPE = 'urn:example:pid:v1';
export const UNKNOWN_TYPE = 'urn:example:unknown:v1';
export const VALUE_PREFIX = 'V@L-';

/** Paths drawn from a small pool so that generated requests hit allow, deny, broad, and unknown rules. */
const PATHS: readonly (readonly (string | number | null)[])[] = [
  ['age_over_18'],
  ['birth_date'],
  ['family_name'],
  ['resident_address'],
  ['resident_address', 'locality'],
  ['address'],
  ['address', 'locality'],
  ['nationalities', null],
  ['nationalities', 0],
  ['email'],
];

export const propertyPolicy: DisclosurePolicyV1 = {
  schemaVersion: '1.0',
  policyId: 'test.property',
  policyVersion: '1.0.0',
  purposeId: 'property-tests',
  credentials: [
    {
      id: 'age',
      format: 'dc+sd-jwt',
      credentialType: { kind: 'vct', value: ALLOWED_TYPE },
      allowClaims: [
        { path: ['age_over_18'], matching: 'exact' },
        { path: ['address', 'locality'], matching: 'exact' },
        { path: ['nationalities', 0], matching: 'exact' },
      ],
      denyClaims: [
        { path: ['birth_date'], matching: 'exact' },
        { path: ['resident_address'], matching: 'subtree' },
      ],
      disclosureProfile: { mode: 'selective', knownMandatoryPaths: [] },
    },
    {
      id: 'pid',
      format: 'dc+sd-jwt',
      credentialType: { kind: 'vct', value: OTHER_TYPE },
      allowClaims: [
        { path: ['family_name'], matching: 'exact' },
        { path: ['age_over_18'], matching: 'exact' },
      ],
      disclosureProfile: { mode: 'selective', knownMandatoryPaths: [] },
    },
  ],
  defaults: {
    unknownCredential: 'indeterminate',
    unknownClaim: 'deny',
    unknownDisclosure: 'indeterminate',
    registrationEvidenceRequired: false,
    permitValueConstraints: false,
    permitHolderBindingDisabled: true,
    permitMultipleCredentials: false,
  },
};

/** Weighted toward compliant choices so that ALLOW, WARN, and INDETERMINATE outcomes are common. */
const rarely = <T>(arb: fc.Arbitrary<T>): fc.Arbitrary<T | undefined> =>
  fc.oneof({ arbitrary: fc.constant(undefined), weight: 8 }, { arbitrary: arb, weight: 1 });

const pathIndexArb = fc.oneof(
  { arbitrary: fc.constant(0), weight: 6 },
  { arbitrary: fc.integer({ min: 1, max: PATHS.length - 1 }), weight: 3 },
);

const claimArb = (pathIndex: number) =>
  rarely(
    fc.array(
      fc.oneof(
        fc.string({ minLength: 4 }).map((s) => VALUE_PREFIX + s),
        fc.boolean(),
      ),
      { minLength: 1, maxLength: 2 },
    ),
  ).map((values) => ({ path: [...PATHS[pathIndex]!], ...(values && { values }) }));

const typesArb = fc.oneof(
  { arbitrary: fc.constant([ALLOWED_TYPE]), weight: 6 },
  { arbitrary: fc.constant([OTHER_TYPE]), weight: 2 },
  { arbitrary: fc.subarray([ALLOWED_TYPE, OTHER_TYPE, UNKNOWN_TYPE], { minLength: 1 }), weight: 1 },
);

const credentialArb = (id: string) =>
  fc
    .record({
      types: typesArb,
      pathIndices: fc.option(fc.uniqueArray(pathIndexArb, { minLength: 1, maxLength: 3 }), {
        nil: undefined,
        freq: 5,
      }),
      useClaimSets: fc.boolean(),
      multiple: rarely(fc.constant(true)),
      holderBinding: rarely(fc.boolean()),
    })
    .chain(({ types, pathIndices, useClaimSets, multiple, holderBinding }) => {
      const base = {
        id,
        format: 'dc+sd-jwt',
        meta: { vct_values: types },
        ...(multiple && { multiple }),
        ...(holderBinding !== undefined && { require_cryptographic_holder_binding: holderBinding }),
      };
      if (!pathIndices) return fc.constant(base);
      return fc.tuple(...pathIndices.map((i) => claimArb(i))).chain((claims) => {
        const withIds = claims.map((c, i) => ({ id: `c${i}`, ...c }));
        if (!useClaimSets) return fc.constant({ ...base, claims: withIds });
        const ids = withIds.map((c) => c.id);
        return fc
          .array(fc.subarray(ids, { minLength: 1 }), { minLength: 1, maxLength: 3 })
          .map((claimSets) => ({ ...base, claims: withIds, claim_sets: claimSets }));
      });
    });

/** Valid DCQL queries over the property policy's vocabulary. */
export const dcqlArb: fc.Arbitrary<Record<string, unknown>> = fc
  .integer({ min: 1, max: 4 })
  .chain((count) => {
    const ids = Array.from({ length: count }, (_, i) => `q${i}`);
    return fc
      .tuple(fc.tuple(...ids.map((id) => credentialArb(id))), fc.boolean())
      .chain(([credentials, useSets]) => {
        if (!useSets) return fc.constant({ credentials });
        return fc
          .array(
            fc.record({
              required: fc.boolean(),
              options: fc.array(fc.subarray(ids, { minLength: 1 }), { minLength: 1, maxLength: 3 }),
            }),
            { minLength: 1, maxLength: 3 },
          )
          .map((sets) => ({ credentials, credential_sets: sets }));
      });
  });
