/**
 * Public data contract. Behavior and trust semantics are described in
 * docs/api.md and docs/concepts.md; the decisions behind deviations from the
 * original specification are in docs/decisions/0002-public-api.md.
 */

/** Aggregate and per-finding outcome. Precedence: DENY > INDETERMINATE > WARN > ALLOW. */
export type Verdict = 'ALLOW' | 'WARN' | 'DENY' | 'INDETERMINATE';

export type Severity = 'error' | 'warning' | 'info';

/**
 * How much of the request the engine could analyze.
 *
 * - `complete`: every selectable credential and claim was analyzed with the information required.
 * - `partial`: at least one gate or element could not be determined (see `INDETERMINATE` findings).
 * - `unsupported`: the request could not be analyzed at all (invalid DCQL, or no credential
 *   query uses a supported format).
 */
export type Coverage = 'complete' | 'partial' | 'unsupported';

/**
 * Finding category.
 *
 * - `N` protocol invalidity: the request violates OpenID4VP 1.0 DCQL rules.
 * - `A` authorization: the request violates the configured policy or verified registered scope.
 * - `P` privacy or security risk: a query feature that increases disclosure or linkability.
 * - `U` uncertainty: the engine lacks information or semantics to decide.
 * - `O` operational: analysis limits, such as the branch budget.
 */
export type FindingCategory = 'N' | 'A' | 'P' | 'U' | 'O';

/** A claims path pointer (OpenID4VP 1.0 §7): strings, non-negative integers, and null wildcards. */
export type DcqlPath = readonly (string | number | null)[];

export type InputEvidenceState = 'verified' | 'unverified' | 'absent';

export type CredentialTypeSelector = { readonly kind: 'vct' | 'doctype'; readonly value: string };

/** A local, versioned data-minimization policy. Authored and approved outside this library. */
export interface DisclosurePolicyV1 {
  readonly schemaVersion: '1.0';
  readonly policyId: string;
  readonly policyVersion: string;
  readonly purposeId: string;
  readonly description?: string;
  readonly credentials: readonly CredentialRule[];
  readonly defaults: PolicyDefaults;
  /**
   * Names of DCQL extension properties that the policy owner has reviewed and
   * judged not to change what a wallet discloses. Unreviewed extensions yield
   * `UNKNOWN_EXTENSION_REVIEW`.
   */
  readonly reviewedExtensions?: readonly string[];
}

export interface PolicyDefaults {
  /** Credential type or format without a matching rule. */
  readonly unknownCredential: 'indeterminate' | 'deny';
  /** Requested claim path outside the purpose allowlist. */
  readonly unknownClaim: 'indeterminate' | 'deny';
  /** Credential type without a complete disclosure profile. */
  readonly unknownDisclosure: 'indeterminate' | 'warn';
  /** Require caller-supplied, upstream-verified registration evidence. */
  readonly registrationEvidenceRequired: boolean;
  /** Allow `values` filters (still reported as a privacy risk). */
  readonly permitValueConstraints: boolean;
  /** Allow `require_cryptographic_holder_binding: false` (still reported). */
  readonly permitHolderBindingDisabled: boolean;
  /** Allow `multiple: true` (still reported). */
  readonly permitMultipleCredentials: boolean;
  readonly maxCredentialQueries?: number;
  readonly maxClaimQueries?: number;
  /** Wildcard or parent-object selector that the policy cannot prove bounded. Default `indeterminate`. */
  readonly broadSelector?: 'indeterminate' | 'deny';
  /** mdoc `intent_to_retain: true` on a claim without `allowRetention`. Default `deny`. */
  readonly retentionIntent?: 'deny' | 'warn';
  /** Unreviewed DCQL extension property. Default `indeterminate`. */
  readonly unknownExtension?: 'indeterminate' | 'warn';
  /** Verified registration evidence that is stale, mismatched, or incomplete. Default `indeterminate`. */
  readonly invalidRegistrationEvidence?: 'indeterminate' | 'deny';
}

export interface CredentialRule {
  readonly id: string;
  readonly format: 'dc+sd-jwt' | 'mso_mdoc' | (string & {});
  /** `vct` for SD-JWT VC, `doctype` for mdoc. Never compared across formats. */
  readonly credentialType: CredentialTypeSelector;
  readonly allowClaims: readonly ClaimRule[];
  readonly denyClaims?: readonly ClaimRule[];
  /** Known disclosure behavior of the credential type, from a schema the policy author trusts. */
  readonly disclosureProfile?: DisclosureProfile;
}

export interface ClaimRule {
  readonly path: DcqlPath;
  /** `exact` matches exactly this path. `subtree` also matches every descendant. */
  readonly matching: 'exact' | 'subtree';
  readonly reason?: string;
  /** A label chosen by the policy author; not an automated legal classification. */
  readonly classification?: 'ordinary' | 'sensitive' | 'highly-sensitive';
  /** mso_mdoc only, allow rules only: permit `intent_to_retain: true` for matched claims. */
  readonly allowRetention?: boolean;
}

export interface DisclosureProfile {
  readonly mode: 'selective' | 'non-selective' | 'mixed' | 'unknown';
  /**
   * Paths always disclosed when the credential is presented. For `non-selective`
   * credentials, the complete content. Omit when unknown; use `[]` for none.
   */
  readonly knownMandatoryPaths?: readonly DcqlPath[];
  readonly schemaId?: string;
  readonly schemaVersion?: string;
}

/**
 * Relying-party registration scope. The `state` is asserted by the caller:
 * this library performs no cryptographic verification. Only construct
 * `state: 'verified'` evidence in trusted code after verifying the registration
 * upstream. Never derive it from request input.
 */
export interface RegistrationScopeEvidence {
  readonly state: InputEvidenceState;
  readonly provenance?: {
    readonly source: string;
    readonly profile: string;
    readonly verifier: string;
    readonly verifiedAt: string;
    readonly expiresAt?: string;
    readonly digest: string;
  };
  readonly rpId?: string;
  readonly serviceId?: string;
  readonly intendedUseId?: string;
  readonly allowed: readonly {
    readonly format: string;
    readonly credentialType: CredentialTypeSelector;
    readonly claimPaths: readonly DcqlPath[];
  }[];
}

/** The deployment whose request is evaluated, compared exactly against registration evidence. */
export interface RelyingPartyContext {
  readonly rpId: string;
  readonly serviceId?: string;
  readonly intendedUseId?: string;
}

export interface ResourceLimits {
  /** UTF-8 bytes of the DCQL JSON text (measured on the serialized form for objects). Default 262144. */
  readonly maxInputBytes?: number;
  /** JSON nesting depth. Default 32. */
  readonly maxDepth?: number;
  /** Credential queries. Default 32. */
  readonly maxCredentialQueries?: number;
  /** Claim queries across all credential queries. Default 256. */
  readonly maxClaimQueries?: number;
  /** Path segments across all claim paths. Default 1024. */
  readonly maxPathSegments?: number;
  /** Options across all credential_sets and claim_sets. Default 256. */
  readonly maxSetOptions?: number;
}

export interface EvaluateOptions {
  /** Branch combinations to enumerate before reporting `BRANCH_LIMIT_REACHED`. Default 2048. */
  readonly maxBranches?: number;
  readonly limits?: ResourceLimits;
  /**
   * Opt-in diagnostics with internal structures (identifiers, claim paths,
   * extension names). Not a redaction contract: treat events as sensitive and
   * never route them to production logs.
   */
  readonly debug?: (event: DebugEvent) => void;
}

export interface DebugEvent {
  readonly stage: 'normalized' | 'branches' | 'finding';
  readonly data: unknown;
}

export interface EvaluateRequestInput {
  /** The DCQL query: a parsed JSON value or JSON text. */
  readonly dcql: unknown;
  readonly policy: DisclosurePolicyV1;
  readonly registration?: RegistrationScopeEvidence;
  readonly relyingParty?: RelyingPartyContext;
  /** Caller-supplied UTC time (`YYYY-MM-DDTHH:MM:SS[.sss]Z`). The core never reads the clock. */
  readonly evaluationTime: string;
  readonly profile: 'openid4vp-1.0';
  readonly options?: EvaluateOptions;
}

export interface Finding {
  readonly ruleId: RuleId;
  readonly category: FindingCategory;
  readonly severity: Severity;
  readonly verdict: Verdict;
  readonly message: string;
  /** RFC 6901 pointer into the original DCQL input, or `""` for the whole request. */
  readonly jsonPointer: string;
  readonly queryId?: string;
  readonly branchId?: string;
  readonly policyRuleId?: string;
  readonly evidenceIds?: readonly string[];
  readonly remediation?: string;
  readonly standardRefs?: readonly string[];
  /** Safe, derived indicators only. Never contains claim values. */
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface EvaluationResult {
  readonly apiVersion: '1.0';
  readonly verdict: Verdict;
  readonly coverage: Coverage;
  readonly evaluatedAt: string;
  readonly profile: 'openid4vp-1.0';
  readonly engine: {
    readonly name: string;
    readonly version: string;
    readonly rulesVersion: string;
  };
  readonly policy: {
    readonly id: string;
    readonly version: string;
    readonly purposeId: string;
    readonly digest: string;
  };
  /**
   * `verified` only when the caller asserted verification, provenance is
   * complete, and the evidence is fresh and applicable. Still caller-asserted.
   */
  readonly registrationEvidence: InputEvidenceState;
  readonly summary: {
    readonly errors: number;
    readonly warnings: number;
    readonly indeterminate: number;
    readonly info: number;
  };
  readonly findings: readonly Finding[];
  /** Branch combinations: exact up to `maxBranches`, otherwise the saturated count. */
  readonly branchCount: number;
  readonly analyzedBranches: number;
  readonly skippedBranches: number;
  readonly maxBranches: number;
}

export type RuleId =
  | 'DCQL_INVALID'
  | 'CREDENTIAL_TYPE_NOT_ALLOWED'
  | 'CLAIM_NOT_ALLOWED_FOR_PURPOSE'
  | 'CLAIM_EXPLICITLY_DENIED'
  | 'CLAIM_NOT_IN_REGISTERED_SCOPE'
  | 'REGISTRATION_EVIDENCE_MISSING'
  | 'REGISTRATION_EVIDENCE_UNVERIFIED'
  | 'REGISTRATION_EVIDENCE_INVALID_OR_STALE'
  | 'CREDENTIAL_TYPE_AMBIGUOUS'
  | 'UNSUPPORTED_CREDENTIAL_FORMAT'
  | 'UNKNOWN_DISCLOSURE_PROFILE'
  | 'BROAD_CLAIM_SELECTOR'
  | 'CLAIM_SET_NONMINIMAL'
  | 'CREDENTIAL_SET_EXCESSIVE_OPTION'
  | 'OPTIONAL_CREDENTIAL_SET'
  | 'VALUE_FILTER_PROBING_RISK'
  | 'HOLDER_BINDING_DISABLED'
  | 'MULTIPLE_CREDENTIALS_REQUESTED'
  | 'MDOC_RETENTION_REQUESTED'
  | 'MANDATORY_DISCLOSURE_EXCEEDS_POLICY'
  | 'REQUEST_SIZE_EXCEEDS_POLICY'
  | 'UNKNOWN_EXTENSION_REVIEW'
  | 'UNREFERENCED_QUERY'
  | 'BRANCH_LIMIT_REACHED';
