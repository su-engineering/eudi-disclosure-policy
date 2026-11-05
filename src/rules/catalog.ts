import type { FindingCategory, RuleId } from '../types.js';

export interface RuleDefinition {
  readonly id: RuleId;
  readonly category: FindingCategory;
  readonly title: string;
  /** Default outcome, and how policy configuration changes it. */
  readonly outcome: string;
  readonly description: string;
  readonly remediation: string;
  readonly standardRefs: readonly string[];
}

const OID4VP = 'OpenID4VP 1.0';
const ARF = 'EUDI ARF 3.0.0';

/**
 * Stable rule catalog. Rule IDs are part of the public API: they are never
 * renamed or reused, and changes to a rule's trigger or verdict bump
 * RULES_VERSION. docs/rule-reference.md is generated from this table.
 */
export const RULES: Readonly<Record<RuleId, RuleDefinition>> = {
  DCQL_INVALID: {
    id: 'DCQL_INVALID',
    category: 'N',
    title: 'Invalid DCQL query',
    outcome: 'DENY. No further analysis runs.',
    description:
      'The input is not valid JSON or violates OpenID4VP 1.0 DCQL structure: missing or malformed credential queries, unknown references in credential_sets or claim_sets, malformed claims path pointers, empty credential set options, duplicate claim paths within one credential query, or non-integer numbers in values. This is an invalid request, not a privacy judgment.',
    remediation: 'Fix the request so that it validates against OpenID4VP 1.0 §6–7 and Appendix B.',
    standardRefs: [`${OID4VP} §6`, `${OID4VP} §7`, `${OID4VP} Appendix B`],
  },
  CREDENTIAL_TYPE_NOT_ALLOWED: {
    id: 'CREDENTIAL_TYPE_NOT_ALLOWED',
    category: 'A',
    title: 'Credential type has no policy rule',
    outcome: 'INDETERMINATE, or DENY when defaults.unknownCredential is "deny".',
    description:
      'A selectable credential query accepts a format and type (vct or doctype) that no credential rule in the policy matches exactly. A query listing several vct_values is a union: every listed type is evaluated, and one approved type never approves another. Type inheritance is not resolved.',
    remediation:
      'Remove the type from the query, or have the policy owner add a credential rule for exactly this format and type.',
    standardRefs: [`${OID4VP} §6.1`, `${OID4VP} Appendix B.2.3`, `${OID4VP} Appendix B.3.5`],
  },
  CLAIM_NOT_ALLOWED_FOR_PURPOSE: {
    id: 'CLAIM_NOT_ALLOWED_FOR_PURPOSE',
    category: 'A',
    title: 'Claim outside the purpose allowlist',
    outcome: 'DENY, or INDETERMINATE when defaults.unknownClaim is "indeterminate".',
    description:
      'A selectable claims path pointer is not covered by any allow rule of the matched credential rule. Exact rules match only the identical path; subtree rules also match descendants. A child of an exactly allowed path is not allowed.',
    remediation:
      'Request only claims the purpose allows, or have an authorized policy owner approve an explicit exception.',
    standardRefs: [`${OID4VP} §6.3`, `${OID4VP} §7`],
  },
  CLAIM_EXPLICITLY_DENIED: {
    id: 'CLAIM_EXPLICITLY_DENIED',
    category: 'A',
    title: 'Claim hits a deny rule',
    outcome: 'DENY. Deny rules take precedence over allow rules.',
    description:
      'A selectable claims path pointer may disclose data a deny rule forbids: it selects the denied node, one of its ancestors, or a wildcard that includes it, or (for subtree deny rules) a descendant.',
    remediation:
      'Remove the claim from the request. Deny rules exist to block data the purpose must never collect.',
    standardRefs: [`${OID4VP} §7`],
  },
  CLAIM_NOT_IN_REGISTERED_SCOPE: {
    id: 'CLAIM_NOT_IN_REGISTERED_SCOPE',
    category: 'A',
    title: 'Request exceeds the registered scope',
    outcome:
      'DENY. Evaluated only with caller-asserted, complete, fresh, and applicable registration evidence.',
    description:
      'Registration evidence the caller asserts as verified does not list the requested credential type, or no registered claim path covers the requested path. A request for part of a registered claim is in scope; a request for its parent is not.',
    remediation:
      'Request only registered attributes, or update the relying-party registration through the registrar before requesting more.',
    standardRefs: [`${ARF} §6.6.3.3`, 'EUDI TS05', 'EUDI TS06'],
  },
  REGISTRATION_EVIDENCE_MISSING: {
    id: 'REGISTRATION_EVIDENCE_MISSING',
    category: 'U',
    title: 'Registration evidence missing',
    outcome: 'INDETERMINATE.',
    description:
      'The policy requires a registered-scope comparison (defaults.registrationEvidenceRequired) and no evidence was supplied. The request is not treated as registered.',
    remediation:
      'Supply registration evidence verified upstream, or disable the requirement in the policy.',
    standardRefs: [`${ARF} §6.6.3.3`],
  },
  REGISTRATION_EVIDENCE_UNVERIFIED: {
    id: 'REGISTRATION_EVIDENCE_UNVERIFIED',
    category: 'U',
    title: 'Registration evidence not verified',
    outcome: 'INDETERMINATE. The evidence content is not used.',
    description:
      'Registration evidence was supplied with state "unverified". Its content is never used for an authoritative comparison.',
    remediation:
      'Verify the registration cryptographically in trusted code before constructing evidence with state "verified".',
    standardRefs: [`${ARF} §6.6.3.3`, 'EUDI TS05'],
  },
  REGISTRATION_EVIDENCE_INVALID_OR_STALE: {
    id: 'REGISTRATION_EVIDENCE_INVALID_OR_STALE',
    category: 'U',
    title: 'Registration evidence unusable',
    outcome: 'INDETERMINATE, or DENY when defaults.invalidRegistrationEvidence is "deny".',
    description:
      'Evidence asserted as verified lacks complete provenance, was verified after the evaluation time, expired at or before it, or does not apply to the relying party, service, or intended use being evaluated. There is no fallback to unverified content.',
    remediation:
      'Refresh the evidence, supply the matching relyingParty context, or use evidence issued for this service.',
    standardRefs: [`${ARF} §6.6.3.3`, 'EUDI TS05'],
  },
  CREDENTIAL_TYPE_AMBIGUOUS: {
    id: 'CREDENTIAL_TYPE_AMBIGUOUS',
    category: 'U',
    title: 'Accepted types assess differently',
    outcome: 'INDETERMINATE.',
    description:
      'A credential query accepts several types whose policy assessments differ. The wallet, not the verifier, chooses which type is presented, so the safest type cannot be assumed.',
    remediation: 'Split the query by type, or list only types with equivalent policy treatment.',
    standardRefs: [`${OID4VP} Appendix B.3.5`],
  },
  UNSUPPORTED_CREDENTIAL_FORMAT: {
    id: 'UNSUPPORTED_CREDENTIAL_FORMAT',
    category: 'U',
    title: 'Credential format not supported',
    outcome: 'INDETERMINATE. Claims of this query are not interpreted.',
    description:
      'No format adapter can interpret this credential format. Version 1 supports dc+sd-jwt and mso_mdoc. Claims path semantics differ by format, so they are not guessed.',
    remediation: 'Use a supported format, or contribute a format adapter with conformance tests.',
    standardRefs: [`${OID4VP} Appendix B`],
  },
  UNKNOWN_DISCLOSURE_PROFILE: {
    id: 'UNKNOWN_DISCLOSURE_PROFILE',
    category: 'U',
    title: 'Mandatory disclosure unknown',
    outcome: 'INDETERMINATE, or WARN when defaults.unknownDisclosure is "warn".',
    description:
      'The matched credential rule has no disclosure profile, its mode is "unknown", or it omits knownMandatoryPaths. Without it, the engine cannot establish what a presentation discloses beyond the named claims, such as mandatory or non-selectively disclosable fields.',
    remediation:
      'Add a disclosureProfile with knownMandatoryPaths from a credential schema you trust (use [] for none), or set unknownDisclosure to "warn" if assured minimization is not required.',
    standardRefs: [`${OID4VP} §6.4`, `${OID4VP} §6.4.1`],
  },
  BROAD_CLAIM_SELECTOR: {
    id: 'BROAD_CLAIM_SELECTOR',
    category: 'U',
    title: 'Selector broader than the allowlist',
    outcome: 'INDETERMINATE, or DENY when defaults.broadSelector is "deny".',
    description:
      'A claims path pointer selects a parent of an allowed claim, or uses a null wildcard where the policy allows only specific array elements. The selection includes allowed data but may include more, and no allow rule bounds it.',
    remediation:
      'Request the exact allowed paths, or have the policy owner approve the broader path explicitly.',
    standardRefs: [`${OID4VP} §7.1`],
  },
  CLAIM_SET_NONMINIMAL: {
    id: 'CLAIM_SET_NONMINIMAL',
    category: 'P',
    title: 'Claim set alternative discloses more',
    outcome:
      'DENY when the option violates the policy while another option complies, otherwise WARN for a strict superset.',
    description:
      'A claim_sets option requests a strict superset of another option, or violates the policy while another option complies. Option order is only a preference: the wallet may return any option it can satisfy.',
    remediation:
      'Remove the larger or non-compliant option, keeping the least-disclosing alternative.',
    standardRefs: [`${OID4VP} §6.4.1`],
  },
  CREDENTIAL_SET_EXCESSIVE_OPTION: {
    id: 'CREDENTIAL_SET_EXCESSIVE_OPTION',
    category: 'P',
    title: 'Credential set alternative discloses more',
    outcome:
      'DENY when the option violates the policy while another option complies, otherwise WARN for a strict superset.',
    description:
      'A credential_sets option requests a strict superset of the credential queries of another option in the same set, or violates the policy while another option complies. Every option remains selectable.',
    remediation:
      'Remove the excessive option. A compliant alternative does not make a non-compliant one acceptable.',
    standardRefs: [`${OID4VP} §6.2`, `${OID4VP} §6.4.2`],
  },
  OPTIONAL_CREDENTIAL_SET: {
    id: 'OPTIONAL_CREDENTIAL_SET',
    category: 'P',
    title: 'Optional credential set',
    outcome: 'Informational. Its content is fully evaluated like any other request.',
    description:
      'A credential set has required: false. It is not needed to satisfy the use case, but it is still a request for data, and wallets may present it.',
    remediation:
      'Confirm that the optional data is necessary for the stated purpose; otherwise remove the set.',
    standardRefs: [`${OID4VP} §6.2`, `${OID4VP} §6.4.2`],
  },
  VALUE_FILTER_PROBING_RISK: {
    id: 'VALUE_FILTER_PROBING_RISK',
    category: 'P',
    title: 'Claim value filter',
    outcome: 'DENY, or WARN when defaults.permitValueConstraints is true.',
    description:
      'A claims query has a values filter. Value matching is best effort and is not a security or authorization control; whether a credential matches can itself reveal attribute information. Filter values are never included in findings.',
    remediation:
      'Remove the values filter, or have the policy owner permit value constraints for this purpose.',
    standardRefs: [`${OID4VP} §6.3`, `${OID4VP} §6.4.1`, `${OID4VP} §15.4.1`],
  },
  HOLDER_BINDING_DISABLED: {
    id: 'HOLDER_BINDING_DISABLED',
    category: 'P',
    title: 'Holder binding disabled',
    outcome: 'DENY, or WARN when defaults.permitHolderBindingDisabled is true.',
    description:
      'A selectable credential query sets require_cryptographic_holder_binding to false, so a presentation without proof of possession is acceptable.',
    remediation:
      'Remove the property (the default is true), or have the policy owner permit it explicitly.',
    standardRefs: [`${OID4VP} §6.1`],
  },
  MULTIPLE_CREDENTIALS_REQUESTED: {
    id: 'MULTIPLE_CREDENTIALS_REQUESTED',
    category: 'P',
    title: 'Multiple credentials per query',
    outcome: 'DENY, or WARN when defaults.permitMultipleCredentials is true.',
    description:
      'A selectable credential query sets multiple: true, allowing several credentials of the type to be returned.',
    remediation:
      'Remove the property (the default is false), or have the policy owner permit it explicitly.',
    standardRefs: [`${OID4VP} §6.1`],
  },
  MDOC_RETENTION_REQUESTED: {
    id: 'MDOC_RETENTION_REQUESTED',
    category: 'P',
    title: 'mdoc retention intent',
    outcome:
      'DENY, or WARN when defaults.retentionIntent is "warn". Informational when the matching allow rule sets allowRetention.',
    description:
      'An mso_mdoc claims query sets intent_to_retain: true, declaring that the verifier intends to retain the element.',
    remediation:
      'Remove intent_to_retain, or have the policy owner permit retention for the claim with allowRetention.',
    standardRefs: [`${OID4VP} Appendix B.2.4`, 'ISO/IEC 18013-5 §8.3.2.1.2.1'],
  },
  MANDATORY_DISCLOSURE_EXCEEDS_POLICY: {
    id: 'MANDATORY_DISCLOSURE_EXCEEDS_POLICY',
    category: 'A',
    title: 'Mandatory disclosure exceeds policy',
    outcome: 'DENY.',
    description:
      'A path in the disclosure profile’s knownMandatoryPaths is denied or not allowed by the policy. Presenting the credential discloses it regardless of the claims requested.',
    remediation:
      'Use a credential type that does not disclose the field, or have the policy owner allow it for this purpose.',
    standardRefs: [`${OID4VP} §6.4`],
  },
  REQUEST_SIZE_EXCEEDS_POLICY: {
    id: 'REQUEST_SIZE_EXCEEDS_POLICY',
    category: 'A',
    title: 'Request larger than policy limit',
    outcome: 'DENY.',
    description:
      'The request has more credential queries or claim queries than defaults.maxCredentialQueries or defaults.maxClaimQueries.',
    remediation: 'Reduce the request, or have the policy owner raise the limit.',
    standardRefs: [],
  },
  UNKNOWN_EXTENSION_REVIEW: {
    id: 'UNKNOWN_EXTENSION_REVIEW',
    category: 'U',
    title: 'Unreviewed DCQL extension',
    outcome:
      'INDETERMINATE, or WARN when defaults.unknownExtension is "warn". Informational for names listed in reviewedExtensions.',
    description:
      'The request contains a property OpenID4VP 1.0 does not define for this position. It is valid DCQL, and wallets ignore properties they do not know, but a wallet that understands it may disclose differently.',
    remediation:
      'Remove the property, or have the policy owner review it and list its name in reviewedExtensions.',
    standardRefs: [`${OID4VP} §6`],
  },
  UNREFERENCED_QUERY: {
    id: 'UNREFERENCED_QUERY',
    category: 'P',
    title: 'Query never selected',
    outcome: 'Informational.',
    description:
      'A credential query is not referenced by any credential_sets option, or a claims query is not referenced by any claim_sets option. It is never requested and was not evaluated as disclosed.',
    remediation: 'Remove the unused declaration to keep the request auditable.',
    standardRefs: [`${OID4VP} §6.4.1`, `${OID4VP} §6.4.2`],
  },
  BRANCH_LIMIT_REACHED: {
    id: 'BRANCH_LIMIT_REACHED',
    category: 'O',
    title: 'Branch budget exceeded',
    outcome: 'INDETERMINATE. Denials found are still reported.',
    description:
      'The request has more credential and claim set combinations than options.maxBranches (default 2048). Element findings are still complete, but branch-level outcomes are not enumerated, so the request is never allowed.',
    remediation:
      'Simplify credential_sets and claim_sets, or raise maxBranches explicitly after review.',
    standardRefs: [`${OID4VP} §6.4`],
  },
};

export const RULE_IDS: readonly RuleId[] = Object.keys(RULES) as RuleId[];
