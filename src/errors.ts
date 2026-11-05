/**
 * Typed errors thrown by the library. Messages never contain request or
 * policy values: only codes, JSON pointers, and limit names.
 */

export type ErrorCode =
  'POLICY_INVALID' | 'INPUT_INVALID' | 'PROFILE_UNSUPPORTED' | 'RESOURCE_LIMIT_EXCEEDED';

export class EudiDisclosureError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export interface PolicyIssue {
  /** RFC 6901 pointer into the policy document. */
  readonly pointer: string;
  readonly message: string;
}

/** The policy document is malformed, contradictory, or uses an unsupported schema version. */
export class PolicyValidationError extends EudiDisclosureError {
  readonly issues: readonly PolicyIssue[];

  constructor(issues: readonly PolicyIssue[]) {
    const first = issues[0];
    const suffix = issues.length > 1 ? ` (and ${issues.length - 1} more)` : '';
    super(
      'POLICY_INVALID',
      first
        ? `Invalid policy at ${first.pointer || '/'}: ${first.message}${suffix}`
        : 'Invalid policy',
    );
    this.issues = issues;
  }
}

/** Invocation input other than the DCQL query or policy is invalid, such as the evaluation time. */
export class InputValidationError extends EudiDisclosureError {
  readonly field: string;

  constructor(field: string, message: string) {
    super('INPUT_INVALID', message);
    this.field = field;
  }
}

export class UnsupportedProfileError extends EudiDisclosureError {
  constructor() {
    super('PROFILE_UNSUPPORTED', 'Unsupported evaluation profile; expected openid4vp-1.0');
  }
}

/** Input exceeds a resource budget. Evaluation stops before analysis; no partial result exists. */
export class ResourceLimitError extends EudiDisclosureError {
  readonly limit: string;
  readonly max: number;

  constructor(limit: string, max: number) {
    super('RESOURCE_LIMIT_EXCEEDED', `Input exceeds the ${limit} limit of ${max}`);
    this.limit = limit;
    this.max = max;
  }
}
