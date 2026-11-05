/**
 * DCQL structural validation. The audited parser (@openeudi/dcql, pinned in
 * package.json; see docs/decisions/0003-dcql-parser.md) checks OpenID4VP 1.0
 * structure. Supplemental checks cover rules the parser does not enforce.
 * Analysis always runs on the original input, so pointers and extension
 * properties are preserved exactly.
 */
import { DcqlValidationError, validateQuery } from '@openeudi/dcql';
import { measureJson, utf8Length } from '../limits.js';
import { ResourceLimitError } from '../errors.js';
import { pointer } from '../pointer.js';
import { pathsEqual } from './path.js';
import type { DcqlPath, ResourceLimits } from '../types.js';

export interface DcqlProblem {
  readonly pointer: string;
  readonly code: string;
  readonly message: string;
}

export type ParseOutcome =
  | { readonly ok: true; readonly query: Record<string, unknown> }
  | { readonly ok: false; readonly problems: readonly DcqlProblem[] };

const PARSER_MESSAGES: Record<string, string> = {
  missing_field: 'A required DCQL property is missing.',
  invalid_type:
    'A DCQL property has the wrong type or is an empty array where a non-empty one is required.',
  invalid_id: 'A credential or claim id is not a non-empty string of letters, digits, "_" or "-".',
  duplicate_id: 'A credential or claim id is used more than once.',
  unknown_format: 'A credential query format is empty.',
  invalid_claim_path: 'A claims path pointer is malformed for its credential format.',
  invalid_claim_set_reference:
    'claim_sets references an unknown claim id, or is present without claims.',
  invalid_credential_set_reference: 'credential_sets references an unknown credential id.',
};

type JsonRecord = Record<string, unknown>;
const asRecord = (value: unknown): JsonRecord => value as JsonRecord;
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/**
 * Checks the parser leaves to callers: empty credential set options (§6.2),
 * duplicate claim paths in one credential query (§6.1), and non-integer
 * numbers in values (§6.3). Also enforces the query-count budgets.
 */
function supplementalChecks(query: JsonRecord, limits: Required<ResourceLimits>): DcqlProblem[] {
  const problems: DcqlProblem[] = [];
  const credentials = asArray(query['credentials']);
  if (credentials.length > limits.maxCredentialQueries) {
    throw new ResourceLimitError('maxCredentialQueries', limits.maxCredentialQueries);
  }
  let claimCount = 0;
  let segmentCount = 0;
  let optionCount = 0;
  credentials.forEach((credential, i) => {
    optionCount += asArray(asRecord(credential)['claim_sets']).length;
    const claims = asArray(asRecord(credential)['claims']);
    claimCount += claims.length;
    const seen: DcqlPath[] = [];
    claims.forEach((claim, j) => {
      const c = asRecord(claim);
      const path = c['path'] as DcqlPath;
      segmentCount += path.length;
      if (seen.some((other) => pathsEqual(other, path))) {
        problems.push({
          pointer: pointer('credentials', i, 'claims', j, 'path'),
          code: 'duplicate_claim_path',
          message: 'The credential query points to the same claim more than once.',
        });
      }
      seen.push(path);
      asArray(c['values']).forEach((v, k) => {
        if (typeof v === 'number' && !Number.isSafeInteger(v)) {
          problems.push({
            pointer: pointer('credentials', i, 'claims', j, 'values', k),
            code: 'invalid_value_type',
            message: 'values entries must be strings, integers, or booleans.',
          });
        }
      });
    });
  });
  if (claimCount > limits.maxClaimQueries)
    throw new ResourceLimitError('maxClaimQueries', limits.maxClaimQueries);
  if (segmentCount > limits.maxPathSegments)
    throw new ResourceLimitError('maxPathSegments', limits.maxPathSegments);
  if (optionCount > limits.maxSetOptions)
    throw new ResourceLimitError('maxSetOptions', limits.maxSetOptions);

  asArray(query['credential_sets']).forEach((set, i) => {
    const options = asArray(asRecord(set)['options']);
    optionCount += options.length;
    if (optionCount > limits.maxSetOptions)
      throw new ResourceLimitError('maxSetOptions', limits.maxSetOptions);
    options.forEach((option, j) => {
      if (Array.isArray(option) && option.length === 0) {
        problems.push({
          pointer: pointer('credential_sets', i, 'options', j),
          code: 'empty_option',
          message: 'A credential set option must reference at least one credential query.',
        });
      }
    });
  });
  return problems;
}

export function parseDcql(input: unknown, limits: Required<ResourceLimits>): ParseOutcome {
  let value = input;
  if (typeof input === 'string') {
    if (utf8Length(input) > limits.maxInputBytes)
      throw new ResourceLimitError('maxInputBytes', limits.maxInputBytes);
    try {
      value = JSON.parse(input);
    } catch {
      // The engine's own message: platform parse errors can quote input text.
      return {
        ok: false,
        problems: [
          { pointer: '', code: 'invalid_json', message: 'The request is not valid JSON.' },
        ],
      };
    }
  }
  const shape = measureJson(value, limits);
  if (shape) {
    return {
      ok: false,
      problems: [
        {
          pointer: pointer(...shape.pointerSegments),
          code: 'invalid_json',
          message: `The request is not plain JSON data (${shape.reason}).`,
        },
      ],
    };
  }
  try {
    validateQuery(value);
  } catch (error) {
    if (error instanceof DcqlValidationError) {
      return {
        ok: false,
        problems: [
          {
            pointer: error.path,
            code: error.code,
            message: PARSER_MESSAGES[error.code] ?? 'The DCQL query is invalid.',
          },
        ],
      };
    }
    throw error;
  }
  const query = value as JsonRecord;
  const problems = supplementalChecks(query, limits);
  if (problems.length > 0) return { ok: false, problems };
  return { ok: true, query };
}
