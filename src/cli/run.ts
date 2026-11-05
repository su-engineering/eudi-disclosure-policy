/**
 * Command-line shell around the core. All file and stream I/O lives here.
 * Diagnostics never print input content; file paths appear only with
 * --no-redact.
 */
import { readFile, stat } from 'node:fs/promises';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { canonicalJson } from '../canonical.js';
import {
  EudiDisclosureError,
  PolicyValidationError,
  ResourceLimitError,
  UnsupportedProfileError,
} from '../errors.js';
import { evaluateRequest } from '../evaluate.js';
import { DEFAULT_LIMITS } from '../limits.js';
import { validatePolicy } from '../policy/validate.js';
import { RULES } from '../rules/catalog.js';
import { sha256Hex } from '../sha256.js';
import { VERSION } from '../version.js';
import type { EvaluationResult, RuleId } from '../types.js';
import { formatExplain, formatHuman } from './human.js';

export const EXIT = { ok: 0, deny: 1, usage: 2, indeterminate: 3, internal: 4 } as const;

export interface CliIO {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly stdin: () => AsyncIterable<Uint8Array | string>;
  /** Current time, used only when --evaluation-time is omitted. */
  readonly now: () => Date;
}

const USAGE = `Usage:
  eudi-disclosure lint --query <file|-> --policy <file> [options]
  eudi-disclosure policy validate <file> [--format human|json]
  eudi-disclosure explain <RULE_ID>
  eudi-disclosure rules [--format human|json]

Lint options:
  --query <file|->            DCQL query JSON, or - for stdin (never fetched from a URL)
  --policy <file>             Disclosure policy JSON (schemaVersion 1.0)
  --registration <file>       Registration scope evidence. Caller-asserted: a local
                              file is not proof of cryptographic verification
  --rp-id <id>                Relying party evaluated (required to use evidence)
  --service-id <id>           Relying-party service evaluated
  --intended-use <id>         Intended use evaluated
  --profile openid4vp-1.0     Evaluation profile (default and only value)
  --evaluation-time <time>    UTC time, e.g. 2026-11-05T16:00:00Z (default: now)
  --format human|json         Output format (default human)
  --strict                    Exit 1 on WARN as well as DENY
  --max-branches <n>          Branch budget (default 2048)
  --explain <RULE_ID>         Describe a rule instead of linting
  --no-redact                 Show file paths in diagnostics

Exit codes: 0 ALLOW (or WARN without --strict), 1 DENY (or WARN with --strict),
2 usage, input, or policy error, 3 INDETERMINATE or resource limit, 4 internal error.

  -h, --help                  Show this help
  -v, --version               Show the version
`;

class UsageError extends Error {}

const FILE_LIMIT = 1024 * 1024;

async function readSource(
  source: string,
  label: string,
  max: number,
  io: CliIO,
  redact: boolean,
): Promise<string> {
  const name = redact ? `the ${label}` : `${label} ${JSON.stringify(source)}`;
  if (source === '-') {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of io.stdin()) {
      const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk);
      size += buffer.length;
      if (size > max) throw new ResourceLimitError('maxInputBytes', max);
      chunks.push(buffer);
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  let info;
  try {
    info = await stat(source);
  } catch {
    throw new UsageError(`Cannot read ${name}.`);
  }
  if (!info.isFile()) throw new UsageError(`Cannot read ${name}: not a file.`);
  if (info.size > max) throw new ResourceLimitError('maxInputBytes', max);
  return readFile(source, 'utf8');
}

async function readJson(
  source: string,
  label: string,
  io: CliIO,
  redact: boolean,
): Promise<unknown> {
  const text = await readSource(source, label, FILE_LIMIT, io, redact);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // Platform parse errors can quote file content; report only the fact.
    throw new UsageError(`The ${label} is not valid JSON.`);
  }
}

function exitFor(result: EvaluationResult, strict: boolean): number {
  switch (result.verdict) {
    case 'ALLOW':
      return EXIT.ok;
    case 'WARN':
      return strict ? EXIT.deny : EXIT.ok;
    case 'DENY':
      return EXIT.deny;
    case 'INDETERMINATE':
      return EXIT.indeterminate;
  }
}

function parse(args: string[], options: ParseArgsConfig['options']): ReturnType<typeof parseArgs> {
  try {
    return parseArgs({
      args,
      options: { ...options, help: { type: 'boolean', short: 'h' } },
      allowPositionals: true,
      strict: true,
    });
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
}

function format(value: unknown): 'human' | 'json' {
  if (value === undefined || value === 'human') return 'human';
  if (value === 'json') return 'json';
  throw new UsageError('--format must be human or json.');
}

async function lint(args: string[], io: CliIO): Promise<number> {
  const { values, positionals } = parse(args, {
    query: { type: 'string' },
    policy: { type: 'string' },
    registration: { type: 'string' },
    'rp-id': { type: 'string' },
    'service-id': { type: 'string' },
    'intended-use': { type: 'string' },
    profile: { type: 'string' },
    'evaluation-time': { type: 'string' },
    format: { type: 'string' },
    strict: { type: 'boolean' },
    'max-branches': { type: 'string' },
    explain: { type: 'string' },
    redact: { type: 'boolean' },
    'no-redact': { type: 'boolean' },
  });
  if (values['help']) {
    io.stdout(USAGE);
    return EXIT.ok;
  }
  if (typeof values['explain'] === 'string') return explain(values['explain'], io);
  if (positionals.length > 0) throw new UsageError('lint takes no positional arguments.');
  const output = format(values['format']);
  const redact = values['no-redact'] !== true;
  const query = values['query'];
  const policyPath = values['policy'];
  if (typeof query !== 'string' || typeof policyPath !== 'string')
    throw new UsageError('lint needs --query and --policy.');
  if (values['profile'] !== undefined && values['profile'] !== 'openid4vp-1.0')
    throw new UnsupportedProfileError();
  let maxBranches: number | undefined;
  if (typeof values['max-branches'] === 'string') {
    if (!/^\d+$/.test(values['max-branches']))
      throw new UsageError('--max-branches must be a positive integer.');
    maxBranches = Number(values['max-branches']);
  }

  const policy = await readJson(policyPath, 'policy file', io, redact);
  const registration =
    typeof values['registration'] === 'string'
      ? await readJson(values['registration'], 'registration file', io, redact)
      : undefined;
  const dcql = await readSource(query, 'query file', DEFAULT_LIMITS.maxInputBytes, io, redact);
  const rpId = values['rp-id'];
  const serviceId = values['service-id'];
  const intendedUseId = values['intended-use'];
  if ((serviceId !== undefined || intendedUseId !== undefined) && rpId === undefined) {
    throw new UsageError('--service-id and --intended-use need --rp-id.');
  }

  const result = evaluateRequest({
    profile: 'openid4vp-1.0',
    evaluationTime:
      typeof values['evaluation-time'] === 'string'
        ? values['evaluation-time']
        : io.now().toISOString(),
    dcql,
    policy: policy as never,
    ...(registration !== undefined && { registration: registration as never }),
    ...(typeof rpId === 'string' && {
      relyingParty: {
        rpId,
        ...(typeof serviceId === 'string' && { serviceId }),
        ...(typeof intendedUseId === 'string' && { intendedUseId }),
      },
    }),
    ...(maxBranches !== undefined && { options: { maxBranches } }),
  });
  io.stdout(output === 'json' ? canonicalJson(result) + '\n' : formatHuman(result));
  return exitFor(result, values['strict'] === true);
}

async function policyCommand(args: string[], io: CliIO): Promise<number> {
  const { values, positionals } = parse(args, {
    format: { type: 'string' },
    'no-redact': { type: 'boolean' },
  });
  if (values['help']) {
    io.stdout(USAGE);
    return EXIT.ok;
  }
  if (positionals[0] !== 'validate' || positionals.length !== 2)
    throw new UsageError('Usage: eudi-disclosure policy validate <file>');
  const output = format(values['format']);
  const document = await readJson(positionals[1]!, 'policy file', io, values['no-redact'] !== true);
  try {
    const policy = validatePolicy(document);
    const digest = `sha-256:${sha256Hex(canonicalJson(policy))}`;
    io.stdout(
      output === 'json'
        ? canonicalJson({
            valid: true,
            policy: {
              id: policy.policyId,
              version: policy.policyVersion,
              purposeId: policy.purposeId,
              digest,
            },
          }) + '\n'
        : `Policy ${policy.policyId}@${policy.policyVersion} is valid.\nPurpose: ${policy.purposeId}\nDigest: ${digest}\n`,
    );
    return EXIT.ok;
  } catch (error) {
    if (!(error instanceof PolicyValidationError)) throw error;
    io.stdout(
      output === 'json'
        ? canonicalJson({ valid: false, issues: error.issues }) + '\n'
        : `Policy is invalid (${error.issues.length} issue${error.issues.length === 1 ? '' : 's'}):\n${error.issues
            .map((i) => `  ${i.pointer || '/'}: ${i.message}\n`)
            .join('')}`,
    );
    return EXIT.usage;
  }
}

function explain(ruleId: string, io: CliIO): number {
  if (!Object.hasOwn(RULES, ruleId))
    throw new UsageError('Unknown rule ID. Run "eudi-disclosure rules" to list them.');
  io.stdout(formatExplain(RULES[ruleId as RuleId]));
  return EXIT.ok;
}

function rules(args: string[], io: CliIO): number {
  const { values } = parse(args, { format: { type: 'string' } });
  const all = Object.values(RULES);
  io.stdout(
    format(values['format']) === 'json'
      ? canonicalJson(all) + '\n'
      : all.map((r) => `${r.id.padEnd(40)} ${r.category}  ${r.title}\n`).join(''),
  );
  return EXIT.ok;
}

export async function run(argv: readonly string[], io: CliIO): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case 'lint':
        return await lint(rest, io);
      case 'policy':
        return await policyCommand(rest, io);
      case 'explain':
        if (rest.length !== 1) throw new UsageError('Usage: eudi-disclosure explain <RULE_ID>');
        return explain(rest[0]!, io);
      case 'rules':
        return rules(rest, io);
      case '-v':
      case '--version':
        io.stdout(`${VERSION}\n`);
        return EXIT.ok;
      case undefined:
      case '-h':
      case '--help':
        io.stdout(USAGE);
        return command === undefined ? EXIT.usage : EXIT.ok;
      default:
        throw new UsageError(`Unknown command. Run "eudi-disclosure --help".`);
    }
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr(`eudi-disclosure: ${error.message}\n`);
      return EXIT.usage;
    }
    if (error instanceof EudiDisclosureError) {
      io.stderr(`eudi-disclosure: ${error.code}: ${error.message}\n`);
      return error instanceof ResourceLimitError || error instanceof UnsupportedProfileError
        ? EXIT.indeterminate
        : EXIT.usage;
    }
    // Unexpected failures: report the type only; messages and stacks can carry input.
    io.stderr(
      `eudi-disclosure: internal error (${error instanceof Error ? error.name : typeof error}). Please report it.\n`,
    );
    return EXIT.internal;
  }
}
