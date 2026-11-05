import { InputValidationError, ResourceLimitError } from './errors.js';
import type { ResourceLimits } from './types.js';

export const DEFAULT_LIMITS: Required<ResourceLimits> = {
  maxInputBytes: 256 * 1024,
  maxDepth: 32,
  maxCredentialQueries: 32,
  maxClaimQueries: 256,
  maxPathSegments: 1024,
  maxSetOptions: 256,
};

export const DEFAULT_MAX_BRANCHES = 2048;

export function resolveLimits(limits: ResourceLimits | undefined): Required<ResourceLimits> {
  const resolved = { ...DEFAULT_LIMITS };
  if (!limits) return resolved;
  for (const key of Object.keys(DEFAULT_LIMITS) as (keyof ResourceLimits)[]) {
    const value = limits[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new InputValidationError(
        `options.limits.${key}`,
        `options.limits.${key} must be a positive integer`,
      );
    }
    resolved[key] = value;
  }
  return resolved;
}

export function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i++;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

export type JsonShapeProblem = {
  readonly pointerSegments: readonly (string | number)[];
  readonly reason: string;
};

/**
 * Walk a value iteratively, enforcing size and depth budgets before any other
 * processing. Returns a problem if the value is not plain JSON data
 * (functions, class instances, non-finite numbers, and so on). The byte count
 * approximates the UTF-8 size of the compact serialization.
 */
export function measureJson(
  value: unknown,
  limits: Required<ResourceLimits>,
): JsonShapeProblem | undefined {
  let bytes = 0;
  const stack: { value: unknown; depth: number; path: (string | number)[] }[] = [
    { value, depth: 0, path: [] },
  ];
  while (stack.length > 0) {
    const { value: current, depth, path } = stack.pop()!;
    if (depth > limits.maxDepth) throw new ResourceLimitError('maxDepth', limits.maxDepth);
    if (current === null) bytes += 4;
    else if (typeof current === 'boolean') bytes += 5;
    else if (typeof current === 'number') {
      if (!Number.isFinite(current)) return { pointerSegments: path, reason: 'non-finite number' };
      bytes += String(current).length;
    } else if (typeof current === 'string') bytes += utf8Length(current) + 2;
    else if (Array.isArray(current)) {
      bytes += 2 + current.length;
      for (let i = current.length - 1; i >= 0; i--) {
        if (!Object.hasOwn(current, i))
          return { pointerSegments: [...path, i], reason: 'sparse array' };
        stack.push({ value: current[i], depth: depth + 1, path: [...path, i] });
      }
    } else if (typeof current === 'object') {
      const proto: unknown = Object.getPrototypeOf(current);
      if (proto !== Object.prototype && proto !== null)
        return { pointerSegments: path, reason: 'not a plain object' };
      const keys = Object.keys(current);
      bytes += 2 + keys.length;
      for (let i = keys.length - 1; i >= 0; i--) {
        const key = keys[i]!;
        bytes += utf8Length(key) + 3;
        stack.push({
          value: (current as Record<string, unknown>)[key],
          depth: depth + 1,
          path: [...path, key],
        });
      }
    } else {
      return { pointerSegments: path, reason: `unsupported ${typeof current} value` };
    }
    if (bytes > limits.maxInputBytes)
      throw new ResourceLimitError('maxInputBytes', limits.maxInputBytes);
  }
  return undefined;
}
