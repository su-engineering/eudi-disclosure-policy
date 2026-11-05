/**
 * Canonical JSON: object keys sorted by UTF-16 code units, no insignificant
 * whitespace, ECMAScript number serialization. For the JSON values produced by
 * this library, the output matches RFC 8785 (JCS).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Cannot canonicalize a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return (
      '[' +
      value.map((item: unknown) => canonicalJson(item === undefined ? null : item)).join(',') +
      ']'
    );
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(record).sort()) {
      const item = record[key];
      if (item === undefined) continue;
      parts.push(JSON.stringify(key) + ':' + canonicalJson(item));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new TypeError(`Cannot canonicalize a value of type ${typeof value}`);
}
