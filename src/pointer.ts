/** RFC 6901 JSON pointer construction. */
export function pointer(...segments: readonly (string | number)[]): string {
  let out = '';
  for (const segment of segments) {
    out += '/' + String(segment).replaceAll('~', '~0').replaceAll('/', '~1');
  }
  return out;
}

export function appendPointer(base: string, ...segments: readonly (string | number)[]): string {
  return base + pointer(...segments);
}
