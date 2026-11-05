import { createHash } from 'node:crypto';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/index.js';
import { comparePointers } from '../src/engine/findings.js';
import { parseUtc } from '../src/engine/registration.js';
import { pointer } from '../src/pointer.js';
import { sha256Hex } from '../src/sha256.js';
import { utf8Length } from '../src/limits.js';

describe('sha256Hex', () => {
  it('matches known vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('matches node:crypto for arbitrary Unicode, including lone surrogates and block boundaries', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.string({ unit: 'binary', maxLength: 300 }),
          fc.string({ unit: 'grapheme', maxLength: 80 }),
        ),
        (text) => {
          expect(sha256Hex(text)).toBe(createHash('sha256').update(text, 'utf8').digest('hex'));
        },
      ),
      { numRuns: 500 },
    );
    for (const n of [55, 56, 63, 64, 65, 119, 120]) {
      const text = 'x'.repeat(n);
      expect(sha256Hex(text)).toBe(createHash('sha256').update(text).digest('hex'));
    }
  });
});

describe('utf8Length', () => {
  it('matches Buffer.byteLength', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'binary', maxLength: 200 }), (text) => {
        expect(utf8Length(text)).toBe(Buffer.byteLength(text, 'utf8'));
      }),
    );
  });
});

describe('canonicalJson', () => {
  it('sorts keys recursively, drops undefined members, and keeps array order', () => {
    expect(canonicalJson({ b: [3, { y: 1, x: undefined, a: null }], a: 'é' })).toBe(
      '{"a":"é","b":[3,{"a":null,"y":1}]}',
    );
  });

  it('round-trips through JSON.parse', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(JSON.parse(canonicalJson(value))).toEqual(JSON.parse(JSON.stringify(value)));
      }),
    );
  });

  it('rejects values JSON cannot represent', () => {
    expect(() => canonicalJson(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalJson(() => 1)).toThrow(TypeError);
  });
});

describe('pointer', () => {
  it('escapes per RFC 6901', () => {
    expect(pointer('a/b', 'm~n', 0)).toBe('/a~1b/m~0n/0');
  });

  it('orders array indices numerically', () => {
    const sorted = ['/a/10', '/a/2', '/a', '', '/a/2/b', '/b'].sort(comparePointers);
    expect(sorted).toEqual(['', '/a', '/a/2', '/a/2/b', '/a/10', '/b']);
  });
});

describe('parseUtc', () => {
  it.each([
    ['2026-11-05T16:00:00Z', Date.UTC(2026, 10, 5, 16)],
    ['2026-11-05T16:00:00.5Z', Date.UTC(2026, 10, 5, 16) + 500],
    ['2024-02-29T00:00:00.123456789Z', Date.UTC(2024, 1, 29) + 123],
  ])('parses %s', (text, expected) => {
    expect(parseUtc(text)).toBe(expected);
  });

  it.each([
    '2026-11-05T16:00:00',
    '2026-11-05T16:00:00+00:00',
    '2026-11-05 16:00:00Z',
    '2026-02-30T00:00:00Z',
    '2026-13-01T00:00:00Z',
    '2026-11-05T24:00:00Z',
    '2026-11-05T16:60:00Z',
    '2026-11-05',
    '',
  ])('rejects %j', (text) => {
    expect(parseUtc(text)).toBeUndefined();
  });

  it('rejects non-strings', () => {
    expect(parseUtc(1_700_000_000_000)).toBeUndefined();
  });
});
