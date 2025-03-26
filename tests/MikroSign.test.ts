import { createHash, createHmac } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { MikroSign } from '../src/MikroSign';

const SECRET = 'test-secret-key';
const METHOD = 'POST';
const PATH = '/api/update';
const BODY = { version: '1.0.0', commitSha: 'abc123' };

let mikroSign: MikroSign;
let originalDateNow: typeof Date.now;

beforeEach(() => {
  mikroSign = new MikroSign(SECRET);
  originalDateNow = Date.now;
});

afterEach(() => (Date.now = originalDateNow));

const mockDateNow = (timestamp: number) => (Date.now = () => timestamp);

describe('Initialization', () => {
  test('It should create an instance with default options', () => {
    const instance = new MikroSign(SECRET);
    expect(instance).toBeInstanceOf(MikroSign);
  });

  test('It should create an instance with custom options', () => {
    const instance = new MikroSign(SECRET, {
      algorithm: 'sha512',
      maxTimestampAgeMs: 10000
    });
    expect(instance).toBeInstanceOf(MikroSign);
  });

  test('It should throw error if secret is empty', () => {
    expect(() => new MikroSign('')).toThrowError();
  });
});

describe('Signing', () => {
  test('It should return timestamp and signature', () => {
    const result = mikroSign.sign(METHOD, PATH, BODY);
    expect(result).toHaveProperty('timestamp');
    expect(result).toHaveProperty('signature');
    expect(typeof result.timestamp).toBe('number');
    expect(typeof result.signature).toBe('string');
    expect(result.signature.length).toBeGreaterThan(0);
  });

  test('It should generate different signatures for different methods', () => {
    const signature1 = mikroSign.sign('GET', PATH, BODY).signature;
    const signature2 = mikroSign.sign('POST', PATH, BODY).signature;
    expect(signature1).not.toBe(signature2);
  });

  test('It should handle paths with and without leading slash', () => {
    const withSlash = mikroSign.sign(METHOD, '/api/test', BODY);
    const withoutSlash = mikroSign.sign(METHOD, 'api/test', BODY);

    expect(withSlash.signature).toBe(withoutSlash.signature);
  });

  test('It should handle different body types', () => {
    const bodies = [
      { test: 'object' },
      ['array', 'of', 'items'],
      'string-body',
      123,
      null,
      undefined
    ];

    bodies.forEach((body) => {
      const result = mikroSign.sign(METHOD, PATH, body);
      expect(result).toHaveProperty('signature');
    });
  });

  test('It should produce deterministic signatures when timestamp is fixed', () => {
    mockDateNow(1609459200000);
    const sign1 = mikroSign.sign(METHOD, PATH, BODY);
    const sign2 = mikroSign.sign(METHOD, PATH, BODY);
    expect(sign1.signature).toBe(sign2.signature);
  });
});

describe('Verification', () => {
  test('It should verify a valid signature', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);
    const isValid = mikroSign.verify(METHOD, PATH, BODY, timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should reject an invalid signature', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);
    const tampered = signature.replace(/a/g, 'b'); // Tamper with the signature
    const isValid = mikroSign.verify(METHOD, PATH, BODY, timestamp, tampered);
    expect(isValid).toBe(false);
  });

  test('It should reject a valid signature with tampered method', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);
    const isValid = mikroSign.verify('GET', PATH, BODY, timestamp, signature);
    expect(isValid).toBe(false);
  });

  test('It should reject a valid signature with tampered path', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);
    const isValid = mikroSign.verify(METHOD, '/different/path', BODY, timestamp, signature);
    expect(isValid).toBe(false);
  });

  test('It should reject a valid signature with tampered body', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);
    const tamperedBody = { ...BODY, version: '2.0.0' };
    const isValid = mikroSign.verify(METHOD, PATH, tamperedBody, timestamp, signature);
    expect(isValid).toBe(false);
  });

  test('It should reject expired timestamps', () => {
    const now = 1609459200000; // 2021-01-01T00:00:00.000Z
    mockDateNow(now);

    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);

    mockDateNow(now + 6 * 60 * 1000);

    const isValid = mikroSign.verify(METHOD, PATH, BODY, timestamp, signature);
    expect(isValid).toBe(false);
  });

  test('It should accept non-expired timestamps', () => {
    const now = 1609459200000; // 2021-01-01T00:00:00.000Z
    mockDateNow(now);

    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);

    mockDateNow(now + 4 * 60 * 1000);

    const isValid = mikroSign.verify(METHOD, PATH, BODY, timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should handle malformed signatures gracefully', () => {
    const { timestamp } = mikroSign.sign(METHOD, PATH, BODY);
    const badSignatures = [
      '', // Empty string
      'not-a-valid-hex-signature', // Non-hex characters
      '123', // Too short
      '0'.repeat(1000) // Too long
    ];

    badSignatures.forEach((badSignature) => {
      const isValid = mikroSign.verify(METHOD, PATH, BODY, timestamp, badSignature);
      expect(isValid).toBe(false);
    });
  });

  test('It should reject a future timestamp', () => {
    const now = 1609459200000; // 2021-01-01T00:00:00.000Z
    mockDateNow(now);

    const futureTimestamp = now + 60 * 1000; // 1 minute in the future

    const stringToSign = [
      METHOD.toUpperCase(),
      PATH,
      futureTimestamp.toString(),
      createHash('sha256').update(JSON.stringify(BODY)).digest('hex')
    ].join(';');

    const signature = createHmac('sha256', SECRET).update(stringToSign).digest('hex');

    const isValid = mikroSign.verify(METHOD, PATH, BODY, futureTimestamp, signature);
    expect(isValid).toBe(false);
  });
});

describe('Custom configurations', () => {
  test('It should work with different hashing algorithms', () => {
    const algorithms = ['sha1', 'sha256', 'sha512', 'md5'];

    algorithms.forEach((algorithm) => {
      const customSign = new MikroSign(SECRET, { algorithm });
      const { timestamp, signature } = customSign.sign(METHOD, PATH, BODY);
      const isValid = customSign.verify(METHOD, PATH, BODY, timestamp, signature);
      expect(isValid).toBe(true);
    });
  });

  test('It should respect custom timestamp age settings', () => {
    const shortTimeout = new MikroSign(SECRET, { maxTimestampAgeMs: 10000 });

    const now = 1609459200000; // 2021-01-01T00:00:00.000Z
    mockDateNow(now);

    const { timestamp, signature } = shortTimeout.sign(METHOD, PATH, BODY);

    mockDateNow(now + 15 * 1000);

    const isValid = shortTimeout.verify(METHOD, PATH, BODY, timestamp, signature);
    expect(isValid).toBe(false);
  });

  test('It should reject very old timestamps even with large maxTimestampAgeMs', () => {
    const longTimeout = new MikroSign(SECRET, { maxTimestampAgeMs: 86400000 });

    const now = 1609459200000; // 2021-01-01T00:00:00.000Z
    mockDateNow(now);

    const oldTimestamp = now - 86400000 * 2; // 2 days old

    const customStringToSign = [
      METHOD.toUpperCase(),
      PATH,
      oldTimestamp.toString(),
      createHash('sha256').update(JSON.stringify(BODY)).digest('hex')
    ].join(';');

    const signature = createHmac('sha256', SECRET).update(customStringToSign).digest('hex');

    const isValid = longTimeout.verify(METHOD, PATH, BODY, oldTimestamp, signature);
    expect(isValid).toBe(false);
  });
});

describe('Performance', () => {
  test('It should handle large request bodies', () => {
    // Create a large object
    const largeBody = {
      items: Array(1000)
        .fill(0)
        .map((_, i) => ({
          id: i,
          name: `Item ${i}`,
          description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
        }))
    };

    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, largeBody);
    const isValid = mikroSign.verify(METHOD, PATH, largeBody, timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should handle multiple signs and verifies efficiently', () => {
    // Simple performance test - no actual timing assertions
    for (let i = 0; i < 100; i++) {
      const body = { index: i, data: `test-${i}` };
      const { timestamp, signature } = mikroSign.sign(METHOD, PATH, body);
      const isValid = mikroSign.verify(METHOD, PATH, body, timestamp, signature);
      expect(isValid).toBe(true);
    }
  });

  test('It should handle mixed case methods', () => {
    const upperCase = mikroSign.sign('POST', PATH, BODY);
    const lowerCase = mikroSign.sign('post', PATH, BODY);
    const mixedCase = mikroSign.sign('PoSt', PATH, BODY);

    // They should all produce the same signature since methods are normalized
    expect(upperCase.signature).toBe(lowerCase.signature);
    expect(upperCase.signature).toBe(mixedCase.signature);

    expect(mikroSign.verify('POST', PATH, BODY, upperCase.timestamp, upperCase.signature)).toBe(
      true
    );
    expect(mikroSign.verify('post', PATH, BODY, lowerCase.timestamp, lowerCase.signature)).toBe(
      true
    );
    expect(mikroSign.verify('pOsT', PATH, BODY, mixedCase.timestamp, mixedCase.signature)).toBe(
      true
    );
  });
});

describe('Edge cases', () => {
  test('It should handle empty body gracefully', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, '');
    const isValid = mikroSign.verify(METHOD, PATH, '', timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should handle undefined body gracefully', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, undefined);
    const isValid = mikroSign.verify(METHOD, PATH, undefined, timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should handle null body gracefully', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, null);
    const isValid = mikroSign.verify(METHOD, PATH, null, timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should handle root path gracefully', () => {
    const { timestamp, signature } = mikroSign.sign(METHOD, '/', BODY);
    const isValid = mikroSign.verify(METHOD, '/', BODY, timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should treat NaN timestamp as invalid', () => {
    const { signature } = mikroSign.sign(METHOD, PATH, BODY);
    const isValid = mikroSign.verify(METHOD, PATH, BODY, Number.NaN, signature);
    expect(isValid).toBe(false);
  });

  test('It should handle non-string path values', () => {
    // @ts-ignore - Deliberately passing wrong type for test
    const { timestamp, signature } = mikroSign.sign(METHOD, null, BODY);
    // Should not throw but create a default path
    expect(mikroSign.verify(METHOD, '/', BODY, timestamp, signature)).toBe(true);
  });

  test('It should handle non-string method values', () => {
    // @ts-ignore - Deliberately passing wrong type for test
    const result = mikroSign.sign(undefined, PATH, BODY);
    expect(result).toHaveProperty('signature');
  });

  test('It should handle circular references in body', () => {
    const circularObj: any = { name: 'circular' };
    circularObj.self = circularObj;

    expect(() => mikroSign.sign(METHOD, PATH, circularObj)).not.toThrow();
  });

  test('It should normalize body serialization for verification', () => {
    const bodyWithOrder = { a: 1, b: 2, c: 3 };
    const { timestamp, signature } = mikroSign.sign(METHOD, PATH, bodyWithOrder);

    // Verify with same content but different property order
    const bodyWithDifferentOrder = { c: 3, a: 1, b: 2 };
    const isValid = mikroSign.verify(METHOD, PATH, bodyWithDifferentOrder, timestamp, signature);
    expect(isValid).toBe(true);
  });

  test('It should handle extremely large timestamps gracefully', () => {
    const extremeTimestamp = Number.MAX_SAFE_INTEGER;
    const normalSignature = mikroSign.sign(METHOD, PATH, BODY).signature;
    const isValid = mikroSign.verify(METHOD, PATH, BODY, extremeTimestamp, normalSignature);
    expect(isValid).toBe(false);
  });

  test('It should handle negative timestamps gracefully', () => {
    const negativeTimestamp = -1000;
    const normalSignature = mikroSign.sign(METHOD, PATH, BODY).signature;
    const isValid = mikroSign.verify(METHOD, PATH, BODY, negativeTimestamp, normalSignature);
    expect(isValid).toBe(false);
  });

  test('It should ensure all verify checks happen regardless of order', () => {
    const invalidSignature = 'deadbeef'.repeat(8);

    const now = 1609459200000;
    mockDateNow(now);

    const expiredTimestamp = now - 1000000;

    // Called with multiple issues:
    // - expired timestamp
    // - invalid signature
    // - tampered data
    // It should return false, not throw
    expect(() => {
      const isValid = mikroSign.verify(
        'WRONG_METHOD',
        '/wrong/path',
        { wrong: 'body' },
        expiredTimestamp,
        invalidSignature
      );
      expect(isValid).toBe(false);
    }).not.toThrow();
  });

  describe('Security edge cases', () => {
    test('It should be secure against timing attacks with different signature lengths', () => {
      const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);

      // Create invalid signatures of different lengths
      const shorterSig = signature.substring(0, signature.length - 5);
      const longerSig = `${signature}extra`;

      // These should both be rejected
      expect(mikroSign.verify(METHOD, PATH, BODY, timestamp, shorterSig)).toBe(false);
      expect(mikroSign.verify(METHOD, PATH, BODY, timestamp, longerSig)).toBe(false);
    });

    test('It should fail on binary tampering attempts', () => {
      const { timestamp, signature } = mikroSign.sign(METHOD, PATH, BODY);

      // Convert signature to Buffer, change a byte, convert back to hex
      const sigBuffer = Buffer.from(signature, 'hex');
      sigBuffer[10] = (sigBuffer[10] + 1) % 256; // Change one byte
      const tamperedSig = sigBuffer.toString('hex');

      expect(mikroSign.verify(METHOD, PATH, BODY, timestamp, tamperedSig)).toBe(false);
    });

    test('It should verify with the same secret only', () => {
      const originalSign = new MikroSign(SECRET);
      const differentSign = new MikroSign(`${SECRET}different`);

      const { timestamp, signature } = originalSign.sign(METHOD, PATH, BODY);

      expect(originalSign.verify(METHOD, PATH, BODY, timestamp, signature)).toBe(true);

      expect(differentSign.verify(METHOD, PATH, BODY, timestamp, signature)).toBe(false);
    });
  });
});
