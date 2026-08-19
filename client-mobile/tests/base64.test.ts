import { describe, it, expect } from 'vitest';
import { bytesToBase64, base64ToBytes } from '../src/services/base64';

describe('base64', () => {
  it('round-trips arbitrary byte lengths correctly (covers all padding cases)', () => {
    for (let length = 0; length <= 10; length++) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 37 + 5) % 256);
      const encoded = bytesToBase64(bytes);
      const decoded = base64ToBytes(encoded);
      expect(decoded).toEqual(bytes);
    }
  });

  it('round-trips 32 random bytes (typical key size)', () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);

    const encoded = bytesToBase64(bytes);
    const decoded = base64ToBytes(encoded);

    expect(decoded).toEqual(bytes);
  });

  it('matches known test vectors', () => {
    expect(bytesToBase64(new TextEncoder().encode('hello'))).toBe('aGVsbG8=');
    expect(bytesToBase64(new TextEncoder().encode('hi'))).toBe('aGk=');
    expect(bytesToBase64(new TextEncoder().encode(''))).toBe('');
    expect(new TextDecoder().decode(base64ToBytes('aGVsbG8='))).toBe('hello');
  });

  it('throws on invalid base64 characters', () => {
    expect(() => base64ToBytes('not valid base64!!')).toThrow(/invalid character/);
  });
});
