import { describe, it, expect } from 'vitest';
import { hkdfBlake2b } from '../src/encryption/hkdfBlake2b';

describe('hkdfBlake2b', () => {
  it('produces deterministic output for the same input', async () => {
    const ikm = new TextEncoder().encode('some raw dh output');
    const a = await hkdfBlake2b(ikm);
    const b = await hkdfBlake2b(ikm);
    expect(a).toEqual(b);
  });

  it('produces different output for different input', async () => {
    const a = await hkdfBlake2b(new TextEncoder().encode('input a'));
    const b = await hkdfBlake2b(new TextEncoder().encode('input b'));
    expect(a).not.toEqual(b);
  });

  it('produces different output for different info (domain separation)', async () => {
    const ikm = new TextEncoder().encode('shared raw material');
    const a = await hkdfBlake2b(ikm, undefined, new TextEncoder().encode('context A'));
    const b = await hkdfBlake2b(ikm, undefined, new TextEncoder().encode('context B'));
    expect(a).not.toEqual(b);
  });

  it('respects the requested output length', async () => {
    const ikm = new TextEncoder().encode('material');
    const short = await hkdfBlake2b(ikm, undefined, undefined, 16);
    const long = await hkdfBlake2b(ikm, undefined, undefined, 64);
    expect(short.length).toBe(16);
    expect(long.length).toBe(64);
  });

  it('defaults to 32 bytes of output', async () => {
    const out = await hkdfBlake2b(new TextEncoder().encode('x'));
    expect(out.length).toBe(32);
  });
});
