import { describe, it, expect } from 'vitest';
import sodium from 'libsodium-wrappers';
import { encryptMessage, decryptMessage } from '../src/encryption/messageCipher';

async function randomKey(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(32);
}

describe('messageCipher', () => {
  it('encrypts and decrypts a message round-trip correctly', async () => {
    const key = await randomKey();
    const plaintext = new TextEncoder().encode('hello, this is a secret message');

    const { ciphertext, nonce } = await encryptMessage(key, plaintext);
    const decrypted = await decryptMessage(key, ciphertext, nonce);

    expect(new TextDecoder().decode(decrypted)).toBe('hello, this is a secret message');
  });

  it('produces ciphertext that does not contain the plaintext in the clear', async () => {
    const key = await randomKey();
    const plaintext = new TextEncoder().encode('super secret content');

    const { ciphertext } = await encryptMessage(key, plaintext);
    const ciphertextAsText = Buffer.from(ciphertext).toString('utf8');

    expect(ciphertextAsText).not.toContain('super secret content');
  });

  it('produces a different nonce (and ciphertext) for every call, even with the same key and plaintext', async () => {
    const key = await randomKey();
    const plaintext = new TextEncoder().encode('same message twice');

    const first = await encryptMessage(key, plaintext);
    const second = await encryptMessage(key, plaintext);

    expect(first.nonce).not.toEqual(second.nonce);
    expect(first.ciphertext).not.toEqual(second.ciphertext);
  });

  it('rejects decryption with the wrong key', async () => {
    const key = await randomKey();
    const wrongKey = await randomKey();
    const plaintext = new TextEncoder().encode('message for the right recipient only');

    const { ciphertext, nonce } = await encryptMessage(key, plaintext);

    await expect(decryptMessage(wrongKey, ciphertext, nonce)).rejects.toThrow();
  });

  it('rejects decryption if the ciphertext was tampered with', async () => {
    const key = await randomKey();
    const plaintext = new TextEncoder().encode('do not modify me');

    const { ciphertext, nonce } = await encryptMessage(key, plaintext);
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0xff;

    await expect(decryptMessage(key, tampered, nonce)).rejects.toThrow();
  });

  it('rejects decryption if the associated data does not match', async () => {
    const key = await randomKey();
    const plaintext = new TextEncoder().encode('bound to a specific context');
    const originalAD = new TextEncoder().encode('header-v1');
    const wrongAD = new TextEncoder().encode('header-v2');

    const { ciphertext, nonce } = await encryptMessage(key, plaintext, originalAD);

    await expect(decryptMessage(key, ciphertext, nonce, wrongAD)).rejects.toThrow();
  });

  it('rejects a key of the wrong length', async () => {
    const shortKey = new Uint8Array(16);
    const plaintext = new TextEncoder().encode('x');

    await expect(encryptMessage(shortKey, plaintext)).rejects.toThrow(/32 bytes/);
  });
});
