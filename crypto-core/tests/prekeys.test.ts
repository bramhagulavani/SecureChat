import { describe, it, expect } from 'vitest';
import { generateIdentityKeyPair } from '../src/keys/identityKeys';
import {
  generateSignedPreKey,
  verifySignedPreKey,
  generateOneTimePreKeys,
} from '../src/keys/prekeys';

describe('prekeys', () => {
  it('generates a signed prekey whose signature verifies against the signing identity', async () => {
    const identity = await generateIdentityKeyPair();
    const spk = await generateSignedPreKey(identity.signing.privateKey, 1);

    const isValid = await verifySignedPreKey(
      spk.publicKey,
      spk.signature,
      identity.signing.publicKey
    );

    expect(isValid).toBe(true);
  });

  it('rejects a signed prekey verified against the wrong identity', async () => {
    const identityA = await generateIdentityKeyPair();
    const identityB = await generateIdentityKeyPair();
    const spk = await generateSignedPreKey(identityA.signing.privateKey, 1);

    const isValid = await verifySignedPreKey(
      spk.publicKey,
      spk.signature,
      identityB.signing.publicKey
    );

    expect(isValid).toBe(false);
  });

  it('rejects a tampered signed prekey public key', async () => {
    const identity = await generateIdentityKeyPair();
    const spk = await generateSignedPreKey(identity.signing.privateKey, 1);
    const tamperedKey = await generateSignedPreKey(identity.signing.privateKey, 2);

    const isValid = await verifySignedPreKey(
      tamperedKey.publicKey, // different key, original signature
      spk.signature,
      identity.signing.publicKey
    );

    expect(isValid).toBe(false);
  });

  it('generates the requested number of one-time prekeys with sequential ids', async () => {
    const keys = await generateOneTimePreKeys(5, 100);
    expect(keys.length).toBe(5);
    expect(keys.map((k) => k.keyId)).toEqual([100, 101, 102, 103, 104]);
  });

  it('generates unique one-time prekeys', async () => {
    const keys = await generateOneTimePreKeys(10);
    const uniquePublicKeys = new Set(keys.map((k) => Buffer.from(k.publicKey).toString('hex')));
    expect(uniquePublicKeys.size).toBe(10);
  });
});
