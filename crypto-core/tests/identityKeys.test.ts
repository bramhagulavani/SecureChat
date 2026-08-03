import { describe, it, expect } from 'vitest';
import {
  generateIdentityKeyPair,
  serializeIdentityKeyPair,
  deserializeIdentityKeyPair,
  signWithIdentityKey,
  verifyIdentitySignature,
} from '../src/keys/identityKeys';

describe('identityKeys', () => {
  it('generates a signing and agreement keypair with correct byte lengths', async () => {
    const keyPair = await generateIdentityKeyPair();
    expect(keyPair.signing.publicKey.length).toBe(32);
    expect(keyPair.signing.privateKey.length).toBe(64);
    expect(keyPair.agreement.publicKey.length).toBe(32);
    expect(keyPair.agreement.privateKey.length).toBe(32);
  });

  it('generates a unique keypair on every call', async () => {
    const a = await generateIdentityKeyPair();
    const b = await generateIdentityKeyPair();
    expect(Buffer.from(a.signing.publicKey).toString('hex')).not.toBe(
      Buffer.from(b.signing.publicKey).toString('hex')
    );
    expect(Buffer.from(a.agreement.publicKey).toString('hex')).not.toBe(
      Buffer.from(b.agreement.publicKey).toString('hex')
    );
  });

  it('serializes and deserializes a keypair without losing data', async () => {
    const original = await generateIdentityKeyPair();
    const serialized = serializeIdentityKeyPair(original);
    const restored = await deserializeIdentityKeyPair(serialized);

    expect(restored.signing.publicKey).toEqual(original.signing.publicKey);
    expect(restored.signing.privateKey).toEqual(original.signing.privateKey);
    expect(restored.agreement.publicKey).toEqual(original.agreement.publicKey);
    expect(restored.agreement.privateKey).toEqual(original.agreement.privateKey);
  });

  it('signs a message and successfully verifies it with the matching public key', async () => {
    const keyPair = await generateIdentityKeyPair();
    const message = new TextEncoder().encode('hello secure world');

    const signature = await signWithIdentityKey(message, keyPair.signing.privateKey);
    const isValid = await verifyIdentitySignature(message, signature, keyPair.signing.publicKey);

    expect(isValid).toBe(true);
  });

  it('rejects verification if the message was tampered with', async () => {
    const keyPair = await generateIdentityKeyPair();
    const message = new TextEncoder().encode('hello secure world');
    const tamperedMessage = new TextEncoder().encode('hello insecure world');

    const signature = await signWithIdentityKey(message, keyPair.signing.privateKey);
    const isValid = await verifyIdentitySignature(
      tamperedMessage,
      signature,
      keyPair.signing.publicKey
    );

    expect(isValid).toBe(false);
  });

  it('rejects verification if the signature was made by a different keypair', async () => {
    const keyPairA = await generateIdentityKeyPair();
    const keyPairB = await generateIdentityKeyPair();
    const message = new TextEncoder().encode('hello secure world');

    const signature = await signWithIdentityKey(message, keyPairA.signing.privateKey);
    const isValid = await verifyIdentitySignature(message, signature, keyPairB.signing.publicKey);

    expect(isValid).toBe(false);
  });
});
