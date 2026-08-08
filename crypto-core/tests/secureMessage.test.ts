import { describe, it, expect } from 'vitest';
import { generateIdentityKeyPair } from '../src/keys/identityKeys';
import { generateSignedPreKey } from '../src/keys/prekeys';
import { initiateX3DH, receiveX3DH, PreKeyBundle } from '../src/x3dh/x3dh';
import {
  initializeRatchetAsInitiator,
  initializeRatchetAsResponder,
  RatchetState,
} from '../src/ratchet/doubleRatchet';
import { encryptSecureMessage, decryptSecureMessage } from '../src/messaging/secureMessage';

/**
 * Runs the full handshake (X3DH -> ratchet init) that a real client would
 * do, and returns both parties ready to exchange actual messages. This is
 * the complete pipeline: identity keys -> prekeys -> X3DH -> Double Ratchet.
 */
async function setupConversation(): Promise<{ alice: RatchetState; bob: RatchetState }> {
  const aliceIdentity = await generateIdentityKeyPair();
  const bobIdentity = await generateIdentityKeyPair();
  const bobSignedPreKey = await generateSignedPreKey(bobIdentity.signing.privateKey, 1);

  const bobBundle: PreKeyBundle = {
    identitySigningPublicKey: bobIdentity.signing.publicKey,
    identityAgreementPublicKey: bobIdentity.agreement.publicKey,
    signedPreKeyId: bobSignedPreKey.keyId,
    signedPreKeyPublicKey: bobSignedPreKey.publicKey,
    signedPreKeySignature: bobSignedPreKey.signature,
  };

  const x3dhResult = await initiateX3DH(
    { publicKey: aliceIdentity.agreement.publicKey, privateKey: aliceIdentity.agreement.privateKey },
    bobBundle
  );

  const bobSharedSecret = await receiveX3DH(
    { publicKey: bobIdentity.agreement.publicKey, privateKey: bobIdentity.agreement.privateKey },
    { publicKey: bobSignedPreKey.publicKey, privateKey: bobSignedPreKey.privateKey },
    undefined,
    aliceIdentity.agreement.publicKey,
    x3dhResult.ephemeralPublicKey
  );

  const alice = await initializeRatchetAsInitiator(x3dhResult.sharedSecret, bobSignedPreKey.publicKey);
  const bob = initializeRatchetAsResponder(bobSharedSecret, {
    publicKey: bobSignedPreKey.publicKey,
    privateKey: bobSignedPreKey.privateKey,
  });

  return { alice, bob };
}

describe('Secure Message (full pipeline: X3DH -> Double Ratchet -> AEAD)', () => {
  it('Alice sends a real text message and Bob decrypts the exact same text', async () => {
    const { alice, bob } = await setupConversation();

    const plaintext = new TextEncoder().encode('Hey Bob, this message is end-to-end encrypted!');
    const { message, state: aliceState } = await encryptSecureMessage(alice, plaintext);
    const { plaintext: decrypted, state: bobState } = await decryptSecureMessage(bob, message);

    expect(new TextDecoder().decode(decrypted)).toBe('Hey Bob, this message is end-to-end encrypted!');
    expect(aliceState.sendMessageNumber).toBe(1);
    expect(bobState.receiveMessageNumber).toBe(1);
  });

  it('carries on a back-and-forth conversation across multiple messages and a direction flip', async () => {
    const { alice, bob } = await setupConversation();
    let aliceState = alice;
    let bobState = bob;

    const send = async (from: RatchetState, text: string) => {
      const { message, state } = await encryptSecureMessage(from, new TextEncoder().encode(text));
      return { message, state };
    };

    // Alice -> Bob
    const m1 = await send(aliceState, 'Hi Bob');
    aliceState = m1.state;
    const r1 = await decryptSecureMessage(bobState, m1.message);
    bobState = r1.state;
    expect(new TextDecoder().decode(r1.plaintext)).toBe('Hi Bob');

    // Alice -> Bob again
    const m2 = await send(aliceState, 'Still me');
    aliceState = m2.state;
    const r2 = await decryptSecureMessage(bobState, m2.message);
    bobState = r2.state;
    expect(new TextDecoder().decode(r2.plaintext)).toBe('Still me');

    // Bob -> Alice (flips the ratchet direction)
    const m3 = await send(bobState, 'Hey Alice, got your messages');
    bobState = m3.state;
    const r3 = await decryptSecureMessage(aliceState, m3.message);
    aliceState = r3.state;
    expect(new TextDecoder().decode(r3.plaintext)).toBe('Hey Alice, got your messages');

    // Alice -> Bob, on the new ratchet
    const m4 = await send(aliceState, 'Great, talk soon');
    aliceState = m4.state;
    const r4 = await decryptSecureMessage(bobState, m4.message);
    bobState = r4.state;
    expect(new TextDecoder().decode(r4.plaintext)).toBe('Great, talk soon');
  });

  it('fails to decrypt if the ciphertext was tampered with in transit', async () => {
    const { alice, bob } = await setupConversation();

    const { message } = await encryptSecureMessage(alice, new TextEncoder().encode('original message'));
    const tamperedMessage = {
      ...message,
      ciphertext: (() => {
        const copy = new Uint8Array(message.ciphertext);
        copy[0] ^= 0xff;
        return copy;
      })(),
    };

    await expect(decryptSecureMessage(bob, tamperedMessage)).rejects.toThrow();
  });

  it('fails to decrypt if the header was tampered with (associated-data binding works)', async () => {
    const { alice, bob } = await setupConversation();

    const { message } = await encryptSecureMessage(alice, new TextEncoder().encode('trust this header'));
    const tamperedMessage = {
      ...message,
      header: { ...message.header, messageNumber: message.header.messageNumber + 5 },
    };

    await expect(decryptSecureMessage(bob, tamperedMessage)).rejects.toThrow();
  });
});
