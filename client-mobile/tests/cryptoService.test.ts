import { describe, it, expect } from 'vitest';
import {
  generateLocalIdentity,
  buildRegistrationPayload,
  startConversation,
  acceptConversation,
  encryptText,
  decryptText,
  RemotePreKeyBundle,
  WireMessage,
} from '../src/services/cryptoService';

/**
 * Simulates what actually happens between two devices, but entirely
 * in-process: build both identities, shape Bob's into what the server
 * would hand back from GET /users/bob/prekey-bundle, have Alice start a
 * conversation from that, and confirm a real text message round-trips —
 * through the exact functions the app will actually call, including the
 * x3dhInit handshake payload that has to travel with the first message.
 */

function bundleFromLocalIdentity(username: string, local: Awaited<ReturnType<typeof generateLocalIdentity>>): RemotePreKeyBundle {
  const payload = buildRegistrationPayload(username, local);
  return {
    username,
    identitySigningPublicKey: payload.identitySigningPublicKey,
    identityAgreementPublicKey: payload.identityAgreementPublicKey,
    signedPreKey: payload.signedPreKey,
    oneTimePreKey: payload.oneTimePreKeys[0],
  };
}

describe('cryptoService', () => {
  it('generates a registration payload with valid base64 fields', async () => {
    const local = await generateLocalIdentity();
    const payload = buildRegistrationPayload('alice', local);

    expect(payload.username).toBe('alice');
    expect(payload.identitySigningPublicKey.length).toBeGreaterThan(0);
    expect(payload.oneTimePreKeys.length).toBe(100);
    expect(payload.signedPreKey.keyId).toBe(1);
  });

  it('full flow: Alice starts a conversation with Bob and sends a message he decrypts correctly', async () => {
    const alice = await generateLocalIdentity();
    const bob = await generateLocalIdentity();
    const bobBundle = bundleFromLocalIdentity('bob', bob);
    const aliceIdentityAgreementPublicKeyB64 = buildRegistrationPayload('alice', alice).identityAgreementPublicKey;

    // Alice fetches Bob's bundle (simulated) and starts the conversation.
    const started = await startConversation(alice.identity, bobBundle);
    let aliceState = started.state;

    // Alice encrypts her first message, attaching the X3DH handshake info Bob needs.
    const { wireMessage, state: aliceStateAfterSend } = await encryptText(aliceState, 'Hey Bob!');
    aliceState = aliceStateAfterSend;
    const firstMessage: WireMessage = { ...wireMessage, to: 'bob', from: 'alice', x3dhInit: started.x3dhInit };

    // Bob accepts the conversation using Alice's identity key + the x3dhInit payload.
    let bobState = await acceptConversation(
      bob.identity,
      bob.signedPreKey,
      bob.oneTimePreKeys[0],
      aliceIdentityAgreementPublicKeyB64,
      firstMessage.x3dhInit
    );

    const { plaintext, state: bobStateAfterReceive } = await decryptText(bobState, firstMessage);
    bobState = bobStateAfterReceive;

    expect(plaintext).toBe('Hey Bob!');
  });

  it('encryptText/decryptText round-trip across multiple messages once a conversation is established', async () => {
    const alice = await generateLocalIdentity();
    const bob = await generateLocalIdentity();
    const bobBundle = bundleFromLocalIdentity('bob', bob);
    const aliceIdentityAgreementPublicKeyB64 = buildRegistrationPayload('alice', alice).identityAgreementPublicKey;

    const started = await startConversation(alice.identity, bobBundle);
    let aliceState = started.state;

    const send1 = await encryptText(aliceState, 'first message');
    aliceState = send1.state;
    const firstMessage: WireMessage = { ...send1.wireMessage, to: 'bob', from: 'alice', x3dhInit: started.x3dhInit };

    let bobState = await acceptConversation(
      bob.identity,
      bob.signedPreKey,
      bob.oneTimePreKeys[0],
      aliceIdentityAgreementPublicKeyB64,
      firstMessage.x3dhInit
    );

    const recv1 = await decryptText(bobState, firstMessage);
    bobState = recv1.state;
    expect(recv1.plaintext).toBe('first message');

    // Second message doesn't need x3dhInit — the ratchet is already established.
    const send2 = await encryptText(aliceState, 'second message');
    aliceState = send2.state;
    const recv2 = await decryptText(bobState, { ...send2.wireMessage, to: 'bob', from: 'alice' });
    expect(recv2.plaintext).toBe('second message');
  });

  it('throws a clear error if acceptConversation is called without x3dhInit', async () => {
    const bob = await generateLocalIdentity();

    await expect(
      acceptConversation(bob.identity, bob.signedPreKey, bob.oneTimePreKeys[0], 'irrelevant', undefined)
    ).rejects.toThrow(/x3dhInit/);
  });
});
