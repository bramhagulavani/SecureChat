/**
 * Crypto Service
 * --------------
 * The bridge between crypto-core (which works entirely in raw bytes) and
 * the rest of the app (which needs to send JSON over HTTP/WebSocket to the
 * relay server). Nothing in here implements any cryptography itself — it's
 * pure wiring: generate keys, shape them into what the server's API
 * expects, and convert between Uint8Array and base64 at the boundary.
 *
 * Screens and other services should go through this file rather than
 * importing crypto-core directly, so there's exactly one place that knows
 * about the wire format.
 */

import {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  initiateX3DH,
  receiveX3DH,
  initializeRatchetAsInitiator,
  initializeRatchetAsResponder,
  encryptSecureMessage,
  decryptSecureMessage,
  IdentityKeyPair,
  SignedPreKeyPair,
  OneTimePreKeyPair,
  PreKeyBundle,
  RatchetState,
} from '@securechat/crypto-core';
import { bytesToBase64, base64ToBytes } from './base64';

/** Everything a client needs to hang onto locally after generating a fresh identity. */
export interface LocalIdentity {
  identity: IdentityKeyPair;
  signedPreKey: SignedPreKeyPair;
  oneTimePreKeys: OneTimePreKeyPair[];
}

/** Matches the JSON body server/src/api/users.routes.ts expects for POST /users/register. */
export interface RegistrationPayload {
  username: string;
  identitySigningPublicKey: string;
  identityAgreementPublicKey: string;
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKeys: { keyId: number; publicKey: string }[];
}

/** Matches the JSON shape server/src/store/userStore.ts returns from GET /users/:username/prekey-bundle. */
export interface RemotePreKeyBundle {
  username: string;
  identitySigningPublicKey: string;
  identityAgreementPublicKey: string;
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKey?: { keyId: number; publicKey: string };
}

/** Matches the JSON shape server/src/ws/messageRouter.ts sends/expects over the WebSocket. */
export interface WireMessage {
  to?: string;
  from?: string;
  header: { dhPublicKey: string; messageNumber: number; previousChainLength: number };
  ciphertext: string;
  nonce: string;
  /**
   * Only present on the very first message of a new conversation. Carries
   * what the recipient needs to run the receiving side of X3DH — their own
   * ratchet header key (above) is a *different* key, generated independently
   * by the Double Ratchet, and isn't sufficient on its own.
   */
  x3dhInit?: {
    ephemeralPublicKey: string;
    signedPreKeyId: number;
    oneTimePreKeyId?: number;
  };
}

/** What the caller needs to complete X3DH setup: the ratchet state, plus what to attach to the first message. */
export interface StartConversationResult {
  state: RatchetState;
  x3dhInit: {
    ephemeralPublicKey: string;
    signedPreKeyId: number;
    oneTimePreKeyId?: number;
  };
}

const DEFAULT_ONE_TIME_PREKEY_COUNT = 100;

/**
 * Generates a brand-new identity for first-time registration: identity
 * keypair, one signed prekey, and a batch of one-time prekeys. Call this
 * exactly once per account — the caller is responsible for persisting the
 * result (see storageService, coming next) before it's lost.
 */
export async function generateLocalIdentity(): Promise<LocalIdentity> {
  const identity = await generateIdentityKeyPair();
  const signedPreKey = await generateSignedPreKey(identity.signing.privateKey, 1);
  const oneTimePreKeys = await generateOneTimePreKeys(DEFAULT_ONE_TIME_PREKEY_COUNT, 1);

  return { identity, signedPreKey, oneTimePreKeys };
}

/** Shapes a freshly generated identity into the JSON body the registration endpoint expects. */
export function buildRegistrationPayload(username: string, local: LocalIdentity): RegistrationPayload {
  return {
    username,
    identitySigningPublicKey: bytesToBase64(local.identity.signing.publicKey),
    identityAgreementPublicKey: bytesToBase64(local.identity.agreement.publicKey),
    signedPreKey: {
      keyId: local.signedPreKey.keyId,
      publicKey: bytesToBase64(local.signedPreKey.publicKey),
      signature: bytesToBase64(local.signedPreKey.signature),
    },
    oneTimePreKeys: local.oneTimePreKeys.map((k) => ({
      keyId: k.keyId,
      publicKey: bytesToBase64(k.publicKey),
    })),
  };
}

/**
 * Starts a new conversation as the initiator ("Alice"): runs X3DH against a
 * bundle fetched from the server, then sets up the Double Ratchet. Returns
 * the ratchet state to persist and use for every message in this
 * conversation, plus the X3DH handshake info that MUST be attached to the
 * first message sent (see WireMessage.x3dhInit) — without it, the
 * recipient has no way to derive the matching shared secret.
 */
export async function startConversation(
  myIdentity: IdentityKeyPair,
  theirBundle: RemotePreKeyBundle
): Promise<StartConversationResult> {
  const bundle: PreKeyBundle = {
    identitySigningPublicKey: base64ToBytes(theirBundle.identitySigningPublicKey),
    identityAgreementPublicKey: base64ToBytes(theirBundle.identityAgreementPublicKey),
    signedPreKeyId: theirBundle.signedPreKey.keyId,
    signedPreKeyPublicKey: base64ToBytes(theirBundle.signedPreKey.publicKey),
    signedPreKeySignature: base64ToBytes(theirBundle.signedPreKey.signature),
    ...(theirBundle.oneTimePreKey && {
      oneTimePreKeyId: theirBundle.oneTimePreKey.keyId,
      oneTimePreKeyPublicKey: base64ToBytes(theirBundle.oneTimePreKey.publicKey),
    }),
  };

  const x3dhResult = await initiateX3DH(
    { publicKey: myIdentity.agreement.publicKey, privateKey: myIdentity.agreement.privateKey },
    bundle
  );

  const state = await initializeRatchetAsInitiator(x3dhResult.sharedSecret, bundle.signedPreKeyPublicKey);

  return {
    state,
    x3dhInit: {
      ephemeralPublicKey: bytesToBase64(x3dhResult.ephemeralPublicKey),
      signedPreKeyId: x3dhResult.usedSignedPreKeyId,
      oneTimePreKeyId: x3dhResult.usedOneTimePreKeyId,
    },
  };
}

/**
 * Accepts an incoming conversation as the responder ("Bob"): runs the
 * receiving side of X3DH using the sender's identity key and the X3DH
 * ephemeral key from their first message's `x3dhInit` field (NOT the
 * ratchet header's dhPublicKey — that's a separate key), then sets up the
 * Double Ratchet.
 */
export async function acceptConversation(
  myIdentity: IdentityKeyPair,
  mySignedPreKey: SignedPreKeyPair,
  myOneTimePreKey: OneTimePreKeyPair | undefined,
  theirIdentityAgreementPublicKeyB64: string,
  x3dhInit: WireMessage['x3dhInit']
): Promise<RatchetState> {
  if (!x3dhInit) {
    throw new Error('acceptConversation: first message is missing x3dhInit — cannot complete handshake');
  }

  const sharedSecret = await receiveX3DH(
    { publicKey: myIdentity.agreement.publicKey, privateKey: myIdentity.agreement.privateKey },
    { publicKey: mySignedPreKey.publicKey, privateKey: mySignedPreKey.privateKey },
    myOneTimePreKey
      ? { publicKey: myOneTimePreKey.publicKey, privateKey: myOneTimePreKey.privateKey }
      : undefined,
    base64ToBytes(theirIdentityAgreementPublicKeyB64),
    base64ToBytes(x3dhInit.ephemeralPublicKey)
  );

  return initializeRatchetAsResponder(sharedSecret, {
    publicKey: mySignedPreKey.publicKey,
    privateKey: mySignedPreKey.privateKey,
  });
}

/** Encrypts a plaintext string and returns the wire-ready JSON shape plus the advanced ratchet state. */
export async function encryptText(
  state: RatchetState,
  plaintext: string
): Promise<{ wireMessage: Omit<WireMessage, 'to' | 'from'>; state: RatchetState }> {
  const { message, state: newState } = await encryptSecureMessage(
    state,
    new TextEncoder().encode(plaintext)
  );

  return {
    wireMessage: {
      header: {
        dhPublicKey: bytesToBase64(message.header.dhPublicKey),
        messageNumber: message.header.messageNumber,
        previousChainLength: message.header.previousChainLength,
      },
      ciphertext: bytesToBase64(message.ciphertext),
      nonce: bytesToBase64(message.nonce),
    },
    state: newState,
  };
}

/** Decrypts a message received over the wire and returns the plaintext plus the advanced ratchet state. */
export async function decryptText(
  state: RatchetState,
  wireMessage: WireMessage
): Promise<{ plaintext: string; state: RatchetState }> {
  const { plaintext, state: newState } = await decryptSecureMessage(state, {
    header: {
      dhPublicKey: base64ToBytes(wireMessage.header.dhPublicKey),
      messageNumber: wireMessage.header.messageNumber,
      previousChainLength: wireMessage.header.previousChainLength,
    },
    ciphertext: base64ToBytes(wireMessage.ciphertext),
    nonce: base64ToBytes(wireMessage.nonce),
  });

  return { plaintext: new TextDecoder().decode(plaintext), state: newState };
}
