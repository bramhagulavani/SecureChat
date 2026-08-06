/**
 * X3DH (Extended Triple Diffie-Hellman)
 * --------------------------------------
 * Lets two users establish a shared secret the very first time they talk —
 * including when the recipient is offline — by combining several
 * Diffie-Hellman operations over key material the recipient published in
 * advance (see prekeys.ts).
 *
 * Roles:
 *   - Initiator ("Alice"): wants to start a conversation. Fetches Bob's
 *     prekey bundle from the server and runs `initiateX3DH`.
 *   - Recipient ("Bob"): published the bundle earlier. When Alice's first
 *     message arrives (carrying her identity key + a fresh ephemeral key),
 *     Bob runs `receiveX3DH` to arrive at the *same* shared secret.
 *
 * The four DH computations (mirrored on each side):
 *   DH1 = DH(IK_a,  SPK_b)   DH2 = DH(EK_a, IK_b)
 *   DH3 = DH(EK_a,  SPK_b)   DH4 = DH(EK_a, OPK_b)   [only if a one-time prekey was used]
 *
 * IK = identity (agreement) key, SPK = signed prekey, EK = ephemeral key,
 * OPK = one-time prekey. Subscript a = Alice (initiator), b = Bob (recipient).
 *
 * Because DH(x_priv, Y_pub) === DH(y_priv, X_pub) for Diffie-Hellman, Alice
 * and Bob each compute the same four raw secrets from opposite sides, then
 * feed them through HKDF to derive an identical shared secret.
 *
 * The shared secret produced here becomes the root key that seeds the
 * Double Ratchet (implemented separately).
 */

import sodium from 'libsodium-wrappers';
import { hkdfBlake2b } from '../encryption/hkdfBlake2b';
import { verifySignedPreKey } from '../keys/prekeys';

export interface PreKeyBundle {
  identitySigningPublicKey: Uint8Array;
  identityAgreementPublicKey: Uint8Array;
  signedPreKeyId: number;
  signedPreKeyPublicKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  oneTimePreKeyId?: number;
  oneTimePreKeyPublicKey?: Uint8Array;
}

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface X3DHInitiatorResult {
  sharedSecret: Uint8Array;
  ephemeralPublicKey: Uint8Array; // send this to the recipient alongside the first message
  usedSignedPreKeyId: number;
  usedOneTimePreKeyId?: number;
}

const HKDF_INFO = new TextEncoder().encode('SecureChat X3DH v1');
// A 32-byte 0xFF prefix, per the X3DH spec, included in the KDF input for
// domain separation from any protocol that might reuse these keys for
// signing (we don't, since identity/agreement keys are already split — see
// identityKeys.ts — but we keep this for spec fidelity and future-proofing).
const F_PREFIX = new Uint8Array(32).fill(0xff);

let readyPromise: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready;
  }
  await readyPromise;
}

function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return sodium.crypto_scalarmult(privateKey, publicKey);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Run by the party starting the conversation ("Alice"). Requires Bob's
 * published prekey bundle (fetched from the server) and Alice's own
 * long-term identity (agreement) keypair.
 *
 * Throws if the signed prekey's signature doesn't verify against the
 * claimed identity — this is the check that prevents a malicious or
 * compromised server from substituting its own prekey into the handshake.
 */
export async function initiateX3DH(
  initiatorIdentityKeyPair: KeyPair,
  recipientBundle: PreKeyBundle
): Promise<X3DHInitiatorResult> {
  await ensureReady();

  const signatureValid = await verifySignedPreKey(
    recipientBundle.signedPreKeyPublicKey,
    recipientBundle.signedPreKeySignature,
    recipientBundle.identitySigningPublicKey
  );
  if (!signatureValid) {
    throw new Error(
      'X3DH: signed prekey signature verification failed — refusing to proceed (possible MITM)'
    );
  }

  const ephemeralKeyPair = sodium.crypto_box_keypair();

  const dh1 = dh(initiatorIdentityKeyPair.privateKey, recipientBundle.signedPreKeyPublicKey);
  const dh2 = dh(ephemeralKeyPair.privateKey, recipientBundle.identityAgreementPublicKey);
  const dh3 = dh(ephemeralKeyPair.privateKey, recipientBundle.signedPreKeyPublicKey);

  const dhOutputs = [dh1, dh2, dh3];
  if (recipientBundle.oneTimePreKeyPublicKey) {
    const dh4 = dh(ephemeralKeyPair.privateKey, recipientBundle.oneTimePreKeyPublicKey);
    dhOutputs.push(dh4);
  }

  const ikm = concatBytes(F_PREFIX, ...dhOutputs);
  const sharedSecret = await hkdfBlake2b(ikm, undefined, HKDF_INFO, 32);

  return {
    sharedSecret,
    ephemeralPublicKey: ephemeralKeyPair.publicKey,
    usedSignedPreKeyId: recipientBundle.signedPreKeyId,
    usedOneTimePreKeyId: recipientBundle.oneTimePreKeyId,
  };
}

/**
 * Run by the party who published the prekey bundle ("Bob"), once Alice's
 * first message arrives carrying her identity public key and the ephemeral
 * public key she generated. Bob supplies the private halves of whichever
 * signed prekey (and, if used, one-time prekey) the message references.
 *
 * Produces the same sharedSecret Alice computed in initiateX3DH, provided
 * both sides used matching key material.
 */
export async function receiveX3DH(
  recipientIdentityKeyPair: KeyPair,
  recipientSignedPreKeyPair: KeyPair,
  recipientOneTimePreKeyPair: KeyPair | undefined,
  initiatorIdentityAgreementPublicKey: Uint8Array,
  initiatorEphemeralPublicKey: Uint8Array
): Promise<Uint8Array> {
  await ensureReady();

  const dh1 = dh(recipientSignedPreKeyPair.privateKey, initiatorIdentityAgreementPublicKey);
  const dh2 = dh(recipientIdentityKeyPair.privateKey, initiatorEphemeralPublicKey);
  const dh3 = dh(recipientSignedPreKeyPair.privateKey, initiatorEphemeralPublicKey);

  const dhOutputs = [dh1, dh2, dh3];
  if (recipientOneTimePreKeyPair) {
    const dh4 = dh(recipientOneTimePreKeyPair.privateKey, initiatorEphemeralPublicKey);
    dhOutputs.push(dh4);
  }

  const ikm = concatBytes(F_PREFIX, ...dhOutputs);
  return hkdfBlake2b(ikm, undefined, HKDF_INFO, 32);
}
