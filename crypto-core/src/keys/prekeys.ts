/**
 * Prekeys
 * -------
 * X3DH needs each user to publish key material to the server *ahead of time*,
 * so someone can start an encrypted conversation with them even while they're
 * offline. Two kinds:
 *
 *  - Signed Prekey (SPK): a medium-term X25519 keypair, rotated periodically
 *    (e.g. weekly). Published along with a signature (made with the user's
 *    identity *signing* key) so a malicious server can't swap in its own key
 *    and MITM the handshake.
 *
 *  - One-Time Prekeys (OPK): a batch of single-use X25519 keypairs. The server
 *    hands one out per incoming handshake request and then discards it. This
 *    adds forward secrecy to the very first message, even before the Double
 *    Ratchet has had a chance to run. Running low on OPKs on the server means
 *    the client should generate and upload more.
 */

import sodium from 'libsodium-wrappers';
import { signWithIdentityKey, verifyIdentitySignature } from './identityKeys';

export interface SignedPreKeyPair {
  keyId: number;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  signature: Uint8Array; // signature over publicKey, made with the identity signing key
}

export interface OneTimePreKeyPair {
  keyId: number;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

let readyPromise: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready;
  }
  await readyPromise;
}

/**
 * Generates a new signed prekey, signed by the caller's identity signing key.
 * `keyId` should be a monotonically increasing id chosen by the caller, so
 * clients/servers can reference which prekey a handshake used.
 */
export async function generateSignedPreKey(
  identitySigningPrivateKey: Uint8Array,
  keyId: number
): Promise<SignedPreKeyPair> {
  await ensureReady();

  const keyPair = sodium.crypto_box_keypair();
  const signature = await signWithIdentityKey(keyPair.publicKey, identitySigningPrivateKey);

  return {
    keyId,
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    signature,
  };
}

/**
 * Verifies that a signed prekey's public key was actually signed by the
 * claimed identity. Any client receiving a prekey bundle from the server
 * MUST call this before using the prekey — it's what prevents a compromised
 * or malicious server from substituting its own key into the handshake.
 */
export async function verifySignedPreKey(
  signedPreKeyPublicKey: Uint8Array,
  signature: Uint8Array,
  identitySigningPublicKey: Uint8Array
): Promise<boolean> {
  return verifyIdentitySignature(signedPreKeyPublicKey, signature, identitySigningPublicKey);
}

/**
 * Generates a batch of one-time prekeys, with sequential ids starting at
 * `startId`. Typical usage: generate ~100 at account creation / whenever the
 * server reports the pool is running low, and upload the public halves.
 */
export async function generateOneTimePreKeys(
  count: number,
  startId: number = 0
): Promise<OneTimePreKeyPair[]> {
  await ensureReady();

  const keys: OneTimePreKeyPair[] = [];
  for (let i = 0; i < count; i++) {
    const keyPair = sodium.crypto_box_keypair();
    keys.push({
      keyId: startId + i,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    });
  }
  return keys;
}
