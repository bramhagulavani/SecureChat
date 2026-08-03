/**
 * Identity Keys
 * -------------
 * Every user has a long-term "identity" made of two keypairs:
 *   - signing:   Ed25519 keypair, used to sign prekeys and verify identity (authentication).
 *   - agreement: X25519 keypair, used for Diffie-Hellman key agreement (X3DH, ratchet steps).
 *
 * We deliberately use two separate keypairs instead of one dual-purpose key.
 * This is simpler and safer to reason about than XEdDSA-style key reuse,
 * at the cost of a slightly larger identity bundle. For a real-world MVP,
 * clarity and auditability win over the extra ~32 bytes.
 *
 * No cryptographic primitive here is custom-built — everything is delegated
 * to libsodium, which wraps well-audited, battle-tested implementations.
 */

import sodium from 'libsodium-wrappers';

export interface IdentityKeyPair {
  signing: {
    publicKey: Uint8Array; // 32 bytes
    privateKey: Uint8Array; // 64 bytes (libsodium convention: seed + public key)
  };
  agreement: {
    publicKey: Uint8Array; // 32 bytes
    privateKey: Uint8Array; // 32 bytes
  };
}

export interface SerializedIdentityKeyPair {
  signing: { publicKey: string; privateKey: string };
  agreement: { publicKey: string; privateKey: string };
}

let readyPromise: Promise<void> | null = null;

/** Ensures libsodium's WASM module is loaded before any crypto call. */
async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready;
  }
  await readyPromise;
}

/**
 * Generates a brand-new identity keypair for a user.
 * This should be called once per user, at account creation time,
 * and the private keys must never leave the user's device unencrypted.
 */
export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  await ensureReady();

  const signingKeyPair = sodium.crypto_sign_keypair();
  const agreementKeyPair = sodium.crypto_box_keypair();

  return {
    signing: {
      publicKey: signingKeyPair.publicKey,
      privateKey: signingKeyPair.privateKey,
    },
    agreement: {
      publicKey: agreementKeyPair.publicKey,
      privateKey: agreementKeyPair.privateKey,
    },
  };
}

/** Converts raw key bytes into base64 strings for storage/transmission. */
export function serializeIdentityKeyPair(
  keyPair: IdentityKeyPair
): SerializedIdentityKeyPair {
  return {
    signing: {
      publicKey: sodium.to_base64(keyPair.signing.publicKey),
      privateKey: sodium.to_base64(keyPair.signing.privateKey),
    },
    agreement: {
      publicKey: sodium.to_base64(keyPair.agreement.publicKey),
      privateKey: sodium.to_base64(keyPair.agreement.privateKey),
    },
  };
}

/** Restores a keypair from its serialized (base64) form. */
export async function deserializeIdentityKeyPair(
  serialized: SerializedIdentityKeyPair
): Promise<IdentityKeyPair> {
  await ensureReady();
  return {
    signing: {
      publicKey: sodium.from_base64(serialized.signing.publicKey),
      privateKey: sodium.from_base64(serialized.signing.privateKey),
    },
    agreement: {
      publicKey: sodium.from_base64(serialized.agreement.publicKey),
      privateKey: sodium.from_base64(serialized.agreement.privateKey),
    },
  };
}

/** Signs an arbitrary message with the identity signing key (e.g. to sign a prekey bundle). */
export async function signWithIdentityKey(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  await ensureReady();
  return sodium.crypto_sign_detached(message, privateKey);
}

/** Verifies a signature produced by signWithIdentityKey. */
export async function verifyIdentitySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  await ensureReady();
  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}
