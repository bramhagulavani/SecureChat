/**
 * Message Cipher
 * --------------
 * Encrypts/decrypts individual message payloads once the Double Ratchet has
 * derived a per-message key. This is the layer that actually touches
 * message content — everything before this point (X3DH, the ratchet) only
 * produces key material.
 *
 * We use XChaCha20-Poly1305 (IETF variant) rather than AES-256-GCM for two
 * practical reasons:
 *
 *   1. It's included in `libsodium-wrappers`' minimal build — no need to
 *      pull in the larger "sumo" build just for AES-GCM (same story as the
 *      HKDF/HMAC situation documented in hkdfBlake2b.ts).
 *   2. Its 24-byte nonce is large enough to generate randomly for every
 *      message with negligible collision risk. AES-GCM's 12-byte nonce is
 *      not — reusing a nonce with the same key catastrophically breaks
 *      AEAD security, so AES-GCM would need a carefully managed counter
 *      across devices, restarts, and clock skew. XChaCha20's nonce space is
 *      big enough that "just use randombytes_buf" is safe.
 *
 * Both are AEAD ciphers with equivalent security guarantees; this is a
 * practical substitution, not a downgrade.
 */

import sodium from 'libsodium-wrappers';

let readyPromise: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready;
  }
  await readyPromise;
}

export interface EncryptedPayload {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Encrypts `plaintext` under `key` (must be exactly 32 bytes — a ratchet
 * message key is the expected input). `associatedData` is authenticated
 * but NOT encrypted: the caller should pass a serialized form of the
 * ratchet header here, so that if anyone tampers with the header in
 * transit (which travels alongside the ciphertext, unencrypted), decryption
 * fails rather than silently accepting a mismatched header.
 */
export async function encryptMessage(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0)
): Promise<EncryptedPayload> {
  await ensureReady();

  if (key.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    throw new Error(
      `encryptMessage: key must be ${sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES} bytes, got ${key.length}`
    );
  }

  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    associatedData,
    null,
    nonce,
    key
  );

  return { ciphertext: new Uint8Array(ciphertext), nonce: new Uint8Array(nonce) };
}

/**
 * Decrypts a payload produced by encryptMessage. Throws if the ciphertext,
 * nonce, key, or associatedData don't all match what was used to encrypt —
 * AEAD authentication means any tampering with any of them causes this to
 * fail loudly rather than returning corrupted plaintext.
 */
export async function decryptMessage(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0)
): Promise<Uint8Array> {
  await ensureReady();

  if (key.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    throw new Error(
      `decryptMessage: key must be ${sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES} bytes, got ${key.length}`
    );
  }

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    associatedData,
    nonce,
    key
  );

  return new Uint8Array(plaintext);
}
