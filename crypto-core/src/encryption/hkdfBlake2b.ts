/**
 * HKDF-BLAKE2b
 * -------------
 * Raw Diffie-Hellman output is NOT safe to use directly as an encryption
 * key — it can have structure/bias. HKDF takes that raw material and derives
 * clean, uniformly-random key bytes from it. X3DH and the Double Ratchet
 * both rely on this.
 *
 * HKDF (RFC 5869) is defined generically over any HMAC-compatible hash — it
 * doesn't have to be SHA-256. We use BLAKE2b via libsodium's
 * `crypto_generichash` in keyed mode as the underlying PRF, because
 * `libsodium-wrappers` ships a size-reduced build that excludes
 * `crypto_auth_hmacsha256` (that function only exists in the larger "sumo"
 * build). Keyed BLAKE2b is libsodium's own recommended HMAC-equivalent
 * construction, so this is standard practice, not an improvised primitive —
 * still nothing hand-rolled at the cipher level.
 */

import sodium from 'libsodium-wrappers';

let readyPromise: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready;
  }
  await readyPromise;
}

const HASH_LEN = 32; // BLAKE2b output size we standardize on (well within its 16-64 byte keyed range)

// Local alias: sodium's typings return Uint8Array<ArrayBufferLike>, which recent
// TypeScript lib versions treat as distinct from the default Uint8Array<ArrayBuffer>.
// We work in this looser type internally and only normalize at the public boundary,
// rather than fighting the type checker on every intermediate variable.
type Bytes = Uint8Array<ArrayBufferLike>;

/** Keyed BLAKE2b, used here as the HMAC-equivalent PRF. `key` must be 16-64 bytes. */
function prf(key: Bytes, message: Bytes): Bytes {
  return sodium.crypto_generichash(HASH_LEN, message, key);
}

/** HKDF-Extract: condenses (possibly non-uniform) input keying material into a fixed-length pseudorandom key. */
function extract(salt: Bytes, ikm: Bytes): Bytes {
  return prf(salt, ikm);
}

/** HKDF-Expand: stretches the pseudorandom key into `length` bytes of output keying material, bound to `info`. */
function expand(prk: Bytes, info: Bytes, length: number): Uint8Array {
  const blocksNeeded = Math.ceil(length / HASH_LEN);
  if (blocksNeeded > 255) {
    throw new Error('HKDF: requested length too large');
  }

  let previousBlock: Bytes = new Uint8Array(0);
  const output = new Uint8Array(blocksNeeded * HASH_LEN);

  for (let i = 0; i < blocksNeeded; i++) {
    const input: Bytes = new Uint8Array(previousBlock.length + info.length + 1);
    input.set(previousBlock, 0);
    input.set(info, previousBlock.length);
    input[input.length - 1] = i + 1;

    const block = prf(prk, input);
    output.set(block, i * HASH_LEN);
    previousBlock = block;
  }

  return new Uint8Array(output.slice(0, length));
}

/**
 * Runs full HKDF-BLAKE2b: Extract then Expand.
 * @param ikm    Input keying material (e.g. concatenated raw DH outputs)
 * @param salt   Optional salt. Must be 16-64 bytes (BLAKE2b keyed-mode key size range).
 *               Defaults to a 32-byte zero string when none is specified.
 * @param info   Context/application-specific info, binds the derived key to its purpose. Defaults to empty.
 * @param length Desired output length in bytes. Defaults to 32 - enough for a symmetric key.
 */
export async function hkdfBlake2b(
  ikm: Uint8Array,
  salt: Uint8Array = new Uint8Array(HASH_LEN),
  info: Uint8Array = new Uint8Array(0),
  length: number = 32
): Promise<Uint8Array> {
  await ensureReady();
  const prk = extract(salt, ikm);
  return expand(prk, info, length);
}

/**
 * Exposes the raw keyed-BLAKE2b PRF directly (not the full HKDF construction).
 * Used by the Double Ratchet's symmetric-key ratchet (KDF_CK), which per the
 * Signal spec derives each step from a single keyed-hash call with a fixed
 * constant byte, not a full HKDF pass. `key` must be 16-64 bytes.
 */
export async function keyedBlake2b(
  key: Uint8Array,
  message: Uint8Array,
  outputLength: number = HASH_LEN
): Promise<Uint8Array> {
  await ensureReady();
  return new Uint8Array(sodium.crypto_generichash(outputLength, message, key));
}
