/**
 * Secure Message
 * --------------
 * Glues the Double Ratchet (key evolution) and the message cipher (AEAD
 * encryption) together into the two functions an application actually
 * calls: encrypt a plaintext message, or decrypt one that arrived.
 *
 * The ratchet header is serialized and passed as AEAD associated data, so
 * the header — which necessarily travels in the clear alongside the
 * ciphertext, since the recipient needs it before they can even derive the
 * right message key — is cryptographically bound to the ciphertext. Any
 * tampering with the header (e.g. swapping in a different DH public key)
 * causes decryption to fail rather than silently being accepted.
 */

import { RatchetState, RatchetHeader, ratchetEncrypt, ratchetDecrypt } from '../ratchet/doubleRatchet';
import { encryptMessage, decryptMessage } from '../encryption/messageCipher';

export interface SecureMessage {
  header: RatchetHeader;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export interface EncryptResult {
  message: SecureMessage;
  state: RatchetState;
}

export interface DecryptResult {
  plaintext: Uint8Array;
  state: RatchetState;
}

/**
 * Deterministically serializes a ratchet header into bytes, for use as AEAD
 * associated data. Both sender and receiver compute this independently from
 * the same header fields, so it must stay byte-for-byte stable.
 */
function serializeHeader(header: RatchetHeader): Uint8Array {
  const out = new Uint8Array(header.dhPublicKey.length + 8);
  out.set(header.dhPublicKey, 0);
  const view = new DataView(out.buffer, out.byteOffset + header.dhPublicKey.length, 8);
  view.setUint32(0, header.messageNumber, false);
  view.setUint32(4, header.previousChainLength, false);
  return out;
}

/**
 * Encrypts a plaintext message: advances the sender's ratchet by one step
 * to get a fresh message key, then seals the plaintext under that key with
 * the header bound in as associated data.
 */
export async function encryptSecureMessage(
  state: RatchetState,
  plaintext: Uint8Array
): Promise<EncryptResult> {
  const { header, messageKey, state: newState } = await ratchetEncrypt(state);
  const associatedData = serializeHeader(header);
  const { ciphertext, nonce } = await encryptMessage(messageKey, plaintext, associatedData);

  return {
    message: { header, ciphertext, nonce },
    state: newState,
  };
}

/**
 * Decrypts a received message: advances the receiver's ratchet using the
 * message's header (running a DH ratchet step first if needed) to recover
 * the matching message key, then opens the ciphertext. Throws if the
 * ciphertext, nonce, or header were tampered with, or if the ratchet
 * doesn't have a valid receiving chain for this header (e.g. out-of-order
 * delivery — see doubleRatchet.ts's documented limitation).
 */
export async function decryptSecureMessage(
  state: RatchetState,
  message: SecureMessage
): Promise<DecryptResult> {
  const { messageKey, state: newState } = await ratchetDecrypt(state, message.header);
  const associatedData = serializeHeader(message.header);
  const plaintext = await decryptMessage(messageKey, message.ciphertext, message.nonce, associatedData);

  return { plaintext, state: newState };
}
