/**
 * Ratchet State
 * -------------
 * Holds everything one party needs to keep sending/receiving encrypted
 * messages with the Double Ratchet after the initial X3DH handshake.
 *
 * Two kinds of key evolution happen here, matching the Signal spec:
 *
 *  - KDF_RK (DH ratchet step): whenever a new DH public key arrives from the
 *    other party, mix a fresh Diffie-Hellman output into the root key,
 *    producing a new root key + a new chain key. This is what gives
 *    post-compromise security — even if a chain key leaked, the next DH
 *    ratchet step "heals" the conversation.
 *
 *  - KDF_CK (symmetric-key ratchet step): every single message advances the
 *    relevant chain key one step, producing a one-time message key and a
 *    new chain key. This is what gives forward secrecy within a chain — a
 *    leaked message key can't be used to derive any other message's key.
 */

import sodium from 'libsodium-wrappers';
import { hkdfBlake2b, keyedBlake2b } from '../encryption/hkdfBlake2b';

export interface DHKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface RatchetState {
  rootKey: Uint8Array;
  dhSelfKeyPair: DHKeyPair;
  dhRemotePublicKey: Uint8Array | null;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendMessageNumber: number;
  receiveMessageNumber: number;
  previousSendingChainLength: number;
}

let readyPromise: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready;
  }
  await readyPromise;
}

/** Generates a fresh X25519 keypair for use as a ratchet DH key. */
export async function generateDHKeyPair(): Promise<DHKeyPair> {
  await ensureReady();
  const keyPair = sodium.crypto_box_keypair();
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

/** Raw Diffie-Hellman: DH(a_priv, B_pub) === DH(b_priv, A_pub). */
export async function diffieHellman(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<Uint8Array> {
  await ensureReady();
  return new Uint8Array(sodium.crypto_scalarmult(privateKey, publicKey));
}

const RK_INFO = new TextEncoder().encode('SecureChat DoubleRatchet RootKey v1');

/**
 * KDF_RK: DH ratchet step. Combines the current root key with a fresh DH
 * output to derive a new root key and a new chain key (sending or
 * receiving, depending on which side of the ratchet just turned).
 */
export async function kdfRootKey(
  rootKey: Uint8Array,
  dhOutput: Uint8Array
): Promise<{ rootKey: Uint8Array; chainKey: Uint8Array }> {
  const output = await hkdfBlake2b(dhOutput, rootKey, RK_INFO, 64);
  return {
    rootKey: output.slice(0, 32),
    chainKey: output.slice(32, 64),
  };
}

// Fixed single-byte inputs, per the Signal spec's KDF_CK construction:
// the message key and the next chain key are each a keyed hash of the
// current chain key with a different constant byte.
const CHAIN_KEY_CONSTANT = new Uint8Array([0x02]);
const MESSAGE_KEY_CONSTANT = new Uint8Array([0x01]);

/**
 * KDF_CK: symmetric-key ratchet step. Advances a chain key by one message,
 * producing a one-time message key and the next chain key. Called once per
 * message sent or received.
 */
export async function kdfChainKey(
  chainKey: Uint8Array
): Promise<{ messageKey: Uint8Array; nextChainKey: Uint8Array }> {
  const [messageKey, nextChainKey] = await Promise.all([
    keyedBlake2b(chainKey, MESSAGE_KEY_CONSTANT, 32),
    keyedBlake2b(chainKey, CHAIN_KEY_CONSTANT, 32),
  ]);
  return { messageKey, nextChainKey };
}
