/**
 * Double Ratchet
 * --------------
 * Takes the shared secret from X3DH and turns it into an ever-evolving
 * stream of per-message keys, in both directions, for the lifetime of a
 * conversation.
 *
 * This module produces *message keys* - one-time symmetric keys, one per
 * message. It does not perform the actual AEAD encryption/decryption of
 * message content; that's a thin layer on top (coming next, in
 * `encryption/`), which will take a message key from here and use it with
 * AES-256-GCM or ChaCha20-Poly1305 to seal the plaintext. Separating the two
 * keeps the ratchet's state machine easy to test and reason about in
 * isolation.
 *
 * Roles, mirroring x3dh.ts:
 *   - Alice ("initiator") calls `initializeRatchetAsInitiator` right after
 *     `initiateX3DH`, using Bob's signed-prekey public key as the initial
 *     remote DH key.
 *   - Bob ("responder") calls `initializeRatchetAsResponder` right after
 *     `receiveX3DH`, using the same signed-prekey keypair he already has.
 *
 * Known limitation (documented, not silently swallowed): this
 * implementation assumes messages arrive in order within a chain and does
 * not yet store skipped message keys for out-of-order delivery. Real-world
 * transport can reorder messages, so that's flagged as follow-up work
 * before this goes into the actual messaging pipeline.
 */

import {
  DHKeyPair,
  RatchetState,
  generateDHKeyPair,
  diffieHellman,
  kdfRootKey,
  kdfChainKey,
} from './ratchetState';

export type { RatchetState, DHKeyPair } from './ratchetState';

export interface RatchetHeader {
  dhPublicKey: Uint8Array;
  messageNumber: number;
  previousChainLength: number;
}

export interface RatchetSendResult {
  header: RatchetHeader;
  messageKey: Uint8Array;
  state: RatchetState;
}

export interface RatchetReceiveResult {
  messageKey: Uint8Array;
  state: RatchetState;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Alice's side: called immediately after `initiateX3DH`. Generates a fresh
 * DH keypair and does the first DH ratchet step right away, so she has a
 * sending chain ready before she's received anything back from Bob.
 *
 * @param sharedSecret       The 32-byte output of initiateX3DH.
 * @param remoteDHPublicKey  Bob's signed-prekey public key (the same one used in X3DH).
 */
export async function initializeRatchetAsInitiator(
  sharedSecret: Uint8Array,
  remoteDHPublicKey: Uint8Array
): Promise<RatchetState> {
  const selfKeyPair = await generateDHKeyPair();
  const dhOutput = await diffieHellman(selfKeyPair.privateKey, remoteDHPublicKey);
  const { rootKey, chainKey: sendingChainKey } = await kdfRootKey(sharedSecret, dhOutput);

  return {
    rootKey,
    dhSelfKeyPair: selfKeyPair,
    dhRemotePublicKey: remoteDHPublicKey,
    sendingChainKey,
    receivingChainKey: null,
    sendMessageNumber: 0,
    receiveMessageNumber: 0,
    previousSendingChainLength: 0,
  };
}

/**
 * Bob's side: called immediately after `receiveX3DH`. Bob doesn't yet know
 * Alice's ratchet DH key, so no chains exist until her first message
 * arrives and triggers a DH ratchet step in `ratchetDecrypt`.
 *
 * @param sharedSecret  The 32-byte output of receiveX3DH.
 * @param selfKeyPair   Bob's existing signed-prekey keypair (reused as his first ratchet key).
 */
export function initializeRatchetAsResponder(
  sharedSecret: Uint8Array,
  selfKeyPair: DHKeyPair
): RatchetState {
  return {
    rootKey: sharedSecret,
    dhSelfKeyPair: selfKeyPair,
    dhRemotePublicKey: null,
    sendingChainKey: null,
    receivingChainKey: null,
    sendMessageNumber: 0,
    receiveMessageNumber: 0,
    previousSendingChainLength: 0,
  };
}

/**
 * Advances the sending chain by one step and returns a message key to
 * encrypt the next outgoing message with, plus the header the recipient
 * needs to stay in sync (which DH key was used, and where in the chain).
 */
export async function ratchetEncrypt(state: RatchetState): Promise<RatchetSendResult> {
  if (!state.sendingChainKey) {
    throw new Error(
      'ratchetEncrypt: no sending chain established yet (responder must receive a message first)'
    );
  }

  const { messageKey, nextChainKey } = await kdfChainKey(state.sendingChainKey);

  const header: RatchetHeader = {
    dhPublicKey: state.dhSelfKeyPair.publicKey,
    messageNumber: state.sendMessageNumber,
    previousChainLength: state.previousSendingChainLength,
  };

  const newState: RatchetState = {
    ...state,
    sendingChainKey: nextChainKey,
    sendMessageNumber: state.sendMessageNumber + 1,
  };

  return { header, messageKey, state: newState };
}

/**
 * Processes an incoming message's header. If it carries a new DH public key
 * (i.e. the other party just turned the ratchet), performs a full DH
 * ratchet step first - deriving a fresh receiving chain (and priming a
 * fresh sending chain) - before advancing the symmetric ratchet to recover
 * this message's key.
 */
export async function ratchetDecrypt(
  state: RatchetState,
  header: RatchetHeader
): Promise<RatchetReceiveResult> {
  let workingState = state;

  const isNewRatchetKey =
    !workingState.dhRemotePublicKey || !bytesEqual(header.dhPublicKey, workingState.dhRemotePublicKey);

  if (isNewRatchetKey) {
    // Step 1: derive the receiving chain using our existing DH keypair against their new public key.
    const dhOutput1 = await diffieHellman(workingState.dhSelfKeyPair.privateKey, header.dhPublicKey);
    const { rootKey: rootKeyAfterReceive, chainKey: receivingChainKey } = await kdfRootKey(
      workingState.rootKey,
      dhOutput1
    );

    // Step 2: generate our own new DH keypair and derive a fresh sending chain, priming our next turn.
    const newSelfKeyPair = await generateDHKeyPair();
    const dhOutput2 = await diffieHellman(newSelfKeyPair.privateKey, header.dhPublicKey);
    const { rootKey: rootKeyAfterSend, chainKey: sendingChainKey } = await kdfRootKey(
      rootKeyAfterReceive,
      dhOutput2
    );

    workingState = {
      rootKey: rootKeyAfterSend,
      dhSelfKeyPair: newSelfKeyPair,
      dhRemotePublicKey: header.dhPublicKey,
      sendingChainKey,
      receivingChainKey,
      sendMessageNumber: 0,
      receiveMessageNumber: 0,
      previousSendingChainLength: workingState.sendMessageNumber,
    };
  }

  if (!workingState.receivingChainKey) {
    throw new Error('ratchetDecrypt: no receiving chain established');
  }

  if (header.messageNumber !== workingState.receiveMessageNumber) {
    // Out-of-order / skipped-message handling isn't implemented yet - see module docstring.
    throw new Error(
      `ratchetDecrypt: out-of-order message (expected messageNumber ${workingState.receiveMessageNumber}, got ${header.messageNumber}) - skipped-message keys not yet supported`
    );
  }

  const { messageKey, nextChainKey } = await kdfChainKey(workingState.receivingChainKey);

  const newState: RatchetState = {
    ...workingState,
    receivingChainKey: nextChainKey,
    receiveMessageNumber: workingState.receiveMessageNumber + 1,
  };

  return { messageKey, state: newState };
}
