/**
 * Double Ratchet
 * --------------
 * Takes the shared secret from X3DH and turns it into an ever-evolving
 * stream of per-message keys, in both directions, for the lifetime of a
 * conversation.
 *
 * This module produces *message keys* — one-time symmetric keys, one per
 * message. It does not perform the actual AEAD encryption/decryption of
 * message content; see encryption/messageCipher.ts and
 * messaging/secureMessage.ts for that layer.
 *
 * Roles, mirroring x3dh.ts:
 *   - Alice ("initiator") calls `initializeRatchetAsInitiator` right after
 *     `initiateX3DH`, using Bob's signed-prekey public key as the initial
 *     remote DH key.
 *   - Bob ("responder") calls `initializeRatchetAsResponder` right after
 *     `receiveX3DH`, using the same signed-prekey keypair he already has.
 *
 * Out-of-order delivery: if a message arrives numbered ahead of what's
 * expected, the messages in between are not lost — their keys are derived
 * and cached (see ratchetState.ts's skipped-message-key store) so that if
 * they arrive later, they can still be decrypted. This also applies across
 * a DH ratchet step: any unreceived messages in the *old* chain (signaled
 * by the header's previousChainLength) are skipped and cached before
 * switching to the new chain, exactly as the Signal spec describes. Both
 * the per-step skip count and the total cache size are bounded, so a
 * malicious peer can't use a huge claimed message number to force
 * unbounded work or memory use — see MAX_SKIP_PER_CHAIN_STEP and
 * MAX_STORED_SKIPPED_KEYS in ratchetState.ts.
 *
 * A message number *below* what's expected, and not found in the skipped
 * cache, is treated as a duplicate/replay and rejected.
 */

import {
  DHKeyPair,
  RatchetState,
  generateDHKeyPair,
  diffieHellman,
  kdfRootKey,
  kdfChainKey,
  skipChainMessages,
  skippedKeyLabel,
  withSkippedMessageKeysAdded,
  withSkippedMessageKeyRemoved,
} from './ratchetState';

export type { RatchetState, DHKeyPair, SkippedMessageKeyStore } from './ratchetState';

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
    skippedMessageKeys: new Map(),
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
    skippedMessageKeys: new Map(),
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
 * Processes an incoming message's header and returns the message key to
 * decrypt it with. Handles three cases:
 *
 *  1. The header's DH key matches our current remote key and its message
 *     number is next-in-line: normal symmetric ratchet advance.
 *  2. The header's DH key matches but the message number is ahead of
 *     expected: skip forward, caching the intermediate keys, then return
 *     the requested one.
 *  3. The header's DH key is new: perform a full DH ratchet step (skipping
 *     any remaining messages in the old chain first, per previousChainLength),
 *     then proceed as in case 1/2 on the new chain.
 *
 * A message number below what's expected is looked up in the skipped-key
 * cache; if it's not there, it's treated as a duplicate/replay and rejected.
 */
export async function ratchetDecrypt(
  state: RatchetState,
  header: RatchetHeader
): Promise<RatchetReceiveResult> {
  // Case: this message's key was already derived and cached from an earlier skip — use it directly.
  const cachedLabel = await skippedKeyLabel(header.dhPublicKey, header.messageNumber);
  const cachedKey = state.skippedMessageKeys.get(cachedLabel);
  if (cachedKey) {
    return {
      messageKey: cachedKey,
      state: { ...state, skippedMessageKeys: withSkippedMessageKeyRemoved(state.skippedMessageKeys, cachedLabel) },
    };
  }

  let workingState = state;

  const isNewRatchetKey =
    !workingState.dhRemotePublicKey || !bytesEqual(header.dhPublicKey, workingState.dhRemotePublicKey);

  if (isNewRatchetKey) {
    // Before switching chains, cache any messages we never received on the OLD receiving chain.
    if (workingState.receivingChainKey && workingState.dhRemotePublicKey) {
      const { chainKey: exhaustedChainKey, skipped } = await skipChainMessages(
        workingState.dhRemotePublicKey,
        workingState.receivingChainKey,
        workingState.receiveMessageNumber,
        header.previousChainLength
      );
      void exhaustedChainKey; // old chain is being retired; only its cached keys matter going forward
      workingState = {
        ...workingState,
        skippedMessageKeys: withSkippedMessageKeysAdded(workingState.skippedMessageKeys, skipped),
      };
    }

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
      ...workingState,
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

  if (header.messageNumber > workingState.receiveMessageNumber) {
    // Message arrived ahead of expected: skip forward, caching the intermediate keys.
    const { chainKey: advancedChainKey, skipped } = await skipChainMessages(
      header.dhPublicKey,
      workingState.receivingChainKey,
      workingState.receiveMessageNumber,
      header.messageNumber
    );
    workingState = {
      ...workingState,
      receivingChainKey: advancedChainKey,
      receiveMessageNumber: header.messageNumber,
      skippedMessageKeys: withSkippedMessageKeysAdded(workingState.skippedMessageKeys, skipped),
    };
  } else if (header.messageNumber < workingState.receiveMessageNumber) {
    // Already passed this point in the chain and it wasn't in the skipped cache above: duplicate/replay.
    throw new Error(
      `ratchetDecrypt: duplicate or already-processed message (messageNumber ${header.messageNumber}, expected ${workingState.receiveMessageNumber})`
    );
  }

  const finalReceivingChainKey = workingState.receivingChainKey;
  if (!finalReceivingChainKey) {
    throw new Error('ratchetDecrypt: no receiving chain established');
  }

  const { messageKey, nextChainKey } = await kdfChainKey(finalReceivingChainKey);

  const newState: RatchetState = {
    ...workingState,
    receivingChainKey: nextChainKey,
    receiveMessageNumber: workingState.receiveMessageNumber + 1,
  };

  return { messageKey, state: newState };
}
