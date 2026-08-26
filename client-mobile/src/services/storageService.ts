/**
 * Storage Service
 * ---------------
 * Persists everything that currently only lives in memory: the local
 * identity (keys generated once at registration) and per-conversation
 * ratchet state (which evolves with every message). Without this, closing
 * the app loses the user's identity and every conversation's key material —
 * not just an inconvenience, since a new identity can't decrypt anything
 * encrypted under the old one.
 *
 * Storage adapter is pluggable and defaults to
 * `@react-native-async-storage/async-storage` on-device. Under Node (this
 * package's own tests, or any environment where the native module isn't
 * available), it falls back automatically to an in-memory adapter — this
 * makes the module safely importable and testable outside React Native,
 * but that fallback is NOT persistent. On-device, AsyncStorage itself is
 * NOT secure storage either — it's unencrypted local storage, adequate for
 * ratchet state (which is useless without the identity key anyway) but NOT
 * where long-term private identity key material should end up in a
 * production build. That needs the platform keystore/secure enclave (e.g.
 * via `react-native-keychain`) — flagged here as unresolved, not silently
 * treated as solved.
 */

import {
  IdentityKeyPair,
  SignedPreKeyPair,
  OneTimePreKeyPair,
  RatchetState,
} from '@securechat/crypto-core';
import { bytesToBase64, base64ToBytes } from './base64';
import type { LocalIdentity } from './cryptoService';

export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  getAllKeys(): Promise<string[]>;
}

function createInMemoryAdapter(): StorageAdapter {
  const memory = new Map<string, string>();
  return {
    async getItem(key) {
      return memory.has(key) ? memory.get(key)! : null;
    },
    async setItem(key, value) {
      memory.set(key, value);
    },
    async removeItem(key) {
      memory.delete(key);
    },
    async getAllKeys() {
      return Array.from(memory.keys());
    },
  };
}

function createDefaultAdapter(): StorageAdapter {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('@react-native-async-storage/async-storage');
    const AsyncStorage = mod.default ?? mod;
    // Accessing a native module outside React Native throws synchronously
    // on some platforms and only on first real call on others — probe here
    // so the fallback decision happens at module-load time, consistently.
    if (typeof AsyncStorage?.getItem !== 'function') {
      throw new Error('AsyncStorage native module not available');
    }
    return AsyncStorage;
  } catch {
    return createInMemoryAdapter();
  }
}

let adapter: StorageAdapter = createDefaultAdapter();

/** Test/advanced use only: swap the storage backend (e.g. inject a mock in tests). */
export function __setStorageAdapterForTesting(customAdapter: StorageAdapter): void {
  adapter = customAdapter;
}

const IDENTITY_KEY = 'securechat:identity';
const CONVERSATION_KEY_PREFIX = 'securechat:conversation:';

// --- Serialization helpers -------------------------------------------------

interface SerializedLocalIdentity {
  identity: {
    signing: { publicKey: string; privateKey: string };
    agreement: { publicKey: string; privateKey: string };
  };
  signedPreKey: { keyId: number; publicKey: string; privateKey: string; signature: string };
  oneTimePreKeys: { keyId: number; publicKey: string; privateKey: string }[];
}

function serializeLocalIdentity(local: LocalIdentity): SerializedLocalIdentity {
  return {
    identity: {
      signing: {
        publicKey: bytesToBase64(local.identity.signing.publicKey),
        privateKey: bytesToBase64(local.identity.signing.privateKey),
      },
      agreement: {
        publicKey: bytesToBase64(local.identity.agreement.publicKey),
        privateKey: bytesToBase64(local.identity.agreement.privateKey),
      },
    },
    signedPreKey: {
      keyId: local.signedPreKey.keyId,
      publicKey: bytesToBase64(local.signedPreKey.publicKey),
      privateKey: bytesToBase64(local.signedPreKey.privateKey),
      signature: bytesToBase64(local.signedPreKey.signature),
    },
    oneTimePreKeys: local.oneTimePreKeys.map((k) => ({
      keyId: k.keyId,
      publicKey: bytesToBase64(k.publicKey),
      privateKey: bytesToBase64(k.privateKey),
    })),
  };
}

function deserializeLocalIdentity(data: SerializedLocalIdentity): LocalIdentity {
  const identity: IdentityKeyPair = {
    signing: {
      publicKey: base64ToBytes(data.identity.signing.publicKey),
      privateKey: base64ToBytes(data.identity.signing.privateKey),
    },
    agreement: {
      publicKey: base64ToBytes(data.identity.agreement.publicKey),
      privateKey: base64ToBytes(data.identity.agreement.privateKey),
    },
  };

  const signedPreKey: SignedPreKeyPair = {
    keyId: data.signedPreKey.keyId,
    publicKey: base64ToBytes(data.signedPreKey.publicKey),
    privateKey: base64ToBytes(data.signedPreKey.privateKey),
    signature: base64ToBytes(data.signedPreKey.signature),
  };

  const oneTimePreKeys: OneTimePreKeyPair[] = data.oneTimePreKeys.map((k) => ({
    keyId: k.keyId,
    publicKey: base64ToBytes(k.publicKey),
    privateKey: base64ToBytes(k.privateKey),
  }));

  return { identity, signedPreKey, oneTimePreKeys };
}

interface SerializedRatchetState {
  rootKey: string;
  dhSelfKeyPair: { publicKey: string; privateKey: string };
  dhRemotePublicKey: string | null;
  sendingChainKey: string | null;
  receivingChainKey: string | null;
  sendMessageNumber: number;
  receiveMessageNumber: number;
  previousSendingChainLength: number;
  skippedMessageKeys: [string, string][]; // Map entries as [id, base64Key] pairs
}

function serializeRatchetState(state: RatchetState): SerializedRatchetState {
  return {
    rootKey: bytesToBase64(state.rootKey),
    dhSelfKeyPair: {
      publicKey: bytesToBase64(state.dhSelfKeyPair.publicKey),
      privateKey: bytesToBase64(state.dhSelfKeyPair.privateKey),
    },
    dhRemotePublicKey: state.dhRemotePublicKey ? bytesToBase64(state.dhRemotePublicKey) : null,
    sendingChainKey: state.sendingChainKey ? bytesToBase64(state.sendingChainKey) : null,
    receivingChainKey: state.receivingChainKey ? bytesToBase64(state.receivingChainKey) : null,
    sendMessageNumber: state.sendMessageNumber,
    receiveMessageNumber: state.receiveMessageNumber,
    previousSendingChainLength: state.previousSendingChainLength,
    skippedMessageKeys: Array.from(state.skippedMessageKeys.entries()).map(([id, key]) => [
      id,
      bytesToBase64(key),
    ]),
  };
}

function deserializeRatchetState(data: SerializedRatchetState): RatchetState {
  return {
    rootKey: base64ToBytes(data.rootKey),
    dhSelfKeyPair: {
      publicKey: base64ToBytes(data.dhSelfKeyPair.publicKey),
      privateKey: base64ToBytes(data.dhSelfKeyPair.privateKey),
    },
    dhRemotePublicKey: data.dhRemotePublicKey ? base64ToBytes(data.dhRemotePublicKey) : null,
    sendingChainKey: data.sendingChainKey ? base64ToBytes(data.sendingChainKey) : null,
    receivingChainKey: data.receivingChainKey ? base64ToBytes(data.receivingChainKey) : null,
    sendMessageNumber: data.sendMessageNumber,
    receiveMessageNumber: data.receiveMessageNumber,
    previousSendingChainLength: data.previousSendingChainLength,
    skippedMessageKeys: new Map(data.skippedMessageKeys.map(([id, key]) => [id, base64ToBytes(key)])),
  };
}

// --- Public API --------------------------------------------------------

export async function saveLocalIdentity(local: LocalIdentity): Promise<void> {
  await adapter.setItem(IDENTITY_KEY, JSON.stringify(serializeLocalIdentity(local)));
}

export async function loadLocalIdentity(): Promise<LocalIdentity | null> {
  const raw = await adapter.getItem(IDENTITY_KEY);
  if (!raw) return null;
  return deserializeLocalIdentity(JSON.parse(raw));
}

export async function clearLocalIdentity(): Promise<void> {
  await adapter.removeItem(IDENTITY_KEY);
}

function conversationKey(conversationId: string): string {
  return `${CONVERSATION_KEY_PREFIX}${conversationId}`;
}

export async function saveRatchetState(conversationId: string, state: RatchetState): Promise<void> {
  await adapter.setItem(conversationKey(conversationId), JSON.stringify(serializeRatchetState(state)));
}

export async function loadRatchetState(conversationId: string): Promise<RatchetState | null> {
  const raw = await adapter.getItem(conversationKey(conversationId));
  if (!raw) return null;
  return deserializeRatchetState(JSON.parse(raw));
}

export async function deleteRatchetState(conversationId: string): Promise<void> {
  await adapter.removeItem(conversationKey(conversationId));
}

export async function listConversationIds(): Promise<string[]> {
  const keys = await adapter.getAllKeys();
  return keys
    .filter((k) => k.startsWith(CONVERSATION_KEY_PREFIX))
    .map((k) => k.slice(CONVERSATION_KEY_PREFIX.length));
}
