import { describe, it, expect, beforeEach } from 'vitest';
import { generateLocalIdentity } from '../src/services/cryptoService';
import {
  saveLocalIdentity,
  loadLocalIdentity,
  clearLocalIdentity,
  saveRatchetState,
  loadRatchetState,
  deleteRatchetState,
  listConversationIds,
  __setStorageAdapterForTesting,
} from '../src/services/storageService';
import { initializeRatchetAsResponder } from '@securechat/crypto-core';

/**
 * Explicitly inject a fresh in-memory adapter per test, rather than relying
 * on the module's automatic Node fallback, so tests are isolated from each
 * other and from whatever adapter storageService happened to default to.
 */
function freshAdapter() {
  const memory = new Map<string, string>();
  return {
    async getItem(key: string) {
      return memory.has(key) ? memory.get(key)! : null;
    },
    async setItem(key: string, value: string) {
      memory.set(key, value);
    },
    async removeItem(key: string) {
      memory.delete(key);
    },
    async getAllKeys() {
      return Array.from(memory.keys());
    },
  };
}

beforeEach(() => {
  __setStorageAdapterForTesting(freshAdapter());
});

describe('storageService', () => {
  it('returns null when no identity has been saved', async () => {
    expect(await loadLocalIdentity()).toBeNull();
  });

  it('saves and loads a local identity with all key material intact', async () => {
    const local = await generateLocalIdentity();

    await saveLocalIdentity(local);
    const loaded = await loadLocalIdentity();

    expect(loaded).not.toBeNull();
    expect(loaded!.identity.signing.publicKey).toEqual(local.identity.signing.publicKey);
    expect(loaded!.identity.signing.privateKey).toEqual(local.identity.signing.privateKey);
    expect(loaded!.identity.agreement.publicKey).toEqual(local.identity.agreement.publicKey);
    expect(loaded!.signedPreKey.signature).toEqual(local.signedPreKey.signature);
    expect(loaded!.oneTimePreKeys.length).toBe(local.oneTimePreKeys.length);
    expect(loaded!.oneTimePreKeys[0].publicKey).toEqual(local.oneTimePreKeys[0].publicKey);
  });

  it('clears a saved identity', async () => {
    const local = await generateLocalIdentity();
    await saveLocalIdentity(local);
    await clearLocalIdentity();

    expect(await loadLocalIdentity()).toBeNull();
  });

  it('saves and loads ratchet state with all fields intact, including an empty skipped-key store', async () => {
    const bob = await generateLocalIdentity();
    const state = initializeRatchetAsResponder(new Uint8Array(32).fill(7), {
      publicKey: bob.signedPreKey.publicKey,
      privateKey: bob.signedPreKey.privateKey,
    });

    await saveRatchetState('conversation-1', state);
    const loaded = await loadRatchetState('conversation-1');

    expect(loaded).not.toBeNull();
    expect(loaded!.rootKey).toEqual(state.rootKey);
    expect(loaded!.dhSelfKeyPair.publicKey).toEqual(state.dhSelfKeyPair.publicKey);
    expect(loaded!.dhRemotePublicKey).toBeNull();
    expect(loaded!.sendMessageNumber).toBe(0);
    expect(loaded!.skippedMessageKeys.size).toBe(0);
  });

  it('round-trips a non-empty skipped-message-key store correctly', async () => {
    const bob = await generateLocalIdentity();
    const state = initializeRatchetAsResponder(new Uint8Array(32).fill(3), {
      publicKey: bob.signedPreKey.publicKey,
      privateKey: bob.signedPreKey.privateKey,
    });
    state.skippedMessageKeys.set('abc:0', new Uint8Array(32).fill(9));
    state.skippedMessageKeys.set('abc:1', new Uint8Array(32).fill(11));

    await saveRatchetState('conversation-2', state);
    const loaded = await loadRatchetState('conversation-2');

    expect(loaded!.skippedMessageKeys.size).toBe(2);
    expect(loaded!.skippedMessageKeys.get('abc:0')).toEqual(new Uint8Array(32).fill(9));
    expect(loaded!.skippedMessageKeys.get('abc:1')).toEqual(new Uint8Array(32).fill(11));
  });

  it('returns null for a conversation that was never saved', async () => {
    expect(await loadRatchetState('nonexistent')).toBeNull();
  });

  it('deletes ratchet state for a specific conversation', async () => {
    const bob = await generateLocalIdentity();
    const state = initializeRatchetAsResponder(new Uint8Array(32).fill(1), {
      publicKey: bob.signedPreKey.publicKey,
      privateKey: bob.signedPreKey.privateKey,
    });

    await saveRatchetState('to-delete', state);
    await deleteRatchetState('to-delete');

    expect(await loadRatchetState('to-delete')).toBeNull();
  });

  it('lists saved conversation ids without leaking the identity key or unrelated keys', async () => {
    const local = await generateLocalIdentity();
    const bob = await generateLocalIdentity();
    const state = initializeRatchetAsResponder(new Uint8Array(32), {
      publicKey: bob.signedPreKey.publicKey,
      privateKey: bob.signedPreKey.privateKey,
    });

    await saveLocalIdentity(local);
    await saveRatchetState('alice-bob', state);
    await saveRatchetState('alice-carol', state);

    const ids = await listConversationIds();

    expect(ids.sort()).toEqual(['alice-bob', 'alice-carol']);
  });
});
