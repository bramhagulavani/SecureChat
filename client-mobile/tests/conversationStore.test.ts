import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import type http from 'http';
// @ts-ignore
import { startServer } from '@securechat/server/dist/index';
// @ts-ignore
import { reset as resetUsers } from '@securechat/server/dist/store/userStore';
// @ts-ignore
import { reset as resetQueue } from '@securechat/server/dist/store/messageQueue';
// @ts-ignore
import { reset as resetConnections } from '@securechat/server/dist/ws/connectionManager';
// @ts-ignore
import { reset as resetChallenges } from '@securechat/server/dist/auth/challengeStore';
import { createConversationStore } from '../src/state/conversationStore';
import {
  __setStorageAdapterForTesting,
  loadUsername,
  loadLocalIdentity,
  loadRatchetState,
} from '../src/services/storageService';

let server: http.Server;
let port: number;
let httpBaseUrl: string;
let wsBaseUrl: string;

function createMemoryAdapter() {
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

beforeEach(async () => {
  resetUsers();
  resetQueue();
  resetConnections();
  resetChallenges();
  __setStorageAdapterForTesting(createMemoryAdapter());

  server = startServer(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  port = (server.address() as AddressInfo).port;
  httpBaseUrl = `http://127.0.0.1:${port}`;
  wsBaseUrl = `ws://127.0.0.1:${port}/ws`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function uniqueUsername(base: string): string {
  return `${base}-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

async function waitForCondition(predicate: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Condition timed out');
}

describe('ConversationStore (Zustand)', () => {
  it('registers a new user, saves credentials to storage, and updates store state', async () => {
    const store = createConversationStore();
    const aliceUsername = uniqueUsername('alice');

    await store.getState().registerNewUser(httpBaseUrl, aliceUsername);

    const state = store.getState();
    expect(state.currentUsername).toBe(aliceUsername);
    expect(state.localIdentity).not.toBeNull();
    expect(state.localIdentity?.oneTimePreKeys.length).toBe(100);

    // Verify storage persistence
    expect(await loadUsername()).toBe(aliceUsername);
    expect(await loadLocalIdentity()).not.toBeNull();
  });

  it('rehydrates existing user on app start (loadExistingUser)', async () => {
    const initialStore = createConversationStore();
    const aliceUsername = uniqueUsername('alice');
    await initialStore.getState().registerNewUser(httpBaseUrl, aliceUsername);

    // Create a new fresh store instance simulating app reload
    const freshStore = createConversationStore();
    expect(freshStore.getState().currentUsername).toBeNull();

    const loaded = await freshStore.getState().loadExistingUser();
    expect(loaded).toBe(true);
    expect(freshStore.getState().currentUsername).toBe(aliceUsername);
    expect(freshStore.getState().localIdentity).not.toBeNull();
  });

  it('completes full two-way end-to-end conversation between Alice and Bob over real relay', async () => {
    const aliceStore = createConversationStore();
    const bobStore = createConversationStore();

    const aliceUsername = uniqueUsername('alice');
    const bobUsername = uniqueUsername('bob');

    // 1. Both register on the server
    await aliceStore.getState().registerNewUser(httpBaseUrl, aliceUsername);
    await bobStore.getState().registerNewUser(httpBaseUrl, bobUsername);

    // 2. Both connect their WebSockets via signed-challenge authentication
    await aliceStore.getState().connectSocket(wsBaseUrl, httpBaseUrl);
    await bobStore.getState().connectSocket(wsBaseUrl, httpBaseUrl);

    expect(aliceStore.getState().connectionStatus).toBe('connected');
    expect(bobStore.getState().connectionStatus).toBe('connected');

    // 3. Alice sends a message to Bob (auto-initiating X3DH and Double Ratchet)
    await aliceStore.getState().sendMessage(bobUsername, 'Hello Bob! This is message 1.');

    // Verify Alice's local store updated immediately
    const aliceConv = aliceStore.getState().conversations[bobUsername];
    expect(aliceConv).toBeDefined();
    expect(aliceConv.messages.length).toBe(1);
    expect(aliceConv.messages[0].text).toBe('Hello Bob! This is message 1.');
    expect(aliceConv.messages[0].isOutbound).toBe(true);

    // 4. Wait for Bob's store to receive over WebSocket, auto-run acceptConversation, and decrypt
    await waitForCondition(() => {
      const conv = bobStore.getState().conversations[aliceUsername];
      return Boolean(conv && conv.messages.length === 1);
    });

    const bobConv = bobStore.getState().conversations[aliceUsername];
    expect(bobConv.messages[0].text).toBe('Hello Bob! This is message 1.');
    expect(bobConv.messages[0].from).toBe(aliceUsername);
    expect(bobConv.messages[0].isOutbound).toBe(false);
    expect(bobConv.unreadCount).toBe(1);

    // 5. Bob replies to Alice (turning the Double Ratchet)
    await bobStore.getState().sendMessage(aliceUsername, 'Hey Alice! Ratchet turned successfully.');

    // 6. Wait for Alice to receive and decrypt Bob's reply
    await waitForCondition(() => {
      const conv = aliceStore.getState().conversations[bobUsername];
      return Boolean(conv && conv.messages.length === 2);
    });

    const aliceConvUpdated = aliceStore.getState().conversations[bobUsername];
    expect(aliceConvUpdated.messages[1].text).toBe('Hey Alice! Ratchet turned successfully.');
    expect(aliceConvUpdated.messages[1].from).toBe(bobUsername);
    expect(aliceConvUpdated.messages[1].isOutbound).toBe(false);

    // 7. Carry on multiple subsequent turns to ensure ratcheting continues seamlessly
    await aliceStore.getState().sendMessage(bobUsername, 'Turn 3 from Alice');
    await waitForCondition(() => {
      return bobStore.getState().conversations[aliceUsername]?.messages.length === 3;
    });

    await bobStore.getState().sendMessage(aliceUsername, 'Turn 4 from Bob');
    await waitForCondition(() => {
      return aliceStore.getState().conversations[bobUsername]?.messages.length === 4;
    });

    expect(aliceStore.getState().conversations[bobUsername].messages[2].text).toBe('Turn 3 from Alice');
    expect(aliceStore.getState().conversations[bobUsername].messages[3].text).toBe('Turn 4 from Bob');
    expect(bobStore.getState().conversations[aliceUsername].messages[2].text).toBe('Turn 3 from Alice');
    expect(bobStore.getState().conversations[aliceUsername].messages[3].text).toBe('Turn 4 from Bob');

    // Clean up connections
    aliceStore.getState().disconnectSocket();
    bobStore.getState().disconnectSocket();
  });

  it('delivers messages sent while recipient was offline when they connect', async () => {
    const aliceStore = createConversationStore();
    const bobStore = createConversationStore();

    const aliceUsername = uniqueUsername('alice');
    const bobUsername = uniqueUsername('bob');

    // Both register
    await aliceStore.getState().registerNewUser(httpBaseUrl, aliceUsername);
    await bobStore.getState().registerNewUser(httpBaseUrl, bobUsername);

    // Only Alice connects her socket
    await aliceStore.getState().connectSocket(wsBaseUrl, httpBaseUrl);

    // Alice sends to Bob who is currently offline
    await aliceStore.getState().sendMessage(bobUsername, 'Offline message waiting for Bob');

    // Bob connects his socket now
    await bobStore.getState().connectSocket(wsBaseUrl, httpBaseUrl);

    // Bob receives the queued message on connect
    await waitForCondition(() => {
      const conv = bobStore.getState().conversations[aliceUsername];
      return Boolean(conv && conv.messages.length === 1);
    });

    const bobConv = bobStore.getState().conversations[aliceUsername];
    expect(bobConv.messages[0].text).toBe('Offline message waiting for Bob');

    aliceStore.getState().disconnectSocket();
    bobStore.getState().disconnectSocket();
  });

  it('resets unread count when setting active conversation', async () => {
    const store = createConversationStore();
    const aliceUsername = uniqueUsername('alice');
    const bobUsername = uniqueUsername('bob');

    await store.getState().registerNewUser(httpBaseUrl, aliceUsername);

    // Simulate receiving an unread message
    store.setState({
      conversations: {
        [bobUsername]: {
          peerUsername: bobUsername,
          ratchetState: {} as any,
          messages: [],
          unreadCount: 5,
        },
      },
    });

    expect(store.getState().conversations[bobUsername].unreadCount).toBe(5);

    // Open chat
    store.getState().setActiveConversation(bobUsername);

    expect(store.getState().activeConversationId).toBe(bobUsername);
    expect(store.getState().conversations[bobUsername].unreadCount).toBe(0);
  });
});
