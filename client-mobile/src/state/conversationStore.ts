/**
 * Conversation Store (Zustand)
 * ----------------------------
 * Central application state management for SecureChat.
 * Ties together cryptoService, storageService, authService, and socketService.
 *
 * Responsibilities:
 *   - User identity lifecycle: registration, hydration from local storage, logout.
 *   - WebSocket connectivity: signed-challenge connection with live status.
 *   - Conversation lifecycle:
 *     - Starting a conversation (X3DH as initiator).
 *     - Accepting incoming conversations (X3DH as responder).
 *     - Encrypting/decrypting ratcheted messages (Double Ratchet + AEAD).
 *     - Auto-attaching `x3dhInit` to the first message in header.
 *     - Persisting evolving `RatchetState` after every send and receive.
 *     - Local thread history management.
 */

import { createStore } from 'zustand';
import type { RatchetState } from '@securechat/crypto-core';
import {
  LocalIdentity,
  RemotePreKeyBundle,
  WireMessage,
  generateLocalIdentity,
  buildRegistrationPayload,
  startConversation,
  acceptConversation,
  encryptText,
  decryptText,
} from '../services/cryptoService';
import {
  saveLocalIdentity,
  loadLocalIdentity,
  clearLocalIdentity,
  saveUsername,
  loadUsername,
  clearUsername,
  saveRatchetState,
  loadRatchetState,
  listConversationIds,
} from '../services/storageService';
import { getSignedConnectionParams } from '../services/authService';
import { connect, SecureChatSocket, RelayEnvelope } from '../services/socketService';

export interface StoredMessage {
  id: string;
  from: string;
  to: string;
  text: string;
  timestamp: number;
  isOutbound: boolean;
}

export interface ConversationRecord {
  peerUsername: string;
  ratchetState: RatchetState;
  messages: StoredMessage[];
  pendingX3dhInit?: WireMessage['header']['x3dhInit'];
  unreadCount: number;
}

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface ConversationState {
  currentUsername: string | null;
  localIdentity: LocalIdentity | null;
  connectionStatus: ConnectionStatus;
  serverBaseUrl: string | null;
  serverWsUrl: string | null;
  conversations: Record<string, ConversationRecord>;
  activeConversationId: string | null;
  error: string | null;
  socket: SecureChatSocket | null;

  // Actions
  registerNewUser: (serverBaseUrl: string, username: string) => Promise<void>;
  loadExistingUser: () => Promise<boolean>;
  clearUser: () => Promise<void>;
  connectSocket: (serverWsUrl: string, serverBaseUrl: string) => Promise<void>;
  disconnectSocket: () => void;
  startConversationWith: (serverBaseUrl: string, peerUsername: string) => Promise<void>;
  sendMessage: (peerUsername: string, text: string, optionalServerBaseUrl?: string) => Promise<void>;
  setActiveConversation: (peerUsername: string | null) => void;
  setError: (error: string | null) => void;
}

/**
 * Creates an isolated conversation store. Used directly in tests for multi-client
 * simulation (e.g. Alice and Bob in separate store instances), and by the default hook.
 */
export function createConversationStore() {
  return createStore<ConversationState>((set, get) => ({
    currentUsername: null,
    localIdentity: null,
    connectionStatus: 'disconnected',
    serverBaseUrl: null,
    serverWsUrl: null,
    conversations: {},
    activeConversationId: null,
    error: null,
    socket: null,

    registerNewUser: async (serverBaseUrl: string, username: string) => {
      try {
        set({ error: null });
        const local = await generateLocalIdentity();
        await saveLocalIdentity(local);
        await saveUsername(username);

        const payload = buildRegistrationPayload(username, local);
        const res = await fetch(`${serverBaseUrl}/users/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          const body = await res.text();
          throw new Error(`Registration failed (${res.status}): ${body}`);
        }

        set({
          currentUsername: username,
          localIdentity: local,
          serverBaseUrl,
          conversations: {},
          error: null,
        });
      } catch (err: any) {
        set({ error: err.message ?? String(err) });
        throw err;
      }
    },

    loadExistingUser: async () => {
      try {
        const username = await loadUsername();
        const localIdentity = await loadLocalIdentity();

        if (!username || !localIdentity) {
          return false;
        }

        const conversationIds = await listConversationIds();
        const conversations: Record<string, ConversationRecord> = {};

        for (const peer of conversationIds) {
          const ratchetState = await loadRatchetState(peer);
          if (ratchetState) {
            conversations[peer] = {
              peerUsername: peer,
              ratchetState,
              messages: [],
              unreadCount: 0,
            };
          }
        }

        set({
          currentUsername: username,
          localIdentity,
          conversations,
          connectionStatus: 'disconnected',
          error: null,
        });
        return true;
      } catch (err: any) {
        set({ error: err.message ?? String(err) });
        return false;
      }
    },

    clearUser: async () => {
      get().disconnectSocket();
      await clearLocalIdentity();
      await clearUsername();
      set({
        currentUsername: null,
        localIdentity: null,
        conversations: {},
        activeConversationId: null,
        connectionStatus: 'disconnected',
        error: null,
      });
    },

    connectSocket: async (serverWsUrl: string, serverBaseUrl: string) => {
      const { currentUsername, localIdentity } = get();
      if (!currentUsername || !localIdentity) {
        throw new Error('Cannot connect socket: no user is logged in');
      }

      set({ connectionStatus: 'connecting', serverWsUrl, serverBaseUrl, error: null });

      try {
        const params = await getSignedConnectionParams(
          serverBaseUrl,
          currentUsername,
          localIdentity.identity
        );

        const socket = await connect(serverWsUrl, params, async (envelope: RelayEnvelope) => {
          if (envelope.type !== 'message' || !envelope.payload) {
            return;
          }

          const payload = envelope.payload;
          const sender = payload.from;
          const {
            conversations: currentConversations,
            localIdentity: curLocal,
            currentUsername: curUser,
            activeConversationId,
          } = get();

          if (!curLocal) return;

          try {
            let workingRatchetState: RatchetState;
            const existingConv = currentConversations[sender];

            if (!existingConv) {
              // First message from this peer: must contain x3dhInit in header
              const x3dhInit = payload.header.x3dhInit;
              if (!x3dhInit) {
                throw new Error(`First message from ${sender} is missing x3dhInit`);
              }

              // Fetch sender's prekey bundle to get their identity agreement public key
              const bundleRes = await fetch(
                `${serverBaseUrl}/users/${encodeURIComponent(sender)}/prekey-bundle`
              );
              if (!bundleRes.ok) {
                throw new Error(`Failed to fetch prekey bundle for sender ${sender}`);
              }
              const senderBundle = (await bundleRes.json()) as RemotePreKeyBundle;

              // Find matching one-time prekey if used
              const otk =
                x3dhInit.oneTimePreKeyId !== undefined
                  ? curLocal.oneTimePreKeys.find((k) => k.keyId === x3dhInit.oneTimePreKeyId)
                  : undefined;

              workingRatchetState = await acceptConversation(
                curLocal.identity,
                curLocal.signedPreKey,
                otk,
                senderBundle.identityAgreementPublicKey,
                x3dhInit
              );
            } else {
              workingRatchetState = existingConv.ratchetState;
            }

            const { plaintext, state: updatedRatchetState } = await decryptText(
              workingRatchetState,
              payload
            );

            await saveRatchetState(sender, updatedRatchetState);

            const storedMsg: StoredMessage = {
              id: `msg_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
              from: sender,
              to: curUser ?? '',
              text: plaintext,
              timestamp: payload.sentAt ?? Date.now(),
              isOutbound: false,
            };

            const isCurrentActive = activeConversationId === sender;

            set((state) => ({
              conversations: {
                ...state.conversations,
                [sender]: {
                  peerUsername: sender,
                  ratchetState: updatedRatchetState,
                  messages: [...(state.conversations[sender]?.messages ?? []), storedMsg],
                  pendingX3dhInit: state.conversations[sender]?.pendingX3dhInit,
                  unreadCount: isCurrentActive
                    ? 0
                    : (state.conversations[sender]?.unreadCount ?? 0) + 1,
                },
              },
            }));
          } catch (decryptErr: any) {
            console.error(`Failed to decrypt message from ${sender}:`, decryptErr);
          }
        });

        set({ socket, connectionStatus: 'connected' });
      } catch (err: any) {
        set({ connectionStatus: 'error', error: err.message ?? String(err) });
        throw err;
      }
    },

    disconnectSocket: () => {
      const { socket } = get();
      if (socket) {
        socket.close();
      }
      set({ socket: null, connectionStatus: 'disconnected' });
    },

    startConversationWith: async (serverBaseUrl: string, peerUsername: string) => {
      const { localIdentity } = get();
      if (!localIdentity) {
        throw new Error('No local identity loaded');
      }

      const bundleRes = await fetch(
        `${serverBaseUrl}/users/${encodeURIComponent(peerUsername)}/prekey-bundle`
      );
      if (!bundleRes.ok) {
        throw new Error(`Failed to fetch prekey bundle for ${peerUsername} (${bundleRes.status})`);
      }
      const remoteBundle = (await bundleRes.json()) as RemotePreKeyBundle;

      const started = await startConversation(localIdentity.identity, remoteBundle);
      await saveRatchetState(peerUsername, started.state);

      set((state) => ({
        conversations: {
          ...state.conversations,
          [peerUsername]: {
            peerUsername,
            ratchetState: started.state,
            messages: state.conversations[peerUsername]?.messages ?? [],
            pendingX3dhInit: started.x3dhInit,
            unreadCount: state.conversations[peerUsername]?.unreadCount ?? 0,
          },
        },
      }));
    },

    sendMessage: async (peerUsername: string, text: string, optionalServerBaseUrl?: string) => {
      const {
        socket,
        localIdentity,
        currentUsername,
        conversations,
        serverBaseUrl: stateBaseUrl,
      } = get();

      if (!currentUsername || !localIdentity) {
        throw new Error('User not logged in');
      }
      if (!socket) {
        throw new Error('Cannot send message: socket not connected');
      }

      let conv = conversations[peerUsername];
      if (!conv) {
        const baseUrl = optionalServerBaseUrl ?? stateBaseUrl;
        if (!baseUrl) {
          throw new Error('Server URL required to start conversation');
        }
        await get().startConversationWith(baseUrl, peerUsername);
        conv = get().conversations[peerUsername];
      }

      if (!conv) {
        throw new Error(`Could not initialize conversation with ${peerUsername}`);
      }

      const { wireMessage, state: newRatchetState } = await encryptText(conv.ratchetState, text);

      const outgoingHeader: WireMessage['header'] = {
        ...wireMessage.header,
        ...(conv.pendingX3dhInit ? { x3dhInit: conv.pendingX3dhInit } : {}),
      };

      const outgoing: Omit<WireMessage, 'to' | 'from'> = {
        header: outgoingHeader,
        ciphertext: wireMessage.ciphertext,
        nonce: wireMessage.nonce,
      };

      socket.send(peerUsername, outgoing);
      await saveRatchetState(peerUsername, newRatchetState);

      const messageRecord: StoredMessage = {
        id: `msg_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
        from: currentUsername,
        to: peerUsername,
        text,
        timestamp: Date.now(),
        isOutbound: true,
      };

      set((state) => ({
        conversations: {
          ...state.conversations,
          [peerUsername]: {
            ...conv,
            ratchetState: newRatchetState,
            messages: [...(state.conversations[peerUsername]?.messages ?? []), messageRecord],
            pendingX3dhInit: undefined, // Cleared after attaching to first message
          },
        },
      }));
    },

    setActiveConversation: (peerUsername: string | null) => {
      set((state) => {
        const updatedConversations = { ...state.conversations };
        if (peerUsername && updatedConversations[peerUsername]) {
          updatedConversations[peerUsername] = {
            ...updatedConversations[peerUsername],
            unreadCount: 0,
          };
        }
        return {
          activeConversationId: peerUsername,
          conversations: updatedConversations,
        };
      });
    },

    setError: (error: string | null) => {
      set({ error });
    },
  }));
}
