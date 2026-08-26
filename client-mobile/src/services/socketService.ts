/**
 * Socket Service
 * --------------
 * Thin wrapper around the platform's global `WebSocket` (available both in
 * React Native and in Node 18+/22, which is what lets this be tested under
 * Node without a mocking library) that speaks the relay server's wire
 * protocol from server/src/ws/messageRouter.ts and server/src/index.ts.
 *
 * Deliberately does NOT handle reconnection, backoff, or queuing outgoing
 * sends while disconnected — those are real product concerns (flagged as
 * follow-up) but adding them here would make this harder to test in
 * isolation. This module's job is just: open a correctly-authenticated
 * connection, and give the caller a clean way to send/receive relay
 * messages over it.
 */

import { SignedConnectionParams } from './authService';
import { WireMessage } from './cryptoService';

export interface RelayEnvelope {
  type: 'message' | 'error';
  payload?: WireMessage & { from: string; sentAt: number };
  error?: string;
}

export interface SecureChatSocket {
  readonly socket: WebSocket;
  send(to: string, message: Omit<WireMessage, 'to' | 'from'>): void;
  close(): void;
}

/** Builds the WebSocket URL the server's verifyClient hook expects. */
export function buildWebSocketUrl(serverWsUrl: string, params: SignedConnectionParams): string {
  const url = new URL(serverWsUrl);
  url.searchParams.set('username', params.username);
  url.searchParams.set('signature', params.signature);
  return url.toString();
}

/**
 * Opens a connection using pre-signed connection params (see
 * getSignedConnectionParams in authService.ts) and resolves once the
 * connection is actually open. Rejects if the server refuses the upgrade
 * (e.g. bad signature, expired/missing challenge — see server/src/index.ts's
 * verifyClient) or if the connection errors before opening.
 */
export function connect(
  serverWsUrl: string,
  params: SignedConnectionParams,
  onMessage: (envelope: RelayEnvelope) => void
): Promise<SecureChatSocket> {
  return new Promise((resolve, reject) => {
    const url = buildWebSocketUrl(serverWsUrl, params);
    const socket = new WebSocket(url);

    const handleOpen = () => {
      socket.removeEventListener('error', handleEarlyError);
      resolve({
        socket,
        send(to, message) {
          socket.send(JSON.stringify({ to, ...message }));
        },
        close() {
          socket.close();
        },
      });
    };

    const handleEarlyError = () => {
      reject(new Error('WebSocket connection failed or was refused by the server'));
    };

    socket.addEventListener('open', handleOpen, { once: true });
    socket.addEventListener('error', handleEarlyError, { once: true });

    socket.addEventListener('message', (event: MessageEvent) => {
      try {
        const envelope = JSON.parse(event.data.toString()) as RelayEnvelope;
        onMessage(envelope);
      } catch {
        onMessage({ type: 'error', error: 'Received malformed message from server' });
      }
    });
  });
}
