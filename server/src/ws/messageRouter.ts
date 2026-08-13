/**
 * Message Router
 * --------------
 * The core relay logic: takes an incoming message from one client and
 * either forwards it immediately (if the recipient is connected) or queues
 * it for later delivery (if not).
 *
 * SECURITY INVARIANT: this function only ever touches the `header`,
 * `ciphertext`, and `nonce` fields as opaque values. It does not decode
 * base64 into bytes, does not import anything from crypto-core (the server
 * package doesn't even list crypto-core as a dependency), and does not
 * inspect message content beyond routing metadata (`from`, `to`). If a
 * change to this file starts requiring a decryption key, that's a sign the
 * architecture has been violated — stop and reconsider.
 */

import type { WebSocket } from 'ws';
import { getConnection, isConnected } from './connectionManager';
import { enqueue, drain, QueuedMessage } from '../store/messageQueue';

export interface IncomingRelayMessage {
  to: string;
  header: unknown;
  ciphertext: string;
  nonce: string;
}

export interface OutgoingRelayMessage extends IncomingRelayMessage {
  from: string;
  sentAt: number;
}

/**
 * Routes one message from `from` to `to`. If the recipient is connected,
 * sends it immediately over their socket. Otherwise queues it — it'll be
 * delivered by `deliverQueuedMessages` next time they connect.
 */
export function routeMessage(from: string, message: IncomingRelayMessage): void {
  const queuedMessage: QueuedMessage = {
    from,
    to: message.to,
    header: message.header,
    ciphertext: message.ciphertext,
    nonce: message.nonce,
    sentAt: Date.now(),
  };

  const recipientSocket = getConnection(message.to);

  if (recipientSocket && isConnected(message.to)) {
    sendToSocket(recipientSocket, queuedMessage);
  } else {
    enqueue(queuedMessage);
  }
}

/** Delivers everything queued for a user, in order, over their newly-opened socket. */
export function deliverQueuedMessages(username: string, socket: WebSocket): void {
  const queued = drain(username);
  for (const message of queued) {
    sendToSocket(socket, message);
  }
}

function sendToSocket(socket: WebSocket, message: QueuedMessage): void {
  const outgoing: OutgoingRelayMessage = {
    from: message.from,
    to: message.to,
    header: message.header,
    ciphertext: message.ciphertext,
    nonce: message.nonce,
    sentAt: message.sentAt,
  };
  socket.send(JSON.stringify({ type: 'message', payload: outgoing }));
}
    