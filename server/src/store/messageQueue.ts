/**
 * Message Queue
 * -------------
 * Holds ciphertext blobs for recipients who aren't currently connected, so
 * they can be delivered as soon as the recipient reconnects. Like
 * userStore.ts, this only ever handles opaque data — a queued message here
 * is exactly the bytes the sender's client produced, untouched.
 *
 * In-memory placeholder for what should eventually be durable storage
 * (so messages survive a server restart) — flagged as Phase 2 follow-up.
 */

export interface QueuedMessage {
  from: string;
  to: string;
  header: unknown; // ratchet header, opaque to the server
  ciphertext: string; // base64
  nonce: string; // base64
  sentAt: number; // epoch ms
}

const queues = new Map<string, QueuedMessage[]>();

export function reset(): void {
  queues.clear();
}

export function enqueue(message: QueuedMessage): void {
  const existing = queues.get(message.to) ?? [];
  existing.push(message);
  queues.set(message.to, existing);
}

/** Removes and returns all queued messages for a recipient, in delivery order. */
export function drain(username: string): QueuedMessage[] {
  const messages = queues.get(username) ?? [];
  queues.delete(username);
  return messages;
}

export function queuedCount(username: string): number {
  return queues.get(username)?.length ?? 0;
}
