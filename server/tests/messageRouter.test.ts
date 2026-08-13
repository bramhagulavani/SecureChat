import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { WebSocket } from 'ws';
import { routeMessage, deliverQueuedMessages } from '../src/ws/messageRouter';
import { addConnection, reset as resetConnections } from '../src/ws/connectionManager';
import { reset as resetQueue, queuedCount } from '../src/store/messageQueue';

function fakeSocket() {
  return { send: vi.fn() } as unknown as WebSocket;
}

describe('messageRouter', () => {
  beforeEach(() => {
    resetConnections();
    resetQueue();
  });

  it('delivers immediately to a connected recipient', () => {
    const bobSocket = fakeSocket();
    addConnection('bob', bobSocket);

    routeMessage('alice', { to: 'bob', header: { n: 0 }, ciphertext: 'ct', nonce: 'n' });

    expect(bobSocket.send).toHaveBeenCalledTimes(1);
    const sentPayload = JSON.parse((bobSocket.send as any).mock.calls[0][0]);
    expect(sentPayload.type).toBe('message');
    expect(sentPayload.payload.from).toBe('alice');
    expect(sentPayload.payload.ciphertext).toBe('ct');
  });

  it('queues the message when the recipient is not connected', () => {
    routeMessage('alice', { to: 'bob', header: { n: 0 }, ciphertext: 'ct', nonce: 'n' });

    expect(queuedCount('bob')).toBe(1);
  });

  it('delivers queued messages in order once the recipient connects', () => {
    routeMessage('alice', { to: 'bob', header: { n: 0 }, ciphertext: 'first', nonce: 'n1' });
    routeMessage('alice', { to: 'bob', header: { n: 1 }, ciphertext: 'second', nonce: 'n2' });

    const bobSocket = fakeSocket();
    deliverQueuedMessages('bob', bobSocket);

    expect(bobSocket.send).toHaveBeenCalledTimes(2);
    const first = JSON.parse((bobSocket.send as any).mock.calls[0][0]);
    const second = JSON.parse((bobSocket.send as any).mock.calls[1][0]);
    expect(first.payload.ciphertext).toBe('first');
    expect(second.payload.ciphertext).toBe('second');
    expect(queuedCount('bob')).toBe(0);
  });

  it('never inspects or transforms ciphertext/header content — passes it through byte-for-byte', () => {
    const bobSocket = fakeSocket();
    addConnection('bob', bobSocket);

    const opaqueHeader = { dhPublicKey: 'not-real-but-opaque', messageNumber: 7, previousChainLength: 3 };
    routeMessage('alice', { to: 'bob', header: opaqueHeader, ciphertext: 'unchanged-ciphertext', nonce: 'unchanged-nonce' });

    const sentPayload = JSON.parse((bobSocket.send as any).mock.calls[0][0]);
    expect(sentPayload.payload.header).toEqual(opaqueHeader);
    expect(sentPayload.payload.ciphertext).toBe('unchanged-ciphertext');
    expect(sentPayload.payload.nonce).toBe('unchanged-nonce');
  });
});
