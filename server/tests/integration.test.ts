import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import WebSocket from 'ws';
import http from 'http';
import { startServer } from '../src/index';
import { reset as resetUsers } from '../src/store/userStore';
import { reset as resetConnections } from '../src/ws/connectionManager';
import { reset as resetQueue } from '../src/store/messageQueue';

/**
 * These tests boot a real HTTP + WebSocket server on a random free port and
 * connect real `ws` clients to it — this is the closest thing to "does two
 * users actually talking over the network work" that we can verify without
 * a browser or a mobile client.
 */

let server: http.Server;
let port: number;

function wsUrl(username: string): string {
  return `ws://127.0.0.1:${port}/ws?username=${encodeURIComponent(username)}`;
}

function waitForOpen(socket: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.once('open', () => resolve());
    socket.once('error', reject);
  });
}

function waitForMessage(socket: WebSocket): Promise<any> {
  return new Promise((resolve) => {
    socket.once('message', (data) => resolve(JSON.parse(data.toString())));
  });
}

beforeEach(async () => {
  resetUsers();
  resetConnections();
  resetQueue();
  server = startServer(0); // port 0 = OS assigns a free port
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('relay server integration', () => {
  it('responds on the health check endpoint', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    expect(res.status).toBe(200);
  });

  it('relays a ciphertext message from one connected client to another in real time', async () => {
    const alice = new WebSocket(wsUrl('alice'));
    const bob = new WebSocket(wsUrl('bob'));
    await Promise.all([waitForOpen(alice), waitForOpen(bob)]);

    const received = waitForMessage(bob);
    alice.send(JSON.stringify({ to: 'bob', header: { n: 0 }, ciphertext: 'hello-bob-ciphertext', nonce: 'nonce123' }));

    const message = await received;
    expect(message.type).toBe('message');
    expect(message.payload.from).toBe('alice');
    expect(message.payload.ciphertext).toBe('hello-bob-ciphertext');

    alice.close();
    bob.close();
  });

  it('queues a message for an offline recipient and delivers it on connect', async () => {
    const alice = new WebSocket(wsUrl('alice'));
    await waitForOpen(alice);

    // Bob isn't connected yet.
    alice.send(JSON.stringify({ to: 'bob', header: { n: 0 }, ciphertext: 'queued-for-bob', nonce: 'n1' }));
    await new Promise((resolve) => setTimeout(resolve, 50)); // let the server process it

    const bob = new WebSocket(wsUrl('bob'));
    const received = waitForMessage(bob);
    await waitForOpen(bob);

    const message = await received;
    expect(message.payload.ciphertext).toBe('queued-for-bob');

    alice.close();
    bob.close();
  });

  it('completes a full registration + prekey-bundle-fetch + relay flow for two users', async () => {
    const registerAlice = await fetch(`http://127.0.0.1:${port}/users/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'alice',
        identitySigningPublicKey: 'alice-signing-pub',
        identityAgreementPublicKey: 'alice-agreement-pub',
        signedPreKey: { keyId: 1, publicKey: 'alice-spk-pub', signature: 'alice-spk-sig' },
        oneTimePreKeys: [{ keyId: 1, publicKey: 'alice-otk-1' }],
      }),
    });
    expect(registerAlice.status).toBe(201);

    const registerBob = await fetch(`http://127.0.0.1:${port}/users/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'bob',
        identitySigningPublicKey: 'bob-signing-pub',
        identityAgreementPublicKey: 'bob-agreement-pub',
        signedPreKey: { keyId: 1, publicKey: 'bob-spk-pub', signature: 'bob-spk-sig' },
        oneTimePreKeys: [{ keyId: 1, publicKey: 'bob-otk-1' }],
      }),
    });
    expect(registerBob.status).toBe(201);

    // Alice fetches Bob's bundle to start X3DH (real crypto happens client-side, in crypto-core).
    const bundleRes = await fetch(`http://127.0.0.1:${port}/users/bob/prekey-bundle`);
    const bundle = await bundleRes.json();
    expect(bundle.identityAgreementPublicKey).toBe('bob-agreement-pub');
    expect(bundle.oneTimePreKey.publicKey).toBe('bob-otk-1');

    // Now Alice sends Bob a message over the relay, as if it were real ratcheted ciphertext.
    const alice = new WebSocket(wsUrl('alice'));
    const bob = new WebSocket(wsUrl('bob'));
    await Promise.all([waitForOpen(alice), waitForOpen(bob)]);

    const received = waitForMessage(bob);
    alice.send(
      JSON.stringify({
        to: 'bob',
        header: { dhPublicKey: 'alice-ratchet-pub', messageNumber: 0, previousChainLength: 0 },
        ciphertext: 'real-ciphertext-would-go-here',
        nonce: 'real-nonce-would-go-here',
      })
    );

    const message = await received;
    expect(message.payload.ciphertext).toBe('real-ciphertext-would-go-here');

    alice.close();
    bob.close();
  });
});
