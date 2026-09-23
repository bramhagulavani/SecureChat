import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import WebSocket from 'ws';
import http from 'http';
import nacl from 'tweetnacl';
import { startServer } from '../src/index';
import { reset as resetUsers, registerUser } from '../src/store/userStore';
import { reset as resetConnections } from '../src/ws/connectionManager';
import { reset as resetQueue } from '../src/store/messageQueue';
import { reset as resetChallenges } from '../src/auth/challengeStore';

/**
 * These tests boot a real HTTP + WebSocket server on a random free port and
 * connect real `ws` clients to it using signed-challenge authentication.
 */

let server: http.Server;
let port: number;

beforeEach(async () => {
  resetUsers();
  resetConnections();
  resetQueue();
  resetChallenges();
  server = startServer(0); // port 0 = OS assigns a free port
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function registerAndConnect(username: string): Promise<{ ws: WebSocket; keypair: nacl.SignKeyPair }> {
  const keypair = nacl.sign.keyPair();
  const identitySigningPublicKey = Buffer.from(keypair.publicKey).toString('base64');

  registerUser({
    username,
    identitySigningPublicKey,
    identityAgreementPublicKey: 'dummy-agreement-pub',
    signedPreKey: { keyId: 1, publicKey: 'dummy-spk', signature: 'dummy-sig' },
    oneTimePreKeys: [{ keyId: 1, publicKey: 'dummy-otk-1' }],
  });

  const challengeRes = await fetch(`http://127.0.0.1:${port}/users/${username}/auth/challenge`, { method: 'POST' });
  const { challenge } = (await challengeRes.json()) as { challenge: string };

  const sigBytes = nacl.sign.detached(Buffer.from(challenge, 'base64'), keypair.secretKey);
  const signature = Buffer.from(sigBytes).toString('base64');

  const ws = new WebSocket(
    `ws://127.0.0.1:${port}/ws?username=${encodeURIComponent(username)}&signature=${encodeURIComponent(signature)}`
  );

  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  return { ws, keypair };
}

function waitForMessage(socket: WebSocket): Promise<any> {
  return new Promise((resolve) => {
    socket.once('message', (data) => resolve(JSON.parse(data.toString())));
  });
}

describe('relay server integration', () => {
  it('responds on the health check endpoint', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    expect(res.status).toBe(200);
  });

  it('relays a ciphertext message from one connected client to another in real time', async () => {
    const { ws: alice } = await registerAndConnect('alice');
    const { ws: bob } = await registerAndConnect('bob');

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
    const { ws: alice } = await registerAndConnect('alice');

    // Register Bob without connecting his socket yet
    const bobKeypair = nacl.sign.keyPair();
    const bobSigningPub = Buffer.from(bobKeypair.publicKey).toString('base64');
    registerUser({
      username: 'bob',
      identitySigningPublicKey: bobSigningPub,
      identityAgreementPublicKey: 'bob-agreement-pub',
      signedPreKey: { keyId: 1, publicKey: 'bob-spk', signature: 'bob-sig' },
      oneTimePreKeys: [],
    });

    // Alice sends to offline Bob
    alice.send(JSON.stringify({ to: 'bob', header: { n: 0 }, ciphertext: 'queued-for-bob', nonce: 'n1' }));
    await new Promise((resolve) => setTimeout(resolve, 50)); // let the server process it

    // Bob connects now
    const challengeRes = await fetch(`http://127.0.0.1:${port}/users/bob/auth/challenge`, { method: 'POST' });
    const { challenge } = (await challengeRes.json()) as { challenge: string };
    const sigBytes = nacl.sign.detached(Buffer.from(challenge, 'base64'), bobKeypair.secretKey);
    const signature = Buffer.from(sigBytes).toString('base64');

    const bob = new WebSocket(
      `ws://127.0.0.1:${port}/ws?username=bob&signature=${encodeURIComponent(signature)}`
    );

    const received = waitForMessage(bob);
    await new Promise<void>((resolve, reject) => {
      bob.once('open', () => resolve());
      bob.once('error', reject);
    });

    const message = await received;
    expect(message.payload.ciphertext).toBe('queued-for-bob');

    alice.close();
    bob.close();
  });

  it('completes a full registration + prekey-bundle-fetch + relay flow for two users', async () => {
    const aliceKeypair = nacl.sign.keyPair();
    const bobKeypair = nacl.sign.keyPair();

    const registerAlice = await fetch(`http://127.0.0.1:${port}/users/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'alice',
        identitySigningPublicKey: Buffer.from(aliceKeypair.publicKey).toString('base64'),
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
        identitySigningPublicKey: Buffer.from(bobKeypair.publicKey).toString('base64'),
        identityAgreementPublicKey: 'bob-agreement-pub',
        signedPreKey: { keyId: 1, publicKey: 'bob-spk-pub', signature: 'bob-spk-sig' },
        oneTimePreKeys: [{ keyId: 1, publicKey: 'bob-otk-1' }],
      }),
    });
    expect(registerBob.status).toBe(201);

    // Alice fetches Bob's bundle to start X3DH
    const bundleRes = await fetch(`http://127.0.0.1:${port}/users/bob/prekey-bundle`);
    const bundle = await bundleRes.json();
    expect(bundle.identityAgreementPublicKey).toBe('bob-agreement-pub');
    expect(bundle.oneTimePreKey.publicKey).toBe('bob-otk-1');

    // Both connect using signed challenges
    const aliceChalRes = await fetch(`http://127.0.0.1:${port}/users/alice/auth/challenge`, { method: 'POST' });
    const { challenge: aliceChal } = (await aliceChalRes.json()) as { challenge: string };
    const aliceSig = Buffer.from(
      nacl.sign.detached(Buffer.from(aliceChal, 'base64'), aliceKeypair.secretKey)
    ).toString('base64');

    const bobChalRes = await fetch(`http://127.0.0.1:${port}/users/bob/auth/challenge`, { method: 'POST' });
    const { challenge: bobChal } = (await bobChalRes.json()) as { challenge: string };
    const bobSig = Buffer.from(
      nacl.sign.detached(Buffer.from(bobChal, 'base64'), bobKeypair.secretKey)
    ).toString('base64');

    const alice = new WebSocket(
      `ws://127.0.0.1:${port}/ws?username=alice&signature=${encodeURIComponent(aliceSig)}`
    );
    const bob = new WebSocket(
      `ws://127.0.0.1:${port}/ws?username=bob&signature=${encodeURIComponent(bobSig)}`
    );

    await Promise.all([
      new Promise<void>((resolve, reject) => {
        alice.once('open', () => resolve());
        alice.once('error', reject);
      }),
      new Promise<void>((resolve, reject) => {
        bob.once('open', () => resolve());
        bob.once('error', reject);
      }),
    ]);

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
