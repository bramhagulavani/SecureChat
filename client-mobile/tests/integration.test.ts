import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import type http from 'http';
// @ts-ignore -- devDependency-only, test-time cross-package integration; see package.json note
import { startServer } from '@securechat/server/dist/index';
// @ts-ignore
import { reset as resetUsers } from '@securechat/server/dist/store/userStore';
// @ts-ignore
import { reset as resetQueue } from '@securechat/server/dist/store/messageQueue';
// @ts-ignore
import { reset as resetConnections } from '@securechat/server/dist/ws/connectionManager';
// @ts-ignore
import { reset as resetChallenges } from '@securechat/server/dist/auth/challengeStore';
import { generateLocalIdentity, buildRegistrationPayload, startConversation, acceptConversation, encryptText, decryptText, WireMessage } from '../src/services/cryptoService';
import { getSignedConnectionParams } from '../src/services/authService';
import { connect, RelayEnvelope } from '../src/services/socketService';

/**
 * The capstone test for this batch of work: boots a REAL server (the exact
 * same startServer used in production, from the server package) and drives
 * it using the mobile client's REAL auth and socket code — not mocks of
 * either side. If this passes, registration, signed-challenge auth,
 * WebSocket connection, and the full X3DH -> Double Ratchet -> AEAD crypto
 * pipeline all genuinely interoperate across the client/server boundary.
 */

let server: http.Server;
let port: number;
let httpBaseUrl: string;
let wsBaseUrl: string;

beforeEach(async () => {
  resetUsers();
  resetQueue();
  resetConnections();
  resetChallenges();
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

async function registerOnServer(username: string, local: Awaited<ReturnType<typeof generateLocalIdentity>>) {
  const payload = buildRegistrationPayload(username, local);
  const res = await fetch(`${httpBaseUrl}/users/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  expect(res.status).toBe(201);
  return payload;
}

describe('client-mobile <-> server integration', () => {
  it('registers, authenticates with a real signed challenge, and connects over a real WebSocket', async () => {
    const aliceUsername = uniqueUsername('alice');
    const alice = await generateLocalIdentity();
    await registerOnServer(aliceUsername, alice);

    const connectionParams = await getSignedConnectionParams(httpBaseUrl, aliceUsername, alice.identity);
    expect(connectionParams.username).toBe(aliceUsername);

    const received: RelayEnvelope[] = [];
    const aliceSocket = await connect(wsBaseUrl, connectionParams, (envelope) => received.push(envelope));

    expect(aliceSocket.socket.readyState).toBe(WebSocket.OPEN);
    aliceSocket.close();
  });

  it('rejects connecting with a forged signature (server verifyClient actually enforces this)', async () => {
    const aliceUsername = uniqueUsername('alice');
    const alice = await generateLocalIdentity();
    await registerOnServer(aliceUsername, alice);

    // Get a real challenge, but sign it with the WRONG identity's key.
    const impostor = await generateLocalIdentity();
    const params = await getSignedConnectionParams(httpBaseUrl, aliceUsername, impostor.identity);

    await expect(connect(wsBaseUrl, params, () => {})).rejects.toThrow();
  });

  it('completes the full pipeline end-to-end: register, auth, connect, and exchange a real encrypted message over the real relay', async () => {
    const aliceUsername = uniqueUsername('alice');
    const bobUsername = uniqueUsername('bob');
    const alice = await generateLocalIdentity();
    const bob = await generateLocalIdentity();
    await registerOnServer(aliceUsername, alice);
    const bobPayload = await registerOnServer(bobUsername, bob);

    // Alice fetches Bob's real published bundle from the real server.
    const bundleRes = await fetch(`${httpBaseUrl}/users/${bobUsername}/prekey-bundle`);
    expect(bundleRes.status).toBe(200);
    const bobBundle = await bundleRes.json();

    // Both connect over real, separately-authenticated WebSocket connections.
    const aliceParams = await getSignedConnectionParams(httpBaseUrl, aliceUsername, alice.identity);
    const bobParams = await getSignedConnectionParams(httpBaseUrl, bobUsername, bob.identity);

    const bobReceived: RelayEnvelope[] = [];
    const bobSocket = await connect(wsBaseUrl, bobParams, (envelope) => bobReceived.push(envelope));
    const aliceSocket = await connect(wsBaseUrl, aliceParams, () => {});

    // Real X3DH handshake against Bob's real published bundle.
    const started = await startConversation(alice.identity, bobBundle);
    const { wireMessage } = await encryptText(started.state, 'Hello Bob, this is really encrypted!');
    const firstMessage: Omit<WireMessage, 'to' | 'from'> = {
      ...wireMessage,
      header: { ...wireMessage.header, x3dhInit: started.x3dhInit },
    };

    aliceSocket.send(bobUsername, firstMessage);

    // Wait for Bob's socket to actually receive it over the real relay.
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timed out waiting for message')), 2000);
      const interval = setInterval(() => {
        if (bobReceived.length > 0) {
          clearInterval(interval);
          clearTimeout(timeout);
          resolve();
        }
      }, 20);
    });

    expect(bobReceived[0].type).toBe('message');
    const payload = bobReceived[0].payload!;
    expect(payload.from).toBe(aliceUsername);

    // Bob completes his side of X3DH using what actually arrived over the wire,
    // then decrypts using the real ratchet + AEAD.
    const aliceIdentityAgreementB64 = buildRegistrationPayload(aliceUsername, alice).identityAgreementPublicKey;
    const bobRatchetState = await acceptConversation(
      bob.identity,
      bob.signedPreKey,
      bob.oneTimePreKeys[0],
      aliceIdentityAgreementB64,
      payload.header.x3dhInit
    );
    const { plaintext } = await decryptText(bobRatchetState, payload);

    expect(plaintext).toBe('Hello Bob, this is really encrypted!');

    aliceSocket.close();
    bobSocket.close();
    void bobPayload; // registered but unused directly beyond the fetch call above
  });
});
