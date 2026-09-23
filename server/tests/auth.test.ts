import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { AddressInfo } from 'net';
import WebSocket from 'ws';
import http from 'http';
import nacl from 'tweetnacl';
import { startServer } from '../src/index';
import { reset as resetUsers, registerUser } from '../src/store/userStore';
import { reset as resetConnections } from '../src/ws/connectionManager';
import { reset as resetQueue } from '../src/store/messageQueue';
import { reset as resetChallenges, createChallenge, consumeChallenge } from '../src/auth/challengeStore';
import { verifyAuthSignature } from '../src/auth/verifySignature';

let server: http.Server;
let port: number;

beforeEach(async () => {
  resetUsers();
  resetConnections();
  resetQueue();
  resetChallenges();
  server = startServer(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function createTestUser(username: string) {
  const signKeyPair = nacl.sign.keyPair();
  const identitySigningPublicKey = Buffer.from(signKeyPair.publicKey).toString('base64');
  registerUser({
    username,
    identitySigningPublicKey,
    identityAgreementPublicKey: 'dummy-agreement-pub',
    signedPreKey: { keyId: 1, publicKey: 'dummy-spk', signature: 'dummy-sig' },
    oneTimePreKeys: [],
  });
  return { username, signKeyPair, identitySigningPublicKey };
}

describe('Server Authentication (signed-challenge)', () => {
  describe('challengeStore & verifySignature unit tests', () => {
    it('creates and consumes a valid challenge', () => {
      const challenge = createChallenge('user1');
      expect(typeof challenge).toBe('string');
      expect(challenge.length).toBeGreaterThan(0);

      const consumed = consumeChallenge('user1');
      expect(consumed).toBe(challenge);

      // Single-use: consuming again returns null (replay rejection)
      expect(consumeChallenge('user1')).toBeNull();
    });

    it('verifies a valid Ed25519 signature', () => {
      const keypair = nacl.sign.keyPair();
      const challenge = createChallenge('user2');
      const challengeBytes = Buffer.from(challenge, 'base64');
      const signature = nacl.sign.detached(challengeBytes, keypair.secretKey);

      const isValid = verifyAuthSignature(
        challenge,
        Buffer.from(signature).toString('base64'),
        Buffer.from(keypair.publicKey).toString('base64')
      );
      expect(isValid).toBe(true);
    });

    it('rejects a signature from the wrong keypair', () => {
      const keypair1 = nacl.sign.keyPair();
      const keypair2 = nacl.sign.keyPair();
      const challenge = createChallenge('user3');
      const challengeBytes = Buffer.from(challenge, 'base64');
      const signature = nacl.sign.detached(challengeBytes, keypair1.secretKey);

      const isValid = verifyAuthSignature(
        challenge,
        Buffer.from(signature).toString('base64'),
        Buffer.from(keypair2.publicKey).toString('base64') // wrong pubkey
      );
      expect(isValid).toBe(false);
    });
  });

  describe('HTTP challenge API & WebSocket upgrade verification', () => {
    it('issues a challenge via POST /users/:username/auth/challenge', async () => {
      createTestUser('alice');
      const res = await fetch(`http://127.0.0.1:${port}/users/alice/auth/challenge`, { method: 'POST' });
      expect(res.status).toBe(200);
      const data = (await res.json()) as { challenge: string };
      expect(typeof data.challenge).toBe('string');
    });

    it('returns 404 for challenge request on non-existent user', async () => {
      const res = await fetch(`http://127.0.0.1:${port}/users/nonexistent/auth/challenge`, { method: 'POST' });
      expect(res.status).toBe(404);
    });

    it('allows WebSocket connection with a valid signed challenge', async () => {
      const { username, signKeyPair } = createTestUser('alice');
      const challengeRes = await fetch(`http://127.0.0.1:${port}/users/${username}/auth/challenge`, { method: 'POST' });
      const { challenge } = (await challengeRes.json()) as { challenge: string };

      const sigBytes = nacl.sign.detached(Buffer.from(challenge, 'base64'), signKeyPair.secretKey);
      const signature = Buffer.from(sigBytes).toString('base64');

      const ws = new WebSocket(
        `ws://127.0.0.1:${port}/ws?username=${username}&signature=${encodeURIComponent(signature)}`
      );

      await new Promise<void>((resolve, reject) => {
        ws.once('open', () => resolve());
        ws.once('error', reject);
      });

      expect(ws.readyState).toBe(WebSocket.OPEN);
      ws.close();
    });

    it('rejects WebSocket connection without signature', async () => {
      createTestUser('alice');
      const ws = new WebSocket(`ws://127.0.0.1:${port}/ws?username=alice`);

      await expect(
        new Promise<void>((resolve, reject) => {
          ws.once('open', () => resolve());
          ws.once('error', reject);
        })
      ).rejects.toThrow();
    });

    it('rejects WebSocket connection with forged signature (impersonation protection)', async () => {
      createTestUser('alice');
      const impostor = nacl.sign.keyPair();

      const challengeRes = await fetch(`http://127.0.0.1:${port}/users/alice/auth/challenge`, { method: 'POST' });
      const { challenge } = (await challengeRes.json()) as { challenge: string };

      // Impostor signs Alice's challenge with impostor's key
      const sigBytes = nacl.sign.detached(Buffer.from(challenge, 'base64'), impostor.secretKey);
      const signature = Buffer.from(sigBytes).toString('base64');

      const ws = new WebSocket(
        `ws://127.0.0.1:${port}/ws?username=alice&signature=${encodeURIComponent(signature)}`
      );

      await expect(
        new Promise<void>((resolve, reject) => {
          ws.once('open', () => resolve());
          ws.once('error', reject);
        })
      ).rejects.toThrow();
    });

    it('rejects challenge replay on subsequent connection attempt', async () => {
      const { username, signKeyPair } = createTestUser('alice');
      const challengeRes = await fetch(`http://127.0.0.1:${port}/users/${username}/auth/challenge`, { method: 'POST' });
      const { challenge } = (await challengeRes.json()) as { challenge: string };

      const sigBytes = nacl.sign.detached(Buffer.from(challenge, 'base64'), signKeyPair.secretKey);
      const signature = Buffer.from(sigBytes).toString('base64');

      const wsUrl = `ws://127.0.0.1:${port}/ws?username=${username}&signature=${encodeURIComponent(signature)}`;

      // 1st connection succeeds (consumes challenge)
      const ws1 = new WebSocket(wsUrl);
      await new Promise<void>((resolve, reject) => {
        ws1.once('open', () => resolve());
        ws1.once('error', reject);
      });
      ws1.close();

      // 2nd connection with same signature fails because challenge was consumed
      const ws2 = new WebSocket(wsUrl);
      await expect(
        new Promise<void>((resolve, reject) => {
          ws2.once('open', () => resolve());
          ws2.once('error', reject);
        })
      ).rejects.toThrow();
    });
  });
});
