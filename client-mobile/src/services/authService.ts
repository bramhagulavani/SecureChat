/**
 * Auth Service
 * ------------
 * Client-side half of the signed-challenge WebSocket auth flow implemented
 * in server/src/auth/. Mirrors server/src/index.ts's documented flow
 * exactly:
 *
 *   1. POST /users/:username/auth/challenge -> { challenge: base64 }
 *   2. Sign the challenge bytes with the identity SIGNING private key
 *      (never sent to the server).
 *   3. Build a WebSocket URL carrying ?username=X&signature=Y — the server
 *      verifies this during the upgrade itself (see socketService.ts).
 *
 * The challenge is single-use and short-lived (60s server-side), so
 * `getSignedConnectionParams` should be called fresh for every connection
 * attempt, not cached and reused — matching the documented limitation in
 * server/src/index.ts that there's no longer-lived session concept yet.
 */

import { signWithIdentityKey, IdentityKeyPair } from '@securechat/crypto-core';
import { bytesToBase64, base64ToBytes } from './base64';

export interface SignedConnectionParams {
  username: string;
  signature: string; // base64
}

/**
 * Requests a fresh challenge for `username` and signs it with the
 * identity's signing private key. Returns exactly what's needed to build
 * the WebSocket URL — see `buildWebSocketUrl` in socketService.ts.
 */
export async function getSignedConnectionParams(
  serverBaseUrl: string,
  username: string,
  identity: IdentityKeyPair
): Promise<SignedConnectionParams> {
  const challengeRes = await fetch(`${serverBaseUrl}/users/${encodeURIComponent(username)}/auth/challenge`, {
    method: 'POST',
  });

  if (!challengeRes.ok) {
    const body = await challengeRes.text();
    throw new Error(`Failed to fetch auth challenge (${challengeRes.status}): ${body}`);
  }

  const { challenge } = (await challengeRes.json()) as { challenge: string };
  const challengeBytes = base64ToBytes(challenge);

  const signature = await signWithIdentityKey(challengeBytes, identity.signing.privateKey);

  return { username, signature: bytesToBase64(signature) };
}
