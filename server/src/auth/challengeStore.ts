/**
 * Challenge Store
 * ---------------
 * In-memory storage for WebSocket authentication challenges.
 *
 * Flow:
 *   1. Client calls POST /users/:username/auth/challenge.
 *   2. Server generates a random 32-byte challenge (Node built-in crypto,
 *      not libsodium — keeping libsodium out of the server) with a 60-second
 *      TTL and stores it here.
 *   3. Client signs the challenge with their identity signing private key.
 *   4. Client connects to WebSocket with ?username=...&signature=...
 *   5. Server consumes the challenge here (single-use: prevents replay)
 *      and verifies the signature.
 */

import crypto from 'crypto';

interface ChallengeRecord {
  challenge: string; // base64
  expiresAt: number;
}

const CHALLENGE_TTL_MS = 60 * 1000; // 60 seconds

const challenges = new Map<string, ChallengeRecord>();

export function reset(): void {
  challenges.clear();
}

/**
 * Creates and stores a fresh, random, single-use 32-byte challenge for the user.
 * Overwrites any previously issued unused challenge.
 */
export function createChallenge(username: string): string {
  const challenge = crypto.randomBytes(32).toString('base64');
  challenges.set(username, {
    challenge,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });
  return challenge;
}

/**
 * Consumes (retrieves and immediately removes) the active challenge for the user.
 * Returns null if no challenge exists or if the challenge has expired.
 */
export function consumeChallenge(username: string): string | null {
  const record = challenges.get(username);
  if (!record) return null;

  challenges.delete(username);

  if (Date.now() > record.expiresAt) {
    return null;
  }

  return record.challenge;
}
