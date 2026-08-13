/**
 * User Store
 * ----------
 * In-memory storage for registered users and their published key material.
 * Everything here is opaque base64-encoded bytes as far as the server is
 * concerned — it never decodes them into anything meaningful, only stores
 * and hands them back out. That's on purpose: the server has no business
 * understanding key material, only routing it.
 *
 * This is intentionally a placeholder for a real database (Postgres, per
 * the project roadmap). The interface is kept narrow and storage-agnostic
 * so swapping the implementation later doesn't require touching the API
 * layer that calls it — see docs/crypto-spec.md's Phase 2 notes.
 */

export interface SignedPreKeyRecord {
  keyId: number;
  publicKey: string; // base64
  signature: string; // base64
}

export interface OneTimePreKeyRecord {
  keyId: number;
  publicKey: string; // base64
}

export interface UserRecord {
  username: string;
  identitySigningPublicKey: string; // base64
  identityAgreementPublicKey: string; // base64
  signedPreKey: SignedPreKeyRecord;
  oneTimePreKeys: OneTimePreKeyRecord[]; // consumed (removed) one at a time as bundles are fetched
}

export interface PreKeyBundleResponse {
  username: string;
  identitySigningPublicKey: string;
  identityAgreementPublicKey: string;
  signedPreKey: SignedPreKeyRecord;
  oneTimePreKey?: OneTimePreKeyRecord;
}

const users = new Map<string, UserRecord>();

export function reset(): void {
  users.clear();
}

export function userExists(username: string): boolean {
  return users.has(username);
}

export function registerUser(record: UserRecord): void {
  if (users.has(record.username)) {
    throw new Error(`User "${record.username}" is already registered`);
  }
  users.set(record.username, record);
}

/**
 * Returns a prekey bundle for the given username, consuming (removing) one
 * one-time prekey in the process if any are available. Returns null if the
 * user doesn't exist.
 */
export function fetchAndConsumePreKeyBundle(username: string): PreKeyBundleResponse | null {
  const user = users.get(username);
  if (!user) return null;

  const oneTimePreKey = user.oneTimePreKeys.shift(); // undefined if none left — X3DH still works without one

  return {
    username: user.username,
    identitySigningPublicKey: user.identitySigningPublicKey,
    identityAgreementPublicKey: user.identityAgreementPublicKey,
    signedPreKey: user.signedPreKey,
    oneTimePreKey,
  };
}

/** Adds more one-time prekeys to a user's pool (e.g. when running low). */
export function addOneTimePreKeys(username: string, keys: OneTimePreKeyRecord[]): void {
  const user = users.get(username);
  if (!user) {
    throw new Error(`Cannot add prekeys: user "${username}" not found`);
  }
  user.oneTimePreKeys.push(...keys);
}

export function remainingOneTimePreKeyCount(username: string): number {
  return users.get(username)?.oneTimePreKeys.length ?? 0;
}
