/**
 * User & Prekey API
 * -----------------
 * Two things happen here:
 *   - Registration: a client publishes their identity keys, signed prekey,
 *     and a batch of one-time prekeys.
 *   - Bundle fetch: another client fetches that published material to run
 *     X3DH and start a conversation, even if the user is offline.
 *
 * Every field handled in this file is an opaque base64 string as far as the
 * server is concerned. Nothing here decodes key material into anything
 * meaningful — it's stored and handed back out unchanged. The server package
 * doesn't even depend on crypto-core, by design: it has no way to decrypt
 * anything even if this code had a bug.
 */

import { Router, Request, Response } from 'express';
import {
  registerUser,
  userExists,
  fetchAndConsumePreKeyBundle,
  addOneTimePreKeys,
  remainingOneTimePreKeyCount,
  SignedPreKeyRecord,
  OneTimePreKeyRecord,
} from '../store/userStore';

export const usersRouter = Router();

interface RegisterRequestBody {
  username: string;
  identitySigningPublicKey: string;
  identityAgreementPublicKey: string;
  signedPreKey: SignedPreKeyRecord;
  oneTimePreKeys: OneTimePreKeyRecord[];
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function validateRegisterBody(body: unknown): body is RegisterRequestBody {
  if (typeof body !== 'object' || body === null) return false;
  const b = body as Record<string, unknown>;

  if (!isNonEmptyString(b.username)) return false;
  if (!isNonEmptyString(b.identitySigningPublicKey)) return false;
  if (!isNonEmptyString(b.identityAgreementPublicKey)) return false;

  const spk = b.signedPreKey as Record<string, unknown> | undefined;
  if (!spk || typeof spk.keyId !== 'number' || !isNonEmptyString(spk.publicKey) || !isNonEmptyString(spk.signature)) {
    return false;
  }

  if (!Array.isArray(b.oneTimePreKeys)) return false;
  for (const otk of b.oneTimePreKeys) {
    if (typeof otk !== 'object' || otk === null) return false;
    const k = otk as Record<string, unknown>;
    if (typeof k.keyId !== 'number' || !isNonEmptyString(k.publicKey)) return false;
  }

  return true;
}

usersRouter.post('/register', (req: Request, res: Response) => {
  if (!validateRegisterBody(req.body)) {
    return res.status(400).json({ error: 'Invalid registration payload' });
  }

  const body = req.body as RegisterRequestBody;

  if (userExists(body.username)) {
    return res.status(409).json({ error: `Username "${body.username}" is already taken` });
  }

  registerUser({
    username: body.username,
    identitySigningPublicKey: body.identitySigningPublicKey,
    identityAgreementPublicKey: body.identityAgreementPublicKey,
    signedPreKey: body.signedPreKey,
    oneTimePreKeys: body.oneTimePreKeys,
  });

  return res.status(201).json({ username: body.username });
});

usersRouter.get('/:username/prekey-bundle', (req: Request, res: Response) => {
  const { username } = req.params;
  const bundle = fetchAndConsumePreKeyBundle(username);

  if (!bundle) {
    return res.status(404).json({ error: `User "${username}" not found` });
  }

  return res.status(200).json(bundle);
});

interface AddPreKeysRequestBody {
  oneTimePreKeys: OneTimePreKeyRecord[];
}

function validateAddPreKeysBody(body: unknown): body is AddPreKeysRequestBody {
  if (typeof body !== 'object' || body === null) return false;
  const b = body as Record<string, unknown>;
  if (!Array.isArray(b.oneTimePreKeys)) return false;
  for (const otk of b.oneTimePreKeys) {
    if (typeof otk !== 'object' || otk === null) return false;
    const k = otk as Record<string, unknown>;
    if (typeof k.keyId !== 'number' || !isNonEmptyString(k.publicKey)) return false;
  }
  return true;
}

usersRouter.post('/:username/prekeys', (req: Request, res: Response) => {
  const { username } = req.params;

  if (!userExists(username)) {
    return res.status(404).json({ error: `User "${username}" not found` });
  }
  if (!validateAddPreKeysBody(req.body)) {
    return res.status(400).json({ error: 'Invalid prekeys payload' });
  }

  addOneTimePreKeys(username, (req.body as AddPreKeysRequestBody).oneTimePreKeys);
  return res.status(200).json({ remaining: remainingOneTimePreKeyCount(username) });
});
