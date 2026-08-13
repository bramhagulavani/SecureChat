import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import { reset } from '../src/store/userStore';

describe('User & Prekey API', () => {
  beforeEach(() => {
    reset();
  });

  const validRegisterBody = {
    username: 'alice',
    identitySigningPublicKey: 'base64-signing-pub',
    identityAgreementPublicKey: 'base64-agreement-pub',
    signedPreKey: {
      keyId: 1,
      publicKey: 'base64-spk-pub',
      signature: 'base64-spk-sig',
    },
    oneTimePreKeys: [
      { keyId: 1, publicKey: 'base64-otk-1' },
      { keyId: 2, publicKey: 'base64-otk-2' },
    ],
  };

  it('registers a new user successfully', async () => {
    const app = createApp();
    const res = await request(app).post('/users/register').send(validRegisterBody);

    expect(res.status).toBe(201);
    expect(res.body.username).toBe('alice');
  });

  it('rejects registering the same username twice', async () => {
    const app = createApp();
    await request(app).post('/users/register').send(validRegisterBody);
    const res = await request(app).post('/users/register').send(validRegisterBody);

    expect(res.status).toBe(409);
  });

  it('rejects registration with a missing required field', async () => {
    const app = createApp();
    const { signedPreKey, ...incomplete } = validRegisterBody;
    void signedPreKey;

    const res = await request(app).post('/users/register').send(incomplete);

    expect(res.status).toBe(400);
  });

  it('fetches a prekey bundle for a registered user, consuming one one-time prekey', async () => {
    const app = createApp();
    await request(app).post('/users/register').send(validRegisterBody);

    const res = await request(app).get('/users/alice/prekey-bundle');

    expect(res.status).toBe(200);
    expect(res.body.username).toBe('alice');
    expect(res.body.signedPreKey.publicKey).toBe('base64-spk-pub');
    expect(res.body.oneTimePreKey.publicKey).toBe('base64-otk-1');
  });

  it('hands out a different one-time prekey on each subsequent fetch', async () => {
    const app = createApp();
    await request(app).post('/users/register').send(validRegisterBody);

    const first = await request(app).get('/users/alice/prekey-bundle');
    const second = await request(app).get('/users/alice/prekey-bundle');

    expect(first.body.oneTimePreKey.keyId).toBe(1);
    expect(second.body.oneTimePreKey.keyId).toBe(2);
  });

  it('returns a bundle with no one-time prekey once the pool is exhausted', async () => {
    const app = createApp();
    await request(app).post('/users/register').send(validRegisterBody);

    await request(app).get('/users/alice/prekey-bundle');
    await request(app).get('/users/alice/prekey-bundle');
    const third = await request(app).get('/users/alice/prekey-bundle');

    expect(third.status).toBe(200);
    expect(third.body.oneTimePreKey).toBeUndefined();
    // Identity + signed prekey are still there — X3DH can proceed without an OPK.
    expect(third.body.signedPreKey.publicKey).toBe('base64-spk-pub');
  });

  it('returns 404 for a prekey bundle request on an unregistered user', async () => {
    const app = createApp();
    const res = await request(app).get('/users/nobody/prekey-bundle');

    expect(res.status).toBe(404);
  });

  it('allows replenishing one-time prekeys for an existing user', async () => {
    const app = createApp();
    await request(app).post('/users/register').send(validRegisterBody);
    await request(app).get('/users/alice/prekey-bundle');
    await request(app).get('/users/alice/prekey-bundle');

    const res = await request(app)
      .post('/users/alice/prekeys')
      .send({ oneTimePreKeys: [{ keyId: 3, publicKey: 'base64-otk-3' }] });

    expect(res.status).toBe(200);
    expect(res.body.remaining).toBe(1);
  });

  it('returns 404 when replenishing prekeys for an unregistered user', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/users/nobody/prekeys')
      .send({ oneTimePreKeys: [{ keyId: 1, publicKey: 'x' }] });

    expect(res.status).toBe(404);
  });
});
