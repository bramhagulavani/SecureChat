
  import { describe, it, expect } from 'vitest';
  import { generateIdentityKeyPair } from '../src/keys/identityKeys';
  import { generateSignedPreKey, generateOneTimePreKeys } from '../src/keys/prekeys';
  import { initiateX3DH, receiveX3DH, PreKeyBundle } from '../src/x3dh/x3dh';

  /** Sets up Bob's identity + prekeys and the public bundle Alice would fetch from the server. */
  async function setupBob(withOneTimePreKey: boolean) {
    const identity = await generateIdentityKeyPair();
    const signedPreKey = await generateSignedPreKey(identity.signing.privateKey, 1);
    const oneTimePreKeys = withOneTimePreKey ? await generateOneTimePreKeys(1, 0) : [];
    const oneTimePreKey = oneTimePreKeys[0];

    const bundle: PreKeyBundle = {
      identitySigningPublicKey: identity.signing.publicKey,
      identityAgreementPublicKey: identity.agreement.publicKey,
      signedPreKeyId: signedPreKey.keyId,
      signedPreKeyPublicKey: signedPreKey.publicKey,
      signedPreKeySignature: signedPreKey.signature,
      ...(oneTimePreKey && {
        oneTimePreKeyId: oneTimePreKey.keyId,
        oneTimePreKeyPublicKey: oneTimePreKey.publicKey,
      }),
    };

    return { identity, signedPreKey, oneTimePreKey, bundle };
  }

  describe('X3DH', () => {
    it('initiator and recipient derive the same shared secret (with a one-time prekey)', async () => {
      const alice = await generateIdentityKeyPair();
      const bob = await setupBob(true);

      const aliceResult = await initiateX3DH(
        { publicKey: alice.agreement.publicKey, privateKey: alice.agreement.privateKey },
        bob.bundle
      );

      const bobSharedSecret = await receiveX3DH(
        { publicKey: bob.identity.agreement.publicKey, privateKey: bob.identity.agreement.privateKey },
        { publicKey: bob.signedPreKey.publicKey, privateKey: bob.signedPreKey.privateKey },
        { publicKey: bob.oneTimePreKey!.publicKey, privateKey: bob.oneTimePreKey!.privateKey },
        alice.agreement.publicKey,
        aliceResult.ephemeralPublicKey
      );

      expect(aliceResult.sharedSecret).toEqual(bobSharedSecret);
      expect(aliceResult.sharedSecret.length).toBe(32);
    });

    it('initiator and recipient derive the same shared secret (without a one-time prekey)', async () => {
      const alice = await generateIdentityKeyPair();
      const bob = await setupBob(false);

      const aliceResult = await initiateX3DH(
        { publicKey: alice.agreement.publicKey, privateKey: alice.agreement.privateKey },
        bob.bundle
      );

      const bobSharedSecret = await receiveX3DH(
        { publicKey: bob.identity.agreement.publicKey, privateKey: bob.identity.agreement.privateKey },
        { publicKey: bob.signedPreKey.publicKey, privateKey: bob.signedPreKey.privateKey },
        undefined,
        alice.agreement.publicKey,
        aliceResult.ephemeralPublicKey
      );

      expect(aliceResult.sharedSecret).toEqual(bobSharedSecret);
    });

    it('produces a different shared secret than a with-OPK handshake would (sanity check DH4 matters)', async () => {
      const alice = await generateIdentityKeyPair();
      const bobWith = await setupBob(true);

      const withOpk = await initiateX3DH(
        { publicKey: alice.agreement.publicKey, privateKey: alice.agreement.privateKey },
        bobWith.bundle
      );

      const bundleWithoutOpk: PreKeyBundle = {
        ...bobWith.bundle,
        oneTimePreKeyId: undefined,
        oneTimePreKeyPublicKey: undefined,
      };
      const withoutOpk = await initiateX3DH(
        { publicKey: alice.agreement.publicKey, privateKey: alice.agreement.privateKey },
        bundleWithoutOpk
      );

      expect(withOpk.sharedSecret).not.toEqual(withoutOpk.sharedSecret);
    });

    it('rejects a prekey bundle whose signed prekey signature does not verify', async () => {
      const alice = await generateIdentityKeyPair();
      const bob = await setupBob(true);
      const attacker = await generateIdentityKeyPair();

      // Attacker swaps in their own signed prekey but keeps Bob's claimed identity —
      // simulates a malicious/compromised server tampering with the published bundle.
      const forgedSignedPreKey = await generateSignedPreKey(attacker.signing.privateKey, 99);
      const tamperedBundle: PreKeyBundle = {
        ...bob.bundle,
        signedPreKeyPublicKey: forgedSignedPreKey.publicKey,
        signedPreKeySignature: forgedSignedPreKey.signature,
      };

      await expect(
        initiateX3DH(
          { publicKey: alice.agreement.publicKey, privateKey: alice.agreement.privateKey },
          tamperedBundle
        )
      ).rejects.toThrow(/signature verification failed/);
    });

    it('produces different shared secrets for two different initiators talking to the same recipient', async () => {
      const alice = await generateIdentityKeyPair();
      const carol = await generateIdentityKeyPair();
      const bob = await setupBob(false);

      const aliceResult = await initiateX3DH(
        { publicKey: alice.agreement.publicKey, privateKey: alice.agreement.privateKey },
        bob.bundle
      );
      const carolResult = await initiateX3DH(
        { publicKey: carol.agreement.publicKey, privateKey: carol.agreement.privateKey },
        bob.bundle
      );

      expect(aliceResult.sharedSecret).not.toEqual(carolResult.sharedSecret);
    });
  });
