/**
 * Signature Verification
 * ----------------------
 * Verifies Ed25519 detached signatures using tweetnacl (not libsodium-wrappers),
 * ensuring the server never requires libsodium and cannot accidentally reach
 * for any decryption routines.
 */

import nacl from 'tweetnacl';

/**
 * Verifies an Ed25519 signature over a base64-encoded challenge message.
 *
 * @param challengeBase64                 The base64 challenge string previously issued.
 * @param signatureBase64                 The base64 Ed25519 detached signature.
 * @param identitySigningPublicKeyBase64  The user's registered Ed25519 identity signing public key.
 */
export function verifyAuthSignature(
  challengeBase64: string,
  signatureBase64: string,
  identitySigningPublicKeyBase64: string
): boolean {
  try {
    const messageBytes = Buffer.from(challengeBase64, 'base64');
    const signatureBytes = Buffer.from(signatureBase64, 'base64');
    const publicKeyBytes = Buffer.from(identitySigningPublicKeyBase64, 'base64');

    if (signatureBytes.length !== nacl.sign.signatureLength) {
      return false;
    }
    if (publicKeyBytes.length !== nacl.sign.publicKeyLength) {
      return false;
    }

    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch {
    return false;
  }
}
