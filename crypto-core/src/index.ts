export {
  generateIdentityKeyPair,
  serializeIdentityKeyPair,
  deserializeIdentityKeyPair,
  signWithIdentityKey,
  verifyIdentitySignature,
} from './keys/identityKeys';

export type {
  IdentityKeyPair,
  SerializedIdentityKeyPair,
} from './keys/identityKeys';

export {
  generateSignedPreKey,
  verifySignedPreKey,
  generateOneTimePreKeys,
} from './keys/prekeys';

export type { SignedPreKeyPair, OneTimePreKeyPair } from './keys/prekeys';

export { hkdfBlake2b, keyedBlake2b } from './encryption/hkdfBlake2b';

export { initiateX3DH, receiveX3DH } from './x3dh/x3dh';

export type { PreKeyBundle, KeyPair, X3DHInitiatorResult } from './x3dh/x3dh';

export {
  initializeRatchetAsInitiator,
  initializeRatchetAsResponder,
  ratchetEncrypt,
  ratchetDecrypt,
} from './ratchet/doubleRatchet';

export type {
  RatchetState,
  DHKeyPair,
  RatchetHeader,
  RatchetSendResult,
  RatchetReceiveResult,
} from './ratchet/doubleRatchet';

export { encryptMessage, decryptMessage } from './encryption/messageCipher';
export type { EncryptedPayload } from './encryption/messageCipher';

export { encryptSecureMessage, decryptSecureMessage } from './messaging/secureMessage';
export type { SecureMessage, EncryptResult, DecryptResult } from './messaging/secureMessage';

// Coming in later phases:
// - Skipped-message-key handling for out-of-order delivery (ratchet)
// - Server relay integration
