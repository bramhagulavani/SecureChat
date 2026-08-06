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

export { hkdfBlake2b } from './encryption/hkdfBlake2b';

export { initiateX3DH, receiveX3DH } from './x3dh/x3dh';

export type { PreKeyBundle, KeyPair, X3DHInitiatorResult } from './x3dh/x3dh';

// Coming in later phases:
// export * from './ratchet/doubleRatchet';
// export * from './encryption/aesGcm';
