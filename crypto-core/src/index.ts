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

// Coming in later phases:
// export * from './x3dh/x3dh';
// export * from './ratchet/doubleRatchet';
// export * from './encryption/aesGcm';
