# Crypto Spec — SecureChat

## Implemented so far

### Identity Keys (`crypto-core/src/keys/identityKeys.ts`)
Each user has two keypairs at registration:
- **Signing key** — Ed25519 (`crypto_sign_keypair`). Used to sign prekey bundles so a
  man-in-the-middle can't swap in their own prekeys undetected.
- **Agreement key** — X25519 (`crypto_box_keypair`). Used for Diffie-Hellman key
  agreement in X3DH and later in the Double Ratchet.

We use two separate keypairs rather than one dual-purpose key (as Signal's XEdDSA does)
for simplicity and auditability. Trade-off: slightly larger identity bundle; benefit:
no custom signature-scheme conversion code to get wrong.

All primitives come from `libsodium-wrappers` — nothing here is hand-rolled.

## Coming next (Phase 1 continued)

- **X3DH** (`crypto-core/src/x3dh/x3dh.ts`): initial key agreement using identity key,
  signed prekey, and one-time prekey, producing a shared secret for the first message.
- **Double Ratchet** (`crypto-core/src/ratchet/doubleRatchet.ts`): per-message key
  evolution (symmetric-key ratchet) plus periodic DH ratchet steps, giving forward
  secrecy and post-compromise security.
- **Encryption primitives** (`crypto-core/src/encryption/`): AES-256-GCM or
  ChaCha20-Poly1305 for the actual message payload, keyed by ratchet output.

## Known packaging note

`libsodium-wrappers`' ESM build (`dist/modules-esm/`) has a relative import that only
resolves under bundler-style module resolution, not plain Node ESM. Vitest is
configured in `crypto-core/vitest.config.ts` to alias the package to its CommonJS
build instead, which resolves correctly. If the mobile client's bundler
(Metro/webpack) hits the same issue, apply the same alias there.
