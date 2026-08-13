# SecureChat

End-to-end encrypted messaging app. See `docs/project-plan.md` for the full roadmap.

## Status: Phase 1 — Crypto Core

Currently implemented:
- [x] Project structure
- [x] `crypto-core` package scaffolded
- [x] Identity key generation (Ed25519 signing + X25519 key agreement pair) with tests
- [x] Prekeys (signed + one-time) with signature verification, with tests
- [x] HKDF-BLAKE2b key derivation, with tests
- [x] X3DH key exchange — initiator/recipient both derive the same shared secret, with tests
- [x] Double Ratchet — per-message key evolution + DH ratchet healing, with tests
- [x] Skipped-message-key handling — out-of-order/late messages decrypt correctly,
      bounded against DoS, with tests
- [x] AEAD message encryption (XChaCha20-Poly1305) with tests
- [x] Full pipeline proven end-to-end: X3DH → Double Ratchet → AEAD, real text
      message encrypted by Alice and decrypted correctly by Bob, with tests
- [ ] Key persistence (secure on-device storage)
- [ ] Server relay
- [ ] Mobile client

**42/42 tests passing** across `crypto-core`. The core crypto pipeline for 1:1
messaging — including out-of-order delivery — is functionally complete. Persistence,
networking, and UI remain.

## Packages

| Package | Purpose |
|---|---|
| `crypto-core` | All cryptographic logic. No networking, no UI. Fully unit tested in isolation. |
| `server` | Relay server — routes ciphertext only, never decrypts. |
| `client-mobile` | React Native app (UI + local encrypted storage). |

## Getting Started (crypto-core)

```bash
cd crypto-core
npm install
npm test
```

## Security Principle

No custom cryptographic primitives are implemented from scratch. All encryption, key exchange, and signing operations use `libsodium` (via `libsodium-wrappers`), a widely audited library. See `docs/crypto-spec.md`.
