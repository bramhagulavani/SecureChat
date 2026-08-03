# SecureChat

End-to-end encrypted messaging app. See `docs/project-plan.md` for the full roadmap.

## Status: Phase 0 — Foundations

Currently implemented:
- [x] Project structure
- [x] `crypto-core` package scaffolded
- [x] Identity key generation (Ed25519 signing + X25519 key agreement pair) with tests
- [ ] X3DH key exchange
- [ ] Double Ratchet
- [ ] Server relay
- [ ] Mobile client

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
