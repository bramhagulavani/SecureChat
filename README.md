# SecureChat

End-to-end encrypted messaging app. See `docs/project-plan.md` for the full roadmap.

## Status: Phase 2 — Relay Server

Currently implemented:
- [x] Project structure
- [x] `crypto-core` package — identity keys, prekeys, HKDF, X3DH, Double Ratchet
      (with out-of-order handling), AEAD encryption. Full pipeline proven
      end-to-end. **42/42 tests passing.**
- [x] `server` package — HTTP registration + prekey-bundle API, WebSocket relay
      with offline message queuing. Never decrypts anything — doesn't even depend
      on `crypto-core`. **17/17 tests passing**, including real end-to-end tests
      with actual WebSocket clients against a real running server.
- [ ] Server auth (WebSocket identity is currently just a query param — documented,
      unresolved limitation, not safe for real users yet)
- [ ] Durable storage (server currently stores everything in memory)
- [ ] Key persistence on-device (crypto-core currently stores everything in memory)
- [ ] Mobile client

See `docs/crypto-spec.md` for exact scope, design rationale, and known limitations
of both packages.

## Packages

| Package | Purpose | Status |
|---|---|---|
| `crypto-core` | All cryptographic logic. No networking, no UI. | 42/42 tests passing |
| `server` | Relay server — routes ciphertext only, never decrypts. | 17/17 tests passing |
| `client-mobile` | React Native app (UI + local encrypted storage). | Not started |

## Getting Started

### crypto-core

```bash
cd crypto-core
npm install
npm test
```

### server

```bash
cd server
npm install
npm test        # runs the full test suite, including real client/server integration tests
npm run dev      # starts the server on http://localhost:3000 (WebSocket at /ws)
```

Quick manual check once it's running:
```bash
curl http://localhost:3000/health
```

## Security Principle

No custom cryptographic primitives are implemented from scratch. All encryption, key exchange, and signing operations use `libsodium` (via `libsodium-wrappers`), a widely audited library. See `docs/crypto-spec.md`.

The `server` package is architected so it cannot decrypt messages even if a bug were introduced: it never imports `crypto-core`, and only ever handles opaque base64 strings.
