# SecureChat

End-to-end encrypted messaging app. See `docs/project-plan.md` for the full roadmap.

## Status: Phase 3 — Mobile Client (in progress)

Currently implemented:
- [x] Project structure
- [x] `crypto-core` package — identity keys, prekeys, HKDF, X3DH, Double Ratchet
      (with out-of-order/skipped-message handling), AEAD encryption (XChaCha20-
      Poly1305). Full pipeline proven end-to-end. **42/42 tests passing.**
- [x] `server` package — HTTP registration + prekey-bundle API, WebSocket relay
      with offline message queuing, and signed-challenge authentication (proves
      ownership of an identity key before a connection is accepted — including
      tested impersonation and replay-attack rejection). Never decrypts
      anything — doesn't even depend on `crypto-core`. **35/35 tests passing**,
      including real end-to-end tests with actual WebSocket clients against a
      real running server.
- [x] `client-mobile` — crypto service layer bridging `crypto-core`'s raw bytes
      to the server's base64/JSON wire format (registration payloads, X3DH
      handshake init, encrypt/decrypt helpers), plus a Metro config aliasing
      `libsodium-wrappers` (WASM, unsupported by Hermes) to a native RN
      binding. **8/8 tests passing**, including a full simulated two-device
      message round-trip through the exact functions the app calls.
- [ ] Mobile UI/screens (onboarding, chat list, chat view) — not yet built
- [ ] On-device secure key/message persistence — not yet built
- [ ] Server auth session/reconnect handling (currently requires a fresh
      signed challenge per connection — a usability gap, not a security one)
- [ ] Durable server-side storage (currently in-memory only)

See `docs/crypto-spec.md` for exact scope, design rationale, and known limitations
of all three packages.

## Packages

| Package | Purpose | Status |
|---|---|---|
| `crypto-core` | All cryptographic logic. No networking, no UI. | 42/42 tests passing |
| `server` | Relay server — routes ciphertext only, never decrypts, requires signed-challenge auth to connect. | 35/35 tests passing |
| `client-mobile` | React Native app. Crypto/wire-format bridge built; UI and storage not yet started. | 8/8 tests passing |

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
npm test         # runs the full test suite, including real client/server integration tests
npm run dev       # starts the server on http://localhost:3000 (WebSocket at /ws)
```

Quick manual check once it's running:
```bash
curl http://localhost:3000/health
```

### client-mobile

The crypto/wire-format layer can be tested standalone under Node (no device or
simulator needed):

```bash
cd client-mobile
npm install
npm test
```

Running the actual app requires a configured React Native environment
(Android Studio / Xcode) and is not yet set up, since there's no UI to run.

## Security Principle

No custom cryptographic primitives are implemented from scratch. All encryption, key exchange, and signing operations use `libsodium` (via `libsodium-wrappers` on Node/server, `react-native-libsodium` on-device). See `docs/crypto-spec.md`.

The `server` package is architected so it cannot decrypt messages even if a bug were introduced: it never imports `crypto-core`, and only ever handles opaque base64 strings. WebSocket connections require a signed challenge proving ownership of the claimed identity's signing key before the upgrade is accepted.