# SecureChat

End-to-end encrypted messaging app. See [`docs/project-plan.md`](docs/project-plan.md)
for the broader roadmap and [`docs/crypto-spec.md`](docs/crypto-spec.md) for the
implemented cryptographic design.

## Status: Core Crypto, Relay Server, and State Store Complete

The repository contains a fully tested cryptographic core (X3DH + Double Ratchet + AEAD), an authenticated relay server (signed-challenge WebSocket auth), and the mobile client's complete service and state management layer (Zustand conversation store).

Implemented:
- [x] `crypto-core`: identity signing/agreement keys, signed and one-time prekeys,
      HKDF-BLAKE2b, X3DH, Double Ratchet state management (including out-of-order & skipped keys),
      XChaCha20-Poly1305 AEAD, and the secure-message pipeline (42/42 tests passing).
- [x] `server`: HTTP health, registration, prekey-bundle, replenishment, and signed-challenge auth
      endpoints (`POST /users/:username/auth/challenge`); WebSocket ciphertext relay with
      `tweetnacl` Ed25519 signature verification; offline message queuing (26/26 tests passing).
- [x] `client-mobile` service & state layer: base64 wire format, X3DH setup, message encryption/decryption,
      local identity & username storage, per-conversation ratchet state persistence, signed WebSocket auth,
      and the Zustand `conversationStore` managing the end-to-end messaging lifecycle (25/25 tests passing).
- [x] End-to-end integration coverage across all packages (93/93 passing automated tests).

Current limitations & remaining roadmap:
- [ ] The server stores users, prekeys, and queued messages in memory; state is lost on server restart (database backing needed for production).
- [ ] Mobile persistence currently uses AsyncStorage (in-memory adapter in Node tests). Long-term private identity keys need platform keystore/Secure Enclave (e.g. `react-native-keychain`).
- [ ] React Native UI screens (`OnboardingScreen`, `ChatListScreen`, `ChatScreen`, `ContactVerificationScreen`) and navigation remain to be built.

## Packages

| Package | Purpose | Validation |
|---|---|---|
| `crypto-core` | Cryptographic primitives and Double Ratchet messaging state. Pure, no I/O. | 42/42 tests passing (`tsc` build clean) |
| `server` | Opaque HTTP/WebSocket relay with signed-challenge authentication. | 26/26 tests passing (`tsc` build clean) |
| `client-mobile` | React Native service layer, local storage, and Zustand conversation store. | 25/25 tests passing (`tsc` build clean) |

## Getting Started

### crypto-core

```bash
cd crypto-core
npm install
npm test
npm run build
```

### server

```bash
cd server
npm install
npm test
npm run dev       # starts the server on http://localhost:3000 (WebSocket at /ws)
```

Quick manual check once it's running:
```bash
curl http://localhost:3000/health
```

### client-mobile

Install the package dependencies, then test the service layer under Node (no
device or simulator needed):

```bash
cd client-mobile
npm install
npm test
```

Running the actual app requires a configured React Native environment
(Android Studio / Xcode). No application screens are currently included.

## Security Principle

No custom cryptographic primitives are implemented from scratch. The crypto core
uses `libsodium-wrappers`; the mobile package is configured for
`react-native-libsodium` on-device. See `docs/crypto-spec.md`.

The `server` package cannot decrypt messages by design: it never imports
`crypto-core` and only handles opaque base64 strings plus routing metadata. Its
current WebSocket username check is suitable for local development only and must
be replaced with authenticated connection handling before a real deployment.