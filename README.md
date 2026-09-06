# SecureChat

End-to-end encrypted messaging app. See [`docs/project-plan.md`](docs/project-plan.md)
for the broader roadmap and [`docs/crypto-spec.md`](docs/crypto-spec.md) for the
implemented cryptographic design.

## Status: Phase 3 foundation in progress

The repository currently contains a tested cryptographic core, an in-memory relay
server, and the mobile client's service layer. The React Native screens and a
production-ready persistence/authentication layer are still to be built.

Implemented:
- [x] `crypto-core`: identity signing/agreement keys, signed and one-time prekeys,
      HKDF-BLAKE2b, X3DH, Double Ratchet state management, XChaCha20-Poly1305,
      and the secure-message integration layer.
- [x] `server`: HTTP health, registration, prekey-bundle, and prekey-replenishment
      endpoints; WebSocket ciphertext relay; offline message queuing.
- [x] `client-mobile` service layer: base64 wire-format conversion, registration
      payloads, X3DH setup, message encryption/decryption helpers, local identity
      and ratchet-state serialization, and WebSocket URL/connection helpers.
- [x] End-to-end integration coverage exists for the client service layer and the
      server relay path.

Current limitations:
- [ ] Crypto-core has 30/32 tests passing. Two secure-message tests currently fail
      because the ratchet imports skipped-message-key helpers that are not exported
      by `ratchetState.ts`.
- [ ] The server stores users, prekeys, and queued messages in memory only; all
      state is lost on restart.
- [ ] WebSocket identity is currently taken from the `?username=` query parameter.
      The client has a signed-challenge helper, but the server does not yet expose
      or verify the corresponding challenge flow.
- [ ] Mobile persistence currently defaults to AsyncStorage (or an in-memory
      adapter in Node tests). Long-term private identity keys still need platform
      keystore/Secure Enclave storage.
- [ ] React Native UI screens, navigation, reconnect/backoff behavior, and message
      history are not implemented.
- [ ] The mobile package's dependencies must be installed before its Vitest suite
      can run in a fresh checkout.

## Packages

| Package | Purpose | Current validation |
|---|---|---|
| `crypto-core` | Cryptographic primitives and messaging state. No networking or UI. | 30/32 tests passing; 2 known failures above |
| `server` | Opaque HTTP/WebSocket relay with in-memory stores. | 17/17 tests passing |
| `client-mobile` | React Native service layer and persistence adapters. | 20 test cases defined; run after install |

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