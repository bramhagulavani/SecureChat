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

### Prekeys (`crypto-core/src/keys/prekeys.ts`)
- **Signed prekey**: a medium-term X25519 keypair signed by the identity signing key,
  so a malicious server can't substitute its own key into the handshake undetected.
  `verifySignedPreKey` must be called by any client consuming a bundle from the server.
- **One-time prekeys**: a batch of single-use X25519 keypairs, generated ahead of time
  and handed out one-per-handshake by the server. Adds forward secrecy to the very
  first message.

### HKDF (`crypto-core/src/encryption/hkdfBlake2b.ts`)
Standard HKDF-Extract-then-Expand (RFC 5869), built on keyed BLAKE2b
(`crypto_generichash`) rather than HMAC-SHA256. `libsodium-wrappers`' minimal build
doesn't include `crypto_auth_hmacsha256` — that only exists in the larger "sumo"
build — so we use libsodium's own recommended HMAC-equivalent (keyed BLAKE2b) as the
underlying PRF. HKDF is generic over the hash used; this is standard practice, not an
improvised primitive.

### X3DH (`crypto-core/src/x3dh/x3dh.ts`)
Implements the Extended Triple Diffie-Hellman handshake: `initiateX3DH` (run by the
party starting a conversation) and `receiveX3DH` (run by the party who published the
prekey bundle) each independently compute 3-4 raw ECDH outputs and feed them through
HKDF to arrive at an identical shared secret — verified directly in
`tests/x3dh.test.ts`. `initiateX3DH` also verifies the recipient's signed-prekey
signature and throws if it doesn't match, refusing to proceed on a possible MITM.

This shared secret becomes the root key that will seed the Double Ratchet.

## Coming next (Phase 1 continued)

- **Double Ratchet** (`crypto-core/src/ratchet/doubleRatchet.ts`): per-message key
  evolution (symmetric-key ratchet) plus periodic DH ratchet steps, giving forward
  secrecy and post-compromise security, seeded by the X3DH shared secret above.
- **Encryption primitives** (`crypto-core/src/encryption/`): AES-256-GCM or
  ChaCha20-Poly1305 for the actual message payload, keyed by ratchet output.

## Known packaging notes

- `libsodium-wrappers`' ESM build (`dist/modules-esm/`) has a relative import that
  only resolves under bundler-style module resolution, not plain Node ESM. Vitest is
  configured in `crypto-core/vitest.config.ts` to alias the package to its CommonJS
  build instead, which resolves correctly. If the mobile client's bundler
  (Metro/webpack) hits the same issue, apply the same alias there.
- `libsodium-wrappers` (the minimal build) excludes some functions present in the full
  API, notably `crypto_auth_hmacsha256` — see the HKDF note above. If a future phase
  needs a function that's missing, check whether it's a minimal-vs-sumo issue before
  assuming it's unavailable in libsodium generally.
- TypeScript 5.7+'s stricter `Uint8Array<TArrayBuffer>` generics can conflict with
  values coming back from `libsodium-wrappers`' typings (`Uint8Array<ArrayBufferLike>`
  vs the default `Uint8Array<ArrayBuffer>`). Where this bites, we work in a local
  `Bytes = Uint8Array<ArrayBufferLike>` alias internally and normalize at the function
  boundary — see `hkdfBlake2b.ts` for the pattern.
