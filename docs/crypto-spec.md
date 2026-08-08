# Crypto Spec — SecureChat

## Implemented so far

### Identity Keys (`crypto-core/src/keys/identityKeys.ts`)
Each user has two keypairs at registration:
- **Signing key** — Ed25519 (`crypto_sign_keypair`). Used to sign prekey bundles so a
  man-in-the-middle can't swap in their own prekeys undetected.
- **Agreement key** — X25519 (`crypto_box_keypair`). Used for Diffie-Hellman key
  agreement in X3DH and the Double Ratchet.

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
improvised primitive. Also exports `keyedBlake2b`, the raw single-call PRF used
directly by the Double Ratchet's chain-key step.

### X3DH (`crypto-core/src/x3dh/x3dh.ts`)
Implements the Extended Triple Diffie-Hellman handshake: `initiateX3DH` (run by the
party starting a conversation) and `receiveX3DH` (run by the party who published the
prekey bundle) each independently compute 3-4 raw ECDH outputs and feed them through
HKDF to arrive at an identical shared secret — verified directly in
`tests/x3dh.test.ts`. `initiateX3DH` also verifies the recipient's signed-prekey
signature and throws if it doesn't match, refusing to proceed on a possible MITM.

This shared secret becomes the root key that seeds the Double Ratchet.

### Double Ratchet (`crypto-core/src/ratchet/`)
- `ratchetState.ts`: state types, DH keypair generation, and the two ratchet-specific
  KDFs — `kdfRootKey` (DH ratchet step, HKDF-BLAKE2b) and `kdfChainKey` (symmetric
  ratchet step: a single keyed-BLAKE2b call per message, using constant byte 0x01 to
  derive the message key and 0x02 to derive the next chain key, per the Signal
  spec's KDF_CK construction).
- `doubleRatchet.ts`: `initializeRatchetAsInitiator` / `initializeRatchetAsResponder`
  set up each side right after X3DH (Bob reuses his signed-prekey keypair as his
  starting ratchet key). `ratchetEncrypt` advances the sending chain by one message.
  `ratchetDecrypt` advances the receiving chain, automatically running a full DH
  ratchet step first whenever the incoming header carries a DH public key that's new
  to that side.
- Verified in `tests/doubleRatchet.test.ts` (6 tests): matching keys between Alice and
  Bob, distinct keys per message (forward secrecy), staying in sync across several
  messages and across a direction flip, and — the key property — a simulated leaked
  message key no longer matches anything produced after the next DH ratchet step
  (post-compromise "healing").
- Produces *message keys* only, not ciphertext — see "Coming next" below.

**Current, honestly-documented limitation**: this implementation assumes in-order
delivery within a chain. An out-of-order message currently causes `ratchetDecrypt` to
throw rather than being silently mishandled (covered by a dedicated test), but there
is no skipped-message-key store yet, so a message that's lost or arrives very late
can't currently be recovered. Real-world transport can reorder or drop messages, so
this needs to be solved — likely a bounded skipped-key cache, Signal-style — before
the ratchet goes into the actual client/server pipeline.

## Coming next (Phase 1 wrap-up)

- **AEAD encryption layer** (`crypto-core/src/encryption/`): take a message key from
  the ratchet and actually seal/open message content. Leading candidate:
  XChaCha20-Poly1305, since it's in `libsodium-wrappers`' minimal build (unlike
  AES-GCM) and its 24-byte nonce is large enough to generate randomly per message
  without a managed counter.
- **Skipped-message-key handling** in the ratchet, so out-of-order or delayed
  messages can still be decrypted — needed before Phase 2 wiring.

## Coming after that (Phase 2)

- **Relay server**: WebSocket connection manager + ciphertext-only message router,
  registration and prekey-bundle publishing API.
- **Mobile client integration**: wire `crypto-core` into `client-mobile`, local
  encrypted message storage, the actual chat UI.
- **Wire format**: define how a ratcheted message (header + ciphertext + nonce) gets
  serialized for transport and stored/retrieved from the relay.

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
