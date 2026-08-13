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
  to that side. It also handles **out-of-order and skipped messages**: if a header's
  message number is ahead of what's expected, the intermediate message keys are
  derived and cached (bounded — see below) rather than discarded, so a late-arriving
  earlier message can still be decrypted from the cache. This applies across a DH
  ratchet step too, using the header's `previousChainLength` field to know how many
  messages were left unreceived on the old chain before it was retired. A message
  number below what's expected and not found in the cache is treated as a
  duplicate/replay and rejected.
- Both the per-step skip count and the total cache size are bounded
  (`MAX_SKIP_PER_CHAIN_STEP`, `MAX_STORED_SKIPPED_KEYS` in `ratchetState.ts`), so a
  peer claiming a huge message-number jump can't force unbounded work or memory use.
- Verified in `tests/doubleRatchet.test.ts` (10 tests): matching keys between Alice
  and Bob, distinct keys per message (forward secrecy), staying in sync across
  several messages and across a direction flip, healing after a simulated key leak
  (post-compromise security), decrypting a message that arrives ahead of schedule,
  later decrypting an earlier message from the skipped-key cache, out-of-order
  delivery across a DH ratchet step, rejecting a replayed message, and rejecting an
  unreasonably large claimed gap.
- Produces *message keys* only, not ciphertext — see Message Cipher below.

### Message Cipher (`crypto-core/src/encryption/messageCipher.ts`)
AEAD encryption for individual message payloads, using XChaCha20-Poly1305 (IETF
variant) instead of AES-256-GCM. Two practical reasons: it's in
`libsodium-wrappers`' minimal build (no need for the larger "sumo" build, same
situation as HKDF/HMAC — see below), and its 24-byte nonce is large enough to
generate randomly per message with negligible collision risk — AES-GCM's 12-byte
nonce isn't, and would need a managed counter instead. Same AEAD security guarantees
either way; this is a practical substitution, not a downgrade. Verified in
`tests/messageCipher.test.ts` (7 tests): round-trip correctness, wrong key rejected,
tampered ciphertext rejected, tampered associated data rejected, wrong key length
rejected, and nonce/ciphertext uniqueness across repeated calls.

### Secure Message (`crypto-core/src/messaging/secureMessage.ts`)
Thin integration layer: `encryptSecureMessage` / `decryptSecureMessage` combine the
ratchet and the cipher into the two calls an application actually needs. The ratchet
header is deterministically serialized and passed as AEAD associated data, binding
the (necessarily unencrypted) header to the ciphertext — a tampered header fails
decryption rather than being silently accepted.

**This closes the loop**: `tests/secureMessage.test.ts` runs the complete pipeline —
identity keys → prekeys → X3DH → Double Ratchet → AEAD — and proves Alice can send a
real text message that Bob decrypts back to the exact same text, including a
multi-message back-and-forth conversation across a ratchet direction flip, and that
tampering with either the ciphertext or the header is detected and rejected.

## Coming next (Phase 1 wrap-up)

- **Key storage**: secure persistence of identity/prekey/ratchet state on-device
  (currently everything lives only in memory for the duration of a test/process).

## Phase 2: Relay Server (`server/`)

A real, tested HTTP + WebSocket server. Deliberately architected so it *cannot*
decrypt anything even if a bug were introduced: `server/package.json` does not
depend on `crypto-core` at all, and every field the server touches — keys,
signatures, ciphertext, nonces — is stored and forwarded as an opaque base64
string. Verified in 17 tests across three files, including two integration tests
that boot a real server and connect real WebSocket clients.

- **`store/userStore.ts`**: in-memory registration + prekey bundle storage. Each
  bundle fetch consumes (removes) one one-time prekey, mirroring the real X3DH flow;
  a bundle with no one-time prekeys left still works (X3DH degrades gracefully).
  Placeholder for a real database — the interface is narrow enough that swapping in
  Postgres later shouldn't require touching the API layer.
- **`store/messageQueue.ts`**: in-memory per-recipient queue for offline delivery.
  Also a placeholder for durable storage (messages currently don't survive a restart).
- **`ws/connectionManager.ts`**: tracks which usernames have an open socket.
- **`ws/messageRouter.ts`**: the actual relay — forwards to a connected recipient
  immediately, or queues for later. Only ever touches `from`/`to` routing metadata
  and passes `header`/`ciphertext`/`nonce` through untouched; verified directly by a
  test asserting byte-for-byte pass-through.
- **`api/users.routes.ts`**: `POST /users/register`, `GET /users/:username/prekey-bundle`,
  `POST /users/:username/prekeys` (replenishment).
- **`index.ts` / `app.ts`**: wires HTTP + WebSocket onto one server; `app.ts` is
  separated out so tests can exercise the Express app directly via `supertest`
  without binding a real port.

**Documented limitation, not yet solved**: WebSocket identity is just a
`?username=` query param with no authentication. Fine for local dev and these
tests; anyone could claim any username in a real deployment. Needs a signed
challenge or session token before this goes near real users — flagged clearly in
`index.ts`'s docstring so it isn't missed.

## Coming after that (Phase 2 wrap-up)

- **Server auth**: replace the bare `?username=` WebSocket identification with a
  signed challenge or session token issued at registration.
- **Durable storage**: swap the in-memory user store and message queue for a real
  database (Postgres, per the original plan) so data survives a restart.
- **Mobile client integration**: wire `crypto-core` into `client-mobile`, local
  encrypted message storage, the actual chat UI, and connect it to this server.

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
