SecureChat/
│
├── README.md
├── .gitignore
├── LICENSE
├── docs/
│   ├── project-plan.md               # the doc from before
│   ├── architecture.md
│   ├── crypto-spec.md                # X3DH + Double Ratchet notes
│   └── threat-model.md
│
├── crypto-core/                      # shared crypto logic (used by both client & server where needed)
│   ├── package.json
│   ├── src/
│   │   ├── keys/
│   │   │   ├── identityKeys.ts       # long-term identity keypair gen
│   │   │   ├── prekeys.ts            # signed prekeys, one-time prekeys
│   │   │   └── keyStorage.ts         # secure local key storage helpers
│   │   ├── x3dh/
│   │   │   └── x3dh.ts               # X3DH key agreement
│   │   ├── ratchet/
│   │   │   ├── doubleRatchet.ts      # Double Ratchet implementation
│   │   │   └── ratchetState.ts
│   │   ├── encryption/
│   │   │   ├── aesGcm.ts             # or chacha20poly1305.ts
│   │   │   └── signatures.ts         # Ed25519 sign/verify
│   │   └── index.ts                  # public exports
│   └── tests/
│       ├── x3dh.test.ts
│       ├── doubleRatchet.test.ts
│       └── encryption.test.ts
│
├── server/                           # relay server (never sees plaintext)
│   ├── package.json
│   ├── src/
│   │   ├── index.ts                  # entry point
│   │   ├── config/
│   │   │   └── env.ts
│   │   ├── ws/
│   │   │   ├── connectionManager.ts  # websocket connections
│   │   │   └── messageRouter.ts      # routes ciphertext, no decryption
│   │   ├── api/
│   │   │   ├── auth.routes.ts        # registration/login (key exchange bootstrap)
│   │   │   ├── prekeys.routes.ts     # publish/fetch prekey bundles
│   │   │   └── users.routes.ts
│   │   ├── db/
│   │   │   ├── schema.sql            # metadata only, no message content
│   │   │   └── models/
│   │   │       ├── User.ts
│   │   │       └── PrekeyBundle.ts
│   │   ├── middleware/
│   │   │   ├── rateLimiter.ts
│   │   │   └── errorHandler.ts
│   │   └── utils/logger.ts           # ensure this NEVER logs plaintext/keys
│   └── tests/
│
├── client-mobile/                    # React Native app
│   ├── package.json
│   ├── App.tsx
│   ├── src/
│   │   ├── screens/
│   │   │   ├── OnboardingScreen.tsx
│   │   │   ├── ChatListScreen.tsx
│   │   │   ├── ChatScreen.tsx
│   │   │   ├── ContactVerificationScreen.tsx  # safety number/fingerprint check
│   │   │   └── SettingsScreen.tsx
│   │   ├── components/
│   │   │   ├── MessageBubble.tsx
│   │   │   └── EncryptionStatusBadge.tsx
│   │   ├── services/
│   │   │   ├── cryptoService.ts      # wraps crypto-core for the app
│   │   │   ├── socketService.ts      # websocket client
│   │   │   └── localStorageService.ts # encrypted on-device DB (e.g. SQLCipher)
│   │   ├── state/                    # Redux/Zustand store
│   │   └── navigation/
│   └── tests/
│
├── client-web/                       # optional, if/when you add web support
│   └── (mirrors client-mobile structure, using Web Crypto API bindings)
│
├── scripts/
│   ├── setup-dev-env.sh
│   └── generate-test-keys.sh
│
└── .github/
    └── workflows/
        ├── ci.yml                    # lint, test, build
        └── security-scan.yml         # dependency/audit checks