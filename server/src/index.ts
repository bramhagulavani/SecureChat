/**
 * SecureChat Relay Server — entry point.
 *
 * Phase 1 (current): placeholder only.
 * Phase 2 will add:
 *   - WebSocket connection manager (src/ws/connectionManager.ts)
 *   - Ciphertext-only message router (src/ws/messageRouter.ts)
 *   - Registration / prekey publishing REST API (src/api/*)
 *
 * Security invariant for this whole package: no function in `server/`
 * should ever import a decryption routine from `crypto-core`. If you find
 * yourself needing one here, that's a sign the design has gone wrong.
 */

console.log('SecureChat relay server — scaffold only, not yet implemented.');
