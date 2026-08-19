/**
 * Base64
 * ------
 * crypto-core works entirely in raw bytes (Uint8Array). The server's HTTP
 * and WebSocket wire format is JSON, which can't carry raw bytes — so
 * every key, ciphertext, and nonce crossing that boundary needs to be
 * base64-encoded on the way out and decoded on the way in.
 *
 * Deliberately hand-rolled rather than relying on `Buffer` (not guaranteed
 * to exist in React Native without a polyfill) or `btoa`/`atob` (not
 * guaranteed in Hermes either). This keeps the function portable across
 * Node (tests) and the RN runtime (device) without depending on either
 * environment's globals.
 */

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToBase64(bytes: Uint8Array): string {
  let result = '';
  let i = 0;

  for (; i + 2 < bytes.length; i += 3) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    result +=
      CHARS[(chunk >> 18) & 0x3f] +
      CHARS[(chunk >> 12) & 0x3f] +
      CHARS[(chunk >> 6) & 0x3f] +
      CHARS[chunk & 0x3f];
  }

  const remaining = bytes.length - i;
  if (remaining === 1) {
    const chunk = bytes[i] << 16;
    result += CHARS[(chunk >> 18) & 0x3f] + CHARS[(chunk >> 12) & 0x3f] + '==';
  } else if (remaining === 2) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8);
    result += CHARS[(chunk >> 18) & 0x3f] + CHARS[(chunk >> 12) & 0x3f] + CHARS[(chunk >> 6) & 0x3f] + '=';
  }

  return result;
}

export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/=+$/, '');
  const bytes: number[] = [];
  let buffer = 0;
  let bitsCollected = 0;

  for (const char of clean) {
    const value = CHARS.indexOf(char);
    if (value === -1) {
      throw new Error(`base64ToBytes: invalid character "${char}"`);
    }
    buffer = (buffer << 6) | value;
    bitsCollected += 6;

    if (bitsCollected >= 8) {
      bitsCollected -= 8;
      bytes.push((buffer >> bitsCollected) & 0xff);
    }
  }

  return new Uint8Array(bytes);
}
