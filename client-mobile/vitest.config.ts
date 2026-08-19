import { defineConfig } from 'vitest/config';
import path from 'path';

// Same libsodium-wrappers ESM workaround as crypto-core/vitest.config.ts.
// This only affects running tests under Node — the actual RN app uses the
// metro.config.js alias to react-native-libsodium instead.
export default defineConfig({
  resolve: {
    alias: {
      'libsodium-wrappers': path.resolve(
        __dirname,
        'node_modules/@securechat/crypto-core/node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js'
      ),
    },
  },
});
