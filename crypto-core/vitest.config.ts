import { defineConfig } from 'vitest/config';
import path from 'path';

// libsodium-wrappers ships an ESM build whose relative import path only
// resolves correctly under bundler-style resolution, not plain Node ESM.
// We alias it to the CommonJS build, which works reliably everywhere
// (Node, Vitest, and — for the client — Metro/webpack via a similar alias).
export default defineConfig({
  resolve: {
    alias: {
      'libsodium-wrappers': path.resolve(
        __dirname,
        'node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js'
      ),
    },
  },
});
