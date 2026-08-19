/**
 * Metro config
 * ------------
 * crypto-core imports `libsodium-wrappers`, which is backed by WebAssembly.
 * React Native's JS engine (Hermes) doesn't support WASM, so that import
 * can't resolve as-is on-device — it works fine under Node (tests, the
 * server) but not in the RN bundle.
 *
 * Fix: alias `libsodium-wrappers` to `react-native-libsodium`, a
 * native-module package that implements the same function names and the
 * same `sodium.ready` pattern. crypto-core's source doesn't need to change
 * at all — every `import sodium from 'libsodium-wrappers'` call in
 * crypto-core resolves to the native binding instead, transparently.
 *
 * This is the same technique used in crypto-core/vitest.config.ts to work
 * around libsodium-wrappers' ESM packaging quirk — alias the import at the
 * bundler level rather than touching the library's own source.
 */

const path = require('path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

const defaultConfig = getDefaultConfig(__dirname);

const config = {
  resolver: {
    extraNodeModules: {
      'libsodium-wrappers': path.resolve(__dirname, 'node_modules/react-native-libsodium'),
    },
  },
};

module.exports = mergeConfig(defaultConfig, config);
