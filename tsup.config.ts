import { readFileSync } from 'node:fs';
import { defineConfig } from 'tsup';

const { version } = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };
const define = { __PACKAGE_VERSION__: JSON.stringify(version) };

export default defineConfig([
  {
    // Portable core: no node: imports, network, clock, or environment access.
    entry: { index: 'src/index.ts' },
    format: ['esm'],
    platform: 'neutral',
    dts: true,
    clean: true,
    treeshake: true,
    sourcemap: true,
    target: 'es2022',
    define,
  },
  {
    // Node-only command-line shell around the core.
    entry: { cli: 'src/cli/main.ts' },
    format: ['esm'],
    platform: 'node',
    dts: false,
    clean: false,
    sourcemap: true,
    target: 'node22',
    banner: { js: '#!/usr/bin/env node' },
    define,
  },
]);
