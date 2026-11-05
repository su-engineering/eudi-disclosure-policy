import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

const { version } = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };

export default defineConfig({
  define: { __PACKAGE_VERSION__: JSON.stringify(version) },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/cli/main.ts'],
      thresholds: { statements: 90, branches: 85, functions: 90, lines: 90 },
    },
  },
});
