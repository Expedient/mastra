import { defineConfig } from 'vitest/config';

export default defineConfig({
  root: process.cwd(),
  test: {
    environment: 'node',
    include: ['packages/core/src/license/index.test.ts'],
    testTimeout: 120_000,
  },
});
