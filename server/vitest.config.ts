import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    env: { PHISHLENS_ENV: 'test' },
    coverage: {
      provider: 'v8',
      include: ['src/analyzers/**', 'src/engine/**', 'src/security/**', 'src/lib/**'],
      reporter: ['text', 'html'],
    },
  },
});
