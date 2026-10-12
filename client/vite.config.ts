import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: { '/api': { target: 'http://127.0.0.1:4000', changeOrigin: false } },
  },
  preview: { port: 4173, host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:4000' } },
  build: { sourcemap: false, target: 'es2022' },
  test: { include: ['src/**/*.test.ts'], environment: 'node' },
});
