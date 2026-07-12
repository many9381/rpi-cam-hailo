/// <reference types="vitest/config" />

import { configDefaults, defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

const productionCsp = "default-src 'self'; img-src 'self' blob:; " +
  "object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    ws: process.env.VITEST ? false : undefined,
    proxy: {
      '/api': {
        target: process.env.CF_WEB_API_TARGET ?? 'https://127.0.0.1:8443',
        secure: false,
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    headers: {
      'Content-Security-Policy': productionCsp,
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        chunkFileNames: 'app.js',
        inlineDynamicImports: true,
        assetFileNames: (asset) =>
          asset.name?.endsWith('.css') ? 'styles.css' : '[name][extname]',
        manualChunks: undefined,
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './vitest.setup.ts',
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
