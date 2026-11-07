import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    // Authentication and passkeys run on ratchetd's HTTPS origin. Build and
    // embed for end-to-end use; the Vite server is only a layout preview.
  },
});

