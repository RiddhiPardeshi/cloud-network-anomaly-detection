import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: 'localhost',  // Match the browser URL (localhost:3000)
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: false,  // Keep original origin (localhost)
        secure: false,
        ws: true,
      },
    },
  },
  build: {
    outDir: '../frontend/dist',
    emptyOutDir: true,
  },
});
