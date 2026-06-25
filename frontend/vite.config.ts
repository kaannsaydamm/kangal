import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    tailwindcss(),
    react()
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        // Vite runs in the `frontend` container; backend lives in `backend`.
        // In dev, allow override via env so the host can also proxy to localhost:8000.
        target: process.env.VITE_BACKEND_URL || 'http://backend:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: process.env.VITE_BACKEND_WS_URL || 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})