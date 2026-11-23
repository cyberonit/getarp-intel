import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// "npm run dev" proxies the API to a local getarp API for development.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': { target: 'http://127.0.0.1:8000', ws: true } } },
  build: { sourcemap: false, chunkSizeWarningLimit: 400 },
})
