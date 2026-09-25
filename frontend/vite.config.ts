import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const target = process.env.VITE_API_TARGET ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true,
    port: 3000,
    proxy: { '/api': target, '/health': target },
  },
  preview: { port: 3000, proxy: { '/api': target, '/health': target } },
})
