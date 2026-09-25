import { defineConfig } from '@playwright/test'

// Assumes backend on :8000 and frontend on :3000 are running (make backend / make frontend).
export default defineConfig({
  testDir: './tests',
  timeout: 90_000,
  use: { baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:3000', viewport: { width: 1440, height: 900 } },
})
