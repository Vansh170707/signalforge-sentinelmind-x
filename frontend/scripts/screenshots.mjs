// Capture product screenshots for docs and the pitch deck (backend :8000 + frontend :3000 must be running).
// Usage: node scripts/screenshots.mjs [outDir]
import { chromium } from '@playwright/test'

const BASE = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:3000'
const API = process.env.API_URL ?? 'http://127.0.0.1:8000'
const out = process.argv[2] ?? '../docs/screenshots'
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const post = (p, body) => fetch(API + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }).then((r) => r.json())
const get = (p) => fetch(API + p).then((r) => r.json())

await post('/api/v1/stream/stop')
const load = await post('/api/v1/demo/load', { seed: 7, run_pipeline: true })
for (let i = 0; i < 120; i++) {
  const run = await get(`/api/v1/pipeline/${load.run_id}`)
  if (run.status === 'completed' || run.status === 'failed') break
  await sleep(500)
}
const top = (await get('/api/v1/incidents?page_size=1')).items[0].incident_id
await post(`/api/v1/incidents/${top}/brief`, {})

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 })
const shot = async (name, opts = {}) => { await page.screenshot({ path: `${out}/${name}.png`, ...opts }); console.log('saved', name) }

await page.goto(`${BASE}/`); await sleep(2500); await shot('01-command-center')
await page.goto(`${BASE}/incidents`); await sleep(2000); await shot('02-incident-queue')
await page.goto(`${BASE}/incidents/${top}`); await sleep(3000); await shot('03-incident-detail')
const graph = page.getByRole('heading', { name: 'Entity and attack graph' })
await graph.scrollIntoViewIfNeeded(); await sleep(2500)
await shot('04-incident-graph-timeline', { fullPage: false })
await page.locator('section', { has: graph }).screenshot({ path: `${out}/05-entity-graph.png` }); console.log('saved 05-entity-graph')
await page.goto(`${BASE}/evaluation`); await sleep(3000); await shot('06-evaluation-lab')
await page.goto(`${BASE}/live`); await sleep(800)
await page.getByRole('button', { name: 'Start live stream' }).first().click()
for (let i = 0; i < 120; i++) {
  const s = await get('/api/v1/stream/state')
  if (s.sim_time && s.sim_time.slice(11, 16) >= '04:40') break
  await sleep(250)
}
await sleep(1500); await shot('07-live-stream')
await post('/api/v1/stream/stop')
await page.goto(`${BASE}/incidents/${top}`); await sleep(2500)
await page.locator('button[title="Open source alert evidence"]').first().click(); await sleep(1200); await shot('08-evidence-drawer')
await browser.close()
