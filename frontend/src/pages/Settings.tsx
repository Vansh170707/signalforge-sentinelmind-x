import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, ErrorState, Loading, Panel } from '../components/ui'

const PROVIDER_ROLE: Record<string, string> = {
  jev: 'Paid typed decisions (Choice / Score / Noul) — one request per incident, capped at 15% of risk',
  gemini: 'Primary deep narrative (free tier, synthetic data only)',
  groq: 'Fast free fallback, strict JSON schema',
  foundry: 'Optional Microsoft Foundry / Azure OpenAI narrative provider',
  template: 'Deterministic, always-available fallback brief',
}

export default function Settings() {
  const qc = useQueryClient()
  const s = useQuery({ queryKey: ['settings'], queryFn: api.settings })
  const [seed, setSeed] = useState(7)
  const [viaSentinel, setViaSentinel] = useState(false)
  const load = useMutation({ mutationFn: () => api.loadDemo(seed, viaSentinel ? 'sentinel' : 'native'), onSuccess: () => qc.invalidateQueries() })
  const upload = useMutation({ mutationFn: (f: File) => api.upload(f), onSuccess: () => qc.invalidateQueries() })
  const reset = useMutation({ mutationFn: api.resetDemo, onSuccess: () => qc.invalidateQueries() })
  if (s.isLoading) return <Loading rows={6} />
  if (s.error) return <ErrorState error={s.error} onRetry={() => s.refetch()} />
  const v = s.data!
  return (
    <>
      <PageHeader title="Settings & Demo" subtitle="Provider routing, pipeline configuration and dataset controls." />
      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="AI providers" subtitle={`Narrative order: ${v.narrative_order.join(' → ')}`}>
          <ul className="divide-y divide-ink-800">
            {Object.entries(v.providers).map(([k, p]) => (
              <li key={k} className="flex items-start justify-between gap-4 py-3">
                <div>
                  <div className="font-mono text-sm font-semibold text-slate-100">{k}</div>
                  <div className="text-xs text-slate-500">{PROVIDER_ROLE[k]}</div>
                  <div className="mt-1 font-mono text-[11px] text-slate-400">
                    {Object.entries(p).filter(([kk]) => kk !== 'configured').map(([kk, vv]) => `${kk}=${String(vv)}`).join('  ')}
                  </div>
                </div>
                <span className={`shrink-0 rounded px-2 py-0.5 text-xs ring-1 ring-inset ${p.configured ? 'text-emerald-300 ring-emerald-500/30' : 'text-slate-500 ring-ink-600'}`}>
                  {p.configured ? 'configured' : 'no key'}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-slate-500">Keys are read from environment variables on the server only; never sent to the browser.</p>
        </Panel>
        <div className="space-y-6">
          <Panel title="Pipeline configuration">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-ink-800">
                {[
                  ...Object.entries(v.correlation).map(([k, x]) => [`correlation.${k}`, x]),
                  ['risk_config_version', v.risk_config_version],
                  ['prompt_version', v.prompt_version],
                  ['attack_catalog_version', v.attack_catalog_version],
                  ['database', v.database],
                ].map(([k, x]) => (
                  <tr key={String(k)}><td className="py-2 font-mono text-xs text-slate-400">{k}</td><td className="py-2 text-right font-mono text-slate-100">{String(x)}</td></tr>
                ))}
              </tbody>
            </table>
          </Panel>
          <Panel title="Demo dataset" subtitle="Synthetic, labeled, reproducible. Alternate seeds test robustness.">
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-sm text-slate-400" htmlFor="seed">Seed</label>
              <input id="seed" type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} className="w-24 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 font-mono text-sm text-slate-200" />
              <Button variant="primary" onClick={() => load.mutate()} disabled={load.isPending}>{load.isPending ? 'Loading…' : 'Generate & load'}</Button>
              <Button variant="danger" onClick={() => reset.mutate()} disabled={reset.isPending}>Reset environment</Button>
            </div>
            <label className="mt-3 flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={viaSentinel} onChange={(e) => setViaSentinel(e.target.checked)} className="accent-cyan-500" />
              Ingest through the Microsoft Sentinel connector (renders the corpus as SecurityAlert export rows first)
            </label>
            {load.data && (
              <div className="mt-3 text-sm text-slate-300">
                Seed {load.data.seed}{load.data.via === 'sentinel' && ' via Sentinel connector'}: {load.data.batch.received.toLocaleString()} received, {load.data.batch.accepted.toLocaleString()} accepted, {load.data.batch.duplicates} duplicates, {load.data.batch.rejected} rejected
                {load.data.batch.converted_from_sentinel ? `, ${load.data.batch.converted_from_sentinel.toLocaleString()} mapped from SecurityAlert rows` : ''}.
                <ul className="mt-2 space-y-1 font-mono text-[11px] text-rose-300/80">
                  {load.data.rejected_rows.map((r) => <li key={r.row_index}>row {r.row_index} {r.alert_id}: {r.errors.join('; ')}</li>)}
                </ul>
              </div>
            )}
            {reset.isSuccess && <div className="mt-3 text-sm text-slate-400">Environment reset.</div>}
            <div className="mt-5 border-t border-ink-700 pt-4">
              <div className="text-sm font-medium text-slate-200">Import alerts</div>
              <p className="mt-0.5 text-xs text-slate-500">
                JSONL, JSON or CSV. Microsoft Sentinel <span className="font-mono">SecurityAlert</span> exports (KQL results or Log Analytics API responses) are detected and mapped automatically. Run the pipeline afterwards.
              </p>
              <input
                type="file"
                accept=".json,.jsonl,.csv"
                aria-label="Upload alerts file"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) upload.mutate(f); e.target.value = '' }}
                className="mt-2 block text-sm text-slate-400 file:mr-3 file:rounded-lg file:border-0 file:bg-ink-700 file:px-3 file:py-1.5 file:text-sm file:text-slate-200 hover:file:bg-ink-600"
              />
              {upload.isPending && <div className="mt-2 text-sm text-slate-400">Uploading…</div>}
              {upload.data && (
                <div className="mt-2 text-sm text-slate-300">
                  {upload.data.received.toLocaleString()} received · {upload.data.accepted.toLocaleString()} accepted · {upload.data.duplicates} duplicates · {upload.data.rejected} rejected
                  {upload.data.converted_from_sentinel ? ` · ${upload.data.converted_from_sentinel.toLocaleString()} from Sentinel` : ''}
                </div>
              )}
              {upload.error && <div className="mt-2"><ErrorState error={upload.error} /></div>}
            </div>
            {(load.error || reset.error) && <div className="mt-3"><ErrorState error={load.error ?? reset.error} /></div>}
          </Panel>
        </div>
      </div>
    </>
  )
}
