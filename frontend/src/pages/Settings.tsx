import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bot, Cpu, Database, RotateCcw, SlidersHorizontal, Upload } from 'lucide-react'
import { useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, Card, Chip, ErrorState, Loading } from '../components/ui'

const PROVIDER_ROLE: Record<string, string> = {
  jev: 'Typed triage decisions (Choice, Score, Noul). One request per incident, capped at 15% of risk.',
  mercury: 'Primary narrative brief. Diffusion LLM, strict JSON schema, about 3 s.',
  groq: 'Fallback briefs on GPT-OSS 120B, then 20B. Strict JSON schema.',
  gemini: 'Fallback briefs (3.8 Flash, then 3.1 Flash-Lite). Synthetic data only.',
  foundry: 'Optional Microsoft Foundry / Azure OpenAI provider (adapter ready).',
  template: 'Deterministic brief. Always available, no network.',
}

export default function Settings() {
  const qc = useQueryClient()
  const s = useQuery({ queryKey: ['settings'], queryFn: api.settings })
  const [seed, setSeed] = useState(7)
  const [viaSentinel, setViaSentinel] = useState(false)
  const load = useMutation({ mutationFn: () => api.loadDemo(seed, viaSentinel ? 'sentinel' : 'native'), onSuccess: () => qc.invalidateQueries() })
  const reset = useMutation({ mutationFn: api.resetDemo, onSuccess: () => qc.invalidateQueries() })
  const upload = useMutation({ mutationFn: (f: File) => api.upload(f), onSuccess: () => qc.invalidateQueries() })
  if (s.isLoading) return <Loading rows={8} />
  if (s.error) return <ErrorState error={s.error} onRetry={() => s.refetch()} />
  const v = s.data!
  return (
    <>
      <PageHeader eyebrow="Configure" title="Settings and data" subtitle="Provider routing, pipeline configuration, datasets and connectors." />
      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="AI providers" description={`Narrative order: ${v.narrative_order.join(' → ')}`} icon={Bot} bodyClass="p-0">
          <ul className="divide-y divide-line">
            {Object.entries(v.providers).map(([k, p]) => (
              <li key={k} className="flex items-start justify-between gap-4 px-5 py-4">
                <div className="min-w-0">
                  <div className="text-sm font-semibold capitalize text-fg">{k}</div>
                  <div className="mt-0.5 text-[13px] text-fg-subtle">{PROVIDER_ROLE[k]}</div>
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {Object.entries(p).filter(([kk]) => kk !== 'configured').map(([kk, vv]) => <Chip key={kk} mono>{kk}={String(vv)}</Chip>)}
                  </div>
                </div>
                <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${p.configured ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : 'bg-subtle text-fg-subtle ring-line'}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${p.configured ? 'bg-emerald-500' : 'bg-line-strong'}`} />
                  {p.configured ? 'Configured' : 'No key'}
                </span>
              </li>
            ))}
          </ul>
          <p className="border-t border-line px-5 py-3 text-xs text-fg-subtle">Keys live in server environment variables only and are never sent to the browser.</p>
        </Card>
        <div className="space-y-6">
          <Card title="Pipeline configuration" icon={SlidersHorizontal} bodyClass="p-0">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-line">
                {[
                  ...Object.entries(v.correlation).map(([k, x]) => [`correlation.${k}`, x]),
                  ['risk_config_version', v.risk_config_version],
                  ['prompt_version', v.prompt_version],
                  ['attack_catalog_version', v.attack_catalog_version],
                  ['database', v.database],
                ].map(([k, x]) => (
                  <tr key={String(k)}><td className="px-5 py-2.5 font-mono text-xs text-fg-subtle">{k}</td><td className="px-5 py-2.5 text-right font-mono text-[13px] font-medium text-fg">{String(x)}</td></tr>
                ))}
              </tbody>
            </table>
          </Card>
          <Card title="Demo dataset" description="Synthetic, labeled and reproducible. Alternate seeds test robustness." icon={Database}>
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-sm font-medium text-fg-2" htmlFor="seed">Seed</label>
              <input id="seed" type="number" value={seed} onChange={(e) => setSeed(Number(e.target.value))} className="h-9 w-24 rounded-lg border border-line-strong bg-white px-3 font-mono text-sm text-fg shadow-[var(--shadow-xs)]" />
              <Button variant="primary" icon={Database} onClick={() => load.mutate()} loading={load.isPending}>Generate and load</Button>
              <Button variant="danger" icon={RotateCcw} onClick={() => reset.mutate()} loading={reset.isPending}>Reset environment</Button>
            </div>
            <label className="mt-4 flex cursor-pointer items-start gap-2.5 rounded-lg border border-line bg-subtle/50 p-3 text-sm text-fg-2">
              <input type="checkbox" checked={viaSentinel} onChange={(e) => setViaSentinel(e.target.checked)} className="mt-0.5 h-4 w-4 accent-[#0f6cbd]" />
              <span><span className="font-semibold">Ingest through the Microsoft Sentinel connector.</span> Renders the corpus as SecurityAlert export rows first, then maps them back.</span>
            </label>
            {load.data && (
              <div className="mt-3 rounded-lg bg-brand-50/60 px-3 py-2 text-[13px] text-brand-800">
                Seed {load.data.seed}{load.data.via === 'sentinel' && ' via Sentinel connector'}: {load.data.batch.received.toLocaleString()} received, {load.data.batch.accepted.toLocaleString()} accepted, {load.data.batch.duplicates} duplicates, {load.data.batch.rejected} rejected
                {load.data.batch.converted_from_sentinel ? `, ${load.data.batch.converted_from_sentinel.toLocaleString()} mapped from SecurityAlert rows` : ''}.
                {load.data.rejected_rows.length > 0 && (
                  <ul className="mt-1.5 space-y-0.5 font-mono text-[11px] text-red-700">
                    {load.data.rejected_rows.map((r) => <li key={r.row_index}>row {r.row_index} {r.alert_id}: {r.errors.join('; ')}</li>)}
                  </ul>
                )}
              </div>
            )}
            {reset.isSuccess && <div className="mt-3 text-sm text-fg-subtle">Environment reset. AI caches were kept.</div>}
            {(load.error || reset.error) && <div className="mt-3"><ErrorState error={load.error ?? reset.error} /></div>}
          </Card>
          <Card title="Import alerts" description="JSONL, JSON or CSV. Microsoft Sentinel SecurityAlert exports (KQL results or Log Analytics responses) are detected automatically." icon={Upload}>
            <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-line-strong bg-subtle/40 px-6 py-8 text-center transition hover:border-brand-400 hover:bg-brand-50/40">
              <Upload className="h-6 w-6 text-brand-600" />
              <span className="mt-2 text-sm font-semibold text-fg">Choose a file to upload</span>
              <span className="text-xs text-fg-subtle">Run the pipeline afterwards</span>
              <input
                type="file"
                accept=".json,.jsonl,.csv"
                aria-label="Upload alerts file"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) upload.mutate(f); e.target.value = '' }}
                className="sr-only"
              />
            </label>
            {upload.isPending && <div className="mt-3 flex items-center gap-2 text-sm text-fg-subtle"><Cpu className="h-4 w-4 animate-pulse" /> Uploading and normalizing…</div>}
            {upload.data && (
              <div className="mt-3 text-[13px] text-fg-2">
                {upload.data.received.toLocaleString()} received · {upload.data.accepted.toLocaleString()} accepted · {upload.data.duplicates} duplicates · {upload.data.rejected} rejected
                {upload.data.converted_from_sentinel ? ` · ${upload.data.converted_from_sentinel.toLocaleString()} from Sentinel` : ''}
              </div>
            )}
            {upload.error && <div className="mt-3"><ErrorState error={upload.error} /></div>}
          </Card>
        </div>
      </div>
    </>
  )
}
