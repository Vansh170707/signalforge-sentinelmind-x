import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import type { Overview } from '../types/api'
import { PageHeader } from '../components/Layout'
import { Button, EmptyState, ErrorState, Kpi, Loading, Panel, RiskPill, SEV_COLOR, SeverityBadge, fmtTime } from '../components/ui'
import { STAGE_LABELS, usePipeline } from '../hooks/usePipeline'

const nf = new Intl.NumberFormat('en-US')
const PIPELINE_STEPS = ['loading_alerts', 'entities', 'correlation', 'anomaly', 'chain_mitre_risk', 'persisting', 'evaluation']

export default function CommandCenter() {
  const qc = useQueryClient()
  const overview = useQuery({ queryKey: ['overview'], queryFn: api.overview })
  const { current, running, start } = usePipeline()
  const load = useMutation({
    mutationFn: () => api.loadDemo(7),
    onSuccess: () => qc.invalidateQueries(),
  })
  const o = overview.data
  const hasAlerts = (o?.alerts ?? 0) > 0
  const hasIncidents = (o?.incidents ?? 0) > 0

  return (
    <>
      <PageHeader
        title="Command Center"
        subtitle="From 10,000 alerts to the incidents that matter — correlated, risk-ranked and evidence-backed."
        actions={
          <>
            <Button size="lg" onClick={() => load.mutate()} disabled={load.isPending || running}>
              {load.isPending ? 'Generating 10k alerts…' : hasAlerts ? 'Reload Demo Data' : 'Load Demo'}
            </Button>
            <Button size="lg" variant="primary" onClick={() => start.mutate()} disabled={!hasAlerts || running || start.isPending}>
              {running ? 'Pipeline running…' : 'Run Intelligence Pipeline'}
            </Button>
          </>
        }
      />
      {load.error && <div className="mb-4"><ErrorState error={load.error} /></div>}
      {start.error && <div className="mb-4"><ErrorState error={start.error} /></div>}
      {load.data && !running && !hasIncidents && (
        <div className="mb-4 rounded-lg border border-cyan-500/25 bg-cyan-500/5 px-4 py-3 text-sm text-cyan-100">
          Loaded {nf.format(load.data.batch.received)} rows in {(load.data.duration_ms / 1000).toFixed(1)} s ·{' '}
          {nf.format(load.data.batch.accepted)} accepted · {load.data.batch.duplicates} duplicates collapsed ·{' '}
          {load.data.batch.rejected} malformed rows rejected with row-level errors. Now run the pipeline.
        </div>
      )}

      <PipelineProgress run={current} running={running} />

      {overview.isLoading ? (
        <Loading rows={4} />
      ) : overview.error ? (
        <ErrorState error={overview.error} onRetry={() => overview.refetch()} />
      ) : !hasAlerts ? (
        <EmptyState title="No alerts loaded" action={<Button variant="primary" onClick={() => load.mutate()}>Load Demo</Button>}>
          Load the reproducible synthetic corpus: 10,000 alerts with six planted stories hidden in benign noise and exact ground truth.
        </EmptyState>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Kpi label="Raw alerts received" value={nf.format(o!.received)} hint={`${nf.format(o!.duplicates)} dup · ${o!.rejected} rejected`} />
            <Kpi label="Unique alerts" value={nf.format(o!.alerts)} hint="normalized & enriched" />
            <Kpi label="Incidents" value={hasIncidents ? nf.format(o!.incidents) : '—'} hint="explainable correlation" tone="accent" />
            <Kpi label="Critical / High" value={hasIncidents ? o!.critical_high : '—'} hint="need attention now" tone="critical" />
            <Kpi label="Alert compression" value={o!.compression_ratio ? `${o!.compression_ratio}×` : '—'} hint="alerts per incident" />
            <Kpi label="Alerts per actionable" value={o!.alert_to_actionable_ratio ? nf.format(Math.round(o!.alert_to_actionable_ratio)) : '—'} hint="noise removed per critical/high" />
          </div>

          {hasIncidents && <Funnel o={o!} />}

          <div className="mt-6 grid gap-6 xl:grid-cols-[1.35fr_1fr]">
            <Panel title="Top incidents" subtitle="Risk-ranked queue head" actions={<Link to="/incidents" className="text-xs text-cyan-300 hover:underline">Open queue →</Link>} bodyClass="p-2">
              {!hasIncidents ? (
                <EmptyState title="No incidents yet">Run the intelligence pipeline to correlate alerts into incidents.</EmptyState>
              ) : (
                <ul className="divide-y divide-ink-800">
                  {o!.top_incidents.map((i) => (
                    <li key={i.incident_id}>
                      <Link to={`/incidents/${i.incident_id}`} className="group flex items-center gap-4 rounded-lg px-3 py-3 hover:bg-ink-800/60">
                        <span className="w-6 text-center font-mono text-xs text-slate-500">#{i.rank}</span>
                        <span className={i.severity === 'critical' ? 'pulse-critical rounded-md' : ''}><SeverityBadge severity={i.severity} /></span>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium text-slate-100 group-hover:text-cyan-200">{i.title}</div>
                          <div className="mt-0.5 flex flex-wrap gap-x-3 text-xs text-slate-500">
                            <span className="font-mono">{i.incident_id}</span>
                            <span>{i.alert_count} alerts</span>
                            <span>{fmtTime(i.first_seen)}</span>
                            {i.mitre_ids.slice(0, 3).map((t) => <span key={t} className="font-mono text-slate-400">{t}</span>)}
                          </div>
                        </div>
                        <RiskPill score={i.risk_score} severity={i.severity} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="Alert volume by hour (UTC)" subtitle="Raw alert severity mix across the day">
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={o!.hourly} margin={{ left: -18, right: 4, top: 4 }}>
                    <CartesianGrid stroke="#1d2a3e" vertical={false} />
                    <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: '#0b111b', border: '1px solid #2a3a53', borderRadius: 8, fontSize: 12 }} cursor={{ fill: '#141e2e' }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    {['informational', 'low', 'medium', 'high', 'critical'].map((s) => (
                      <Bar key={s} dataKey={s} stackId="a" fill={SEV_COLOR[s]} fillOpacity={s === 'informational' ? 0.5 : 0.9} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>
          </div>
        </>
      )}
    </>
  )
}

function PipelineProgress({ run, running }: { run: ReturnType<typeof usePipeline>['current']; running: boolean }) {
  if (!run) return null
  const failed = run.status === 'failed'
  const idx = run.stage === 'done' ? 5 : run.stage === 'jev_decisions' ? 6 : PIPELINE_STEPS.indexOf(run.stage)
  const stats = run.stats as { incidents?: number; runtime_ms?: number; candidate_pairs?: number; accepted_edges?: number }
  return (
    <div className={`mb-6 rounded-xl border px-4 py-3 ${failed ? 'border-rose-500/40 bg-rose-500/5' : 'border-ink-700 bg-ink-900/80'}`}>
      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${running ? 'animate-pulse bg-cyan-400' : failed ? 'bg-rose-500' : 'bg-emerald-400'}`} />
          <span className="font-semibold text-slate-200">
            {running ? `Running · ${STAGE_LABELS[run.stage] ?? run.stage}` : failed ? 'Pipeline failed' : 'Pipeline complete'}
          </span>
          <span className="font-mono text-xs text-slate-500">{run.run_id}</span>
        </div>
        {!running && !failed && stats.runtime_ms !== undefined && (
          <span className="text-xs text-slate-400">
            {nf.format(stats.candidate_pairs ?? 0)} candidate pairs → {nf.format(stats.accepted_edges ?? 0)} edges → {nf.format(stats.incidents ?? 0)} incidents in {(stats.runtime_ms / 1000).toFixed(1)} s
          </span>
        )}
      </div>
      {failed && <div className="mt-1 text-sm text-rose-200">{run.error}</div>}
      <div className="mt-3 grid grid-cols-7 gap-1.5">
        {PIPELINE_STEPS.map((s, i) => {
          const done = !running && !failed ? true : i < idx
          const active = running && i === idx
          return (
            <div key={s}>
              <div className={`h-1.5 rounded-full ${done ? 'bg-cyan-500' : active ? 'animate-pulse bg-cyan-400/70' : 'bg-ink-700'}`} />
              <div className={`mt-1 hidden truncate text-[10px] sm:block ${active ? 'text-cyan-300' : 'text-slate-500'}`}>{STAGE_LABELS[s]}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function Funnel({ o }: { o: Overview }) {
  const steps = [
    { label: 'raw alerts', value: o.received },
    { label: 'unique alerts', value: o.alerts },
    { label: 'incidents', value: o.incidents },
    { label: 'medium+ review', value: (o.incident_severity.medium ?? 0) + o.critical_high },
    { label: 'critical / high', value: o.critical_high },
  ]
  const max = steps[0].value || 1
  return (
    <div className="mt-6 rounded-xl border border-ink-700 bg-ink-900/80 p-4">
      <div className="mb-3 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-300">Attention funnel</div>
      <div className="grid gap-2">
        {steps.map((s, i) => (
          <div key={s.label} className="grid grid-cols-[130px_1fr_80px] items-center gap-3 text-sm">
            <span className="text-slate-400">{s.label}</span>
            <div className="h-6 overflow-hidden rounded bg-ink-800">
              <div
                className="h-full rounded"
                style={{
                  width: `${Math.max(0.8, (Math.log10(s.value + 1) / Math.log10(max + 1)) * 100)}%`,
                  background: i === steps.length - 1 ? 'var(--color-sev-critical)' : `rgb(34 211 238 / ${0.85 - i * 0.14})`,
                }}
              />
            </div>
            <span className="tabular text-right font-mono font-semibold text-slate-100">{nf.format(s.value)}</span>
          </div>
        ))}
      </div>
      <div className="mt-2 text-[11px] text-slate-500">Bar length on log scale.</div>
    </div>
  )
}
