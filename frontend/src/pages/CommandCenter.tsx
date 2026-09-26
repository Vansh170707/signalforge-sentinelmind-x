import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Boxes, ChevronRight, CircleCheck, Database, Filter, LoaderCircle, Siren, Sparkles, TriangleAlert } from 'lucide-react'
import { motion } from 'motion/react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, Card, Chip, CountUp, EmptyState, ErrorState, Item, Loading, RiskMeter, SEV_COLOR, SeverityBadge, StatCard, Stagger, ease, fmtTime } from '../components/ui'
import { STAGE_LABELS, usePipeline } from '../hooks/usePipeline'
import type { Overview, PipelineRun } from '../types/api'

const nf = new Intl.NumberFormat('en-US')
const PIPELINE_STEPS = ['loading_alerts', 'entities', 'correlation', 'anomaly', 'chain_mitre_risk', 'persisting', 'evaluation']
const SEV_ORDER = ['informational', 'low', 'medium', 'high', 'critical']

export default function CommandCenter() {
  const qc = useQueryClient()
  const overview = useQuery({ queryKey: ['overview'], queryFn: api.overview })
  const { current, running, start } = usePipeline()
  const load = useMutation({ mutationFn: () => api.loadDemo(7), onSuccess: () => qc.invalidateQueries() })
  const o = overview.data
  const hasAlerts = (o?.alerts ?? 0) > 0
  const hasIncidents = (o?.incidents ?? 0) > 0

  return (
    <>
      <PageHeader
        eyebrow="Security operations · synthetic demo tenant"
        title="Command Center"
        subtitle="From 10,000 alerts to the incidents that matter: correlated, risk-ranked and backed by evidence."
        actions={
          <>
            <Button icon={Database} onClick={() => load.mutate()} loading={load.isPending} disabled={running}>
              {load.isPending ? 'Generating 10k alerts…' : hasAlerts ? 'Reload demo data' : 'Load Demo'}
            </Button>
            <Button variant="primary" icon={Sparkles} onClick={() => start.mutate()} disabled={!hasAlerts || running || start.isPending}>
              {running ? 'Pipeline running…' : 'Run Intelligence Pipeline'}
            </Button>
          </>
        }
      />
      {(load.error || start.error) && <div className="mb-5"><ErrorState error={load.error ?? start.error} /></div>}
      {load.data && !running && !hasIncidents && (
        <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} className="mb-5 flex items-start gap-3 rounded-xl border border-brand-200 bg-brand-50/70 px-4 py-3 text-sm text-brand-800">
          <CircleCheck className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Loaded {nf.format(load.data.batch.received)} rows in {(load.data.duration_ms / 1000).toFixed(1)} s: {nf.format(load.data.batch.accepted)} accepted,
            {' '}{load.data.batch.duplicates} duplicates collapsed, {load.data.batch.rejected} malformed rows rejected with row-level errors. Run the pipeline next.
          </span>
        </motion.div>
      )}

      {current && <PipelineCard run={current} running={running} />}

      {overview.isLoading ? (
        <Loading rows={5} />
      ) : overview.error ? (
        <ErrorState error={overview.error} onRetry={() => overview.refetch()} />
      ) : !hasAlerts ? (
        <EmptyState icon={Database} title="No alerts loaded" action={<Button variant="primary" icon={Database} onClick={() => load.mutate()}>Load Demo</Button>}>
          Load the reproducible synthetic corpus: 10,000 alerts with six planted stories hidden in benign noise, with exact ground truth.
        </EmptyState>
      ) : (
        <Stagger className="space-y-6">
          <Item>
            <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
              <StatCard label="Raw alerts received" value={o!.received} icon={Database} hint={`${nf.format(o!.duplicates)} duplicates · ${o!.rejected} rejected`} />
              <StatCard label="Correlated incidents" value={hasIncidents ? o!.incidents : '—'} icon={Boxes} tone="brand" hint="explainable graph correlation" />
              <StatCard label="Critical & high" value={hasIncidents ? o!.critical_high : '—'} icon={Siren} tone="critical" hint="need attention now" />
              <StatCard label="Alert compression" value={o!.compression_ratio ?? '—'} decimals={2} suffix="×" icon={Filter} hint="alerts per incident" />
            </div>
          </Item>
          {hasIncidents && <Item><Funnel o={o!} /></Item>}
          <Item>
            <div className="grid gap-6 xl:grid-cols-[1.45fr_1fr]">
              <Card
                title="Priority queue"
                description="Highest-risk incidents right now"
                icon={TriangleAlert}
                bodyClass="p-2"
                actions={<Link to="/incidents" className="inline-flex items-center gap-1 text-[13px] font-semibold text-brand-600 hover:text-brand-700">View all <ArrowRight className="h-3.5 w-3.5" /></Link>}
              >
                {!hasIncidents ? (
                  <div className="p-3"><EmptyState icon={Sparkles} title="No incidents yet">Run the intelligence pipeline to correlate alerts into incidents.</EmptyState></div>
                ) : (
                  <Stagger>
                    {o!.top_incidents.map((i) => (
                      <Item key={i.incident_id}>
                        <Link to={`/incidents/${i.incident_id}`} className="group flex items-center gap-4 rounded-lg px-3 py-3 transition-colors hover:bg-subtle">
                          <span className="w-6 text-center text-[13px] font-medium text-fg-faint">{i.rank}</span>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={i.severity} size="sm" />
                              <span className="truncate text-sm font-semibold text-fg group-hover:text-brand-700">{i.title}</span>
                            </div>
                            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-subtle">
                              <span className="font-mono">{i.incident_id}</span>
                              <span>{i.alert_count} alerts</span>
                              <span>{fmtTime(i.first_seen)}</span>
                              {i.mitre_ids.slice(0, 3).map((t) => <Chip key={t} mono>{t}</Chip>)}
                            </div>
                          </div>
                          <RiskMeter score={i.risk_score} severity={i.severity} />
                          <ChevronRight className="h-4 w-4 text-fg-faint transition group-hover:translate-x-0.5 group-hover:text-brand-600" />
                        </Link>
                      </Item>
                    ))}
                  </Stagger>
                )}
              </Card>
              <Card title="Alert volume by hour" description="Raw alert severity mix across the day (UTC)">
                <div className="h-[300px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={o!.hourly} margin={{ left: -20, right: 4, top: 4 }} barCategoryGap={3}>
                      <CartesianGrid stroke="#eef0f3" vertical={false} />
                      <XAxis dataKey="hour" tick={{ fill: '#98a2b3', fontSize: 11 }} axisLine={false} tickLine={false} interval={2} />
                      <YAxis tick={{ fill: '#98a2b3', fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip cursor={{ fill: '#f2f4f7' }} contentStyle={{ borderRadius: 10, border: '1px solid #e4e7ec', boxShadow: '0 12px 16px -4px rgb(16 24 40 / 0.08)', fontSize: 12 }} />
                      {SEV_ORDER.map((s, i) => (
                        <Bar key={s} dataKey={s} stackId="a" fill={SEV_COLOR[s]} fillOpacity={s === 'informational' ? 0.45 : 0.9} radius={i === SEV_ORDER.length - 1 ? [3, 3, 0, 0] : 0} animationDuration={900} />
                      ))}
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-fg-subtle">
                  {SEV_ORDER.slice().reverse().map((s) => (
                    <span key={s} className="inline-flex items-center gap-1.5 capitalize"><span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLOR[s] }} />{s === 'informational' ? 'info' : s}</span>
                  ))}
                </div>
              </Card>
            </div>
          </Item>
        </Stagger>
      )}
    </>
  )
}

function PipelineCard({ run, running }: { run: PipelineRun; running: boolean }) {
  const failed = run.status === 'failed'
  const idx = run.stage === 'done' ? 5 : run.stage === 'jev_decisions' ? 6 : PIPELINE_STEPS.indexOf(run.stage)
  const stats = run.stats as { incidents?: number; runtime_ms?: number; candidate_pairs?: number; accepted_edges?: number; jev?: { ok?: number } }
  return (
    <div className={`mb-6 rounded-xl border bg-surface px-5 py-4 shadow-[var(--shadow-card)] ${failed ? 'border-red-200' : 'border-line'}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          {running ? <LoaderCircle className="h-4 w-4 animate-spin text-brand-600" /> : failed ? <TriangleAlert className="h-4 w-4 text-red-600" /> : <CircleCheck className="h-4 w-4 text-emerald-600" />}
          <span className="text-sm font-semibold text-fg">
            {running ? `Running · ${STAGE_LABELS[run.stage] ?? run.stage}` : failed ? 'Pipeline failed' : 'Pipeline complete'}
          </span>
          <span className="font-mono text-xs text-fg-faint">{run.run_id}</span>
        </div>
        {!running && !failed && stats.runtime_ms !== undefined && (
          <span className="text-[13px] text-fg-subtle">
            {nf.format(stats.candidate_pairs ?? 0)} candidate pairs → {nf.format(stats.accepted_edges ?? 0)} edges → <span className="font-semibold text-fg-2">{nf.format(stats.incidents ?? 0)} incidents</span> in {(stats.runtime_ms / 1000).toFixed(1)} s
            {stats.jev?.ok ? ` · ${stats.jev.ok} Jev decisions` : ''}
          </span>
        )}
      </div>
      {failed && <div className="mt-2 text-sm text-red-700">{run.error}</div>}
      <div className="mt-4 grid grid-cols-7 gap-2">
        {PIPELINE_STEPS.map((s, i) => {
          const done = (!running && !failed) || i < idx
          const active = running && i === idx
          return (
            <div key={s}>
              <div className="relative h-1.5 overflow-hidden rounded-full bg-muted">
                <motion.div
                  className={`absolute inset-y-0 left-0 rounded-full ${active ? 'bg-brand-400' : 'bg-brand-600'}`}
                  initial={false}
                  animate={{ width: done ? '100%' : active ? '60%' : '0%' }}
                  transition={{ duration: 0.5, ease }}
                />
              </div>
              <div className={`mt-1.5 hidden truncate text-[11px] font-medium sm:block ${active ? 'text-brand-700' : done ? 'text-fg-muted' : 'text-fg-faint'}`}>{STAGE_LABELS[s]}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function Funnel({ o }: { o: Overview }) {
  const steps = [
    { label: 'Raw alerts', value: o.received, note: 'from identity, endpoint, network, data and cloud tools' },
    { label: 'Unique alerts', value: o.alerts, note: 'validated, normalized, deduplicated' },
    { label: 'Incidents', value: o.incidents, note: 'graph-correlated with reasons' },
    { label: 'Worth a look', value: (o.incident_severity.medium ?? 0) + o.critical_high, note: 'medium and above' },
    { label: 'Act now', value: o.critical_high, note: 'critical and high' },
  ]
  const max = Math.log10(steps[0].value + 1)
  return (
    <Card title="Attention funnel" description="How the pipeline turns alert volume into analyst attention" bodyClass="px-5 pb-5 pt-4">
      <div className="grid grid-cols-5 items-end gap-2">
        {steps.map((s, i) => {
          const h = 36 + 110 * (Math.log10(s.value + 1) / max)
          const last = i === steps.length - 1
          return (
            <div key={s.label} className="flex flex-col">
              <div className="mb-2 flex items-baseline gap-1.5">
                <CountUp value={s.value} className={`tabular text-2xl font-semibold tracking-tight ${last ? 'text-red-600' : 'text-fg'}`} />
              </div>
              <div className="relative flex h-[146px] items-end">
                <motion.div
                  className="w-full rounded-lg"
                  style={{ background: last ? 'linear-gradient(180deg,#f97066,#d92d20)' : `linear-gradient(180deg, rgb(15 108 189 / ${0.35 + i * 0.12}), rgb(15 108 189 / ${0.55 + i * 0.1}))` }}
                  initial={{ height: 0 }}
                  animate={{ height: h }}
                  transition={{ duration: 0.8, delay: 0.08 * i, ease }}
                />
                {!last && <ChevronRight className="absolute -right-3.5 bottom-3 z-10 h-5 w-5 rounded-full bg-white text-fg-faint shadow-[var(--shadow-xs)] ring-1 ring-line" />}
              </div>
              <div className="mt-2.5 text-[13px] font-semibold text-fg-2">{s.label}</div>
              <div className="text-xs text-fg-subtle">{s.note}</div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}
