import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bot, FlaskConical, Medal, Network, Play, Radar, Timer, TriangleAlert } from 'lucide-react'
import { motion } from 'motion/react'
import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, Card, Chip, CountUp, EmptyState, ErrorState, Item, Loading, Stagger, StatCard, ease, pct } from '../components/ui'
import type { DetectionMetrics, EvaluationResponse } from '../types/api'

export default function EvaluationLab() {
  const q = useQuery({ queryKey: ['evaluation'], queryFn: api.evaluation })
  if (q.isLoading) return <Loading rows={10} />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  const e = q.data!
  return (
    <>
      <PageHeader eyebrow="Assurance" title="Evaluation Lab" subtitle="Every number here is computed from labeled ground truth or measured live. Nothing is hard-coded." />
      {!e.available || !e.metrics ? <EmptyState icon={FlaskConical} title="No evaluation yet">{e.reason}</EmptyState> : <Metrics e={e} />}
      <div className="mt-6"><TriageExperiment /></div>
    </>
  )
}

const SCENARIO_LABEL: Record<string, string> = {
  privileged_account_compromise: 'Privileged account compromise (golden story)',
  dc_credential_theft_exfil: 'DC credential theft and exfiltration',
  password_spray: 'Password spray with successful sign-ins',
  impossible_travel_mailbox: 'Impossible travel and mailbox access',
  malicious_document_scripting: 'Malicious document scripting',
  benign_maintenance_critical_server: 'Approved maintenance on the finance server',
}

function Gauge({ label, value, hint }: { label: string; value: number | null | undefined; hint: string }) {
  const v = value ?? 0
  const r = 42
  const c = Math.PI * r
  return (
    <div className="flex flex-col items-center rounded-xl border border-line bg-surface px-4 pb-4 pt-5 shadow-[var(--shadow-card)]">
      <svg width="112" height="64" viewBox="0 0 112 64">
        <path d={`M 14 58 A ${r} ${r} 0 0 1 98 58`} fill="none" stroke="var(--color-muted)" strokeWidth="9" strokeLinecap="round" />
        <motion.path
          d={`M 14 58 A ${r} ${r} 0 0 1 98 58`}
          fill="none"
          stroke={v >= 0.95 ? '#079455' : v >= 0.8 ? '#0f6cbd' : '#ef6820'}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c * (1 - v) }}
          transition={{ duration: 1.1, ease }}
        />
      </svg>
      <CountUp value={v * 100} decimals={1} suffix="%" className="tabular -mt-3 text-2xl font-semibold tracking-tight text-fg" />
      <div className="mt-1 text-[13px] font-semibold text-fg-2">{label}</div>
      <div className="text-xs text-fg-subtle">{hint}</div>
    </div>
  )
}

function Metrics({ e }: { e: EvaluationResponse }) {
  const m = e.metrics!
  const c = m.correlation
  const p = m.priority
  const ruleF1 = m.detection.rules_only.f1
  const ifF1 = m.detection.rules_plus_isolation_forest.f1
  return (
    <Stagger className="space-y-6">
      <Item>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
          <Gauge label="Pairwise precision" value={c.pairwise_precision} hint="grouped pairs truly together" />
          <Gauge label="Pairwise recall" value={c.pairwise_recall} hint="true pairs grouped" />
          <Gauge label="Incident purity" value={c.incident_purity} hint="dominant ground-truth share" />
          <Gauge label="Top-3 critical recall" value={p.top3_critical_recall} hint="planted critical in top 3" />
          <Gauge label="Top-5 high+critical" value={p.top5_high_critical_recall} hint="planted high/critical" />
          <Gauge label="Benign kept below high" value={1 - p.false_high_rate} hint={`${p.false_high_count} of ${p.benign_incidents} false-high`} />
        </div>
      </Item>
      <Item>
        <div className="grid gap-6 xl:grid-cols-2">
          <Card title="Planted story ranks" description="Where each labeled story landed in the risk-ranked queue" icon={Medal}>
            <ul className="space-y-2.5">
              {p.planted_incident_ranks.map((r, i) => (
                <motion.li key={r.ground_truth_incident_id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.06, ease }} className="flex items-center gap-4 rounded-xl border border-line px-4 py-3">
                  <span className={`tabular flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-base font-semibold ${!r.malicious ? 'bg-emerald-50 text-emerald-700' : (r.rank ?? 99) <= 5 ? 'bg-brand-50 text-brand-700' : 'bg-subtle text-fg-muted'}`}>#{r.rank ?? '—'}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-semibold text-fg">{SCENARIO_LABEL[r.scenario] ?? r.scenario.replaceAll('_', ' ')}</div>
                    <div className="text-xs text-fg-subtle">expected priority: {r.expected_priority}</div>
                  </div>
                  {r.malicious ? <Chip tone="brand">attack</Chip> : <Chip tone="green">benign lookalike</Chip>}
                </motion.li>
              ))}
            </ul>
          </Card>
          <Card title="Correlation quality" description={`${c.alerts_evaluated?.toLocaleString()} alerts against ${c.ground_truth_incidents?.toLocaleString()} ground-truth incidents`} icon={Network}>
            <div className="grid grid-cols-2 gap-3">
              {[
                ['Pairwise F1', pct(c.pairwise_f1)],
                ['Over-merge rate', pct(c.over_merge_rate, 2)],
                ['Split rate', pct(c.split_rate, 2)],
                ['Singleton rate', pct(c.singleton_rate)],
                ['Generated incidents', c.generated_incidents?.toLocaleString()],
                ['Compression', `${c.compression_ratio}×`],
              ].map(([k, v]) => (
                <div key={k} className="rounded-xl bg-subtle/70 px-4 py-3">
                  <div className="text-xs text-fg-subtle">{k}</div>
                  <div className="tabular mt-0.5 text-lg font-semibold text-fg">{v}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </Item>
      <Item>
        <div className="grid gap-6 xl:grid-cols-2">
          <Card title="Anomaly detection" description="Alert level, threshold 0.5 against malicious labels" icon={Radar}>
            <div className="mb-5 flex items-end gap-6">
              {[['Rules only', ruleF1, '#98a2b3'], ['Rules + Isolation Forest', ifF1, '#0f6cbd']].map(([label, v, color]) => (
                <div key={label as string} className="flex-1">
                  <div className="mb-1.5 flex justify-between text-[13px]"><span className="font-medium text-fg-2">{label}</span><span className="tabular font-semibold text-fg">F1 {pct(v as number)}</span></div>
                  <div className="h-3 overflow-hidden rounded-full bg-muted">
                    <motion.div className="h-full rounded-full" style={{ background: color as string }} initial={{ width: 0 }} animate={{ width: `${(v as number) * 100}%` }} transition={{ duration: 0.9, ease }} />
                  </div>
                </div>
              ))}
            </div>
            <DetectionTable rows={[['Rules only', m.detection.rules_only], ['Rules + Isolation Forest', m.detection.rules_plus_isolation_forest]]} />
          </Card>
          <Card title="AI layer" description="Structured output, citation validity, decisions and runtime" icon={Bot}>
            <div className="grid grid-cols-2 gap-3">
              <StatCard label="Briefs generated" value={Number(m.llm.briefs ?? 0)} hint={`${m.llm.model_briefs ?? 0} by models · ${m.llm.template_fallbacks ?? 0} fallbacks`} />
              <StatCard label="Citation validity" value={m.llm.citation_validity_rate != null ? `${((m.llm.citation_validity_rate as number) * 100).toFixed(1)}%` : '—'} hint="every cited alert belongs to the incident" />
              <StatCard label="Jev decisions" value={Number(m.jev.decisions ?? 0)} hint={m.jev.median_latency_ms ? `median ${m.jev.median_latency_ms} ms` : 'none cached'} />
              <StatCard label="Pipeline runtime" value={m.runtime_ms.total ? `${(m.runtime_ms.total / 1000).toFixed(2)} s` : '—'} hint={`seed ${String(m.dataset.seed)} · ${String(m.dataset.dataset)}`} />
            </div>
          </Card>
        </div>
      </Item>
    </Stagger>
  )
}

function DetectionTable({ rows }: { rows: [string, DetectionMetrics][] }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="border-b border-line text-left text-xs text-fg-subtle">
          <th className="pb-2 font-medium">Model</th><th className="pb-2 text-right font-medium">Precision</th><th className="pb-2 text-right font-medium">Recall</th><th className="pb-2 text-right font-medium">F1</th><th className="pb-2 text-right font-medium">FPR</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {rows.map(([name, d]) => (
          <tr key={name}>
            <td className="py-2.5 font-medium text-fg-2">{name}</td>
            <td className="tabular py-2.5 text-right text-fg-muted">{pct(d.precision)}</td>
            <td className="tabular py-2.5 text-right text-fg-muted">{pct(d.recall)}</td>
            <td className="tabular py-2.5 text-right font-semibold text-fg">{pct(d.f1)}</td>
            <td className="tabular py-2.5 text-right text-fg-muted">{pct(d.false_positive_rate, 2)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function TriageExperiment() {
  const qc = useQueryClient()
  const eval_ = useQuery({ queryKey: ['evaluation'], queryFn: api.evaluation })
  const [participant, setParticipant] = useState('')
  const [mode, setMode] = useState<'baseline' | 'assisted'>('baseline')
  const [start, setStart] = useState<number | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const timer = useRef<number | null>(null)
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current) }, [])
  const save = useMutation({
    mutationFn: (correct: boolean) => api.addTrial({ participant: participant || 'anonymous', mode, seconds: Math.max(1, elapsed), correct }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['evaluation'] }); setStart(null); setElapsed(0) },
  })
  const begin = () => {
    const t = Date.now()
    setStart(t)
    setElapsed(0)
    if (timer.current) window.clearInterval(timer.current)
    timer.current = window.setInterval(() => setElapsed(Math.round((Date.now() - t) / 1000)), 250)
  }
  const stop = () => { if (timer.current) window.clearInterval(timer.current) }
  const s = eval_.data?.triage_experiment
  return (
    <Card title="Triage-time experiment" description="Task: find the highest-priority incident and explain why. A uses the raw Alert Explorer; B uses SentinelMind incidents. Medians are reported." icon={Timer}>
      <div className="grid gap-6 lg:grid-cols-[1fr_1.2fr]">
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <input value={participant} onChange={(e) => setParticipant(e.target.value)} placeholder="Participant name" className="h-9 rounded-lg border border-line-strong bg-white px-3 text-sm text-fg shadow-[var(--shadow-xs)] placeholder:text-fg-faint focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-100" />
            <div className="inline-flex rounded-lg bg-subtle p-1 ring-1 ring-inset ring-line">
              {(['baseline', 'assisted'] as const).map((m) => (
                <button key={m} onClick={() => setMode(m)} className={`relative rounded-md px-3 py-1 text-[13px] font-medium ${mode === m ? 'text-fg' : 'text-fg-subtle'}`}>
                  {mode === m && <motion.span layoutId="mode" className="absolute inset-0 rounded-md bg-white shadow-[var(--shadow-xs)]" transition={{ type: 'spring', stiffness: 500, damping: 38 }} />}
                  <span className="relative">{m === 'baseline' ? 'A · raw alerts' : 'B · SentinelMind'}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="tabular w-28 font-mono text-4xl font-semibold text-fg">{elapsed}s</div>
            {start === null ? <Button variant="primary" icon={Play} onClick={begin}>Start timer</Button> : (
              <>
                <Button onClick={() => { stop(); save.mutate(true) }} disabled={save.isPending}>Stop · correct</Button>
                <Button variant="danger" onClick={() => { stop(); save.mutate(false) }} disabled={save.isPending}>Stop · wrong</Button>
              </>
            )}
          </div>
          {save.error && <ErrorState error={save.error} />}
          {!s?.trials && <div className="flex items-start gap-2 text-xs text-fg-subtle"><TriangleAlert className="mt-0.5 h-3.5 w-3.5" />No trials yet. The pitch quotes a triage-time reduction only after real trials are recorded.</div>}
        </div>
        <div className="grid grid-cols-3 gap-3">
          <StatCard label="A · median" value={s?.baseline.median_seconds != null ? `${s.baseline.median_seconds.toFixed(0)}s` : '—'} hint={`n=${s?.baseline.n ?? 0} · accuracy ${pct(s?.baseline.accuracy ?? null, 0)}`} />
          <StatCard label="B · median" value={s?.assisted.median_seconds != null ? `${s.assisted.median_seconds.toFixed(0)}s` : '—'} hint={`n=${s?.assisted.n ?? 0} · accuracy ${pct(s?.assisted.accuracy ?? null, 0)}`} />
          <StatCard label="Reduction" value={s?.triage_reduction_pct != null ? `${s.triage_reduction_pct}%` : '—'} tone="brand" hint="measured, not assumed" />
        </div>
      </div>
    </Card>
  )
}
