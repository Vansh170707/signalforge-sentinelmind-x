import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, EmptyState, ErrorState, Kpi, Loading, Panel, pct } from '../components/ui'
import type { DetectionMetrics } from '../types/api'

export default function EvaluationLab() {
  const q = useQuery({ queryKey: ['evaluation'], queryFn: api.evaluation })
  if (q.isLoading) return <Loading rows={8} />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  const e = q.data!
  return (
    <>
      <PageHeader
        title="Evaluation Lab"
        subtitle="Every number below is computed from the labeled ground truth or measured — nothing is hard-coded."
      />
      {!e.available || !e.metrics ? (
        <EmptyState title="No evaluation yet">{e.reason}</EmptyState>
      ) : (
        <Metrics e={e} />
      )}
      <div className="mt-6"><TriageExperiment /></div>
    </>
  )
}

function Metrics({ e }: { e: NonNullable<Awaited<ReturnType<typeof api.evaluation>>> }) {
  const m = e.metrics!
  const c = m.correlation
  const p = m.priority
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Pairwise precision" value={pct(c.pairwise_precision)} hint="grouped pairs truly together" tone="accent" />
        <Kpi label="Pairwise recall" value={pct(c.pairwise_recall)} hint="true pairs grouped" tone="accent" />
        <Kpi label="Incident purity" value={pct(c.incident_purity)} hint="dominant GT share" />
        <Kpi label="Top-3 critical recall" value={pct(p.top3_critical_recall, 0)} hint="planted critical in top 3" tone="critical" />
        <Kpi label="Top-5 high+crit recall" value={pct(p.top5_high_critical_recall, 0)} hint="planted high/critical" />
        <Kpi label="False-high rate" value={pct(p.false_high_rate, 2)} hint={`${p.false_high_count} of ${p.benign_incidents} benign`} />
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Correlation quality" subtitle={`${c.alerts_evaluated?.toLocaleString()} alerts vs ${c.ground_truth_incidents?.toLocaleString()} ground-truth incidents`}>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-ink-800">
              {[
                ['Pairwise F1', pct(c.pairwise_f1)],
                ['Over-merge rate', pct(c.over_merge_rate, 2)],
                ['Split rate', pct(c.split_rate, 2)],
                ['Singleton rate', pct(c.singleton_rate)],
                ['Generated incidents', c.generated_incidents?.toLocaleString()],
                ['Compression ratio', `${c.compression_ratio}×`],
              ].map(([k, v]) => (
                <tr key={k}><td className="py-2 text-slate-400">{k}</td><td className="py-2 text-right font-mono text-slate-100">{v}</td></tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Planted incident ranks" subtitle="Where each labeled story landed in the risk-ranked queue">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-[11px] uppercase tracking-wide text-slate-500"><th className="pb-2 font-medium">Scenario</th><th className="pb-2 font-medium">Expected</th><th className="pb-2 text-right font-medium">Rank</th></tr></thead>
            <tbody className="divide-y divide-ink-800">
              {p.planted_incident_ranks.map((r) => (
                <tr key={r.ground_truth_incident_id}>
                  <td className="py-2 text-slate-200">{r.scenario.replaceAll('_', ' ')}{!r.malicious && <span className="ml-2 rounded bg-emerald-500/10 px-1.5 text-[10px] text-emerald-300">benign</span>}</td>
                  <td className="py-2 text-slate-400">{r.expected_priority}</td>
                  <td className="py-2 text-right font-mono text-lg font-semibold text-slate-50">#{r.rank ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Anomaly detection (alert level)" subtitle="Rules-only vs rules + Isolation Forest, threshold 0.5, malicious labels">
          <DetectionTable rows={[['Rules only', m.detection.rules_only], ['Rules + Isolation Forest', m.detection.rules_plus_isolation_forest]]} />
        </Panel>
        <Panel title="AI layer" subtitle="Structured output, citation validity, providers and runtime">
          <table className="w-full text-sm">
            <tbody className="divide-y divide-ink-800">
              {[
                ['Briefs generated', m.llm.briefs ?? 0],
                ['Model briefs (non-template)', m.llm.model_briefs ?? 0],
                ['Template fallbacks', m.llm.template_fallbacks ?? 0],
                ['Structured-output valid rate', pct(m.llm.structured_output_valid_rate as number | null)],
                ['Citation validity rate', pct(m.llm.citation_validity_rate as number | null)],
                ['Jev decisions (cached)', m.jev.decisions ?? 0],
                ['Jev median latency', m.jev.median_latency_ms ? `${m.jev.median_latency_ms} ms` : '—'],
                ['Pipeline runtime', m.runtime_ms.total ? `${(m.runtime_ms.total / 1000).toFixed(2)} s` : '—'],
              ].map(([k, v]) => (
                <tr key={String(k)}><td className="py-2 text-slate-400">{k}</td><td className="py-2 text-right font-mono text-slate-100">{String(v)}</td></tr>
              ))}
            </tbody>
          </table>
          <div className="mt-2 text-xs text-slate-500">Dataset {String(m.dataset.dataset)} · seed {String(m.dataset.seed)} · run {e.run_id}</div>
        </Panel>
      </div>
    </div>
  )
}

function DetectionTable({ rows }: { rows: [string, DetectionMetrics][] }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-[11px] uppercase tracking-wide text-slate-500">
          <th className="pb-2 font-medium">Model</th><th className="pb-2 text-right font-medium">Precision</th><th className="pb-2 text-right font-medium">Recall</th><th className="pb-2 text-right font-medium">F1</th><th className="pb-2 text-right font-medium">FPR</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-ink-800">
        {rows.map(([name, d]) => (
          <tr key={name}>
            <td className="py-2 text-slate-200">{name}</td>
            <td className="py-2 text-right font-mono">{pct(d.precision)}</td>
            <td className="py-2 text-right font-mono">{pct(d.recall)}</td>
            <td className="py-2 text-right font-mono font-semibold text-cyan-200">{pct(d.f1)}</td>
            <td className="py-2 text-right font-mono">{pct(d.false_positive_rate, 2)}</td>
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
    <Panel title="Triage-time experiment" subtitle="Task: identify the highest-priority incident and explain why. A = raw Alert Explorer, B = SentinelMind incident view. Median reported.">
      <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <input value={participant} onChange={(e) => setParticipant(e.target.value)} placeholder="Participant name" className="rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600" />
            <select value={mode} onChange={(e) => setMode(e.target.value as 'baseline' | 'assisted')} className="rounded-lg border border-ink-600 bg-ink-850 px-2 py-1.5 text-sm text-slate-300">
              <option value="baseline">A · raw alert list</option>
              <option value="assisted">B · SentinelMind incidents</option>
            </select>
          </div>
          <div className="flex items-center gap-3">
            <div className="tabular w-24 font-mono text-3xl font-semibold text-slate-50">{elapsed}s</div>
            {start === null ? <Button variant="primary" onClick={begin}>Start timer</Button> : (
              <>
                <Button onClick={() => { stop(); save.mutate(true) }} disabled={save.isPending}>Stop · correct</Button>
                <Button variant="danger" onClick={() => { stop(); save.mutate(false) }} disabled={save.isPending}>Stop · wrong</Button>
              </>
            )}
          </div>
          {save.error && <ErrorState error={save.error} />}
        </div>
        <div className="grid grid-cols-3 gap-3">
          <Kpi label="A · median" value={s?.baseline.median_seconds != null ? `${s.baseline.median_seconds.toFixed(0)}s` : '—'} hint={`n=${s?.baseline.n ?? 0} · acc ${pct(s?.baseline.accuracy ?? null, 0)}`} />
          <Kpi label="B · median" value={s?.assisted.median_seconds != null ? `${s.assisted.median_seconds.toFixed(0)}s` : '—'} hint={`n=${s?.assisted.n ?? 0} · acc ${pct(s?.assisted.accuracy ?? null, 0)}`} />
          <Kpi label="Reduction" value={s?.triage_reduction_pct != null ? `${s.triage_reduction_pct}%` : '—'} hint="measured, not assumed" tone="accent" />
        </div>
      </div>
    </Panel>
  )
}
