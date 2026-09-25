import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useEvidence } from '../components/EvidenceDrawer'
import { EntityGraph } from '../components/EntityGraph'
import { AlertChip, Button, EmptyState, ErrorState, Loading, Panel, SEV_COLOR, SeverityBadge, fmtClock, fmtTime, pct } from '../components/ui'
import type { AlertRow, BriefResponse, IncidentDetail as Detail } from '../types/api'

export default function IncidentDetail() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: ['incident', id], queryFn: () => api.incident(id) })
  const alerts = useQuery({ queryKey: ['incident-alerts', id], queryFn: () => api.incidentAlerts(id) })
  const graph = useQuery({ queryKey: ['incident-graph', id], queryFn: () => api.incidentGraph(id) })
  const openAlert = useEvidence()

  if (q.isLoading) return <Loading rows={8} />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  const d = q.data!
  return (
    <div className="space-y-6">
      <Header d={d} />
      <div className="grid gap-6 xl:grid-cols-[1.45fr_1fr]">
        <BriefPanel id={id} onOpenAlert={openAlert} />
        <div className="space-y-6">
          <RiskPanel d={d} />
          {d.decision && <JevPanel d={d} />}
          <AnomalyPanel d={d} />
        </div>
      </div>
      <Panel title="Attack timeline" subtitle="Deterministic stage sequence built from alert types, timestamps and ATT&CK mappings">
        <Timeline d={d} alerts={alerts.data?.items} onOpenAlert={openAlert} />
      </Panel>
      <Panel title="Entity / attack graph" subtitle="External IP → identity → host → process → resource. Click to reveal evidence.">
        {graph.isLoading ? <Loading rows={5} /> : graph.error ? <ErrorState error={graph.error} /> : graph.data!.nodes.length === 0 ? (
          <EmptyState title="No entities to graph" />
        ) : (
          <EntityGraph graph={graph.data!} onOpenAlert={openAlert} />
        )}
      </Panel>
      <div className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <MitrePanel d={d} onOpenAlert={openAlert} />
        <FeedbackPanel d={d} />
      </div>
      <SourceAlerts items={alerts.data?.items} loading={alerts.isLoading} onOpenAlert={openAlert} />
    </div>
  )
}

function Header({ d }: { d: Detail }) {
  return (
    <div className="rounded-xl border border-ink-700 bg-gradient-to-br from-ink-850 to-ink-900 p-5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-400">
        <Link to="/incidents" className="text-cyan-300 hover:underline">← Queue</Link>
        <span className="font-mono text-slate-300">{d.incident_id}</span>
        <span>rank #{d.rank}</span>
        <span>{fmtTime(d.first_seen)} → {fmtClock(d.last_seen)}</span>
        <span className="rounded bg-ink-800 px-1.5 py-0.5 uppercase tracking-wide text-slate-300">{d.status}</span>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-5">
        <div className="flex h-20 w-20 shrink-0 flex-col items-center justify-center rounded-2xl border-2" style={{ boxShadow: `0 0 40px -12px ${SEV_COLOR[d.severity]}`, borderColor: SEV_COLOR[d.severity] }}>
          <div className="tabular font-mono text-3xl font-bold text-slate-50">{d.risk_score.toFixed(0)}</div>
          <div className="text-[10px] uppercase tracking-widest text-slate-400">risk</div>
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={d.severity} />
            <span className="text-xs text-slate-400">correlation confidence <span className="font-mono text-slate-200">{d.correlation_confidence.toFixed(2)}</span></span>
            <span className="text-xs text-slate-400">· {d.alert_count} alerts{d.duplicate_count > 0 && ` (+${d.duplicate_count} duplicates collapsed)`}</span>
            <span className="text-xs text-slate-400">· formula <span className="font-mono text-slate-300">{d.risk.formula}</span></span>
          </div>
          <h1 className="mt-1.5 text-2xl font-semibold tracking-tight text-slate-50">{d.title}</h1>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {d.attack_stages.map((s, i) => (
              <span key={s.stage} className="flex items-center gap-1.5 text-xs text-slate-300">
                {i > 0 && <span className="text-slate-600">→</span>}
                <span className="rounded-md bg-ink-800 px-2 py-0.5 ring-1 ring-ink-600">{s.label}</span>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function RiskPanel({ d }: { d: Detail }) {
  const r = d.risk
  const rows = Object.entries(r.contributions).sort((a, b) => b[1] - a[1])
  const max = Math.max(...Object.values(r.weights)) * 100
  return (
    <Panel title={`Why risk = ${r.score.toFixed(0)}`} subtitle={`Weighted factor decomposition (${r.formula}). Weights are configurable.`}>
      <div className="space-y-2.5">
        {rows.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[150px_1fr_52px] items-center gap-3 text-sm">
            <div className="truncate text-slate-300" title={r.labels[k]}>{r.labels[k] ?? k}</div>
            <div className="relative h-4 rounded bg-ink-800" title={`factor ${r.factors[k]?.toFixed(2)} × weight ${r.weights[k]}`}>
              <div className="absolute inset-y-0 left-0 rounded-l bg-ink-600/60" style={{ width: `${(r.weights[k] * 100 / max) * 100}%` }} />
              <div className="absolute inset-y-0 left-0 rounded" style={{ width: `${(v / max) * 100}%`, background: k === 'jev_signal' ? '#a78bfa' : 'var(--color-accent-strong)' }} />
              <span className="absolute inset-y-0 right-1 flex items-center font-mono text-[10px] text-slate-400">×{r.factors[k]?.toFixed(2)}</span>
            </div>
            <div className="tabular text-right font-mono text-slate-100">{v.toFixed(1)}</div>
          </div>
        ))}
      </div>
      <div className="mt-3 flex items-center justify-between border-t border-ink-700 pt-2 text-xs text-slate-500">
        <span>Dark track = maximum possible contribution; bright = actual.</span>
        <span className="font-mono text-slate-300">Σ {r.score.toFixed(1)}</span>
      </div>
      {r.notes?.map((n) => <div key={n} className="mt-2 text-xs text-amber-300">⚠ {n}</div>)}
      {'score' in d.deterministic_risk && d.risk.formula === 'v2-jev' && (
        <div className="mt-2 text-xs text-slate-500">Deterministic-only score (v1): <span className="font-mono text-slate-300">{(d.deterministic_risk as { score: number }).score.toFixed(1)}</span></div>
      )}
    </Panel>
  )
}

function JevPanel({ d }: { d: Detail }) {
  const dec = d.decision!
  if (dec.status !== 'ok') return <Panel title="Jev decision"><div className="text-sm text-amber-300">Jev unavailable: {dec.error}. Deterministic risk used.</div></Panel>
  const j = dec.decision
  return (
    <Panel title="Jev typed decision" subtitle={`${j.served_model ?? dec.model} · ${dec.latency_ms.toFixed(0)} ms · capped at 15% of risk`}>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div><div className="text-xs text-slate-500">Disposition</div><div className="font-semibold capitalize text-violet-200">{j.disposition} <span className="font-mono text-xs text-slate-400">conf {j.disposition_confidence.toFixed(2)}</span></div></div>
        <div><div className="text-xs text-slate-500">Attack family</div><div className="font-semibold text-slate-200">{j.attack_family}</div></div>
        <div><div className="text-xs text-slate-500">P(escalate now)</div><div className="font-mono text-slate-200">{pct(j.p_escalate, 0)}</div></div>
        <div><div className="text-xs text-slate-500">P(false positive)</div><div className="font-mono text-slate-200">{pct(j.p_false_positive, 0)}</div></div>
      </div>
      <div className="mt-3 flex h-2 overflow-hidden rounded-full">
        {Object.entries(j.disposition_probabilities).map(([k, v]) => (
          <div key={k} title={`${k} ${(v * 100).toFixed(0)}%`} style={{ width: `${v * 100}%`, background: { malicious: '#f43f5e', suspicious: '#fb923c', benign: '#34d399', uncertain: '#64748b' }[k] ?? '#64748b' }} />
        ))}
      </div>
      {j.needs_human_review && <div className="mt-2 text-xs text-amber-300">Low confidence — flagged for human review.</div>}
    </Panel>
  )
}

function AnomalyPanel({ d }: { d: Detail }) {
  return (
    <Panel title="Behavioral anomaly" subtitle="Robust z-score rules + Isolation Forest" actions={<span className="font-mono text-sm text-slate-200">{d.anomaly_score.toFixed(2)}</span>}>
      {d.anomaly_reasons.length === 0 ? <div className="text-sm text-slate-500">No behavior deviated from entity baselines.</div> : (
        <ul className="space-y-1.5 text-sm text-slate-300">
          {d.anomaly_reasons.map((r) => <li key={r} className="flex gap-2"><span className="text-cyan-400">◆</span>{r}</li>)}
        </ul>
      )}
    </Panel>
  )
}

function BriefPanel({ id, onOpenAlert }: { id: string; onOpenAlert: (id: string) => void }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['brief', id], queryFn: () => api.brief(id) })
  const gen = useMutation({
    mutationFn: (refresh: boolean) => api.generateBrief(id, refresh),
    onSuccess: (data) => qc.setQueryData(['brief', id], data),
  })
  const [allFacts, setAllFacts] = useState(false)
  const data: BriefResponse | undefined = gen.data ?? q.data
  const b = data?.brief
  return (
    <Panel
      title="AI investigation brief"
      subtitle={data ? (
        <>Generated by <span className="font-mono text-slate-300">{data.provider}</span>{data.model !== data.provider && <> · {data.model}</>} · {fmtTime(data.generated_at)}{data.cached && ' · cached'}</>
      ) : 'Evidence-grounded, citation-validated'}
      actions={
        <Button size="sm" variant="primary" onClick={() => gen.mutate(!!data && data.provider !== 'template')} disabled={gen.isPending}>
          {gen.isPending ? 'Generating…' : data && data.provider !== 'template' ? 'Regenerate' : 'Generate AI brief'}
        </Button>
      }
    >
      {q.isLoading ? <Loading rows={6} /> : q.error ? <ErrorState error={q.error} /> : !b ? null : (
        <div className="space-y-5 text-sm">
          {gen.error && <ErrorState error={gen.error} />}
          {data?.attempts?.some((a) => a.status !== 'ok') && (
            <div className="rounded-md border border-amber-400/25 bg-amber-400/5 px-3 py-2 text-xs text-amber-200">
              Provider routing: {data.attempts.map((a) => `${a.provider} ${a.status}${a.error ? ` (${a.error.slice(0, 60)})` : ''}`).join(' → ')}
              {data.provider === 'template' && ' → deterministic template'}
            </div>
          )}
          {data?.evidence_pack_summary?.instruction_like_text_alert_ids?.length ? (
            <div className="rounded-md border border-rose-400/30 bg-rose-500/5 px-3 py-2 text-xs text-rose-200">
              Instruction-like text found in evidence ({data.evidence_pack_summary.instruction_like_text_alert_ids.map((x) => (
                <AlertChip key={x} id={x} onClick={onOpenAlert} />
              ))}) — treated strictly as untrusted data.
            </div>
          ) : null}
          <p className="leading-relaxed text-slate-200">{b.executive_summary}</p>
          <section>
            <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-emerald-300">Observed facts · cited</h3>
            <ul className="space-y-2">
              {(allFacts ? b.observed_facts : b.observed_facts.slice(0, 5)).map((f, i) => (
                <li key={i} className="rounded-lg border border-emerald-500/15 bg-emerald-500/[0.04] px-3 py-2">
                  <div className="text-slate-200">{f.fact}</div>
                  <div className="mt-1.5 flex flex-wrap gap-1">{f.alert_ids.map((a) => <AlertChip key={a} id={a} onClick={onOpenAlert} />)}</div>
                </li>
              ))}
            </ul>
            {b.observed_facts.length > 5 && (
              <button onClick={() => setAllFacts((x) => !x)} className="mt-2 text-xs text-cyan-300 hover:underline">
                {allFacts ? 'Show fewer facts' : `Show all ${b.observed_facts.length} facts`}
              </button>
            )}
          </section>
          <section>
            <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-violet-300">Hypotheses · not confirmed</h3>
            <ul className="space-y-2">
              {b.hypotheses.map((h, i) => (
                <li key={i} className="flex items-start gap-3 rounded-lg border border-dashed border-violet-400/30 bg-violet-500/[0.04] px-3 py-2">
                  <span className="mt-0.5 shrink-0 rounded bg-violet-500/15 px-1.5 font-mono text-[11px] text-violet-200">{pct(h.confidence, 0)}</span>
                  <span className="italic text-slate-300">{h.hypothesis}</span>
                </li>
              ))}
            </ul>
          </section>
          <div className="grid gap-5 md:grid-cols-2">
            <section>
              <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-cyan-300">Recommended checks (human)</h3>
              <ol className="list-decimal space-y-1 pl-4 text-slate-300">{b.investigation_checks.map((c) => <li key={c}>{c}</li>)}</ol>
            </section>
            <section>
              <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-amber-300">Uncertainties</h3>
              <ul className="space-y-1 text-slate-400">{b.uncertainties.map((c) => <li key={c}>• {c}</li>)}</ul>
            </section>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-ink-700 pt-3 text-xs text-slate-500">
            <span>Overall confidence <span className="font-mono text-slate-300">{b.overall_confidence.toFixed(2)}</span></span>
            <span>
              {data?.validation?.schema_valid ? 'schema ✓' : 'schema ✗'} · citations checked {String(data?.validation?.citations_checked ?? '—')} · prompt {data?.prompt_version}
            </span>
          </div>
          {data?.evidence_pack_summary?.similar_incidents?.length ? (
            <div className="text-xs text-slate-500">
              Similar incidents:{' '}
              {data.evidence_pack_summary.similar_incidents.map((s) => (
                <Link key={s.incident_id} to={`/incidents/${s.incident_id}`} className="mr-2 font-mono text-cyan-300 hover:underline">{s.incident_id} ({s.similarity})</Link>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </Panel>
  )
}

function Timeline({ d, alerts, onOpenAlert }: { d: Detail; alerts?: AlertRow[]; onOpenAlert: (id: string) => void }) {
  const t0 = new Date(d.first_seen).getTime()
  const t1 = Math.max(new Date(d.last_seen).getTime(), t0 + 60_000)
  const pos = (iso: string) => ((new Date(iso).getTime() - t0) / (t1 - t0)) * 100
  const stageOf = useMemo(() => {
    const m = new Map<string, string>()
    d.attack_stages.forEach((s) => s.alert_ids.forEach((a) => m.set(a, s.stage)))
    return m
  }, [d])
  const colors = ['#f43f5e', '#fb923c', '#facc15', '#22d3ee', '#a78bfa', '#34d399', '#f472b6', '#60a5fa', '#e879f9', '#fde047']
  if (d.attack_stages.length === 0) {
    return <div className="text-sm text-slate-500">No attack-stage behaviors in this incident ({d.top_alert_types.map(([t, n]) => `${t} ×${n}`).join(', ')}).</div>
  }
  return (
    <div className="space-y-4">
      <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${d.attack_stages.length}, minmax(0, 1fr))` }}>
        {d.attack_stages.map((s, i) => (
          <div key={s.stage} className="relative rounded-lg border border-ink-700 bg-ink-850 p-3">
            <div className="flex items-center gap-2">
              <span className="flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold text-ink-950" style={{ background: colors[i % colors.length] }}>{i + 1}</span>
              <span className="text-sm font-semibold text-slate-100">{s.label}</span>
            </div>
            <div className="mt-1 font-mono text-[11px] text-slate-400">{fmtClock(s.first_seen)} – {fmtClock(s.last_seen)}</div>
            <div className="mt-1 text-[11px] text-slate-500">{s.alert_ids.length} alerts · conf {s.confidence.toFixed(2)}</div>
            <div className="mt-1 truncate text-[11px] text-slate-500" title={s.alert_types.join(', ')}>{s.alert_types.join(', ')}</div>
            <div className="mt-2 flex flex-wrap gap-1">{s.alert_ids.slice(0, 2).map((a) => <AlertChip key={a} id={a} onClick={onOpenAlert} />)}</div>
          </div>
        ))}
      </div>
      <div>
        <div className="relative h-16 rounded-lg border border-ink-700 bg-ink-950">
          {(alerts ?? []).map((a) => {
            const st = stageOf.get(a.alert_id)
            const idx = st ? d.attack_stages.findIndex((s) => s.stage === st) : -1
            return (
              <button
                key={a.alert_id}
                onClick={() => onOpenAlert(a.alert_id)}
                title={`${a.alert_id} · ${fmtClock(a.timestamp)} · ${a.title}`}
                className="absolute h-3 w-1.5 -translate-x-1/2 rounded-sm opacity-80 transition hover:scale-150 hover:opacity-100"
                style={{ left: `${Math.min(99.5, Math.max(0.5, pos(a.timestamp)))}%`, top: idx >= 0 ? 8 + (idx % 4) * 11 : 50, background: idx >= 0 ? colors[idx % colors.length] : '#475569' }}
              />
            )
          })}
        </div>
        <div className="mt-1 flex justify-between font-mono text-[10px] text-slate-500">
          <span>{fmtClock(d.first_seen)}</span>
          <span>each tick = one alert · click to open evidence</span>
          <span>{fmtClock(d.last_seen)}</span>
        </div>
      </div>
    </div>
  )
}

function MitrePanel({ d, onOpenAlert }: { d: Detail; onOpenAlert: (id: string) => void }) {
  return (
    <Panel title="MITRE ATT&CK" subtitle={`Deterministic mappings · official catalog v${d.mitre[0]?.attack_catalog_version ?? '—'}`}>
      {d.mitre.length === 0 ? <div className="text-sm text-slate-500">No techniques mapped from the evidence.</div> : (
        <ul className="divide-y divide-ink-800">
          {d.mitre.map((m) => (
            <li key={m.technique_id} className="py-2.5">
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <a href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`} target="_blank" rel="noreferrer" className="font-mono text-sm font-semibold text-cyan-300 hover:underline">{m.technique_id}</a>
                  <span className="ml-2 text-sm text-slate-200">{m.name}</span>
                </div>
                <span className="shrink-0 font-mono text-xs text-slate-400">{m.confidence.toFixed(2)}</span>
              </div>
              <div className="mt-0.5 text-xs text-slate-500">{m.tactics.join(' · ')}</div>
              <div className="mt-1 text-[13px] text-slate-300">{m.mapping_reason}</div>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {m.evidence_alert_ids.slice(0, 4).map((a) => <AlertChip key={a} id={a} onClick={onOpenAlert} />)}
                {m.evidence_alert_ids.length > 4 && <span className="text-[11px] text-slate-500">+{m.evidence_alert_ids.length - 4} more</span>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

const VERDICTS = [
  { v: 'confirmed_malicious', label: 'Confirmed malicious', cls: 'danger' as const },
  { v: 'needs_investigation', label: 'Needs investigation', cls: 'secondary' as const },
  { v: 'benign_true_positive', label: 'Benign (expected)', cls: 'secondary' as const },
  { v: 'false_positive', label: 'False positive', cls: 'secondary' as const },
]

function FeedbackPanel({ d }: { d: Detail }) {
  const qc = useQueryClient()
  const [notes, setNotes] = useState('')
  const m = useMutation({
    mutationFn: (verdict: string) => api.feedback(d.incident_id, { verdict, notes: notes || undefined }),
    onSuccess: () => {
      setNotes('')
      qc.invalidateQueries({ queryKey: ['incident', d.incident_id] })
      qc.invalidateQueries({ queryKey: ['incidents'] })
    },
  })
  return (
    <Panel title="Analyst verdict" subtitle="Human-in-the-loop. Advisory system: no automated containment exists.">
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Notes (optional)…"
        rows={2}
        className="w-full rounded-lg border border-ink-600 bg-ink-850 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
      />
      <div className="mt-2 flex flex-wrap gap-2">
        {VERDICTS.map((x) => (
          <Button key={x.v} size="sm" variant={x.cls} onClick={() => m.mutate(x.v)} disabled={m.isPending}>{x.label}</Button>
        ))}
      </div>
      {m.error && <div className="mt-2"><ErrorState error={m.error} /></div>}
      <div className="mt-4">
        <div className="mb-1 text-[11px] uppercase tracking-[0.12em] text-slate-500">History (audited)</div>
        {d.feedback.length === 0 ? <div className="text-sm text-slate-500">No verdicts yet.</div> : (
          <ul className="space-y-1.5 text-sm">
            {d.feedback.map((f) => (
              <li key={f.created_at} className="flex flex-wrap items-baseline gap-2">
                <span className="font-medium text-slate-200">{f.verdict.replaceAll('_', ' ')}</span>
                <span className="text-xs text-slate-500">{f.analyst} · {fmtTime(f.created_at)}</span>
                {f.notes && <span className="text-xs text-slate-400">“{f.notes}”</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  )
}

function SourceAlerts({ items, loading, onOpenAlert }: { items?: AlertRow[]; loading: boolean; onOpenAlert: (id: string) => void }) {
  const [showAll, setShowAll] = useState(false)
  const rows = showAll ? items ?? [] : (items ?? []).slice(0, 25)
  return (
    <Panel title="Source alerts & why grouped" subtitle="Every membership stores its strongest correlation edge and reasons" bodyClass="p-0"
      actions={items && items.length > 25 && <Button size="sm" onClick={() => setShowAll((s) => !s)}>{showAll ? 'Show fewer' : `Show all ${items.length}`}</Button>}>
      {loading ? <div className="p-4"><Loading rows={6} /></div> : (
        <div className="scrollbar-thin overflow-x-auto">
          <table className="w-full min-w-[900px] text-sm">
            <thead>
              <tr className="border-b border-ink-700 text-left text-[11px] uppercase tracking-[0.08em] text-slate-500">
                <th className="px-4 py-2 font-medium">Alert</th>
                <th className="px-2 py-2 font-medium">Time</th>
                <th className="px-2 py-2 font-medium">Sev</th>
                <th className="px-2 py-2 font-medium">Title</th>
                <th className="px-2 py-2 font-medium">Entities</th>
                <th className="px-2 py-2 font-medium">Edge</th>
                <th className="px-4 py-2 font-medium">Why grouped</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800">
              {rows.map((a) => (
                <tr key={a.alert_id} className="hover:bg-ink-800/40">
                  <td className="px-4 py-2"><AlertChip id={a.alert_id} onClick={onOpenAlert} /></td>
                  <td className="whitespace-nowrap px-2 py-2 font-mono text-xs text-slate-400">{fmtClock(a.timestamp)}</td>
                  <td className="px-2 py-2"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-2 py-2 text-slate-200">{a.title}</td>
                  <td className="max-w-[220px] truncate px-2 py-2 font-mono text-xs text-slate-400">{[a.user, a.host, a.src_ip, a.process, a.resource].filter(Boolean).join(' · ')}</td>
                  <td className="px-2 py-2 font-mono text-xs text-slate-300">{a.membership?.edge_score.toFixed(2)}</td>
                  <td className="max-w-[360px] px-4 py-2 text-xs text-slate-400">{a.membership?.reasons.slice(0, 3).join('; ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
