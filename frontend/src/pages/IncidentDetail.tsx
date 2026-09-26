import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity, ArrowLeft, Bot, Brain, CircleCheck, Clock, Download, Gauge, History, Lightbulb, ListChecks, Network, ShieldAlert, Sparkles, Target, TriangleAlert,
} from 'lucide-react'
import { motion } from 'motion/react'
import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useEvidence } from '../components/EvidenceDrawer'
import { EntityGraph } from '../components/EntityGraph'
import { AlertChip, Button, Card, Chip, EmptyState, ErrorState, Item, Loading, RiskRing, SEV_COLOR, SeverityBadge, Stagger, ease, fmtClock, fmtTime, pct } from '../components/ui'
import type { AlertRow, BriefResponse, IncidentDetail as Detail } from '../types/api'

const STAGE_COLORS = ['#d92d20', '#ef6820', '#dc9b04', '#0f6cbd', '#7a5af8', '#079455', '#dd2590', '#2e90fa', '#9e77ed', '#15b79e']

export default function IncidentDetail() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: ['incident', id], queryFn: () => api.incident(id) })
  const alerts = useQuery({ queryKey: ['incident-alerts', id], queryFn: () => api.incidentAlerts(id) })
  const graph = useQuery({ queryKey: ['incident-graph', id], queryFn: () => api.incidentGraph(id) })
  const openAlert = useEvidence()

  if (q.isLoading) return <Loading rows={10} />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  const d = q.data!
  return (
    <Stagger className="space-y-6">
      <Item><Header d={d} /></Item>
      <Item>
        <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
          <BriefPanel id={id} onOpenAlert={openAlert} />
          <div className="space-y-6">
            <RiskPanel d={d} />
            {d.decision && <JevPanel d={d} />}
            <AnomalyPanel d={d} />
          </div>
        </div>
      </Item>
      <Item>
        <Card title="Attack timeline" description="Deterministic stage sequence built from alert types, timestamps and ATT&CK mappings" icon={Clock}>
          <Timeline d={d} alerts={alerts.data?.items} onOpenAlert={openAlert} />
        </Card>
      </Item>
      <Item>
        <Card title="Entity and attack graph" description="External source → identity → host → process → data. Select anything to see its evidence." icon={Network}>
          {graph.isLoading ? <Loading rows={6} /> : graph.error ? <ErrorState error={graph.error} /> : graph.data!.nodes.length === 0 ? (
            <EmptyState icon={Network} title="No entities to graph" />
          ) : (
            <EntityGraph graph={graph.data!} onOpenAlert={openAlert} />
          )}
        </Card>
      </Item>
      <Item>
        <div className="grid gap-6 xl:grid-cols-2">
          <MitrePanel d={d} onOpenAlert={openAlert} />
          <FeedbackPanel d={d} />
        </div>
      </Item>
      <Item><SourceAlerts items={alerts.data?.items} loading={alerts.isLoading} onOpenAlert={openAlert} /></Item>
    </Stagger>
  )
}

function Header({ d }: { d: Detail }) {
  return (
    <div className="rounded-2xl border border-line bg-surface p-6 shadow-[var(--shadow-card)]">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-[13px] text-fg-subtle">
        <Link to="/incidents" className="inline-flex items-center gap-1 font-medium text-brand-600 hover:text-brand-700"><ArrowLeft className="h-4 w-4" /> Incidents</Link>
        <span className="text-line-strong">/</span>
        <span className="font-mono text-fg-2">{d.incident_id}</span>
        <span className="text-line-strong">·</span>
        <span>Rank #{d.rank}</span>
        <span className="text-line-strong">·</span>
        <span>{fmtTime(d.first_seen)} → {fmtClock(d.last_seen)}</span>
        <span className="ml-auto flex items-center gap-2">
          <Chip tone={d.status === 'new' ? 'brand' : 'green'}>{d.status}</Chip>
          <SentinelExportButton id={d.incident_id} />
        </span>
      </div>
      <div className="mt-5 flex flex-wrap items-center gap-6">
        <RiskRing score={d.risk_score} severity={d.severity} size={92} stroke={8} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={d.severity} />
            <Chip>correlation {d.correlation_confidence.toFixed(2)}</Chip>
            <Chip>{d.alert_count} alerts{d.duplicate_count > 0 ? ` · ${d.duplicate_count} duplicates collapsed` : ''}</Chip>
            <Chip tone={d.risk.formula === 'v2-jev' ? 'violet' : 'neutral'} mono>{d.risk.formula}</Chip>
          </div>
          <h1 className="mt-2 text-[26px] font-semibold tracking-tight text-fg">{d.title}</h1>
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            {d.attack_stages.map((s, i) => (
              <motion.span key={s.stage} className="flex items-center gap-1.5" initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.15 + i * 0.07, ease }}>
                {i > 0 && <span className="h-px w-3 bg-line-strong" />}
                <span className="inline-flex items-center gap-1.5 rounded-full bg-white px-2.5 py-1 text-xs font-medium text-fg-2 ring-1 ring-inset ring-line">
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: STAGE_COLORS[i % STAGE_COLORS.length] }} />
                  {s.label}
                </span>
              </motion.span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function SentinelExportButton({ id }: { id: string }) {
  const m = useMutation({
    mutationFn: () => api.sentinelExport(id),
    onSuccess: (payload) => {
      const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `${id}.sentinel-incident.json`
      a.click()
      URL.revokeObjectURL(url)
    },
  })
  return (
    <Button size="sm" icon={Download} onClick={() => m.mutate()} loading={m.isPending} title="Download a Microsoft Sentinel incident payload (nothing is pushed automatically)">
      {m.isError ? 'Export failed, retry' : 'Export to Sentinel'}
    </Button>
  )
}

function RiskPanel({ d }: { d: Detail }) {
  const r = d.risk
  const rows = Object.entries(r.contributions).sort((a, b) => b[1] - a[1])
  const max = Math.max(...Object.values(r.weights)) * 100
  return (
    <Card title={`Why risk = ${r.score.toFixed(0)}`} description="Every point is explained: factor value × configurable weight" icon={Gauge}>
      <div className="space-y-3">
        {rows.map(([k, v], i) => (
          <div key={k} className="grid grid-cols-[148px_1fr_44px] items-center gap-3 text-[13px]">
            <div className="truncate font-medium text-fg-2" title={r.labels[k]}>{r.labels[k] ?? k}</div>
            <div className="relative h-2.5 rounded-full bg-subtle" title={`factor ${r.factors[k]?.toFixed(2)} × weight ${r.weights[k]}`}>
              <div className="absolute inset-y-0 left-0 rounded-full bg-muted" style={{ width: `${((r.weights[k] * 100) / max) * 100}%` }} />
              <motion.div
                className="absolute inset-y-0 left-0 rounded-full"
                style={{ background: k === 'jev_signal' ? '#7a5af8' : '#0f6cbd' }}
                initial={{ width: 0 }}
                animate={{ width: `${(v / max) * 100}%` }}
                transition={{ duration: 0.7, delay: 0.1 + i * 0.05, ease }}
              />
            </div>
            <div className="tabular text-right font-semibold text-fg">{v.toFixed(1)}</div>
          </div>
        ))}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-line pt-3 text-xs text-fg-subtle">
        <span>Light track = maximum possible contribution</span>
        <span className="tabular font-semibold text-fg-2">Σ {r.score.toFixed(1)}</span>
      </div>
      {r.notes?.map((n) => <div key={n} className="mt-2 flex items-start gap-1.5 text-xs text-amber-700"><TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />{n}</div>)}
      {'score' in d.deterministic_risk && d.risk.formula === 'v2-jev' && (
        <div className="mt-2 text-xs text-fg-subtle">Deterministic-only score (v1): <span className="font-semibold text-fg-2">{(d.deterministic_risk as { score: number }).score.toFixed(1)}</span></div>
      )}
    </Card>
  )
}

function JevPanel({ d }: { d: Detail }) {
  const dec = d.decision!
  if (dec.status !== 'ok') return <Card title="Jev decision" icon={Brain}><div className="text-sm text-amber-700">Jev unavailable: {dec.error}. Deterministic risk used.</div></Card>
  const j = dec.decision
  const colors: Record<string, string> = { malicious: '#d92d20', suspicious: '#ef6820', benign: '#079455', uncertain: '#98a2b3' }
  return (
    <Card title="Jev typed decision" description={`${j.served_model ?? dec.model} · ${dec.latency_ms.toFixed(0)} ms · capped at 15% of risk`} icon={Brain}>
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-xs text-fg-subtle">Disposition</div>
          <div className="mt-0.5 font-semibold capitalize" style={{ color: colors[j.disposition] ?? '#344054' }}>{j.disposition} <span className="text-xs font-normal text-fg-subtle">conf {j.disposition_confidence.toFixed(2)}</span></div>
        </div>
        <div><div className="text-xs text-fg-subtle">Attack family</div><div className="mt-0.5 font-semibold capitalize text-fg-2">{j.attack_family}</div></div>
        <div><div className="text-xs text-fg-subtle">Escalate now</div><div className="tabular mt-0.5 font-semibold text-fg-2">{pct(j.p_escalate, 0)}</div></div>
        <div><div className="text-xs text-fg-subtle">False positive</div><div className="tabular mt-0.5 font-semibold text-fg-2">{pct(j.p_false_positive, 0)}</div></div>
      </div>
      <div className="mt-4 flex h-2 overflow-hidden rounded-full bg-subtle">
        {Object.entries(j.disposition_probabilities).map(([k, v], i) => (
          <motion.div key={k} title={`${k} ${(v * 100).toFixed(0)}%`} style={{ background: colors[k] ?? '#98a2b3' }} initial={{ width: 0 }} animate={{ width: `${v * 100}%` }} transition={{ duration: 0.7, delay: i * 0.05, ease }} />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-fg-subtle">
        {Object.entries(j.disposition_probabilities).map(([k, v]) => <span key={k} className="inline-flex items-center gap-1 capitalize"><span className="h-1.5 w-1.5 rounded-full" style={{ background: colors[k] }} />{k} {(v * 100).toFixed(0)}%</span>)}
      </div>
      {j.needs_human_review && <div className="mt-3 flex items-center gap-1.5 rounded-lg bg-amber-50 px-2.5 py-1.5 text-xs font-medium text-amber-800 ring-1 ring-inset ring-amber-200"><TriangleAlert className="h-3.5 w-3.5" /> Low confidence: flagged for human review</div>}
    </Card>
  )
}

function AnomalyPanel({ d }: { d: Detail }) {
  return (
    <Card title="Behavioral anomaly" description="Robust z-score rules + Isolation Forest" icon={Activity} actions={<span className="tabular rounded-md bg-subtle px-2 py-0.5 text-sm font-semibold text-fg">{d.anomaly_score.toFixed(2)}</span>}>
      {d.anomaly_reasons.length === 0 ? <div className="text-sm text-fg-subtle">No behavior deviated from entity baselines.</div> : (
        <ul className="space-y-2 text-[13px] text-fg-2">
          {d.anomaly_reasons.map((r) => <li key={r} className="flex gap-2.5"><span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-500" />{r}</li>)}
        </ul>
      )}
    </Card>
  )
}

function BriefPanel({ id, onOpenAlert }: { id: string; onOpenAlert: (id: string) => void }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['brief', id], queryFn: () => api.brief(id) })
  const gen = useMutation({ mutationFn: (refresh: boolean) => api.generateBrief(id, refresh), onSuccess: (data) => qc.setQueryData(['brief', id], data) })
  const [allFacts, setAllFacts] = useState(false)
  const data: BriefResponse | undefined = gen.data ?? q.data
  const b = data?.brief
  const isModel = !!data && data.provider !== 'template'
  return (
    <Card
      title="AI investigation brief"
      icon={Sparkles}
      description={data ? (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          {isModel ? <Bot className="h-3.5 w-3.5" /> : null}
          {isModel ? <>{data.provider} · <span className="font-mono">{data.model}</span></> : 'Deterministic template'} · {fmtTime(data.generated_at)}{data.cached ? ' · cached' : ''}
        </span>
      ) : 'Evidence-grounded, citation-validated'}
      actions={<Button size="sm" variant="primary" icon={Sparkles} onClick={() => gen.mutate(isModel)} loading={gen.isPending}>{isModel ? 'Regenerate' : 'Generate AI brief'}</Button>}
    >
      {q.isLoading ? <Loading rows={8} /> : q.error ? <ErrorState error={q.error} /> : !b ? null : (
        <div className="space-y-6 text-sm">
          {gen.error && <ErrorState error={gen.error} />}
          {data?.attempts?.some((a) => a.status !== 'ok') && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
              Provider routing: {data.attempts.map((a) => `${a.provider} ${a.status.replace('_', ' ')}`).join(' → ')}{data.provider === 'template' && ' → deterministic template'}
            </div>
          )}
          {data?.evidence_pack_summary?.instruction_like_text_alert_ids?.length ? (
            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
              <ShieldAlert className="h-4 w-4" /> Instruction-like text found in evidence
              {data.evidence_pack_summary.instruction_like_text_alert_ids.map((x) => <AlertChip key={x} id={x} onClick={onOpenAlert} />)}
              <span>treated strictly as untrusted data</span>
            </div>
          ) : null}
          <p className="text-[15px] leading-relaxed text-fg">{b.executive_summary}</p>
          <section>
            <h3 className="mb-2.5 flex items-center gap-2 text-[13px] font-semibold text-emerald-700"><CircleCheck className="h-4 w-4" />Observed facts · cited</h3>
            <ul className="space-y-2">
              {(allFacts ? b.observed_facts : b.observed_facts.slice(0, 5)).map((f, i) => (
                <motion.li key={f.fact + i} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04, ease }} className="rounded-xl border border-line bg-white px-3.5 py-2.5 shadow-[var(--shadow-xs)]">
                  <div className="text-fg-2">{f.fact}</div>
                  <div className="mt-2 flex flex-wrap gap-1">{f.alert_ids.map((a) => <AlertChip key={a} id={a} onClick={onOpenAlert} />)}</div>
                </motion.li>
              ))}
            </ul>
            {b.observed_facts.length > 5 && (
              <button onClick={() => setAllFacts((x) => !x)} className="mt-2 text-[13px] font-semibold text-brand-600 hover:text-brand-700">
                {allFacts ? 'Show fewer facts' : `Show all ${b.observed_facts.length} facts`}
              </button>
            )}
          </section>
          <section>
            <h3 className="mb-2.5 flex items-center gap-2 text-[13px] font-semibold text-violet-700"><Lightbulb className="h-4 w-4" />Hypotheses · not confirmed</h3>
            <ul className="space-y-2">
              {b.hypotheses.map((h, i) => (
                <li key={i} className="flex items-start gap-3 rounded-xl border border-dashed border-violet-300 bg-violet-50/50 px-3.5 py-2.5">
                  <span className="tabular mt-0.5 shrink-0 rounded-md bg-white px-1.5 text-[11px] font-semibold text-violet-700 ring-1 ring-violet-200">{pct(h.confidence, 0)}</span>
                  <span className="italic text-fg-2">{h.hypothesis}</span>
                </li>
              ))}
            </ul>
          </section>
          <div className="grid gap-6 md:grid-cols-2">
            <section>
              <h3 className="mb-2.5 flex items-center gap-2 text-[13px] font-semibold text-brand-700"><ListChecks className="h-4 w-4" />Recommended checks for the analyst</h3>
              <ol className="space-y-1.5">
                {b.investigation_checks.map((c, i) => (
                  <li key={c} className="flex gap-2.5 text-[13px] text-fg-2"><span className="tabular flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-50 text-[11px] font-semibold text-brand-700">{i + 1}</span>{c}</li>
                ))}
              </ol>
            </section>
            <section>
              <h3 className="mb-2.5 flex items-center gap-2 text-[13px] font-semibold text-amber-700"><TriangleAlert className="h-4 w-4" />Uncertainties</h3>
              <ul className="space-y-1.5 text-[13px] text-fg-muted">{b.uncertainties.map((c) => <li key={c} className="flex gap-2"><span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-amber-500" />{c}</li>)}</ul>
            </section>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-3 text-xs text-fg-subtle">
            <span>Overall confidence <span className="tabular font-semibold text-fg-2">{b.overall_confidence.toFixed(2)}</span></span>
            <span className="inline-flex items-center gap-2">
              <Chip tone={data?.validation?.schema_valid ? 'green' : 'neutral'}>schema {data?.validation?.schema_valid ? 'valid' : 'unchecked'}</Chip>
              <Chip tone="green">{String(data?.validation?.citations_checked ?? 0)} citations verified</Chip>
              <Chip mono>prompt {data?.prompt_version}</Chip>
            </span>
          </div>
          {data?.evidence_pack_summary?.similar_incidents?.length ? (
            <div className="text-xs text-fg-subtle">
              Similar incidents:{' '}
              {data.evidence_pack_summary.similar_incidents.map((s) => (
                <Link key={s.incident_id} to={`/incidents/${s.incident_id}`} className="mr-2 font-mono font-medium text-brand-600 hover:underline">{s.incident_id} ({s.similarity})</Link>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </Card>
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
  if (d.attack_stages.length === 0) {
    return <div className="text-sm text-fg-subtle">No attack-stage behaviors in this incident ({d.top_alert_types.map(([t, n]) => `${t} ×${n}`).join(', ')}).</div>
  }
  return (
    <div className="space-y-6">
      <div className="relative">
        <motion.div className="absolute left-[18px] right-[18px] top-[17px] h-0.5 origin-left bg-line-strong" initial={{ scaleX: 0 }} animate={{ scaleX: 1 }} transition={{ duration: 0.9, ease }} />
        <div className="relative grid gap-3" style={{ gridTemplateColumns: `repeat(${d.attack_stages.length}, minmax(0, 1fr))` }}>
          {d.attack_stages.map((s, i) => (
            <motion.div key={s.stage} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 + i * 0.1, ease }}>
              <span className="flex h-9 w-9 items-center justify-center rounded-full border-4 border-white text-xs font-bold text-white shadow-[var(--shadow-xs)]" style={{ background: STAGE_COLORS[i % STAGE_COLORS.length] }}>{i + 1}</span>
              <div className="mt-2.5 rounded-xl border border-line bg-white p-3 shadow-[var(--shadow-xs)]">
                <div className="text-[13px] font-semibold text-fg">{s.label}</div>
                <div className="tabular mt-0.5 text-xs text-fg-subtle">{fmtClock(s.first_seen)} – {fmtClock(s.last_seen)}</div>
                <div className="mt-1.5 text-xs text-fg-muted">{s.alert_ids.length} alerts · conf {s.confidence.toFixed(2)}</div>
                <div className="mt-1 truncate text-[11px] text-fg-faint" title={s.alert_types.join(', ')}>{s.alert_types.join(', ')}</div>
                <div className="mt-2 flex flex-wrap gap-1">{s.alert_ids.slice(0, 2).map((a) => <AlertChip key={a} id={a} onClick={onOpenAlert} />)}</div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
      <div>
        <div className="mb-1.5 text-xs font-medium text-fg-subtle">Every alert on one axis. Select a tick to open its evidence.</div>
        <div className="relative h-[72px] rounded-xl border border-line bg-subtle/50">
          {(alerts ?? []).map((a, n) => {
            const st = stageOf.get(a.alert_id)
            const idx = st ? d.attack_stages.findIndex((s) => s.stage === st) : -1
            return (
              <motion.button
                key={a.alert_id}
                onClick={() => onOpenAlert(a.alert_id)}
                title={`${a.alert_id} · ${fmtClock(a.timestamp)} · ${a.title}`}
                className="absolute h-3.5 w-1.5 -translate-x-1/2 rounded-full transition-transform hover:scale-150"
                style={{ left: `${Math.min(99.4, Math.max(0.6, pos(a.timestamp)))}%`, top: idx >= 0 ? 10 + (idx % 4) * 13 : 55, background: idx >= 0 ? STAGE_COLORS[idx % STAGE_COLORS.length] : '#98a2b3' }}
                initial={{ opacity: 0, scaleY: 0 }}
                animate={{ opacity: 0.9, scaleY: 1 }}
                transition={{ delay: 0.3 + Math.min(n, 160) * 0.004 }}
              />
            )
          })}
        </div>
        <div className="tabular mt-1.5 flex justify-between text-[11px] text-fg-faint">
          <span>{fmtClock(d.first_seen)}</span>
          <span>{fmtClock(d.last_seen)}</span>
        </div>
      </div>
    </div>
  )
}

function MitrePanel({ d, onOpenAlert }: { d: Detail; onOpenAlert: (id: string) => void }) {
  return (
    <Card title="MITRE ATT&CK" description={`Deterministic mappings from the official catalog v${d.mitre[0]?.attack_catalog_version ?? '—'}`} icon={Target}>
      {d.mitre.length === 0 ? <div className="text-sm text-fg-subtle">No techniques mapped from the evidence.</div> : (
        <ul className="-my-3 divide-y divide-line">
          {d.mitre.map((m) => (
            <li key={m.technique_id} className="py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <a href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`} target="_blank" rel="noreferrer" className="font-mono text-[13px] font-semibold text-brand-600 hover:underline">{m.technique_id}</a>
                  <span className="ml-2 text-sm font-medium text-fg">{m.name}</span>
                  <div className="mt-0.5 text-xs text-fg-subtle">{m.tactics.join(' · ')}</div>
                </div>
                <span className="relative mt-1 h-1.5 w-12 shrink-0 overflow-hidden rounded-full bg-muted" title={`confidence ${m.confidence.toFixed(2)}`}>
                  <span className="absolute inset-y-0 left-0 rounded-full bg-brand-600" style={{ width: `${m.confidence * 100}%` }} />
                </span>
              </div>
              <div className="mt-1.5 text-[13px] text-fg-muted">{m.mapping_reason}</div>
              <div className="mt-2 flex flex-wrap gap-1">
                {m.evidence_alert_ids.slice(0, 4).map((a) => <AlertChip key={a} id={a} onClick={onOpenAlert} />)}
                {m.evidence_alert_ids.length > 4 && <span className="self-center text-[11px] text-fg-faint">+{m.evidence_alert_ids.length - 4} more</span>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

const VERDICTS = [
  { v: 'confirmed_malicious', label: 'Confirmed malicious', variant: 'danger' as const },
  { v: 'needs_investigation', label: 'Needs investigation', variant: 'secondary' as const },
  { v: 'benign_true_positive', label: 'Benign (expected)', variant: 'secondary' as const },
  { v: 'false_positive', label: 'False positive', variant: 'secondary' as const },
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
    <Card title="Analyst verdict" description="Human in the loop. Advisory system: nothing is contained automatically." icon={History}>
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Add a note for the record (optional)"
        rows={2}
        className="w-full rounded-lg border border-line-strong bg-white px-3 py-2 text-sm text-fg shadow-[var(--shadow-xs)] placeholder:text-fg-faint focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-100"
      />
      <div className="mt-3 flex flex-wrap gap-2">
        {VERDICTS.map((x) => <Button key={x.v} size="sm" variant={x.variant} onClick={() => m.mutate(x.v)} disabled={m.isPending}>{x.label}</Button>)}
      </div>
      {m.error && <div className="mt-3"><ErrorState error={m.error} /></div>}
      <div className="mt-5 border-t border-line pt-4">
        <div className="mb-2 text-xs font-medium text-fg-subtle">History (audited)</div>
        {d.feedback.length === 0 ? <div className="text-sm text-fg-faint">No verdicts yet.</div> : (
          <ul className="space-y-2.5">
            {d.feedback.map((f) => (
              <motion.li key={f.created_at} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} className="flex items-start gap-2.5 text-sm">
                <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: f.verdict === 'confirmed_malicious' ? SEV_COLOR.critical : '#079455' }} />
                <div>
                  <span className="font-semibold capitalize text-fg">{f.verdict.replaceAll('_', ' ')}</span>
                  <span className="ml-2 text-xs text-fg-subtle">{f.analyst} · {fmtTime(f.created_at)}</span>
                  {f.notes && <div className="text-[13px] text-fg-muted">“{f.notes}”</div>}
                </div>
              </motion.li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  )
}

function SourceAlerts({ items, loading, onOpenAlert }: { items?: AlertRow[]; loading: boolean; onOpenAlert: (id: string) => void }) {
  const [showAll, setShowAll] = useState(false)
  const rows = showAll ? items ?? [] : (items ?? []).slice(0, 25)
  return (
    <Card
      title="Source alerts and why they were grouped"
      description="Every membership stores its strongest correlation edge and the reasons behind it"
      bodyClass="p-0"
      actions={items && items.length > 25 && <Button size="sm" onClick={() => setShowAll((s) => !s)}>{showAll ? 'Show fewer' : `Show all ${items.length}`}</Button>}
    >
      {loading ? <div className="p-5"><Loading rows={8} /></div> : (
        <div className="scrollbar-thin overflow-x-auto">
          <table className="w-full min-w-[960px] text-sm">
            <thead>
              <tr className="border-b border-line bg-subtle/60 text-left text-xs font-medium text-fg-subtle">
                <th className="px-5 py-2.5 font-medium">Alert</th>
                <th className="px-3 py-2.5 font-medium">Time</th>
                <th className="px-3 py-2.5 font-medium">Severity</th>
                <th className="px-3 py-2.5 font-medium">Title</th>
                <th className="px-3 py-2.5 font-medium">Entities</th>
                <th className="px-3 py-2.5 font-medium">Edge</th>
                <th className="px-5 py-2.5 font-medium">Why grouped</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((a) => (
                <tr key={a.alert_id} className="transition-colors hover:bg-subtle/60">
                  <td className="px-5 py-2.5"><AlertChip id={a.alert_id} onClick={onOpenAlert} /></td>
                  <td className="tabular whitespace-nowrap px-3 py-2.5 text-[13px] text-fg-muted">{fmtClock(a.timestamp)}</td>
                  <td className="px-3 py-2.5"><SeverityBadge severity={a.severity} size="sm" /></td>
                  <td className="px-3 py-2.5 text-fg-2">{a.title}</td>
                  <td className="max-w-[220px] truncate px-3 py-2.5 font-mono text-xs text-fg-subtle">{[a.user, a.host, a.src_ip, a.process, a.resource].filter(Boolean).join(' · ')}</td>
                  <td className="tabular px-3 py-2.5 text-[13px] font-semibold text-fg-2">{a.membership?.edge_score.toFixed(2)}</td>
                  <td className="max-w-[380px] px-5 py-2.5 text-xs text-fg-muted">{a.membership?.reasons.slice(0, 3).join('; ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}
