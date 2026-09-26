import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, EmptyState, ErrorState, Kpi, Panel, SEV_COLOR, SeverityBadge } from '../components/ui'
import type { StreamBoardItem, StreamState } from '../types/api'

const nf = new Intl.NumberFormat('en-US')
const SPEEDS = [
  { v: 300, label: '300× · 4.8 min' },
  { v: 900, label: '900× · 96 s' },
  { v: 1800, label: '1800× · 48 s' },
]

const clock = (iso?: string | null) => (iso ? new Date(iso).toISOString().slice(11, 19) : '--:--:--')

export default function LiveStream() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const [speed, setSpeed] = useState(900)
  const cached = qc.getQueryData<StreamState>(['stream'])
  const live = !!cached && ['running', 'paused'].includes(cached.status)
  // Keep polling when the tab is not focused (presenter switching windows must not freeze the board).
  const state = useQuery({
    queryKey: ['stream'],
    queryFn: api.streamState,
    refetchInterval: live ? 700 : false,
    refetchIntervalInBackground: true,
  })
  const set = (s: StreamState) => qc.setQueryData(['stream'], s)
  const start = useMutation({ mutationFn: () => api.streamStart(7, speed), onSuccess: set })
  const pause = useMutation({ mutationFn: api.streamPause, onSuccess: set })
  const stop = useMutation({ mutationFn: api.streamStop, onSuccess: set })
  const changeSpeed = useMutation({ mutationFn: (v: number) => api.streamSpeed(v), onSuccess: set })
  const finalize = useMutation({
    mutationFn: api.streamFinalize,
    onSuccess: () => {
      qc.invalidateQueries()
      nav('/')
    },
  })
  const s = state.data
  const active = !!s && s.status !== 'idle'
  const running = s?.status === 'running'

  return (
    <>
      <PageHeader
        title={<span className="flex items-center gap-3">Live Stream {running && <span className="flex items-center gap-1.5 rounded-full bg-rose-500/15 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-rose-300 ring-1 ring-rose-500/40"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-rose-400" />live</span>}</span>}
        subtitle="The demo day replayed as a live alert feed. Incidents assemble, re-correlate and escalate as evidence arrives."
        actions={
          <>
            <select
              value={speed}
              onChange={(e) => {
                const v = Number(e.target.value)
                setSpeed(v)
                if (active) changeSpeed.mutate(v)
              }}
              className="rounded-lg border border-ink-600 bg-ink-850 px-2 py-2 text-sm text-slate-300"
              aria-label="Replay speed"
            >
              {SPEEDS.map((x) => <option key={x.v} value={x.v}>{x.label}</option>)}
            </select>
            {!active || s?.status === 'finished' || s?.status === 'error' ? (
              <Button variant="primary" size="lg" onClick={() => start.mutate()} disabled={start.isPending}>
                {start.isPending ? 'Starting…' : s?.status === 'finished' ? 'Replay again' : 'Start live stream'}
              </Button>
            ) : (
              <>
                <Button size="lg" onClick={() => pause.mutate()}>{running ? 'Pause' : 'Resume'}</Button>
                <Button size="lg" variant="danger" onClick={() => stop.mutate()}>Stop</Button>
              </>
            )}
            {active && (
              <Button size="lg" onClick={() => finalize.mutate()} disabled={finalize.isPending} title="Persist the day and run the full pipeline with Jev, briefs and evaluation">
                {finalize.isPending ? 'Finalizing…' : 'Finalize → full pipeline'}
              </Button>
            )}
          </>
        }
      />
      {(start.error || finalize.error || state.error) && <div className="mb-4"><ErrorState error={start.error ?? finalize.error ?? state.error} /></div>}
      {s?.status === 'error' && <div className="mb-4"><ErrorState error={s.error} /></div>}
      {!active ? (
        <EmptyState title="Stream is idle" action={<Button variant="primary" onClick={() => start.mutate()}>Start live stream</Button>}>
          Replays 24 hours of the synthetic SOC (10,004 alerts) at up to 1800× speed. Correlation, anomaly scoring,
          ATT&CK mapping and risk re-run every ~1.5 s on everything received so far. No external AI is called while streaming.
        </EmptyState>
      ) : (
        <LiveBody s={s!} />
      )}
    </>
  )
}

function LiveBody({ s }: { s: StreamState }) {
  const pct = Math.round((s.progress ?? 0) * 100)
  return (
    <div className="space-y-6">
      <div className="grid gap-3 lg:grid-cols-[280px_1fr]">
        <div className="rounded-xl border border-ink-700 bg-gradient-to-br from-ink-850 to-ink-900 px-5 py-4">
          <div className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Simulated clock (UTC)</div>
          <div className="tabular mt-1 font-mono text-5xl font-semibold tracking-tight text-slate-50">{clock(s.sim_time)}</div>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-ink-700">
            <div className="h-full rounded-full bg-cyan-400 transition-[width] duration-700" style={{ width: `${pct}%` }} />
          </div>
          <div className="mt-1.5 flex justify-between text-[11px] text-slate-500">
            <span>{pct}% of day · {s.speed}×</span>
            <span>{s.status}{s.pipeline_ms ? ` · re-correlated in ${Math.round(s.pipeline_ms)} ms` : ''}</span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Kpi label="Alerts ingested" value={nf.format(s.alerts ?? 0)} hint={`${nf.format(s.rows_seen ?? 0)} of ${nf.format(s.rows_total ?? 0)} rows`} />
          <Kpi label="Dupes / rejected" value={`${s.duplicates ?? 0} / ${s.rejected ?? 0}`} hint="collapsed / row-level errors" />
          <Kpi label="Incidents" value={nf.format(s.incidents ?? 0)} hint="live correlation" tone="accent" />
          <Kpi label="Critical / High" value={s.critical_high ?? 0} hint="need attention now" tone="critical" />
          <Kpi label="Compression" value={s.compression_ratio ? `${s.compression_ratio}×` : '—'} hint="alerts per incident" />
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <Panel title="Alert arrival rate" subtitle="Alerts per 10 minutes (high/critical overlaid)">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={s.buckets ?? []} margin={{ left: -18, right: 6, top: 6 }}>
                <defs>
                  <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1d2a3e" vertical={false} />
                <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} interval={17} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#0b111b', border: '1px solid #2a3a53', borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="alerts" stroke="#22d3ee" fill="url(#gA)" isAnimationActive={false} />
                <Area type="monotone" dataKey="high" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.25} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Escalation feed" subtitle="Incidents crossing into high / critical" bodyClass="p-2">
          <ul className="scrollbar-thin h-56 space-y-1 overflow-y-auto">
            {(s.events ?? []).length === 0 && <li className="px-2 py-6 text-center text-sm text-slate-500">Watching… nothing actionable yet.</li>}
            {(s.events ?? []).map((e, i) => (
              <li key={`${e.key}-${e.severity}`} className={`flex items-start gap-3 rounded-lg px-2.5 py-2 ${i === 0 ? 'bg-ink-800/80 ring-1 ring-inset ring-ink-600' : ''}`}>
                <span className="mt-0.5 font-mono text-xs text-slate-500">{clock(e.sim_time).slice(0, 5)}</span>
                <span className={e.severity === 'critical' && i === 0 ? 'pulse-critical rounded-md' : ''}><SeverityBadge severity={e.severity} /></span>
                <div className="min-w-0">
                  <div className="truncate text-sm text-slate-200">{e.title}</div>
                  <div className="text-[11px] text-slate-500">{e.kind === 'escalated' ? 'escalated' : 'new'} · risk {e.risk.toFixed(0)} · {e.alert_count} alerts</div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <Panel title="Incident board" subtitle="Top incidents by risk, re-ranked on every correlation pass" bodyClass="p-3">
        {(s.board ?? []).length === 0 ? (
          <div className="py-8 text-center text-sm text-slate-500">Waiting for the first correlation pass…</div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {(s.board ?? []).map((b, i) => <BoardCard key={b.key} b={b} rank={i + 1} />)}
          </div>
        )}
      </Panel>
    </div>
  )
}

function BoardCard({ b, rank }: { b: StreamBoardItem; rank: number }) {
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-850 p-3.5 transition-colors" style={{ borderColor: b.severity === 'critical' ? 'rgb(244 63 94 / 0.45)' : undefined }}>
      <div className="flex items-center gap-3">
        <span className="w-5 font-mono text-xs text-slate-500">#{rank}</span>
        <SeverityBadge severity={b.severity} />
        <div className="min-w-0 flex-1 truncate text-sm font-medium text-slate-100" title={b.title}>{b.title}</div>
        <span className="tabular font-mono text-xl font-semibold text-slate-50">{b.risk.toFixed(0)}</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink-700">
        <div className="h-full rounded-full transition-[width] duration-700 ease-out" style={{ width: `${b.risk}%`, background: SEV_COLOR[b.severity] }} />
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
        <span className="text-slate-400">{b.alert_count} alerts</span>
        {b.stages.map((st) => <span key={st} className="rounded bg-ink-700 px-1.5 py-0.5 text-slate-300">{st}</span>)}
        {b.mitre.slice(0, 4).map((t) => <span key={t} className="font-mono text-cyan-300/80">{t}</span>)}
      </div>
    </div>
  )
}
