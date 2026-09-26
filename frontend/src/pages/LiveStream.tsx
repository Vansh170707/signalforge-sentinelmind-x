import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, ArrowRight, Boxes, Database, Gauge, Pause, Play, Radio, Siren, Square } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, Card, Chip, EmptyState, ErrorState, SEV_COLOR, SeverityBadge, StatCard, ease } from '../components/ui'
import type { StreamBoardItem, StreamState } from '../types/api'

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
  const canStart = !active || s?.status === 'finished' || s?.status === 'error'

  return (
    <>
      <PageHeader
        eyebrow="Real-time mode"
        title={
          <span className="flex items-center gap-3">
            Live Stream
            {running && (
              <span className="inline-flex items-center gap-2 rounded-full bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-700 ring-1 ring-inset ring-red-200">
                <span className="relative flex h-2 w-2"><span className="live-ping absolute inline-flex h-full w-full rounded-full bg-red-400" /><span className="relative h-2 w-2 rounded-full bg-red-500" /></span>
                Live
              </span>
            )}
          </span>
        }
        subtitle="The demo day replayed as a live alert feed. Watch incidents assemble, re-correlate and escalate as evidence arrives."
        actions={
          <>
            <select
              value={speed}
              onChange={(e) => {
                const v = Number(e.target.value)
                setSpeed(v)
                if (active) changeSpeed.mutate(v)
              }}
              className="h-9 rounded-lg border border-line-strong bg-white px-2.5 text-sm text-fg-2 shadow-[var(--shadow-xs)]"
              aria-label="Replay speed"
            >
              {SPEEDS.map((x) => <option key={x.v} value={x.v}>{x.label}</option>)}
            </select>
            {canStart ? (
              <Button variant="primary" icon={Play} onClick={() => start.mutate()} loading={start.isPending}>
                {s?.status === 'finished' ? 'Replay again' : 'Start live stream'}
              </Button>
            ) : (
              <>
                <Button icon={running ? Pause : Play} onClick={() => pause.mutate()}>{running ? 'Pause' : 'Resume'}</Button>
                <Button variant="danger" icon={Square} onClick={() => stop.mutate()}>Stop</Button>
              </>
            )}
            {active && (
              <Button icon={ArrowRight} onClick={() => finalize.mutate()} loading={finalize.isPending} title="Persist the day and run the full pipeline with Jev, briefs and evaluation">
                Finalize → full pipeline
              </Button>
            )}
          </>
        }
      />
      {(start.error || finalize.error || state.error) && <div className="mb-5"><ErrorState error={start.error ?? finalize.error ?? state.error} /></div>}
      {s?.status === 'error' && <div className="mb-5"><ErrorState error={s.error} /></div>}
      {!active ? (
        <EmptyState icon={Radio} title="Stream is idle" action={<Button variant="primary" icon={Play} onClick={() => start.mutate()}>Start live stream</Button>}>
          Replays 24 hours of the synthetic SOC (10,004 alerts) at up to 1800× speed. Correlation, anomaly scoring, ATT&CK mapping and
          risk re-run about every 1.5 s on everything received so far. No external AI is called while streaming.
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
      <div className="grid gap-4 xl:grid-cols-[300px_1fr]">
        <div className="relative overflow-hidden rounded-xl border border-line bg-surface px-5 py-4 shadow-[var(--shadow-card)]">
          <div className="text-[13px] font-medium text-fg-subtle">Simulated clock (UTC)</div>
          <div className="tabular mt-1 font-mono text-[44px] font-semibold leading-none tracking-tight text-fg">{clock(s.sim_time)}</div>
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-muted">
            <motion.div className="h-full rounded-full bg-gradient-to-r from-brand-500 to-brand-700" animate={{ width: `${pct}%` }} transition={{ duration: 0.6, ease }} />
          </div>
          <div className="mt-2 flex flex-wrap justify-between gap-x-3 gap-y-0.5 text-xs text-fg-subtle">
            <span>{pct}% of day · {s.speed}×</span>
            <span>{s.status.charAt(0).toUpperCase() + s.status.slice(1)}{s.pipeline_ms ? ` · ${Math.round(s.pipeline_ms)} ms per pass` : ''}</span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="Alerts ingested" value={(s.alerts ?? 0).toLocaleString()} icon={Database} hint={`${(s.rows_seen ?? 0).toLocaleString()} of ${(s.rows_total ?? 0).toLocaleString()} rows · ${s.duplicates ?? 0} dup · ${s.rejected ?? 0} rejected`} />
          <StatCard label="Incidents" value={(s.incidents ?? 0).toLocaleString()} icon={Boxes} tone="brand" hint="live correlation" />
          <StatCard label="Critical & high" value={String(s.critical_high ?? 0)} icon={Siren} tone="critical" hint="need attention now" />
          <StatCard label="Compression" value={s.compression_ratio ? `${s.compression_ratio}×` : '—'} icon={Gauge} hint="alerts per incident" />
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <Card title="Alert arrival rate" description="Alerts per 10 minutes, with high and critical overlaid" icon={Activity}>
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={s.buckets ?? []} margin={{ left: -20, right: 6, top: 6 }}>
                <defs>
                  <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#0f6cbd" stopOpacity={0.28} />
                    <stop offset="100%" stopColor="#0f6cbd" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="gH" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#d92d20" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#d92d20" stopOpacity={0.03} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#eef0f3" vertical={false} />
                <XAxis dataKey="t" tick={{ fill: '#98a2b3', fontSize: 11 }} axisLine={false} tickLine={false} interval={17} />
                <YAxis tick={{ fill: '#98a2b3', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ borderRadius: 10, border: '1px solid #e4e7ec', boxShadow: '0 12px 16px -4px rgb(16 24 40 / 0.08)', fontSize: 12 }} />
                <Area type="monotone" dataKey="alerts" stroke="#0f6cbd" strokeWidth={2} fill="url(#gA)" isAnimationActive={false} />
                <Area type="monotone" dataKey="high" stroke="#d92d20" strokeWidth={1.5} fill="url(#gH)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Escalation feed" description="Incidents crossing into high or critical" icon={Siren} bodyClass="p-2">
          <ul className="scrollbar-thin h-60 space-y-1 overflow-y-auto">
            {(s.events ?? []).length === 0 && <li className="flex h-full items-center justify-center text-sm text-fg-subtle">Watching the feed… nothing actionable yet.</li>}
            <AnimatePresence initial={false}>
              {(s.events ?? []).map((e, i) => (
                <motion.li
                  key={`${e.key}-${e.severity}`}
                  layout
                  initial={{ opacity: 0, x: -16, backgroundColor: e.severity === 'critical' ? '#fef3f2' : '#fffaeb' }}
                  animate={{ opacity: 1, x: 0, backgroundColor: i === 0 ? (e.severity === 'critical' ? '#fef3f2' : '#fffaeb') : '#ffffff' }}
                  transition={{ duration: 0.4, ease }}
                  className="flex items-start gap-3 rounded-lg px-3 py-2.5"
                >
                  <span className="tabular mt-0.5 font-mono text-xs text-fg-faint">{clock(e.sim_time).slice(0, 5)}</span>
                  <SeverityBadge severity={e.severity} size="sm" />
                  <div className="min-w-0">
                    <div className="truncate text-[13px] font-semibold text-fg">{e.title}</div>
                    <div className="text-xs text-fg-subtle">{e.kind === 'escalated' ? 'Escalated' : 'New'} · risk {e.risk.toFixed(0)} · {e.alert_count} alerts</div>
                  </div>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        </Card>
      </div>

      <Card title="Incident board" description="Top incidents by risk, re-ranked on every correlation pass" icon={Boxes} bodyClass="p-4">
        {(s.board ?? []).length === 0 ? (
          <div className="py-10 text-center text-sm text-fg-subtle">Waiting for the first correlation pass…</div>
        ) : (
          <motion.div layout className="grid gap-3 md:grid-cols-2">
            <AnimatePresence initial={false}>
              {(s.board ?? []).map((b, i) => <BoardCard key={b.key} b={b} rank={i + 1} />)}
            </AnimatePresence>
          </motion.div>
        )}
      </Card>
    </div>
  )
}

function BoardCard({ b, rank }: { b: StreamBoardItem; rank: number }) {
  const hot = b.severity === 'critical'
  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.97 }}
      transition={{ layout: { type: 'spring', stiffness: 380, damping: 34 }, duration: 0.3 }}
      className={`rounded-xl border bg-white p-4 shadow-[var(--shadow-xs)] ${hot ? 'border-red-200 ring-4 ring-red-50' : 'border-line'}`}
    >
      <div className="flex items-center gap-3">
        <span className="tabular w-5 text-[13px] font-medium text-fg-faint">{rank}</span>
        <SeverityBadge severity={b.severity} size="sm" />
        <div className="min-w-0 flex-1 truncate text-sm font-semibold text-fg" title={b.title}>{b.title}</div>
        <motion.span key={Math.round(b.risk)} initial={{ opacity: 0.4, y: -3 }} animate={{ opacity: 1, y: 0 }} className="tabular text-xl font-semibold text-fg">{b.risk.toFixed(0)}</motion.span>
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-muted">
        <motion.div className="h-full rounded-full" style={{ background: SEV_COLOR[b.severity] }} animate={{ width: `${b.risk}%` }} transition={{ duration: 0.7, ease }} />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs text-fg-subtle">{b.alert_count} alerts</span>
        <AnimatePresence initial={false}>
          {b.stages.map((st) => (
            <motion.span key={st} initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.25 }}>
              <Chip>{st}</Chip>
            </motion.span>
          ))}
        </AnimatePresence>
        {b.mitre.slice(0, 4).map((t) => <Chip key={t} mono tone="brand">{t}</Chip>)}
      </div>
    </motion.div>
  )
}
