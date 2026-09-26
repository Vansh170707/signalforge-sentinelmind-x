import { CircleAlert, Inbox, LoaderCircle, type LucideIcon } from 'lucide-react'
import { animate, motion, useInView, useMotionValue, useTransform } from 'motion/react'
import { useEffect, useRef, type ReactNode } from 'react'
import type { Severity } from '../types/api'

/* ------------------------------------------------------------------ tokens */
export const SEV_COLOR: Record<string, string> = {
  critical: '#d92d20',
  high: '#ef6820',
  medium: '#dc9b04',
  low: '#0f6cbd',
  informational: '#98a2b3',
}

const SEV_STYLE: Record<string, string> = {
  critical: 'bg-red-50 text-red-700 ring-red-600/15',
  high: 'bg-orange-50 text-orange-700 ring-orange-600/15',
  medium: 'bg-amber-50 text-amber-800 ring-amber-600/20',
  low: 'bg-brand-50 text-brand-700 ring-brand-600/15',
  informational: 'bg-subtle text-fg-muted ring-line-strong/60',
}

export const ease = [0.22, 1, 0.36, 1] as const

/* ------------------------------------------------------------------ badges & chips */
export function SeverityBadge({ severity, size = 'md' }: { severity: Severity | string; size?: 'sm' | 'md' }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full font-medium capitalize ring-1 ring-inset ${SEV_STYLE[severity] ?? SEV_STYLE.informational} ${size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-0.5 text-xs'}`}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR[severity] ?? SEV_COLOR.informational }} />
      {severity === 'informational' ? 'Info' : severity}
    </span>
  )
}

export function Chip({ children, tone = 'neutral', mono = false, title }: { children: ReactNode; tone?: 'neutral' | 'brand' | 'violet' | 'green'; mono?: boolean; title?: string }) {
  const t = {
    neutral: 'bg-subtle text-fg-2 ring-line',
    brand: 'bg-brand-50 text-brand-700 ring-brand-200',
    violet: 'bg-violet-50 text-violet-700 ring-violet-200',
    green: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  }[tone]
  return (
    <span title={title} className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${t} ${mono ? 'font-mono' : ''}`}>
      {children}
    </span>
  )
}

export function AlertChip({ id, onClick }: { id: string; onClick?: (id: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onClick?.(id)}
      className="rounded-md bg-white px-1.5 py-0.5 font-mono text-[11px] text-brand-700 ring-1 ring-inset ring-line transition hover:bg-brand-50 hover:ring-brand-200"
      title="Open source alert evidence"
    >
      {id}
    </button>
  )
}

/* ------------------------------------------------------------------ risk */
export function RiskMeter({ score, severity }: { score: number; severity: string }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <span className="relative h-1.5 w-14 overflow-hidden rounded-full bg-muted">
        <motion.span
          className="absolute inset-y-0 left-0 rounded-full"
          style={{ background: SEV_COLOR[severity] }}
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.8, ease }}
        />
      </span>
      <span className="tabular w-7 text-right text-sm font-semibold text-fg">{score.toFixed(0)}</span>
    </span>
  )
}

export function RiskRing({ score, severity, size = 76, stroke = 7, label = 'risk' }: { score: number; severity: string; size?: number; stroke?: number; label?: string }) {
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-muted)" strokeWidth={stroke} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={SEV_COLOR[severity]}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c * (1 - score / 100) }}
          transition={{ duration: 1.1, ease }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <CountUp value={score} className="tabular text-xl font-semibold leading-none text-fg" />
        <span className="mt-0.5 text-[10px] font-medium uppercase tracking-wide text-fg-subtle">{label}</span>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ numbers */
export function CountUp({ value, decimals = 0, suffix = '', className = '' }: { value: number; decimals?: number; suffix?: string; className?: string }) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true })
  const mv = useMotionValue(0)
  const text = useTransform(mv, (v) => `${v.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}${suffix}`)
  useEffect(() => {
    if (!inView) return
    const controls = animate(mv, value, { duration: 0.9, ease })
    return () => controls.stop()
  }, [inView, value, mv])
  return <motion.span ref={ref} className={className}>{text}</motion.span>
}

/* ------------------------------------------------------------------ layout primitives */
export function Card({ title, description, actions, children, className = '', bodyClass = 'p-5', icon: Icon }: {
  title?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClass?: string
  icon?: LucideIcon
}) {
  return (
    <section className={`rounded-xl border border-line bg-surface shadow-[var(--shadow-card)] ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-3.5">
          <div className="flex min-w-0 items-start gap-2.5">
            {Icon && <Icon className="mt-0.5 h-4 w-4 shrink-0 text-fg-subtle" strokeWidth={2} />}
            <div className="min-w-0">
              <h2 className="text-[15px] font-semibold text-fg">{title}</h2>
              {description && <p className="mt-0.5 text-[13px] text-fg-subtle">{description}</p>}
            </div>
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}
export const Panel = Card

export function StatCard({ label, value, hint, icon: Icon, tone = 'default', decimals = 0, suffix = '' }: {
  label: string
  value: number | string | null | undefined
  hint?: ReactNode
  icon?: LucideIcon
  tone?: 'default' | 'critical' | 'brand'
  decimals?: number
  suffix?: string
}) {
  const color = tone === 'critical' ? 'text-red-600' : tone === 'brand' ? 'text-brand-600' : 'text-fg'
  return (
    <div className="rounded-xl border border-line bg-surface px-5 py-4 shadow-[var(--shadow-card)]">
      <div className="flex items-center justify-between">
        <span className="text-[13px] font-medium text-fg-subtle">{label}</span>
        {Icon && (
          <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${tone === 'critical' ? 'bg-red-50 text-red-600' : tone === 'brand' ? 'bg-brand-50 text-brand-600' : 'bg-subtle text-fg-subtle'}`}>
            <Icon className="h-3.5 w-3.5" strokeWidth={2.2} />
          </span>
        )}
      </div>
      <div className={`tabular mt-2 text-[28px] font-semibold leading-none tracking-tight ${color}`}>
        {typeof value === 'number' ? <CountUp value={value} decimals={decimals} suffix={suffix} /> : value ?? '—'}
      </div>
      {hint && <div className="mt-2 text-xs text-fg-subtle">{hint}</div>}
    </div>
  )
}
export const Kpi = StatCard

export function Button({ children, onClick, variant = 'secondary', disabled, size = 'md', type = 'button', title, icon: Icon, loading }: {
  children: ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  disabled?: boolean
  size?: 'sm' | 'md' | 'lg'
  type?: 'button' | 'submit'
  title?: string
  icon?: LucideIcon
  loading?: boolean
}) {
  const v = {
    primary: 'bg-brand-600 text-white shadow-[var(--shadow-xs)] hover:bg-brand-700 ring-1 ring-inset ring-brand-700/40',
    secondary: 'bg-white text-fg-2 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-line-strong hover:bg-subtle',
    ghost: 'text-fg-muted hover:bg-subtle hover:text-fg',
    danger: 'bg-white text-red-700 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-red-200 hover:bg-red-50',
  }[variant]
  const s = { sm: 'h-8 px-3 text-[13px] gap-1.5', md: 'h-9 px-3.5 text-sm gap-2', lg: 'h-10 px-4 text-sm gap-2' }[size]
  const I = loading ? LoaderCircle : Icon
  return (
    <motion.button
      whileTap={{ scale: 0.97 }}
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled || loading}
      className={`inline-flex shrink-0 items-center justify-center rounded-lg font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${v} ${s}`}
    >
      {I && <I className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} strokeWidth={2.2} />}
      {children}
    </motion.button>
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton rounded-md ${className}`} />
}

export function Loading({ rows = 3, className = '' }: { rows?: number; className?: string }) {
  return (
    <div className={`space-y-2.5 ${className}`} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => <Skeleton key={i} className="h-5" />)}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error)
  const trace = (error as { traceId?: string })?.traceId
  return (
    <div role="alert" className="flex gap-3 rounded-xl border border-red-200 bg-red-50/70 p-4 text-sm">
      <CircleAlert className="mt-0.5 h-5 w-5 shrink-0 text-red-600" />
      <div className="min-w-0">
        <div className="font-semibold text-red-800">Something went wrong</div>
        <div className="mt-0.5 break-words text-red-700">{msg}</div>
        {trace && <div className="mt-1 font-mono text-[11px] text-red-500">trace {trace}</div>}
        {onRetry && <div className="mt-3"><Button size="sm" variant="danger" onClick={onRetry}>Try again</Button></div>}
      </div>
    </div>
  )
}

export function EmptyState({ title, children, action, icon: Icon = Inbox }: { title: string; children?: ReactNode; action?: ReactNode; icon?: LucideIcon }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-line-strong bg-surface px-6 py-14 text-center">
      <span className="flex h-11 w-11 items-center justify-center rounded-full bg-brand-50 ring-8 ring-brand-50/50">
        <Icon className="h-5 w-5 text-brand-600" />
      </span>
      <div className="mt-4 text-[15px] font-semibold text-fg">{title}</div>
      {children && <div className="mt-1 max-w-md text-sm text-fg-subtle">{children}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}

/* ------------------------------------------------------------------ motion helpers */
export function Stagger({ children, className = '', delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  return (
    <motion.div
      className={className}
      initial="hidden"
      animate="show"
      variants={{ hidden: {}, show: { transition: { staggerChildren: 0.05, delayChildren: delay } } }}
    >
      {children}
    </motion.div>
  )
}

export function Item({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <motion.div
      className={className}
      variants={{ hidden: { opacity: 0, y: 10 }, show: { opacity: 1, y: 0, transition: { duration: 0.35, ease } } }}
    >
      {children}
    </motion.div>
  )
}

/* ------------------------------------------------------------------ formatting */
export const fmtTime = (iso: string) =>
  new Date(iso).toLocaleString('en-GB', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC'

export const fmtClock = (iso: string) =>
  new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' })

export const pct = (x: number | null | undefined, digits = 1) => (x === null || x === undefined ? '—' : `${(x * 100).toFixed(digits)}%`)
