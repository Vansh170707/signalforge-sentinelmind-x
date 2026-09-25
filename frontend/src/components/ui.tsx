import type { ReactNode } from 'react'
import type { Severity } from '../types/api'

export const SEV_COLOR: Record<string, string> = {
  critical: 'var(--color-sev-critical)',
  high: 'var(--color-sev-high)',
  medium: 'var(--color-sev-medium)',
  low: 'var(--color-sev-low)',
  informational: 'var(--color-sev-info)',
}

const SEV_CLASS: Record<string, string> = {
  critical: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  medium: 'bg-yellow-400/10 text-yellow-200 ring-yellow-400/35',
  low: 'bg-sky-400/10 text-sky-300 ring-sky-400/30',
  informational: 'bg-slate-400/10 text-slate-300 ring-slate-400/30',
}

const SEV_ICON: Record<string, string> = { critical: '▲▲', high: '▲', medium: '◆', low: '▽', informational: '·' }

export function SeverityBadge({ severity, className = '' }: { severity: Severity | string; className?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ${SEV_CLASS[severity] ?? SEV_CLASS.informational} ${className}`}
    >
      <span aria-hidden className="text-[9px]">{SEV_ICON[severity] ?? '·'}</span>
      {severity}
    </span>
  )
}

export function RiskPill({ score, severity }: { score: number; severity: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className="relative h-1.5 w-16 overflow-hidden rounded-full bg-ink-700">
        <span className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${score}%`, background: SEV_COLOR[severity] }} />
      </span>
      <span className="tabular w-9 text-right font-mono text-sm font-semibold text-slate-100">{score.toFixed(0)}</span>
    </span>
  )
}

export function Panel({ title, subtitle, actions, children, className = '', bodyClass = 'p-4' }: {
  title?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClass?: string
}) {
  return (
    <section className={`rounded-xl border border-ink-700 bg-ink-900/80 shadow-[0_1px_0_0_rgb(255_255_255/0.03)_inset] ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-ink-700/70 px-4 py-3">
          <div>
            <h2 className="text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-300">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

export function Kpi({ label, value, hint, tone = 'default' }: { label: string; value: ReactNode; hint?: ReactNode; tone?: 'default' | 'critical' | 'accent' }) {
  const toneClass = tone === 'critical' ? 'text-rose-300' : tone === 'accent' ? 'text-cyan-300' : 'text-slate-50'
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-900/80 px-4 py-3.5">
      <div className="text-[11px] font-medium uppercase tracking-[0.1em] text-slate-500">{label}</div>
      <div className={`tabular mt-1 font-mono text-[28px] font-semibold leading-none ${toneClass}`}>{value}</div>
      {hint && <div className="mt-1.5 text-xs text-slate-500">{hint}</div>}
    </div>
  )
}

export function Button({ children, onClick, variant = 'secondary', disabled, size = 'md', type = 'button', title }: {
  children: ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  disabled?: boolean
  size?: 'sm' | 'md' | 'lg'
  type?: 'button' | 'submit'
  title?: string
}) {
  const v = {
    primary: 'bg-cyan-500 text-ink-950 hover:bg-cyan-400 shadow-[0_0_24px_-6px_rgb(34_211_238/0.6)]',
    secondary: 'bg-ink-800 text-slate-200 ring-1 ring-inset ring-ink-600 hover:bg-ink-700',
    ghost: 'text-slate-300 hover:bg-ink-800',
    danger: 'bg-rose-500/15 text-rose-200 ring-1 ring-inset ring-rose-500/40 hover:bg-rose-500/25',
  }[variant]
  const s = { sm: 'px-2.5 py-1 text-xs', md: 'px-3.5 py-2 text-sm', lg: 'px-5 py-3 text-[15px]' }[size]
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 rounded-lg font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${v} ${s}`}
    >
      {children}
    </button>
  )
}

export function AlertChip({ id, onClick }: { id: string; onClick?: (id: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onClick?.(id)}
      className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300 ring-1 ring-inset ring-ink-600 transition hover:bg-cyan-500/15 hover:ring-cyan-500/40"
      title="Open source alert evidence"
    >
      {id}
    </button>
  )
}

export function Loading({ rows = 3, className = '' }: { rows?: number; className?: string }) {
  return (
    <div className={`space-y-2 ${className}`} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton h-5 rounded" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error)
  const trace = (error as { traceId?: string })?.traceId
  return (
    <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-200">
      <div className="font-semibold">Something went wrong</div>
      <div className="mt-1 text-rose-200/80">{msg}</div>
      {trace && <div className="mt-1 font-mono text-[11px] text-rose-300/60">trace {trace}</div>}
      {onRetry && (
        <div className="mt-3">
          <Button size="sm" variant="danger" onClick={onRetry}>Retry</Button>
        </div>
      )}
    </div>
  )
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-ink-600 px-6 py-12 text-center">
      <div className="text-sm font-semibold text-slate-200">{title}</div>
      {children && <div className="mt-1 max-w-md text-sm text-slate-500">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export const fmtTime = (iso: string) =>
  new Date(iso).toLocaleString('en-GB', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC'

export const fmtClock = (iso: string) =>
  new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' })

export const pct = (x: number | null | undefined, digits = 1) => (x === null || x === undefined ? '—' : `${(x * 100).toFixed(digits)}%`)

