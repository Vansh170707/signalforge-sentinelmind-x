import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { api } from '../api/client'

const NAV = [
  { to: '/', label: 'Command Center', icon: 'M3 12h4l3-8 4 16 3-8h4' },
  { to: '/incidents', label: 'Incident Queue', icon: 'M4 6h16M4 12h16M4 18h10' },
  { to: '/alerts', label: 'Alert Explorer', icon: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zm10 17-4.3-4.3' },
  { to: '/evaluation', label: 'Evaluation Lab', icon: 'M4 20V10m6 10V4m6 16v-7m6 7H2' },
  { to: '/settings', label: 'Settings & Demo', icon: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14.5 3h-5l-.4 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2l.4 2.6h5l.4-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z' },
]

export function Layout({ children }: { children: ReactNode }) {
  const health = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 15_000 })
  const settings = useQuery({ queryKey: ['settings'], queryFn: api.settings })
  const p = settings.data?.providers
  return (
    <div className="flex h-full min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-ink-800 bg-ink-900/60 lg:flex">
        <div className="flex items-center gap-2.5 px-5 pb-5 pt-6">
          <svg viewBox="0 0 32 32" className="h-8 w-8" aria-hidden>
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7L16 2z" fill="#0e7490" />
            <path d="M10 16.5l4 4 8-9" fill="none" stroke="#e0f2fe" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <div className="text-[15px] font-bold tracking-tight text-slate-50">SentinelMind X</div>
            <div className="text-[10px] uppercase tracking-[0.16em] text-slate-500">Team SignalForge</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${isActive ? 'bg-cyan-500/10 text-cyan-200 ring-1 ring-inset ring-cyan-500/25' : 'text-slate-400 hover:bg-ink-800 hover:text-slate-200'}`
              }
            >
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d={n.icon} />
              </svg>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-2 border-t border-ink-800 px-5 py-4 text-[11px] text-slate-500">
          <div className="flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${health.data?.status === 'ok' ? 'bg-emerald-400' : health.isError ? 'bg-rose-500' : 'bg-slate-500'}`} />
            API {health.data?.status === 'ok' ? `online · ${health.data.database}` : health.isError ? 'offline' : '…'}
          </div>
          {p && (
            <div className="flex flex-wrap gap-1">
              {(['jev', 'gemini', 'groq', 'foundry', 'template'] as const).map((k) => (
                <span key={k} className={`rounded px-1.5 py-0.5 ring-1 ring-inset ${p[k]?.configured ? 'text-emerald-300 ring-emerald-500/30' : 'text-slate-600 ring-ink-700'}`}>
                  {k}
                </span>
              ))}
            </div>
          )}
          <div>ATT&CK v{health.data?.attack_catalog ?? '…'} · advisory only</div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <nav className="flex gap-1 overflow-x-auto border-b border-ink-800 bg-ink-900/60 px-3 py-2 lg:hidden">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === '/'} className={({ isActive }) => `whitespace-nowrap rounded-md px-3 py-1.5 text-sm ${isActive ? 'bg-cyan-500/10 text-cyan-200' : 'text-slate-400'}`}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <main className="mx-auto w-full max-w-[1500px] flex-1 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
