import { useQuery } from '@tanstack/react-query'
import { FlaskConical, LayoutDashboard, ListChecks, Radio, ScanSearch, Settings, WifiOff, type LucideIcon } from 'lucide-react'
import { motion } from 'motion/react'
import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { api } from '../api/client'

const NAV: { group: string; items: { to: string; label: string; icon: LucideIcon }[] }[] = [
  {
    group: 'Operate',
    items: [
      { to: '/', label: 'Command Center', icon: LayoutDashboard },
      { to: '/live', label: 'Live Stream', icon: Radio },
      { to: '/incidents', label: 'Incidents', icon: ListChecks },
      { to: '/alerts', label: 'Alert Explorer', icon: ScanSearch },
    ],
  },
  { group: 'Assure', items: [{ to: '/evaluation', label: 'Evaluation Lab', icon: FlaskConical }] },
  { group: 'Configure', items: [{ to: '/settings', label: 'Settings & Data', icon: Settings }] },
]

export function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden>
      <rect width="32" height="32" rx="8" fill="#0f6cbd" />
      <path d="M16 6.5 9 9.4v5.1c0 4.6 3 8.3 7 9.5 4-1.2 7-4.9 7-9.5V9.4L16 6.5z" fill="none" stroke="#fff" strokeWidth="2" strokeLinejoin="round" />
      <path d="M12.6 15.6l2.4 2.4 4.6-5" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ProviderDot({ name, on }: { name: string; on: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-fg-muted" title={on ? `${name} configured` : `${name} not configured`}>
      <span className={`h-1.5 w-1.5 rounded-full ${on ? 'bg-emerald-500' : 'bg-line-strong'}`} />
      {name}
    </span>
  )
}

export function Layout({ children }: { children: ReactNode }) {
  const health = useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 15_000 })
  const settings = useQuery({ queryKey: ['settings'], queryFn: api.settings })
  const p = settings.data?.providers
  const ok = health.data?.status === 'ok'
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-[248px] shrink-0 flex-col border-r border-line bg-surface lg:flex">
        <div className="flex items-center gap-2.5 px-5 pb-6 pt-5">
          <Logo />
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight text-fg">SentinelMind X</div>
            <div className="text-xs text-fg-subtle">by Team SignalForge</div>
          </div>
        </div>
        <nav className="flex-1 space-y-6 px-3">
          {NAV.map((g) => (
            <div key={g.group}>
              <div className="px-2.5 pb-1.5 text-xs font-medium text-fg-faint">{g.group}</div>
              <div className="space-y-0.5">
                {g.items.map((n) => (
                  <NavLink key={n.to} to={n.to} end={n.to === '/'} className="block">
                    {({ isActive }) => (
                      <span className={`relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-colors ${isActive ? 'text-brand-700' : 'text-fg-muted hover:bg-subtle hover:text-fg'}`}>
                        {isActive && (
                          <motion.span layoutId="nav-active" className="absolute inset-0 rounded-lg bg-brand-50 ring-1 ring-inset ring-brand-100" transition={{ type: 'spring', stiffness: 500, damping: 38 }} />
                        )}
                        <n.icon className="relative h-[18px] w-[18px]" strokeWidth={2} />
                        <span className="relative">{n.label}</span>
                        {n.to === '/live' && <span className="relative ml-auto rounded-full bg-red-50 px-1.5 text-[10px] font-semibold text-red-600 ring-1 ring-inset ring-red-200">LIVE</span>}
                      </span>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="m-3 rounded-xl border border-line bg-subtle/60 p-3.5">
          <div className="flex items-center gap-2 text-[13px] font-medium text-fg-2">
            <span className="relative flex h-2 w-2">
              {ok && <span className="live-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400" />}
              <span className={`relative inline-flex h-2 w-2 rounded-full ${ok ? 'bg-emerald-500' : health.isError ? 'bg-red-500' : 'bg-line-strong'}`} />
            </span>
            {ok ? 'All systems operational' : health.isError ? 'API offline' : 'Connecting…'}
          </div>
          {p && (
            <div className="mt-2.5 grid grid-cols-2 gap-x-2 gap-y-1.5">
              <ProviderDot name="Jev" on={!!p.jev?.configured} />
              <ProviderDot name="Mercury" on={!!p.mercury?.configured} />
              <ProviderDot name="Groq" on={!!p.groq?.configured} />
              <ProviderDot name="Gemini" on={!!p.gemini?.configured} />
            </div>
          )}
          {health.data?.offline_mode && (
            <div className="mt-2.5 flex items-center gap-1.5 rounded-md bg-amber-50 px-2 py-1 text-xs font-medium text-amber-800 ring-1 ring-inset ring-amber-200">
              <WifiOff className="h-3.5 w-3.5" /> Offline demo mode
            </div>
          )}
          <div className="mt-2.5 border-t border-line pt-2 text-[11px] text-fg-subtle">
            ATT&CK v{health.data?.attack_catalog ?? '…'} · {health.data?.database ?? '…'} · advisory only
          </div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <nav className="flex items-center gap-1 overflow-x-auto border-b border-line bg-surface px-3 py-2 lg:hidden">
          <Logo size={24} />
          {NAV.flatMap((g) => g.items).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === '/'} className={({ isActive }) => `whitespace-nowrap rounded-md px-2.5 py-1.5 text-sm font-medium ${isActive ? 'bg-brand-50 text-brand-700' : 'text-fg-muted'}`}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <main className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-7 sm:px-6 lg:px-10">{children}</main>
      </div>
    </div>
  )
}

export function PageHeader({ title, subtitle, actions, eyebrow }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1.5 text-[13px] font-medium text-brand-600">{eyebrow}</div>}
        <h1 className="text-[26px] font-semibold tracking-tight text-fg">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-[15px] text-fg-subtle">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
