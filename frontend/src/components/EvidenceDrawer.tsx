import { useQuery } from '@tanstack/react-query'
import { ArrowUpRight, FileText, Link2, ShieldAlert, X } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { ErrorState, Loading, SeverityBadge, ease, fmtTime } from './ui'

const Ctx = createContext<(id: string) => void>(() => {})

// eslint-disable-next-line react-refresh/only-export-components
export const useEvidence = () => useContext(Ctx)

export function EvidenceProvider({ children }: { children: ReactNode }) {
  const [alertId, setAlertId] = useState<string | null>(null)
  const open = useCallback((id: string) => setAlertId(id), [])
  return (
    <Ctx.Provider value={open}>
      {children}
      <AnimatePresence>
        {alertId && <EvidenceDrawer key="drawer" alertId={alertId} onClose={() => setAlertId(null)} onOpen={open} />}
      </AnimatePresence>
    </Ctx.Provider>
  )
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="grid grid-cols-[128px_1fr] gap-3 py-2 text-[13px]">
      <div className="text-fg-subtle">{k}</div>
      <div className="break-all font-mono text-fg-2">{v ?? <span className="text-fg-faint">—</span>}</div>
    </div>
  )
}

function EvidenceDrawer({ alertId, onClose, onOpen }: { alertId: string; onClose: () => void; onOpen: (id: string) => void }) {
  const q = useQuery({ queryKey: ['alert', alertId], queryFn: () => api.alert(alertId) })
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  const a = q.data
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={`Alert ${alertId}`}>
      <motion.button
        className="absolute inset-0 bg-slate-900/20 backdrop-blur-[2px]"
        onClick={onClose}
        aria-label="Close evidence"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      />
      <motion.aside
        className="scrollbar-thin relative h-full w-full max-w-[560px] overflow-y-auto border-l border-line bg-surface shadow-[var(--shadow-pop)]"
        initial={{ x: 48, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: 48, opacity: 0 }}
        transition={{ duration: 0.28, ease }}
      >
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-line bg-surface/95 px-6 py-4 backdrop-blur">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-50 text-brand-600"><FileText className="h-4.5 w-4.5" /></span>
            <div>
              <div className="text-xs font-medium text-fg-subtle">Source alert evidence</div>
              <div className="font-mono text-[15px] font-semibold text-fg">{alertId}</div>
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 text-fg-subtle transition hover:bg-subtle hover:text-fg" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </header>
        <div className="space-y-6 p-6">
          {q.isLoading && <Loading rows={8} />}
          {q.error && <ErrorState error={q.error} />}
          {a && (
            <>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="text-xs text-fg-subtle">{a.vendor} · {a.source}</span>
                </div>
                <h3 className="mt-2 text-lg font-semibold text-fg">{a.title}</h3>
                <div className="mt-0.5 text-[13px] text-fg-subtle">{fmtTime(a.timestamp)} · <span className="font-mono">{a.alert_type}</span></div>
              </div>
              {a.membership && (
                <div className="rounded-xl border border-brand-200 bg-brand-50/60 p-4">
                  <div className="flex items-center justify-between text-[13px]">
                    <span className="flex items-center gap-1.5 font-semibold text-brand-800"><Link2 className="h-4 w-4" /> Why grouped into {a.membership.incident_id}</span>
                    <span className="rounded-md bg-white px-1.5 py-0.5 font-mono text-xs text-brand-700 ring-1 ring-brand-200">edge {a.membership.edge_score.toFixed(2)}</span>
                  </div>
                  <ul className="mt-2.5 space-y-1.5 text-[13px] text-fg-2">
                    {a.membership.reasons.map((r) => <li key={r} className="flex gap-2"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-brand-500" />{r}</li>)}
                  </ul>
                  <div className="mt-3 flex flex-wrap items-center gap-3 text-[13px]">
                    {a.membership.linked_alert_id && (
                      <button className="font-mono font-medium text-brand-700 hover:underline" onClick={() => onOpen(a.membership!.linked_alert_id!)}>
                        strongest link {a.membership.linked_alert_id}
                      </button>
                    )}
                    <Link to={`/incidents/${a.membership.incident_id}`} className="inline-flex items-center gap-1 font-medium text-brand-700 hover:underline">
                      Open incident <ArrowUpRight className="h-3.5 w-3.5" />
                    </Link>
                  </div>
                </div>
              )}
              <div className="divide-y divide-line rounded-xl border border-line px-4">
                <Row k="User" v={a.user && <>{a.user}{a.user_display !== a.user && <span className="text-fg-faint"> · raw {a.user_display}</span>}</>} />
                <Row k="Host" v={a.host && <>{a.host}{a.host_display !== a.host && <span className="text-fg-faint"> · raw {a.host_display}</span>}</>} />
                <Row k="Source IP" v={a.src_ip} />
                <Row k="Destination IP" v={a.dst_ip} />
                <Row k="Process" v={a.process} />
                <Row k="Resource" v={a.resource} />
                <Row k="Asset criticality" v={`${a.asset_criticality} / 5`} />
                <Row k="User privilege" v={`${a.user_privilege} / 5`} />
                <Row k="Anomaly score" v={a.anomaly_score?.toFixed(2)} />
                <Row k="Duplicates" v={a.duplicate_count} />
                <Row k="Content hash" v={a.content_hash} />
                <Row k="Raw reference" v={a.raw_event_ref} />
              </div>
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[13px] font-semibold text-fg">Immutable raw payload</span>
                  <span className="inline-flex items-center gap-1 rounded-md bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-800 ring-1 ring-inset ring-amber-200">
                    <ShieldAlert className="h-3 w-3" /> untrusted data · rendered as text
                  </span>
                </div>
                <pre className="scrollbar-thin max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-xl border border-line bg-subtle/70 p-4 font-mono text-[12px] leading-relaxed text-fg-2">
                  {JSON.stringify(a.raw, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </motion.aside>
    </div>
  )
}
