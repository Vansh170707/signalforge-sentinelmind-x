import { useQuery } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { ErrorState, Loading, SeverityBadge, fmtTime } from './ui'

const Ctx = createContext<(id: string) => void>(() => {})

export const useEvidence = () => useContext(Ctx)

export function EvidenceProvider({ children }: { children: ReactNode }) {
  const [alertId, setAlertId] = useState<string | null>(null)
  const open = useCallback((id: string) => setAlertId(id), [])
  return (
    <Ctx.Provider value={open}>
      {children}
      {alertId && <EvidenceDrawer alertId={alertId} onClose={() => setAlertId(null)} onOpen={open} />}
    </Ctx.Provider>
  )
}

function Field({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 py-1 text-[13px]">
      <div className="text-slate-500">{k}</div>
      <div className="break-all font-mono text-slate-200">{v ?? <span className="text-slate-600">—</span>}</div>
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
      <button className="absolute inset-0 bg-black/50 backdrop-blur-[1px]" onClick={onClose} aria-label="Close evidence" />
      <aside className="scrollbar-thin relative h-full w-full max-w-xl overflow-y-auto border-l border-ink-600 bg-ink-900 shadow-2xl">
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-ink-700 bg-ink-900/95 px-5 py-3 backdrop-blur">
          <div>
            <div className="text-[11px] uppercase tracking-[0.12em] text-slate-500">Source alert evidence</div>
            <div className="font-mono text-lg font-semibold text-cyan-300">{alertId}</div>
          </div>
          <button onClick={onClose} className="rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800 hover:text-slate-100" aria-label="Close">✕</button>
        </header>
        <div className="space-y-5 p-5">
          {q.isLoading && <Loading rows={6} />}
          {q.error && <ErrorState error={q.error} />}
          {a && (
            <>
              <div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="text-xs text-slate-500">{a.vendor} · {a.source}</span>
                </div>
                <h3 className="mt-2 text-base font-semibold text-slate-100">{a.title}</h3>
                <div className="text-xs text-slate-500">{fmtTime(a.timestamp)} · {a.alert_type}</div>
              </div>
              {a.membership && (
                <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold uppercase tracking-wide text-cyan-300">Why grouped into {a.membership.incident_id}</span>
                    <span className="font-mono text-cyan-200">edge {a.membership.edge_score.toFixed(2)}</span>
                  </div>
                  <ul className="mt-2 space-y-1 text-[13px] text-slate-300">
                    {a.membership.reasons.map((r) => <li key={r}>• {r}</li>)}
                  </ul>
                  {a.membership.linked_alert_id && (
                    <div className="mt-2 text-xs text-slate-400">
                      Strongest link:{' '}
                      <button className="font-mono text-cyan-300 hover:underline" onClick={() => onOpen(a.membership!.linked_alert_id!)}>
                        {a.membership.linked_alert_id}
                      </button>
                      {' · '}
                      <Link to={`/incidents/${a.membership.incident_id}`} className="text-cyan-300 hover:underline">open incident</Link>
                    </div>
                  )}
                </div>
              )}
              <div className="divide-y divide-ink-800 rounded-lg border border-ink-700 px-3 py-1">
                <Field k="user" v={a.user && <>{a.user} {a.user_display !== a.user && <span className="text-slate-500">(raw: {a.user_display})</span>}</>} />
                <Field k="host" v={a.host && <>{a.host} {a.host_display !== a.host && <span className="text-slate-500">(raw: {a.host_display})</span>}</>} />
                <Field k="src_ip" v={a.src_ip} />
                <Field k="dst_ip" v={a.dst_ip} />
                <Field k="process" v={a.process} />
                <Field k="resource" v={a.resource} />
                <Field k="asset crit." v={`${a.asset_criticality}/5`} />
                <Field k="user privilege" v={`${a.user_privilege}/5`} />
                <Field k="anomaly" v={a.anomaly_score?.toFixed(2)} />
                <Field k="duplicates" v={a.duplicate_count} />
                <Field k="content hash" v={a.content_hash} />
                <Field k="raw ref" v={a.raw_event_ref} />
              </div>
              <div>
                <div className="mb-1.5 flex items-center gap-2 text-[11px] uppercase tracking-[0.12em] text-slate-500">
                  Immutable raw payload
                  <span className="rounded bg-amber-400/10 px-1.5 py-0.5 text-[10px] normal-case tracking-normal text-amber-300 ring-1 ring-amber-400/30">untrusted data · rendered as text</span>
                </div>
                <pre className="scrollbar-thin max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-[12px] leading-relaxed text-slate-300">
                  {JSON.stringify(a.raw, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      </aside>
    </div>
  )
}
