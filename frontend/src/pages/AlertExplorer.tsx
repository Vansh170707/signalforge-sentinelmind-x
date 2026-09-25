import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useEvidence } from '../components/EvidenceDrawer'
import { PageHeader } from '../components/Layout'
import { AlertChip, Button, EmptyState, ErrorState, Loading, Panel, SeverityBadge, fmtTime } from '../components/ui'

export default function AlertExplorer() {
  const open = useEvidence()
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 50
  const params = { q, severity, page, page_size: pageSize }
  const query = useQuery({ queryKey: ['alerts', params], queryFn: () => api.alerts(params), placeholderData: keepPreviousData })
  const data = query.data
  const pages = data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1
  return (
    <>
      <PageHeader title="Alert Explorer" subtitle="Search raw and normalized alerts. This is the haystack the pipeline works through." />
      <Panel
        bodyClass="p-0"
        title={<span>{data ? `${data.total.toLocaleString()} alerts` : 'Alerts'}</span>}
        actions={
          <>
            <input
              value={q}
              onChange={(e) => { setQ(e.target.value); setPage(1) }}
              placeholder="alert id, user, host, IP, type…"
              aria-label="Search alerts"
              className="w-64 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
            />
            <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }} aria-label="Severity" className="rounded-lg border border-ink-600 bg-ink-850 px-2 py-1.5 text-sm text-slate-300">
              <option value="">All severities</option>
              {['critical', 'high', 'medium', 'low', 'informational'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </>
        }
      >
        {query.isLoading ? <div className="p-4"><Loading rows={10} /></div> : query.error ? <div className="p-4"><ErrorState error={query.error} onRetry={() => query.refetch()} /></div> : !data || data.items.length === 0 ? (
          <div className="p-4"><EmptyState title="No alerts">Load the demo dataset or change the search.</EmptyState></div>
        ) : (
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full min-w-[1000px] text-sm">
              <thead>
                <tr className="border-b border-ink-700 text-left text-[11px] uppercase tracking-[0.08em] text-slate-500">
                  <th className="px-4 py-2 font-medium">Alert</th>
                  <th className="px-2 py-2 font-medium">Time</th>
                  <th className="px-2 py-2 font-medium">Severity</th>
                  <th className="px-2 py-2 font-medium">Type / title</th>
                  <th className="px-2 py-2 font-medium">User</th>
                  <th className="px-2 py-2 font-medium">Host</th>
                  <th className="px-2 py-2 font-medium">Source IP</th>
                  <th className="px-2 py-2 font-medium">Anomaly</th>
                  <th className="px-4 py-2 font-medium">Incident</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {data.items.map((a) => (
                  <tr key={a.alert_id} className="hover:bg-ink-800/40">
                    <td className="px-4 py-2"><AlertChip id={a.alert_id} onClick={open} /></td>
                    <td className="whitespace-nowrap px-2 py-2 text-xs text-slate-400">{fmtTime(a.timestamp)}</td>
                    <td className="px-2 py-2"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-2 py-2"><div className="text-slate-200">{a.title}</div><div className="font-mono text-[11px] text-slate-500">{a.alert_type}</div></td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-300">{a.user ?? '—'}</td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-300">{a.host ?? '—'}</td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-300">{a.src_ip ?? '—'}</td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-400">{a.anomaly_score?.toFixed(2) ?? '—'}</td>
                    <td className="px-4 py-2 font-mono text-xs">{a.incident_id ? <Link to={`/incidents/${a.incident_id}`} className="text-cyan-300 hover:underline">{a.incident_id}</Link> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-ink-700 px-4 py-2.5 text-xs text-slate-500">
            <span>page {page} of {pages.toLocaleString()}</span>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Prev</Button>
              <Button size="sm" onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page >= pages}>Next</Button>
            </div>
          </div>
        )}
      </Panel>
    </>
  )
}
