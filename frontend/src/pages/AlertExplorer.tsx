import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, ScanSearch, Search } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { useEvidence } from '../components/EvidenceDrawer'
import { PageHeader } from '../components/Layout'
import { AlertChip, Button, Card, EmptyState, ErrorState, Loading, SeverityBadge, fmtTime } from '../components/ui'

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
      <PageHeader eyebrow="Raw telemetry" title="Alert Explorer" subtitle="Every normalized alert. This is the haystack the pipeline works through." />
      <Card bodyClass="p-0">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div className="text-sm text-fg-subtle">{data ? <><span className="font-semibold text-fg">{data.total.toLocaleString()}</span> alerts</> : 'Alerts'}</div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
              <input
                value={q}
                onChange={(e) => { setQ(e.target.value); setPage(1) }}
                placeholder="Alert ID, user, host, IP or type"
                aria-label="Search alerts"
                className="h-8 w-72 rounded-lg border border-line-strong bg-white pl-8 pr-3 text-[13px] text-fg shadow-[var(--shadow-xs)] placeholder:text-fg-faint focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-100"
              />
            </label>
            <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }} aria-label="Severity" className="h-8 rounded-lg border border-line-strong bg-white px-2 text-[13px] text-fg-2 shadow-[var(--shadow-xs)]">
              <option value="">Any severity</option>
              {['critical', 'high', 'medium', 'low', 'informational'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
        {query.isLoading ? <div className="p-5"><Loading rows={12} /></div> : query.error ? <div className="p-5"><ErrorState error={query.error} onRetry={() => query.refetch()} /></div> : !data || data.items.length === 0 ? (
          <div className="p-5"><EmptyState icon={ScanSearch} title="No alerts">Load the demo dataset or change the search.</EmptyState></div>
        ) : (
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full min-w-[1040px] text-sm">
              <thead>
                <tr className="border-b border-line bg-subtle/60 text-left text-xs font-medium text-fg-subtle">
                  <th className="px-4 py-2.5 font-medium">Alert</th>
                  <th className="px-3 py-2.5 font-medium">Time</th>
                  <th className="px-3 py-2.5 font-medium">Severity</th>
                  <th className="px-3 py-2.5 font-medium">Title</th>
                  <th className="px-3 py-2.5 font-medium">User</th>
                  <th className="px-3 py-2.5 font-medium">Host</th>
                  <th className="px-3 py-2.5 font-medium">Source IP</th>
                  <th className="px-3 py-2.5 font-medium">Anomaly</th>
                  <th className="px-4 py-2.5 font-medium">Incident</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.items.map((a) => (
                  <tr key={a.alert_id} className="transition-colors hover:bg-subtle/60">
                    <td className="px-4 py-2.5"><AlertChip id={a.alert_id} onClick={open} /></td>
                    <td className="whitespace-nowrap px-3 py-2.5 text-[13px] text-fg-muted">{fmtTime(a.timestamp)}</td>
                    <td className="px-3 py-2.5"><SeverityBadge severity={a.severity} size="sm" /></td>
                    <td className="px-3 py-2.5"><div className="font-medium text-fg">{a.title}</div><div className="font-mono text-[11px] text-fg-faint">{a.alert_type}</div></td>
                    <td className="px-3 py-2.5 font-mono text-xs text-fg-2">{a.user ?? '—'}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-fg-2">{a.host ?? '—'}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-fg-2">{a.src_ip ?? '—'}</td>
                    <td className="px-3 py-2.5">
                      {a.anomaly_score != null ? (
                        <span className="inline-flex items-center gap-2">
                          <span className="relative h-1.5 w-10 overflow-hidden rounded-full bg-muted"><span className="absolute inset-y-0 left-0 rounded-full bg-brand-600" style={{ width: `${a.anomaly_score * 100}%` }} /></span>
                          <span className="tabular text-xs text-fg-muted">{a.anomaly_score.toFixed(2)}</span>
                        </span>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs">{a.incident_id ? <Link to={`/incidents/${a.incident_id}`} className="font-medium text-brand-600 hover:underline">{a.incident_id}</Link> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-line px-4 py-3 text-[13px] text-fg-subtle">
            <span>Page {page} of {pages.toLocaleString()}</span>
            <div className="flex gap-2">
              <Button size="sm" icon={ChevronLeft} onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
              <Button size="sm" onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page >= pages}>Next <ChevronRight className="h-4 w-4" /></Button>
            </div>
          </div>
        )}
      </Card>
    </>
  )
}
