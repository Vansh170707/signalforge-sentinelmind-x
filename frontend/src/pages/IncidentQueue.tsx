import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, EmptyState, ErrorState, Loading, Panel, RiskPill, SeverityBadge, fmtTime, pct } from '../components/ui'

const SEVS = ['critical', 'high', 'medium', 'low']

export default function IncidentQueue() {
  const nav = useNavigate()
  const [sev, setSev] = useState<string[]>([])
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [sort, setSort] = useState('risk')
  const [page, setPage] = useState(1)
  const pageSize = 25
  const params = { severity: sev.join(','), q, status, sort, page, page_size: pageSize }
  const query = useQuery({ queryKey: ['incidents', params], queryFn: () => api.incidents(params), placeholderData: keepPreviousData })
  const data = query.data
  const pages = data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1
  const toggle = (s: string) => {
    setPage(1)
    setSev((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))
  }

  return (
    <>
      <PageHeader title="Incident Queue" subtitle="Correlated incidents ranked by explainable, business-aware risk." />
      <Panel
        bodyClass="p-0"
        title={
          <div className="flex flex-wrap items-center gap-2 normal-case tracking-normal">
            {SEVS.map((s) => (
              <button key={s} onClick={() => toggle(s)} className={`rounded-md transition ${sev.includes(s) ? 'ring-2 ring-cyan-400/60' : 'opacity-70 hover:opacity-100'}`}>
                <SeverityBadge severity={s} />
              </button>
            ))}
          </div>
        }
        actions={
          <>
            <input
              value={q}
              onChange={(e) => { setQ(e.target.value); setPage(1) }}
              placeholder="Search title or ID…"
              className="w-48 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
              aria-label="Search incidents"
            />
            <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }} className="rounded-lg border border-ink-600 bg-ink-850 px-2 py-1.5 text-sm text-slate-300" aria-label="Status">
              <option value="">All status</option>
              <option value="new">New</option>
              <option value="triaged">Triaged</option>
              <option value="closed">Closed</option>
            </select>
            <select value={sort} onChange={(e) => setSort(e.target.value)} className="rounded-lg border border-ink-600 bg-ink-850 px-2 py-1.5 text-sm text-slate-300" aria-label="Sort">
              <option value="risk">Sort: risk</option>
              <option value="recent">Sort: most recent</option>
              <option value="alerts">Sort: alert count</option>
            </select>
          </>
        }
      >
        {query.isLoading ? (
          <div className="p-4"><Loading rows={8} /></div>
        ) : query.error ? (
          <div className="p-4"><ErrorState error={query.error} onRetry={() => query.refetch()} /></div>
        ) : !data || data.items.length === 0 ? (
          <div className="p-4">
            <EmptyState title="No incidents match" action={<Link to="/"><Button>Go to Command Center</Button></Link>}>
              Load the demo and run the pipeline, or relax the filters.
            </EmptyState>
          </div>
        ) : (
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full min-w-[1000px] text-sm">
              <thead>
                <tr className="border-b border-ink-700 text-left text-[11px] uppercase tracking-[0.08em] text-slate-500">
                  <th className="px-4 py-2.5 font-medium">#</th>
                  <th className="px-2 py-2.5 font-medium">Risk</th>
                  <th className="px-2 py-2.5 font-medium">Severity</th>
                  <th className="px-2 py-2.5 font-medium">Incident</th>
                  <th className="px-2 py-2.5 font-medium">Alerts</th>
                  <th className="px-2 py-2.5 font-medium">Entities</th>
                  <th className="px-2 py-2.5 font-medium">ATT&CK</th>
                  <th className="px-2 py-2.5 font-medium">Conf.</th>
                  <th className="px-2 py-2.5 font-medium">First seen</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {data.items.map((i) => (
                  <tr key={i.incident_id} onClick={() => nav(`/incidents/${i.incident_id}`)} className="cursor-pointer transition hover:bg-ink-800/50">
                    <td className="px-4 py-3 font-mono text-xs text-slate-500">{i.rank}</td>
                    <td className="px-2 py-3"><RiskPill score={i.risk_score} severity={i.severity} /></td>
                    <td className="px-2 py-3"><SeverityBadge severity={i.severity} /></td>
                    <td className="max-w-[340px] px-2 py-3">
                      <Link to={`/incidents/${i.incident_id}`} onClick={(e) => e.stopPropagation()} className="block truncate font-medium text-slate-100 hover:text-cyan-200">{i.title}</Link>
                      <div className="font-mono text-[11px] text-slate-500">{i.incident_id}{i.risk_formula === 'v2-jev' && <span className="ml-2 text-violet-300">Jev</span>}</div>
                    </td>
                    <td className="tabular px-2 py-3 font-mono text-slate-300">
                      {i.alert_count}
                      {i.duplicate_count > 0 && <span className="ml-1 text-[11px] text-slate-500">+{i.duplicate_count} dup</span>}
                    </td>
                    <td className="max-w-[200px] px-2 py-3">
                      <div className="truncate text-xs text-slate-400">{i.primary_entities.slice(0, 3).map((e) => e.value).join(' · ')}</div>
                    </td>
                    <td className="px-2 py-3">
                      <div className="flex max-w-[160px] flex-wrap gap-1">
                        {i.mitre_ids.slice(0, 3).map((t) => <span key={t} className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">{t}</span>)}
                        {i.mitre_ids.length > 3 && <span className="text-[10px] text-slate-500">+{i.mitre_ids.length - 3}</span>}
                      </div>
                    </td>
                    <td className="tabular px-2 py-3 font-mono text-xs text-slate-400">{pct(i.correlation_confidence, 0)}</td>
                    <td className="whitespace-nowrap px-2 py-3 text-xs text-slate-400">{fmtTime(i.first_seen)}</td>
                    <td className="px-4 py-3 text-xs">
                      <span className={i.status === 'new' ? 'text-slate-300' : i.status === 'closed' ? 'text-slate-500' : 'text-emerald-300'}>{i.status}</span>
                      {i.analyst_verdict && <div className="text-[10px] text-slate-500">{i.analyst_verdict.replaceAll('_', ' ')}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-ink-700 px-4 py-2.5 text-xs text-slate-500">
            <span>{data.total.toLocaleString()} incidents · page {page} of {pages}</span>
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
