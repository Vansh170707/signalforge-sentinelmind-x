import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, ListChecks, Search } from 'lucide-react'
import { motion } from 'motion/react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { PageHeader } from '../components/Layout'
import { Button, Card, Chip, EmptyState, ErrorState, Loading, RiskMeter, SEV_COLOR, SeverityBadge, ease, fmtTime, pct } from '../components/ui'

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
      <PageHeader eyebrow="Triage" title="Incidents" subtitle="Correlated incidents ranked by explainable, business-aware risk." />
      <Card bodyClass="p-0">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {SEVS.map((s) => {
              const on = sev.includes(s)
              return (
                <button
                  key={s}
                  onClick={() => toggle(s)}
                  className={`inline-flex h-8 items-center gap-1.5 rounded-lg px-3 text-[13px] font-medium capitalize ring-1 ring-inset transition ${on ? 'bg-fg text-white ring-fg' : 'bg-white text-fg-muted ring-line-strong hover:bg-subtle'}`}
                >
                  <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
                  {s}
                </button>
              )
            })}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
              <input
                value={q}
                onChange={(e) => { setQ(e.target.value); setPage(1) }}
                placeholder="Search title or ID"
                className="h-8 w-56 rounded-lg border border-line-strong bg-white pl-8 pr-3 text-[13px] text-fg shadow-[var(--shadow-xs)] placeholder:text-fg-faint focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-100"
                aria-label="Search incidents"
              />
            </label>
            <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }} className="h-8 rounded-lg border border-line-strong bg-white px-2 text-[13px] text-fg-2 shadow-[var(--shadow-xs)]" aria-label="Status">
              <option value="">Any status</option>
              <option value="new">New</option>
              <option value="triaged">Triaged</option>
              <option value="closed">Closed</option>
            </select>
            <select value={sort} onChange={(e) => setSort(e.target.value)} className="h-8 rounded-lg border border-line-strong bg-white px-2 text-[13px] text-fg-2 shadow-[var(--shadow-xs)]" aria-label="Sort">
              <option value="risk">Sort by risk</option>
              <option value="recent">Most recent</option>
              <option value="alerts">Most alerts</option>
            </select>
          </div>
        </div>
        {query.isLoading ? (
          <div className="p-5"><Loading rows={10} /></div>
        ) : query.error ? (
          <div className="p-5"><ErrorState error={query.error} onRetry={() => query.refetch()} /></div>
        ) : !data || data.items.length === 0 ? (
          <div className="p-5">
            <EmptyState icon={ListChecks} title="No incidents match" action={<Link to="/"><Button>Go to Command Center</Button></Link>}>
              Load the demo and run the pipeline, or relax the filters.
            </EmptyState>
          </div>
        ) : (
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full min-w-[1040px] text-sm">
              <thead>
                <tr className="border-b border-line bg-subtle/60 text-left text-xs font-medium text-fg-subtle">
                  <th className="w-12 px-4 py-2.5 font-medium">#</th>
                  <th className="px-3 py-2.5 font-medium">Incident</th>
                  <th className="px-3 py-2.5 font-medium">Risk</th>
                  <th className="px-3 py-2.5 font-medium">Alerts</th>
                  <th className="px-3 py-2.5 font-medium">Key entities</th>
                  <th className="px-3 py-2.5 font-medium">ATT&CK</th>
                  <th className="px-3 py-2.5 font-medium">Confidence</th>
                  <th className="px-3 py-2.5 font-medium">First seen</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.items.map((i, idx) => (
                  <motion.tr
                    key={i.incident_id}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25, delay: Math.min(idx, 12) * 0.02, ease }}
                    onClick={() => nav(`/incidents/${i.incident_id}`)}
                    className="group cursor-pointer transition-colors hover:bg-subtle/70"
                  >
                    <td className="px-4 py-3.5 text-[13px] text-fg-faint">{i.rank}</td>
                    <td className="max-w-[380px] px-3 py-3.5">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={i.severity} size="sm" />
                        <Link to={`/incidents/${i.incident_id}`} onClick={(e) => e.stopPropagation()} className="truncate font-semibold text-fg group-hover:text-brand-700">{i.title}</Link>
                      </div>
                      <div className="mt-1 flex items-center gap-2 font-mono text-[11px] text-fg-faint">
                        {i.incident_id}
                        {i.risk_formula === 'v2-jev' && <Chip tone="violet">Jev</Chip>}
                        {i.analyst_verdict && <Chip tone="green">{i.analyst_verdict.replaceAll('_', ' ')}</Chip>}
                      </div>
                    </td>
                    <td className="px-3 py-3.5"><RiskMeter score={i.risk_score} severity={i.severity} /></td>
                    <td className="tabular px-3 py-3.5 text-fg-2">
                      {i.alert_count}
                      {i.duplicate_count > 0 && <span className="ml-1 text-xs text-fg-faint">+{i.duplicate_count} dup</span>}
                    </td>
                    <td className="max-w-[220px] px-3 py-3.5"><div className="truncate text-[13px] text-fg-muted">{i.primary_entities.slice(0, 3).map((e) => e.value).join(' · ')}</div></td>
                    <td className="px-3 py-3.5">
                      <div className="flex max-w-[180px] flex-wrap gap-1">
                        {i.mitre_ids.slice(0, 3).map((t) => <Chip key={t} mono>{t}</Chip>)}
                        {i.mitre_ids.length > 3 && <span className="text-[11px] text-fg-faint">+{i.mitre_ids.length - 3}</span>}
                      </div>
                    </td>
                    <td className="tabular px-3 py-3.5 text-[13px] text-fg-muted">{pct(i.correlation_confidence, 0)}</td>
                    <td className="whitespace-nowrap px-3 py-3.5 text-[13px] text-fg-muted">{fmtTime(i.first_seen)}</td>
                    <td className="px-4 py-3.5">
                      <span className={`inline-flex items-center gap-1.5 text-[13px] font-medium capitalize ${i.status === 'new' ? 'text-fg-2' : i.status === 'closed' ? 'text-fg-faint' : 'text-emerald-700'}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${i.status === 'new' ? 'bg-brand-500' : i.status === 'closed' ? 'bg-line-strong' : 'bg-emerald-500'}`} />
                        {i.status}
                      </span>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-line px-4 py-3 text-[13px] text-fg-subtle">
            <span><span className="font-semibold text-fg-2">{data.total.toLocaleString()}</span> incidents · page {page} of {pages}</span>
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
