import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { api } from '../api/client'

export const STAGE_LABELS: Record<string, string> = {
  queued: 'Queued',
  loading_alerts: 'Loading alerts',
  entities: 'Entity intelligence',
  correlation: 'Graph correlation',
  anomaly: 'Anomaly detection',
  chain_mitre_risk: 'Attack chains · ATT&CK · risk',
  done: 'Ranking incidents',
  persisting: 'Persisting incidents',
  jev_decisions: 'Jev typed decisions',
  evaluation: 'Ground-truth evaluation',
  failed: 'Failed',
}

/** Starts pipeline runs and polls the active run until it completes. */
export function usePipeline() {
  const qc = useQueryClient()
  const [runId, setRunId] = useState<string | null>(null)
  const latest = useQuery({ queryKey: ['pipeline', 'latest'], queryFn: api.latestPipeline })
  const active = runId ?? (latest.data && ['queued', 'running'].includes(latest.data.status) ? latest.data.run_id : null)
  const run = useQuery({
    queryKey: ['pipeline', active],
    queryFn: () => api.pipeline(active!),
    enabled: !!active,
    refetchInterval: (q) => (q.state.data && ['completed', 'failed'].includes(q.state.data.status) ? false : 400),
    refetchIntervalInBackground: true,
  })
  const status = run.data?.status
  useEffect(() => {
    if (status === 'completed' || status === 'failed') {
      qc.invalidateQueries({ predicate: (q) => q.queryKey[0] !== 'pipeline' || q.queryKey[1] === 'latest' })
    }
  }, [status, qc])
  const start = useMutation({
    mutationFn: api.runPipeline,
    onSuccess: (r) => setRunId(r.run_id),
  })
  const current = run.data ?? latest.data ?? null
  const running = !!current && ['queued', 'running'].includes(current.status)
  return { current, running, start }
}
