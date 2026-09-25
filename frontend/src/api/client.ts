import type {
  AlertDetail,
  AlertRow,
  BriefResponse,
  DemoLoadResult,
  EvaluationResponse,
  IncidentDetail,
  IncidentGraph,
  IncidentRow,
  Overview,
  Page,
  PipelineRun,
  SettingsView,
  TriageSummary,
} from '../types/api'

export class ApiError extends Error {
  status: number
  traceId: string | null
  constructor(status: number, message: string, traceId: string | null) {
    super(message)
    this.status = status
    this.traceId = traceId
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  })
  const traceId = res.headers.get('X-Trace-Id')
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      const m = body?.error?.message ?? body?.detail
      message = typeof m === 'string' ? m : JSON.stringify(m)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message, traceId)
  }
  return res.json() as Promise<T>
}

const qs = (params: Record<string, string | number | undefined | null>) => {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const api = {
  health: () => request<{ status: string; database: string; attack_catalog: string; offline_mode?: boolean }>('/health'),
  overview: () => request<Overview>('/api/v1/metrics/overview'),
  evaluation: () => request<EvaluationResponse>('/api/v1/metrics/evaluation'),
  settings: () => request<SettingsView>('/api/v1/settings'),
  resetDemo: () => request<{ status: string }>('/api/v1/demo/reset', { method: 'POST' }),
  loadDemo: (seed: number, via: 'native' | 'sentinel' = 'native') =>
    request<DemoLoadResult>('/api/v1/demo/load', { method: 'POST', body: JSON.stringify({ seed, via }) }),
  sentinelExport: (id: string) => request<Record<string, unknown>>(`/api/v1/incidents/${id}/sentinel`),
  upload: async (file: File) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch('/api/v1/alerts/upload', { method: 'POST', body: form })
    const body = await res.json()
    if (!res.ok) throw new ApiError(res.status, body?.error?.message ?? res.statusText, res.headers.get('X-Trace-Id'))
    return body as DemoLoadResult['batch'] & { rejected_rows: DemoLoadResult['rejected_rows'] }
  },
  runPipeline: () => request<{ run_id: string }>('/api/v1/pipeline/run', { method: 'POST' }),
  pipeline: (runId: string) => request<PipelineRun>(`/api/v1/pipeline/${runId}`),
  latestPipeline: () => request<PipelineRun | null>('/api/v1/pipeline/latest'),
  incidents: (p: { severity?: string; status?: string; q?: string; min_risk?: number; technique?: string; sort?: string; page?: number; page_size?: number }) =>
    request<Page<IncidentRow>>(`/api/v1/incidents${qs(p)}`),
  incident: (id: string) => request<IncidentDetail>(`/api/v1/incidents/${id}`),
  incidentAlerts: (id: string) => request<{ incident_id: string; items: AlertRow[] }>(`/api/v1/incidents/${id}/alerts`),
  incidentGraph: (id: string) => request<IncidentGraph>(`/api/v1/incidents/${id}/graph`),
  brief: (id: string) => request<BriefResponse>(`/api/v1/incidents/${id}/brief`),
  generateBrief: (id: string, refresh = false) =>
    request<BriefResponse>(`/api/v1/incidents/${id}/brief`, { method: 'POST', body: JSON.stringify({ refresh }) }),
  decide: (id: string) => request<unknown>(`/api/v1/incidents/${id}/decision`, { method: 'POST' }),
  feedback: (id: string, body: { verdict: string; notes?: string; corrected_severity?: string | null }) =>
    request<{ status: string }>(`/api/v1/incidents/${id}/feedback`, { method: 'POST', body: JSON.stringify(body) }),
  alerts: (p: { q?: string; severity?: string; alert_type?: string; user?: string; host?: string; incident_id?: string; page?: number; page_size?: number }) =>
    request<Page<AlertRow>>(`/api/v1/alerts${qs(p)}`),
  alert: (id: string) => request<AlertDetail>(`/api/v1/alerts/${id}`),
  addTrial: (body: { participant: string; mode: 'baseline' | 'assisted'; seconds: number; correct: boolean }) =>
    request<TriageSummary>('/api/v1/experiments/triage', { method: 'POST', body: JSON.stringify(body) }),
  refreshEvaluation: () => request<unknown>('/api/v1/metrics/evaluation/refresh', { method: 'POST' }),
}
