export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

export interface EntityRef {
  type: string
  value: string
  role?: string
  alert_count?: number
  rarity?: number | null
}

export interface IncidentRow {
  incident_id: string
  rank: number
  title: string
  status: string
  severity: Severity
  risk_score: number
  correlation_confidence: number
  first_seen: string
  last_seen: string
  alert_count: number
  duplicate_count: number
  primary_entities: EntityRef[]
  mitre_ids: string[]
  risk_formula: string
  analyst_verdict: string | null
  chain_strength: number
  anomaly_score: number
}

export interface Page<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export interface AttackStage {
  stage: string
  label: string
  order: number
  first_seen: string
  last_seen: string
  alert_ids: string[]
  alert_types: string[]
  confidence: number
}

export interface MitreMapping {
  technique_id: string
  name: string
  tactics: string[]
  confidence: number
  evidence_alert_ids: string[]
  mapping_reason: string
  attack_catalog_version: string
}

export interface RiskBreakdown {
  score: number
  severity: Severity
  formula: string
  factors: Record<string, number>
  weights: Record<string, number>
  contributions: Record<string, number>
  labels: Record<string, string>
  notes: string[]
  jev_decision?: JevDecision
}

export interface JevDecision {
  disposition: string
  disposition_confidence: number
  disposition_probabilities: Record<string, number>
  p_malicious: number
  severity_score: number
  severity_normalized: number
  p_escalate: number
  p_false_positive: number
  attack_family: string
  needs_human_review: boolean
  served_model?: string
}

export interface IncidentDetail extends Omit<IncidentRow, 'risk_formula'> {
  anomaly_reasons: string[]
  factors: Record<string, number>
  risk: RiskBreakdown
  deterministic_risk: RiskBreakdown | Record<string, never>
  top_alert_types: [string, number][]
  evidence_hash: string
  attack_stages: AttackStage[]
  mitre: MitreMapping[]
  entities: EntityRef[]
  decision: {
    status: string
    model: string
    decision: JevDecision
    latency_ms: number
    error: string | null
    created_at: string
  } | null
  feedback: { verdict: string; corrected_severity: string | null; notes: string | null; analyst: string; created_at: string }[]
}

export interface Membership {
  edge_score: number
  linked_alert_id: string | null
  reasons: string[]
}

export interface AlertRow {
  alert_id: string
  timestamp: string
  source: string
  vendor: string
  alert_type: string
  title: string
  severity: Severity
  severity_score: number
  confidence: number
  user: string | null
  host: string | null
  src_ip: string | null
  dst_ip: string | null
  process: string | null
  resource: string | null
  asset_criticality: number
  user_privilege: number
  incident_id: string | null
  anomaly_score: number | null
  duplicate_count: number
  attributes: Record<string, unknown>
  membership?: Membership & { incident_id?: string }
}

export interface AlertDetail extends AlertRow {
  user_display: string | null
  host_display: string | null
  raw: Record<string, unknown>
  raw_event_ref: string | null
  content_hash: string
  batch_id: string | null
  rule_anomaly_score: number | null
}

export interface GraphNode {
  id: string
  type: string
  label: string
  role: string
  alert_ids: string[]
  alert_count: number
  rarity: number | null
  stages: string[]
  context: Record<string, unknown>
  degree: number
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  relation: string
  alert_ids: string[]
  alert_count: number
}

export interface IncidentGraph {
  incident_id: string
  nodes: GraphNode[]
  edges: GraphEdge[]
  aggregated: boolean
  total_entities: number
}

export interface Brief {
  executive_summary: string
  observed_facts: { fact: string; alert_ids: string[] }[]
  hypotheses: { hypothesis: string; confidence: number }[]
  why_high_risk: string[]
  affected_entities: string[]
  mitre_explanation: { technique_id: string; technique_name?: string | null; reason: string }[]
  investigation_checks: string[]
  uncertainties: string[]
  overall_confidence: number
}

export interface BriefResponse {
  incident_id: string
  provider: string
  model: string
  status: string
  prompt_version: string
  brief: Brief
  validation: Record<string, unknown>
  attempts: { provider: string; model: string; status: string; error?: string; latency_ms?: number }[]
  latency_ms?: number
  generated_at: string
  cached: boolean
  evidence_pack_summary?: {
    alerts_shown: number
    instruction_like_text_alert_ids: string[]
    similar_incidents: { incident_id: string; title: string; risk_score: number; similarity: number; analyst_verdict: string | null }[]
  }
}

export interface PipelineRun {
  run_id: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  stage: string
  progress: number
  started_at: string
  finished_at: string | null
  stats: Record<string, unknown>
  timings_ms: Record<string, number>
  config: Record<string, unknown>
  error: string | null
}

export interface Overview {
  alerts: number
  received: number
  duplicates: number
  rejected: number
  incidents: number
  incident_severity: Record<string, number>
  alert_severity: Record<string, number>
  critical_high: number
  compression_ratio: number | null
  alert_to_actionable_ratio: number | null
  pipeline: PipelineRun | null
  hourly: ({ hour: string } & Record<string, number | string>)[]
  top_incidents: IncidentRow[]
  verdicts: Record<string, number>
}

export interface DetectionMetrics {
  threshold: number
  precision: number
  recall: number
  f1: number
  false_positive_rate: number
  tp: number
  fp: number
  fn: number
  tn: number
}

export interface EvaluationResponse {
  available: boolean
  reason?: string
  run_id?: string
  created_at?: string
  config?: Record<string, unknown>
  metrics?: {
    correlation: Record<string, number>
    priority: {
      top3_critical_recall: number | null
      top5_high_critical_recall: number | null
      false_high_rate: number
      false_high_count: number
      benign_incidents: number
      planted_incident_ranks: { ground_truth_incident_id: string; scenario: string; expected_priority: string; malicious: boolean; rank: number | null }[]
    }
    detection: { rules_only: DetectionMetrics; rules_plus_isolation_forest: DetectionMetrics }
    llm: Record<string, number | null>
    jev: Record<string, number | null>
    runtime_ms: Record<string, number>
    dataset: Record<string, unknown>
  }
  triage_experiment: TriageSummary
}

export interface TriageSummary {
  trials: number
  baseline: { n: number; median_seconds: number | null; accuracy: number | null }
  assisted: { n: number; median_seconds: number | null; accuracy: number | null }
  triage_reduction_pct: number | null
}

export interface SettingsView {
  providers: Record<string, { configured: boolean } & Record<string, unknown>>
  narrative_order: string[]
  correlation: Record<string, number | string>
  risk_config_version: string
  prompt_version: string
  demo_seed: number
  attack_catalog_version: string
  database: string
}

export interface DemoLoadResult {
  seed: number
  via?: string
  generated_rows: number
  ground_truth_incidents: number
  batch: { batch_id: string; received: number; accepted: number; duplicates: number; rejected: number; duration_ms: number; converted_from_sentinel?: number }
  rejected_rows: { row_index: number; alert_id: string | null; errors: string[] }[]
  duration_ms: number
  run_id?: string
}
