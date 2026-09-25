# Architecture

## Principles (blueprint 7.1)
- **Evidence before generation.** Language models only see a compact evidence pack. They see it after the deterministic and ML stages have built the incident.
- **Provenance everywhere.** Each incident membership stores its strongest edge and its reasons. Each ATT&CK mapping stores its evidence alert IDs. Each risk factor stores its weight and its contribution.
- **Replaceable providers.** `app/llm/base.py` defines `DecisionProvider` and `NarrativeProvider`. Adapters use raw HTTPS. No business module imports a vendor SDK.
- **Graceful degradation.** Without keys, the queue, risk, graph and template brief all work. A 429, timeout or 5xx from a provider triggers failover to the next provider.
- **Read-only AI.** The agent tools only read evidence. No write-capable tool exists.

## Components
| Module | File | Notes |
| --- | --- | --- |
| Ingestion | `services/ingestion.py`, `services/normalization.py` | JSONL / JSON / CSV input. UTC timestamps, canonical user and host, IP validation, SHA-256 content-hash dedupe, row-level rejects. |
| Entity intelligence | `services/entities.py`, `services/context.py` | Rarity = 0.5 × alert-IDF + 0.5 × temporal-spread IDF over 30-minute buckets. A context store (identity directory + CMDB) supplies privilege, criticality and baselines. |
| Correlation | `services/correlation.py` | Candidates are indexed by entity inside a 30-minute window, with at most 30 neighbours per key. Edges use the blueprint weights. A host-pivot relation catches lateral movement. Connected components are cut to at most 300 alerts, first with stricter thresholds and strong-edge filtering, then with Louvain. Threshold 0.40 was tuned on ground truth; the blueprint starting value was 0.45. |
| Anomaly | `services/anomaly.py` | Features: bursts, breadth, novelty (source IP, process vs. software baseline), off-hours and success-after-failures. The rules score uses robust z-scores. Isolation Forest runs on behavioral features only, so static context is not double counted. |
| Attack chain | `services/attack_chain.py` | Ordered stages come from the alert-type catalog, with context rules (for example, 5 or more failures are needed for a credential attack). Strength = coverage × order coherence, plus an entry bonus. |
| ATT&CK | `services/mitre.py` | Deterministic rules map evidence to technique IDs. IDs and names come only from `data/mitre/attack_catalog.json`, built from the official STIX bundle. |
| Risk | `services/risk.py` | v1 formula: blueprint section 17. v2 formula: section 19A.3, where the Jev signal is capped at 15% and gated by confidence. The response includes the full decomposition. |
| Agent | `services/agent.py` | Evidence pack plus four read-only tools. Output is schema-validated and citation-validated. Unknown ATT&CK IDs are rejected. One retry is allowed, then the deterministic template is used. |
| Orchestration | `services/runner.py` | Background pipeline runs with stage progress. Jev decisions are cached by evidence hash. Evaluation is computed after each run. |

## Data model
Tables: `alerts`, `entities`, `alert_entities`, `incidents`, `incident_alerts` (edge score + reasons), `incident_entities`,
`attack_stages`, `incident_mitre`, `decision_runs`, `llm_runs`, `analyst_feedback`, `audit_events`, `evaluation_runs`,
`pipeline_runs`, `ingest_batches` and `triage_trials`. Migrations are in `backend/alembic`. Local development uses SQLite.
Compose uses PostgreSQL 16 with pgvector.

Incident IDs follow the risk rank, so the same input and config give the same IDs. Feedback and cached decisions
use the evidence hash as the key, so they reattach when the pipeline runs again.

## Microsoft fit
- The data model follows the Sentinel structure: alert → incident → entity → timeline → ATT&CK.
- Microsoft Foundry is available as a narrative provider through an OpenAI v1-compatible endpoint (`FOUNDRY_*` env).
- The target cloud deployment is Azure Container Apps for backend and frontend, with Azure Database for PostgreSQL + pgvector.
- Entra ID and Application Insights are stretch goals.
