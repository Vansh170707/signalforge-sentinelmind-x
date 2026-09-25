# Threat model and responsible AI

| Risk | Control | Where |
| --- | --- | --- |
| Prompt injection inside log text | Alert text is passed as `attributes_untrusted`. The system prompt forbids following instructions found in it. Instruction-like patterns are detected and shown to the analyst. | `services/agent.py` |
| Hallucinated facts | Every fact needs alert IDs that belong to the incident. Invalid output gets one retry, then the template is used. | `validate_brief` |
| Hallucinated ATT&CK IDs | Only IDs mapped by the application and present in the official catalog are accepted. Names are always taken from the catalog. | `services/mitre.py`, `validate_brief` |
| Excessive agent privilege | Tools are read-only functions. No write-capable tools exist. No containment is automated. | `services/agent.py` |
| One model dominating ranking | The Jev contribution is at most 15%. Low disposition confidence reduces it and flags human review. The deterministic score is shown next to it. | `services/risk.py` |
| Secrets | Keys are read from env vars on the server only. `.env` is git-ignored. `/api/v1/settings` reports whether a key is configured, never the key itself. | `config.py` |
| SQL injection / XSS | The SQLAlchemy ORM binds parameters. React escapes output and no raw model HTML is rendered. Raw payloads display as JSON text. | — |
| Oversized uploads | 20 MB file limit and a 50k alert cap (HTTP 413). | `api/routes.py` |
| PII | Demo data is fully synthetic, using reserved IP ranges and fake names. Gemini free tier: synthetic data only. | `services/demo_data.py` |
| Auditability | Audit events record ingest, pipeline runs, briefs and verdicts. Each API response has a trace ID. LLM runs store provider, model, prompt version, output hash and validation. | `audit_events`, `llm_runs` |
| Bias in priority | Factors are shown on every incident. The benign critical-asset maintenance scenario is part of the test set. | `test_pipeline_golden.py` |
