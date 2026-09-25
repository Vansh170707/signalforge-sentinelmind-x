# Evaluation

All metrics come from `app/services/evaluation.py`. They are computed against `data/demo/ground_truth.json`, which the
generator writes but the pipeline never reads.

## Dataset
The seeded synthetic corpus contains 10,004 rows:
- 7,500 routine user-session alerts
- 300 server housekeeping alerts
- 1,320 benign security alerts: authorized scans, lockouts, PUA, DLP, admin scripting, VPN travel, dev chatter
- 180 exact duplicates
- 4 malformed rows
- 6 planted stories: privileged-account compromise (golden, 160), password spray (220), malicious-document scripting (90), impossible travel + mailbox (60), DC credential theft + exfiltration (50), and benign change-ticketed maintenance on the critical finance server (120)

Every alert has a ground-truth incident. Benign episodes are labeled too, so pairwise metrics are meaningful.

## Metrics
- **Correlation:** pairwise precision, recall and F1; incident purity; over-merge rate; split rate; singleton rate; compression ratio.
- **Priority:** top-3 critical recall, top-5 high/critical recall, false-high rate (benign incidents rated high or critical), and the rank of each planted story.
- **Detection:** alert-level precision, recall, F1 and FPR. Rules alone are compared with rules + Isolation Forest.
- **LLM:** structured-output valid rate, citation validity rate and template fallbacks. The supported-claim rate is collected by hand with `scripts/evaluate_summaries.py`.
- **Triage time:** trials are recorded in the Evaluation Lab. The metric is the median time for mode A (raw alerts) against mode B (incident view).

## Results for seeds 7, 11, 23 and 42 (`make benchmark`)
| seed | P | R | purity | top-3 crit | top-5 h/c | false-high | F1 rules | F1 +IF |
|---|---|---|---|---|---|---|---|---|
| 7 | 0.998 | 0.995 | 0.995 | 1.00 | 0.80 | 0.0000 | 0.686 | 0.804 |
| 11 | 0.989 | 0.999 | 0.994 | 1.00 | 0.80 | 0.0006 | 0.686 | 0.786 |
| 23 | 0.997 | 0.995 | 0.994 | 1.00 | 0.80 | 0.0000 | 0.686 | 0.801 |
| 42 | 0.995 | 0.990 | 0.993 | 1.00 | 0.80 | 0.0000 | 0.686 | 0.802 |

## With Jev (seed 7, jev-1.13.0, top 25 incidents)
| metric | deterministic v1 | v2 with Jev |
|---|---|---|
| top-3 critical recall | 1.00 | 1.00 |
| top-5 high/critical recall | 0.80 | **1.00** |
| false-high rate | 0.0000 | 0.0000 |
| rank of benign maintenance | #4 (medium) | #6 (medium) |
| Jev median latency | — | 1,054 ms |

## Narrative providers, head to head (top incidents, seed 7)
| provider / model | valid briefs | latency | notes |
|---|---|---|---|
| Inception mercury-2.5, effort `instant` | 10/10 | median 3.2 s, max 4.8 s | full pack; 1M input TPM free tier; primary |
| Inception mercury-2.5, effort `low` | 10/10 | median 4.3 s, two ~35 s outliers | — |
| Groq gpt-oss-120b | 5/5 when under TPM | 3–4 s | strict JSON schema; free plan limit 8K TPM |
| Gemini gemini-3.8-flash (free) | 0/6 | — | 503 "high demand" and timeouts during testing |
| Gemini gemini-3.1-flash-lite (free) | 4/5 | 14–22 s | full evidence pack; one 503 |
| Groq gpt-oss-20b | 1/4 on first test | ~2 s | Groq strict-schema rejections |

## Narrative briefs (Groq gpt-oss-120b)
Top-5 incidents: 5/5 were schema-valid and citation-valid on 120b once uncited facts were dropped (2 dropped on the
spray brief). One prewarm fell back to the template after a Groq 429 caused by the per-minute token limit. The
supported-claim rate still needs manual rating with `scripts/evaluate_summaries.py`.

## Known limitations
- The synthetic data is cleaner than production telemetry. Alternate seeds test robustness but do not prove it on real data.
- With the deterministic v1 formula, attacks on low-value workstations score about 55 and rank below critical-asset activity. The benign maintenance incident ranks #4–5 as *medium*, not high. The Jev signal (v2) and analyst feedback are designed to separate these cases.
- Top-5 high/critical recall is 0.8 because the impossible-travel story ranks #6.
