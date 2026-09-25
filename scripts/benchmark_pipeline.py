"""Robustness benchmark: generate alternate seeds, run the full pipeline, report ground-truth metrics.

Usage: python scripts/benchmark_pipeline.py --seeds 7 11 23 [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.context import ContextStore  # noqa: E402
from app.services.demo_data import generate  # noqa: E402
from app.services.evaluation import correlation_metrics, detection_metrics, priority_metrics  # noqa: E402
from app.services.ingestion import ingest_rows  # noqa: E402
from app.services.pipeline import run_pipeline  # noqa: E402


def bench(seed: int) -> dict:
    rows, gt, ctx_dict = generate(seed)
    ctx = ContextStore.from_dict(json.loads(json.dumps(ctx_dict)))
    t0 = time.perf_counter()
    ingest = ingest_rows(rows, ctx)
    t1 = time.perf_counter()
    out = run_pipeline(ingest.alerts, ctx)
    t2 = time.perf_counter()
    pred = {a: d.incident_id for d in out.incidents for a in d.alert_ids}
    ranked = [{"incident_id": d.incident_id, "severity": d.severity} for d in out.incidents]
    prio = priority_metrics(ranked, pred, gt["alerts"], gt["incidents"])
    return {
        "seed": seed,
        "received": ingest.result.received,
        "accepted": ingest.result.accepted,
        "ingest_s": round(t1 - t0, 2),
        "pipeline_s": round(t2 - t1, 2),
        "correlation": correlation_metrics(pred, gt["alerts"]),
        "priority": prio,
        "detection_rules": detection_metrics(out.alert_rule_anomaly, gt["alerts"], gt["incidents"], 0.5),
        "detection_rules_if": detection_metrics(out.alert_anomaly, gt["alerts"], gt["incidents"], 0.5),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[7, 11, 23])
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    results = [bench(s) for s in args.seeds]
    hdr = f"{'seed':>5} {'alerts':>7} {'pipe s':>7} {'P':>6} {'R':>6} {'purity':>7} {'top3crit':>8} {'top5hc':>7} {'falseHigh':>9} {'F1 rules':>8} {'F1 +IF':>7}"
    print(hdr)
    for r in results:
        c, p = r["correlation"], r["priority"]
        print(f"{r['seed']:>5} {r['accepted']:>7} {r['pipeline_s']:>7} {c['pairwise_precision']:>6.3f} "
              f"{c['pairwise_recall']:>6.3f} {c['incident_purity']:>7.3f} {p['top3_critical_recall']:>8.2f} "
              f"{p['top5_high_critical_recall']:>7.2f} {p['false_high_rate']:>9.4f} "
              f"{r['detection_rules']['f1']:>8.3f} {r['detection_rules_if']['f1']:>7.3f}")
        ranks = ", ".join(f"{x['scenario']}#{x['rank']}" for x in p["planted_incident_ranks"])
        print(f"      ranks: {ranks}")
    if args.json:
        args.json.write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
