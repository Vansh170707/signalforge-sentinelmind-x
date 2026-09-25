"""Export generated briefs for the manual supported-claim evaluation (blueprint 28.4).

Writes a CSV with one row per observed fact / hypothesis. Raters fill `supported` (1/0) by checking the
cited alerts in the UI; then run with --score to compute the supported-claim rate.

Usage:
  python scripts/evaluate_summaries.py --out data/brief_rubric.csv
  python scripts/evaluate_summaries.py --score data/brief_rubric.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def export(out: Path) -> None:
    from sqlalchemy import select

    from app.db import models as m
    from app.db.session import session_scope

    with session_scope() as db, out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["incident_id", "provider", "model", "kind", "text", "cited_alert_ids", "supported"])
        for run in db.scalars(select(m.LlmRun).order_by(m.LlmRun.incident_id)):
            for f in run.output.get("observed_facts", []):
                w.writerow([run.incident_id, run.provider, run.model, "fact", f["fact"], " ".join(f["alert_ids"]), ""])
            for h in run.output.get("hypotheses", []):
                w.writerow([run.incident_id, run.provider, run.model, "hypothesis", h["hypothesis"], "", ""])
    print(f"wrote {out}")


def score(path: Path) -> None:
    rows = [r for r in csv.DictReader(path.open()) if r["kind"] == "fact" and r["supported"].strip() in ("0", "1")]
    if not rows:
        print("no rated facts yet")
        return
    by: dict[str, list[int]] = {}
    for r in rows:
        by.setdefault(r["provider"], []).append(int(r["supported"]))
    for prov, xs in by.items():
        print(f"{prov}: supported-claim rate {sum(xs) / len(xs):.3f} over {len(xs)} rated facts")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    ap.add_argument("--score", type=Path)
    a = ap.parse_args()
    if a.score:
        score(a.score)
    else:
        export(a.out or ROOT / "data" / "brief_rubric.csv")
