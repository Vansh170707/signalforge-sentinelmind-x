"""Pre-compute AI output for the demo and save it to data/ai_cache.json (committed; synthetic data only).

- Jev typed decisions for the top incidents (one request per incident, cached by evidence hash)
- Narrative briefs for the top N incidents through the configured provider order

A fresh clone (or OFFLINE_MODE=true at a venue with bad network) then shows real model output instantly.

Usage: python scripts/prewarm_ai.py [--briefs 12] [--seed 7]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import func, select  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.db import models as m  # noqa: E402
from app.db.session import run_migrations, session_scope  # noqa: E402
from app.services import runner  # noqa: E402


async def main_async(n_briefs: int) -> None:
    s = get_settings()
    print("jev:", await runner.decide_top_incidents(s.jev_top_n))
    with session_scope() as db:
        ids = db.scalars(select(m.Incident.incident_id).order_by(m.Incident.risk_score.desc()).limit(n_briefs)).all()
    for iid in ids:
        r = await runner.brief_for_incident(iid, patient=True)
        print(f"  {iid}: {r['provider']} {r['model']} {r['status']}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--briefs", type=int, default=12)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    if get_settings().offline_mode:
        print("OFFLINE_MODE is on; nothing to prewarm")
        return 1
    run_migrations()
    with session_scope() as db:
        empty = not db.scalar(select(func.count()).select_from(m.Incident))
        if empty:
            print(runner.load_demo(db, args.seed)["batch"])
    if empty:
        runner.start_pipeline_run(background=False)
    asyncio.run(main_async(args.briefs))
    with session_scope() as db:
        print("saved", runner.save_ai_cache_file(db), "->", get_settings().ai_cache_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
