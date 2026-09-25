"""Load the demo corpus into the configured database and run the pipeline (no API server needed).

Usage: python scripts/seed_db.py [--seed 7]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.session import run_migrations, session_scope  # noqa: E402
from app.services import runner  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    run_migrations()
    with session_scope() as db:
        info = runner.load_demo(db, args.seed)
    print({k: v for k, v in info.items() if k != "rejected_rows"})
    run_id = runner.start_pipeline_run(background=False)
    with session_scope() as db:
        from app.db import models as m

        run = db.get(m.PipelineRun, run_id)
        print(run.status, run.stats.get("incidents"), "incidents", run.timings_ms)
        if run.error:
            print(run.error)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
