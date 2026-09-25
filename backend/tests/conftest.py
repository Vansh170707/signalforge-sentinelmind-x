from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

# Isolated database + data directory for the whole test session (set before app modules are imported).
_TMP = Path(tempfile.mkdtemp(prefix="smx-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'test.db'}"
os.environ["DATA_DIR"] = str(_TMP / "data")
for key in ("TYPESAFE_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "FOUNDRY_API_KEY", "INCEPTION_API_KEY"):
    os.environ[key] = ""

from app.services.context import ContextStore  # noqa: E402
from app.services.demo_data import generate  # noqa: E402
from app.services.ingestion import ingest_rows  # noqa: E402
from app.services.pipeline import run_pipeline  # noqa: E402


@pytest.fixture(scope="session")
def demo():
    rows, gt, ctx_dict = generate(7)
    ctx = ContextStore.from_dict(json.loads(json.dumps(ctx_dict)))
    outcome = ingest_rows(rows, ctx)
    out = run_pipeline(outcome.alerts, ctx)
    pred = {a: d.incident_id for d in out.incidents for a in d.alert_ids}
    return {"rows": rows, "gt": gt, "ctx": ctx, "outcome": outcome, "out": out, "pred": pred}


def incident_for_gt(demo, gt_id: str):
    from app.services.evaluation import dominant_truth

    dom = dominant_truth(demo["pred"], demo["gt"]["alerts"])
    for d in demo["out"].incidents:
        if dom.get(d.incident_id, (None,))[0] == gt_id:
            return d
    raise AssertionError(f"no incident for {gt_id}")
