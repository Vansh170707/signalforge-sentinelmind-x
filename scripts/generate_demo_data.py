"""Generate the reproducible synthetic demo corpus (alerts.jsonl, ground_truth.json, context.json).

Usage: python scripts/generate_demo_data.py [--seed 7] [--out data/demo]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.demo_data import write_dataset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "demo")
    args = parser.parse_args()
    print(write_dataset(args.out, args.seed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
