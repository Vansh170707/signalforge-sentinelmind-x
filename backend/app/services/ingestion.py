"""Batch ingestion: parse JSONL / JSON / CSV, normalize row by row, dedupe by content hash."""

from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.schemas.alerts import BatchResult, CanonicalAlert, RejectedRow
from app.services.context import ContextStore
from app.services.normalization import NormalizationError, normalize_alert


@dataclass
class IngestOutcome:
    alerts: list[CanonicalAlert]
    result: BatchResult
    duplicate_of: dict[str, str] = field(default_factory=dict)  # duplicate alert_id -> kept alert_id


def parse_payload(text: str, fmt: str) -> list[dict[str, Any]]:
    fmt = fmt.lower()
    if fmt == "jsonl":
        rows = []
        for i, line in enumerate(text.splitlines()):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                rows.append({"__parse_error__": f"line {i + 1}: {exc.msg}"})
        return rows
    if fmt == "json":
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("alerts", [])
        if not isinstance(data, list):
            raise ValueError("JSON payload must be a list or {\"alerts\": [...]}")
        return data
    if fmt == "csv":
        rows = []
        for row in csv.DictReader(io.StringIO(text)):
            r: dict[str, Any] = {k: (v if v != "" else None) for k, v in row.items() if k}
            if r.get("attributes"):
                try:
                    r["attributes"] = json.loads(r["attributes"])
                except json.JSONDecodeError:
                    r["attributes"] = {"raw": r["attributes"]}
            for num in ("severity_score", "confidence", "asset_criticality", "user_privilege"):
                if r.get(num) is not None:
                    try:
                        r[num] = float(r[num])
                    except ValueError:
                        pass
            rows.append(r)
        return rows
    raise ValueError(f"unsupported format {fmt!r}")


def ingest_rows(rows: list[dict[str, Any]], context: ContextStore | None = None,
                batch_id: str | None = None, existing_hashes: dict[str, str] | None = None) -> IngestOutcome:
    t0 = time.perf_counter()
    batch_id = batch_id or f"BAT-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
    seen: dict[str, CanonicalAlert] = {}
    known = dict(existing_hashes or {})
    accepted: list[CanonicalAlert] = []
    rejected: list[RejectedRow] = []
    duplicate_of: dict[str, str] = {}
    seen_ids: set[str] = set()

    for i, raw in enumerate(rows):
        if not isinstance(raw, dict):
            rejected.append(RejectedRow(row_index=i, errors=["row is not an object"]))
            continue
        if "__parse_error__" in raw:
            rejected.append(RejectedRow(row_index=i, errors=[raw["__parse_error__"]]))
            continue
        try:
            alert = normalize_alert(raw, context)
        except NormalizationError as exc:
            rejected.append(RejectedRow(row_index=i, alert_id=raw.get("alert_id"), errors=exc.errors))
            continue
        if alert.alert_id in seen_ids:
            rejected.append(RejectedRow(row_index=i, alert_id=alert.alert_id, errors=["duplicate alert_id"]))
            continue
        seen_ids.add(alert.alert_id)
        original = seen.get(alert.content_hash)
        if original is not None:
            original.duplicate_count += 1
            duplicate_of[alert.alert_id] = original.alert_id
            continue
        if alert.content_hash in known:
            duplicate_of[alert.alert_id] = known[alert.content_hash]
            continue
        seen[alert.content_hash] = alert
        accepted.append(alert)

    result = BatchResult(
        batch_id=batch_id,
        received=len(rows),
        accepted=len(accepted),
        duplicates=len(duplicate_of),
        rejected=len(rejected),
        rejected_rows=rejected[:200],
        duration_ms=round((time.perf_counter() - t0) * 1000, 1),
    )
    return IngestOutcome(alerts=accepted, result=result, duplicate_of=duplicate_of)
