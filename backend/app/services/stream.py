"""Live SOC mode: replay the demo corpus as an accelerated alert stream and re-correlate continuously.

Micro-batch design: every tick the simulated clock advances by `speed` x real time, newly due rows go through
normal ingestion (validation, normalization, dedupe) and, at most every `analysis_interval` seconds, the full
deterministic pipeline re-runs on everything received so far. Incidents therefore assemble and escalate in
front of the analyst. No external AI is called while streaming; `finalize` loads the same corpus into the
database and runs the regular pipeline (Jev, briefs, evaluation).

Incidents are tracked across ticks by a stable key: the earliest alert ID of the cluster.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.schemas.alerts import CanonicalAlert
from app.services.context import ContextStore
from app.services.correlation import CorrelationConfig
from app.services.ingestion import ingest_rows
from app.services.normalization import parse_timestamp
from app.services.pipeline import run_pipeline

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
BUCKET_MINUTES = 10


@dataclass
class StreamState:
    status: str = "idle"  # idle | running | paused | finished | error
    seed: int = 7
    speed: float = 900.0
    sim_start: datetime | None = None
    sim_end: datetime | None = None
    sim_time: datetime | None = None
    rows_seen: int = 0
    duplicates: int = 0
    rejected: int = 0
    alerts: list[CanonicalAlert] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    board: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    buckets: Counter = field(default_factory=Counter)
    high_buckets: Counter = field(default_factory=Counter)
    max_sev: dict[str, int] = field(default_factory=dict)
    incidents: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    pipeline_ms: float = 0.0
    analyses: int = 0
    error: str | None = None


class StreamEngine:
    def __init__(self, rows: list[dict[str, Any]], ctx: ContextStore, *, seed: int, speed: float,
                 cfg: CorrelationConfig | None = None, analysis_interval: float = 1.5, board_size: int = 8):
        self.ctx = ctx
        self.cfg = cfg or CorrelationConfig()
        self.analysis_interval = analysis_interval
        self.board_size = board_size
        timed: list[tuple[datetime, dict[str, Any]]] = []
        undated: list[dict[str, Any]] = []
        for r in rows:
            try:
                timed.append((parse_timestamp(r.get("timestamp")), r))
            except (ValueError, TypeError, OverflowError):
                undated.append(r)  # malformed: delivered first, rejected by ingestion like any bad row
        timed.sort(key=lambda x: x[0])
        self.queue = timed
        self.undated = undated
        self.total_rows = len(timed) + len(undated)
        self.cursor = 0
        start = timed[0][0].replace(hour=0, minute=0, second=0, microsecond=0) if timed else None
        self.state = StreamState(seed=seed, speed=speed, sim_start=start, sim_time=start,
                                 sim_end=(start + timedelta(days=1)) if start else None)
        self.lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._last_analysis = 0.0

    # ---------------------------------------------------------------- stepping (thread-free, testable)
    def advance(self, sim_seconds: float, analyze: bool = True) -> bool:
        """Advance the simulated clock; returns True when an analysis ran."""
        st = self.state
        if st.sim_time is None or st.sim_end is None:
            return False
        new_time = min(st.sim_end, st.sim_time + timedelta(seconds=sim_seconds))
        batch: list[dict[str, Any]] = []
        if self.undated:
            batch.extend(self.undated)
            self.undated = []
        while self.cursor < len(self.queue) and self.queue[self.cursor][0] <= new_time:
            batch.append(self.queue[self.cursor][1])
            self.cursor += 1
        if batch:
            out = ingest_rows(batch, self.ctx, existing_hashes=st.hashes)
            with self.lock:
                st.rows_seen += len(batch)
                st.duplicates += out.result.duplicates
                st.rejected += out.result.rejected
                for a in out.alerts:
                    st.alerts.append(a)
                    st.hashes[a.content_hash] = a.alert_id
                    b = self._bucket(a.timestamp)
                    st.buckets[b] += 1
                    if a.severity in ("high", "critical"):
                        st.high_buckets[b] += 1
        with self.lock:
            st.sim_time = new_time
        done = self.cursor >= len(self.queue) or new_time >= st.sim_end
        ran = self.analyze() if (analyze or done) else False
        if done:
            with self.lock:
                st.status = "finished"
        return ran

    def _bucket(self, ts: datetime) -> str:
        m = (ts.hour * 60 + ts.minute) // BUCKET_MINUTES * BUCKET_MINUTES
        return f"{m // 60:02d}:{m % 60:02d}"

    def analyze(self) -> bool:
        st = self.state
        with self.lock:
            alerts = list(st.alerts)
        if not alerts:
            return False
        t0 = time.perf_counter()
        out = run_pipeline(alerts, self.ctx, self.cfg)
        ms = (time.perf_counter() - t0) * 1000
        board, events = [], []
        for d in out.incidents:
            key = d.alert_ids[0]
            rank = SEV_RANK.get(d.severity, 0)
            prev = st.max_sev.get(key, -1)
            if rank >= 2 and rank > prev:
                events.append({"sim_time": st.sim_time.isoformat() if st.sim_time else None, "key": key,
                               "kind": "new" if prev < 0 else "escalated", "severity": d.severity,
                               "title": d.title, "risk": d.risk_score, "alert_count": d.alert_count})
            if rank > prev:
                st.max_sev[key] = rank
            if len(board) < self.board_size:
                board.append({"key": key, "title": d.title, "severity": d.severity, "risk": d.risk_score,
                              "alert_count": d.alert_count, "stages": [s["label"] for s in d.attack_stages],
                              "mitre": [m["technique_id"] for m in d.mitre][:6], "first_seen": d.first_seen,
                              "last_seen": d.last_seen, "anomaly": d.anomaly_score,
                              "chain": d.chain_strength})
        with self.lock:
            st.board = board
            st.events = (events + st.events)[:40]
            st.incidents = len(out.incidents)
            st.severity_counts = dict(Counter(d.severity for d in out.incidents))
            st.pipeline_ms = round(ms, 1)
            st.analyses += 1
        return True

    # ---------------------------------------------------------------- background loop
    def start(self) -> None:
        with self.lock:
            self.state.status = "running"
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        last = time.monotonic()
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                dt = now - last
                last = now
                if self.state.status == "running":
                    due = now - self._last_analysis >= self.analysis_interval
                    if self.advance(dt * self.state.speed, analyze=due):
                        self._last_analysis = time.monotonic()
                    if self.state.status == "finished":
                        return
                time.sleep(0.25)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            with self.lock:
                self.state.status = "error"
                self.state.error = str(exc)[:500]

    def pause(self) -> None:
        with self.lock:
            if self.state.status == "running":
                self.state.status = "paused"
            elif self.state.status == "paused":
                self.state.status = "running"

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def set_speed(self, speed: float) -> None:
        with self.lock:
            self.state.speed = speed

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            st = self.state
            total = (st.sim_end - st.sim_start).total_seconds() if st.sim_end and st.sim_start else 1
            done = (st.sim_time - st.sim_start).total_seconds() if st.sim_time and st.sim_start else 0
            n = len(st.alerts)
            buckets = []
            if st.sim_start:
                for i in range(0, 24 * 60, BUCKET_MINUTES):
                    label = f"{i // 60:02d}:{i % 60:02d}"
                    buckets.append({"t": label, "alerts": st.buckets.get(label, 0),
                                    "high": st.high_buckets.get(label, 0)})
            return {
                "status": st.status, "seed": st.seed, "speed": st.speed, "error": st.error,
                "sim_time": st.sim_time.isoformat() if st.sim_time else None,
                "progress": round(min(1.0, done / total), 4) if total else 0,
                "rows_seen": st.rows_seen, "rows_total": self.total_rows,
                "alerts": n, "duplicates": st.duplicates, "rejected": st.rejected,
                "incidents": st.incidents, "severity_counts": st.severity_counts,
                "critical_high": st.severity_counts.get("critical", 0) + st.severity_counts.get("high", 0),
                "compression_ratio": round(n / st.incidents, 2) if st.incidents else None,
                "board": st.board, "events": st.events, "buckets": buckets,
                "pipeline_ms": st.pipeline_ms, "analyses": st.analyses,
            }


_ENGINE: StreamEngine | None = None
_ENGINE_LOCK = threading.Lock()


def current() -> StreamEngine | None:
    return _ENGINE


def replace(engine: StreamEngine | None) -> None:
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            _ENGINE.stop()
        _ENGINE = engine
