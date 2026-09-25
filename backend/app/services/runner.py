"""Orchestration of DB-backed flows: demo load, ingestion, pipeline runs, Jev decisions, briefs, evaluation."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import models as m
from app.db import repository as repo
from app.db.session import session_scope
from app.llm.base import ProviderError
from app.llm.jev import JevDecisionProvider
from app.services import evaluation as ev
from app.services.agent import (
    build_evidence_pack,
    decision_state,
    find_similar_incidents,
    generate_brief,
    narrative_providers,
    output_hash,
)
from app.services.context import ContextStore
from app.services.correlation import CorrelationConfig
from app.services.demo_data import write_dataset
from app.services.ingestion import IngestOutcome, ingest_rows, parse_payload
from app.services.pipeline import run_pipeline
from app.services.risk import compute_risk

_run_lock = threading.Lock()


def demo_dir(settings: Settings | None = None) -> Path:
    return (settings or get_settings()).data_dir / "demo"


@lru_cache
def _context_cached(path: str, mtime: float) -> ContextStore:
    return ContextStore.load(Path(path))


def get_context() -> ContextStore:
    p = demo_dir() / "context.json"
    return _context_cached(str(p), p.stat().st_mtime if p.exists() else 0.0)


def get_ground_truth() -> dict[str, Any] | None:
    p = demo_dir() / "ground_truth.json"
    return json.loads(p.read_text()) if p.exists() else None


def correlation_config(settings: Settings | None = None) -> CorrelationConfig:
    s = settings or get_settings()
    return CorrelationConfig(window_minutes=s.correlation_window_minutes, threshold=s.correlation_edge_threshold,
                             max_component=s.correlation_max_component, max_neighbors=s.correlation_max_neighbors,
                             version=s.correlation_config_version)


# ------------------------------------------------------------------ ingestion / demo
def ingest(db: Session, rows: list[dict[str, Any]], source_name: str | None, trace_id: str | None = None
           ) -> IngestOutcome:
    outcome = ingest_rows(rows, get_context(), existing_hashes=repo.existing_hashes(db))
    known_ids = set(db.scalars(select(m.Alert.alert_id).where(
        m.Alert.alert_id.in_([a.alert_id for a in outcome.alerts][:30000])))) if outcome.alerts else set()
    if known_ids:
        outcome.alerts = [a for a in outcome.alerts if a.alert_id not in known_ids]
        outcome.result.accepted = len(outcome.alerts)
        outcome.result.duplicates += len(known_ids)
    repo.save_batch(db, outcome.result, outcome.alerts, source_name, outcome.duplicate_of)
    repo.audit(db, "alerts.ingest", target_type="batch", target_id=outcome.result.batch_id, trace_id=trace_id,
               received=outcome.result.received, accepted=outcome.result.accepted,
               duplicates=outcome.result.duplicates, rejected=outcome.result.rejected)
    return outcome


def load_demo(db: Session, seed: int, trace_id: str | None = None) -> dict[str, Any]:
    t0 = time.perf_counter()
    info = write_dataset(demo_dir(), seed)
    repo.reset_all(db)
    rows = parse_payload((demo_dir() / "alerts.jsonl").read_text(), "jsonl")
    outcome = ingest(db, rows, f"demo-seed-{seed}", trace_id)
    repo.audit(db, "demo.load", target_type="dataset", target_id=str(seed), trace_id=trace_id)
    return {"seed": seed, "generated_rows": info["rows"], "ground_truth_incidents": info["gt_incidents"],
            "batch": outcome.result.model_dump(exclude={"rejected_rows"}),
            "rejected_rows": [r.model_dump() for r in outcome.result.rejected_rows],
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1)}


# ------------------------------------------------------------------ pipeline runs
def start_pipeline_run(trace_id: str | None = None, background: bool = True) -> str:
    run_id = f"RUN-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
    s = get_settings()
    with session_scope() as db:
        db.add(m.PipelineRun(run_id=run_id, status="queued", stage="queued", progress=0.0, trace_id=trace_id,
                             config={"correlation": correlation_config(s).__dict__,
                                     "risk_config_version": s.risk_config_version,
                                     "prompt_version": s.prompt_version, "jev_model": s.jev_model,
                                     "jev_enabled": bool(s.typesafe_api_key),
                                     "narrative_order": s.narrative_order}))
    if background:
        threading.Thread(target=execute_pipeline_run, args=(run_id,), daemon=True).start()
    else:
        execute_pipeline_run(run_id)
    return run_id


def _progress(run_id: str, stage: str, frac: float, **extra: Any) -> None:
    with session_scope() as db:
        db.execute(update(m.PipelineRun).where(m.PipelineRun.run_id == run_id)
                   .values(stage=stage, progress=round(frac, 3), status="running", **extra))


def execute_pipeline_run(run_id: str) -> None:
    settings = get_settings()
    with _run_lock:
        t0 = time.perf_counter()
        try:
            _progress(run_id, "loading_alerts", 0.02)
            with session_scope() as db:
                alerts = repo.load_alerts(db)
                cached = {d.evidence_hash: d.decision for d in db.scalars(
                    select(m.DecisionRun).where(m.DecisionRun.model == settings.jev_model,
                                                m.DecisionRun.status == "ok"))}
            if not alerts:
                raise ValueError("no alerts loaded; load the demo dataset or ingest alerts first")
            ctx = get_context()
            out = run_pipeline(alerts, ctx, correlation_config(settings), decisions=cached,
                               progress=lambda st, fr: _progress(run_id, st, 0.05 + 0.6 * fr))
            _progress(run_id, "persisting", 0.7)
            ctx_lookup = {f"user:{k}": v for k, v in ctx.users.items()} | \
                {f"host:{k}": v for k, v in ctx.hosts.items()} | {f"resource:{k}": v for k, v in ctx.resources.items()}
            with session_scope() as db:
                repo.save_pipeline_output(db, run_id, out, ctx_lookup)
            jev_stats: dict[str, Any] = {"enabled": False}
            if settings.typesafe_api_key:
                _progress(run_id, "jev_decisions", 0.8)
                jev_stats = asyncio.run(decide_top_incidents(settings.jev_top_n))
            _progress(run_id, "evaluation", 0.92)
            metrics = compute_evaluation(run_id)
            runtime = round((time.perf_counter() - t0) * 1000, 1)
            with session_scope() as db:
                db.execute(update(m.PipelineRun).where(m.PipelineRun.run_id == run_id).values(
                    status="completed", stage="done", progress=1.0, finished_at=datetime.now(UTC),
                    stats={**out.stats, "jev": jev_stats, "runtime_ms": runtime,
                           "evaluation_available": metrics is not None},
                    timings_ms={**out.timings_ms, "total": runtime}))
                repo.audit(db, "pipeline.run", target_type="run", target_id=run_id,
                           incidents=len(out.incidents), runtime_ms=runtime)
            if settings.prewarm_top_n and narrative_providers(settings):
                threading.Thread(target=lambda: asyncio.run(prewarm_briefs(settings.prewarm_top_n)),
                                 daemon=True).start()
        except Exception as exc:  # noqa: BLE001 - surface any failure in run status
            with session_scope() as db:
                db.execute(update(m.PipelineRun).where(m.PipelineRun.run_id == run_id).values(
                    status="failed", stage="failed", error=str(exc)[:2000], finished_at=datetime.now(UTC)))


# ------------------------------------------------------------------ incident views
def incident_view(db: Session, incident_id: str) -> dict[str, Any] | None:
    inc = db.get(m.Incident, incident_id)
    if inc is None:
        return None
    stages = db.scalars(select(m.AttackStage).where(m.AttackStage.incident_id == incident_id)
                        .order_by(m.AttackStage.position)).all()
    mitre = db.scalars(select(m.IncidentMitre).where(m.IncidentMitre.incident_id == incident_id)
                       .order_by(m.IncidentMitre.confidence.desc())).all()
    ents = db.scalars(select(m.IncidentEntity).where(m.IncidentEntity.incident_id == incident_id)).all()
    alert_ids = list(db.scalars(select(m.IncidentAlert.alert_id).where(m.IncidentAlert.incident_id == incident_id)))
    return {
        "incident_id": inc.incident_id, "rank": inc.rank, "title": inc.title, "status": inc.status,
        "severity": inc.severity, "risk_score": inc.risk_score, "correlation_confidence": inc.correlation_confidence,
        "first_seen": inc.first_seen.isoformat(), "last_seen": inc.last_seen.isoformat(),
        "alert_count": inc.alert_count, "duplicate_count": inc.duplicate_count, "chain_strength": inc.chain_strength,
        "anomaly_score": inc.anomaly_score, "anomaly_reasons": inc.anomaly_reasons, "factors": inc.factors,
        "risk": inc.risk, "deterministic_risk": inc.deterministic_risk, "primary_entities": inc.primary_entities,
        "top_alert_types": inc.top_alert_types, "mitre_ids": inc.mitre_ids, "evidence_hash": inc.evidence_hash,
        "template_summary": inc.template_summary, "analyst_verdict": inc.analyst_verdict,
        "attack_stages": [{"stage": s.stage, "label": s.label, "order": s.stage_order, "first_seen": s.first_seen,
                           "last_seen": s.last_seen, "alert_ids": s.alert_ids, "alert_types": s.alert_types,
                           "confidence": s.confidence} for s in stages],
        "mitre": [{"technique_id": t.technique_id, "name": t.name, "tactics": t.tactics, "confidence": t.confidence,
                   "evidence_alert_ids": t.evidence_alert_ids, "mapping_reason": t.mapping_reason,
                   "attack_catalog_version": t.attack_catalog_version} for t in mitre],
        "entities": [{"type": e.entity_type, "value": e.value, "role": e.role, "alert_count": e.alert_count,
                      "rarity": e.rarity} for e in ents],
        "alert_ids": alert_ids,
    }


def incident_alert_dicts(db: Session, incident_id: str) -> list[dict[str, Any]]:
    rows = db.execute(select(m.Alert).join(m.IncidentAlert, m.IncidentAlert.alert_id == m.Alert.alert_id)
                      .where(m.IncidentAlert.incident_id == incident_id).order_by(m.Alert.timestamp)).scalars()
    return [{"alert_id": a.alert_id, "timestamp": a.timestamp.isoformat(), "alert_type": a.alert_type,
             "title": a.title, "severity": a.severity, "user": a.user, "host": a.host, "src_ip": a.src_ip,
             "dst_ip": a.dst_ip, "process": a.process, "resource": a.resource, "attributes": a.attributes}
            for a in rows]


def similar_candidates(db: Session, limit: int = 300) -> list[dict[str, Any]]:
    rows = db.execute(select(m.Incident.incident_id, m.Incident.title, m.Incident.risk_score, m.Incident.mitre_ids,
                             m.Incident.top_alert_types, m.Incident.analyst_verdict)
                      .order_by(m.Incident.risk_score.desc()).limit(limit)).all()
    return [dict(r._mapping) for r in rows]


def evidence_pack_for(db: Session, view: dict[str, Any]) -> dict[str, Any]:
    alerts = incident_alert_dicts(db, view["incident_id"])
    similar = find_similar_incidents(view, similar_candidates(db))
    return build_evidence_pack(view, alerts, get_context(), similar)


# ------------------------------------------------------------------ Jev decisions
async def decide_top_incidents(top_n: int, force: bool = False) -> dict[str, Any]:
    settings = get_settings()
    provider = JevDecisionProvider(settings.typesafe_api_key, settings.jev_model, settings.jev_timeout_seconds)
    if not provider.available():
        return {"enabled": False}
    with session_scope() as db:
        top = db.scalars(select(m.Incident).order_by(m.Incident.risk_score.desc()).limit(top_n)).all()
        cached = set(db.scalars(select(m.DecisionRun.evidence_hash).where(
            m.DecisionRun.model == settings.jev_model, m.DecisionRun.status == "ok")))
        todo = [(i.incident_id, i.evidence_hash) for i in top if force or i.evidence_hash not in cached]
        packs = {iid: evidence_pack_for(db, incident_view(db, iid)) for iid, _ in todo}
    sem = asyncio.Semaphore(settings.jev_max_concurrency)
    results: dict[str, Any] = {}

    async def one(iid: str, ehash: str) -> None:
        async with sem:
            try:
                res = await provider.evaluate(decision_state(packs[iid]))
                results[iid] = ("ok", ehash, res)
            except ProviderError as exc:
                results[iid] = ("error", ehash, str(exc))

    await asyncio.gather(*(one(i, h) for i, h in todo))
    ok = errors = 0
    with session_scope() as db:
        for iid, (status, ehash, res) in results.items():
            existing = db.scalar(select(m.DecisionRun).where(m.DecisionRun.evidence_hash == ehash,
                                                             m.DecisionRun.model == settings.jev_model))
            if existing is not None:
                db.delete(existing)
                db.flush()
            if status == "ok":
                ok += 1
                db.add(m.DecisionRun(incident_id=iid, evidence_hash=ehash, provider="jev", model=settings.jev_model,
                                     status="ok", decision=res.decision | {"served_model": res.model},
                                     raw_response=res.raw, latency_ms=res.latency_ms))
            else:
                errors += 1
                db.add(m.DecisionRun(incident_id=iid, evidence_hash=ehash, provider="jev", model=settings.jev_model,
                                     status="error", error=res))
        db.flush()
        apply_decisions(db)
    return {"enabled": True, "requested": len(todo), "ok": ok, "errors": errors, "cached": len(top) - len(todo)}


def apply_decisions(db: Session) -> None:
    """Recompute v2-jev risk for incidents with a cached decision, then re-rank the queue."""
    settings = get_settings()
    decisions = {d.evidence_hash: d.decision for d in db.scalars(
        select(m.DecisionRun).where(m.DecisionRun.model == settings.jev_model, m.DecisionRun.status == "ok"))}
    for inc in db.scalars(select(m.Incident).where(m.Incident.evidence_hash.in_(list(decisions)))):
        r = compute_risk(inc.factors, decisions[inc.evidence_hash])
        det = compute_risk(inc.factors, None)
        inc.risk = r.as_dict() | {"jev_decision": decisions[inc.evidence_hash]}
        inc.deterministic_risk = det.as_dict()
        inc.risk_score = r.score
        inc.severity = r.severity
    db.flush()
    ranked = db.execute(select(m.Incident.incident_id).order_by(m.Incident.risk_score.desc(),
                                                                 m.Incident.first_seen)).scalars().all()
    db.execute(update(m.Incident), [{"incident_id": iid, "rank": r} for r, iid in enumerate(ranked, start=1)])


# ------------------------------------------------------------------ briefs
async def brief_for_incident(incident_id: str, refresh: bool = False, providers_order: list[str] | None = None,
                             patient: bool = False) -> dict[str, Any] | None:
    settings = get_settings()
    with session_scope() as db:
        view = incident_view(db, incident_id)
        if view is None:
            return None
        providers = narrative_providers(settings, providers_order)
        if not refresh:
            cached = db.scalar(select(m.LlmRun).where(
                m.LlmRun.evidence_hash == view["evidence_hash"], m.LlmRun.prompt_version == settings.prompt_version,
                m.LlmRun.status == "ok").order_by(m.LlmRun.created_at.desc()).limit(1))
            if cached is not None and (cached.provider != "template" or not providers):
                return _brief_payload(cached, cached=True)
        pack = evidence_pack_for(db, view)
    result = await generate_brief(view, pack, providers, patient=patient,
                                  cooldown_seconds=settings.provider_cooldown_seconds)
    with session_scope() as db:
        run = m.LlmRun(incident_id=incident_id, evidence_hash=view["evidence_hash"], provider=result["provider"],
                       model=result["model"], prompt_version=settings.prompt_version,
                       status="ok" if result["provider"] != "template" or not result["attempts"] else "fallback",
                       output=result["brief"], output_hash=output_hash(result["brief"]),
                       validation=result["validation"], attempts=result["attempts"],
                       latency_ms=result["latency_ms"])
        db.add(run)
        db.flush()
        repo.audit(db, "brief.generate", target_type="incident", target_id=incident_id, provider=result["provider"],
                   status=run.status)
        payload = _brief_payload(run, cached=False)
    payload["evidence_pack_summary"] = {
        "alerts_shown": pack["tool_outputs"]["get_incident_evidence"]["alerts_shown"],
        "instruction_like_text_alert_ids": pack["tool_outputs"]["get_incident_evidence"][
            "instruction_like_text_alert_ids"],
        "similar_incidents": pack["tool_outputs"]["find_similar_incidents"],
    }
    return payload


def _brief_payload(run: m.LlmRun, cached: bool) -> dict[str, Any]:
    return {"incident_id": run.incident_id, "provider": run.provider, "model": run.model, "status": run.status,
            "prompt_version": run.prompt_version, "brief": run.output, "validation": run.validation,
            "attempts": run.attempts, "latency_ms": run.latency_ms, "generated_at": run.created_at.isoformat(),
            "cached": cached, "output_hash": run.output_hash}


async def prewarm_briefs(top_n: int) -> None:
    with session_scope() as db:
        ids = db.scalars(select(m.Incident.incident_id).order_by(m.Incident.risk_score.desc()).limit(top_n)).all()
    for iid in ids:
        try:
            await brief_for_incident(iid, patient=True)
        except Exception:  # noqa: BLE001 - prewarm is best-effort
            pass


# ------------------------------------------------------------------ evaluation
def compute_evaluation(run_id: str) -> dict[str, Any] | None:
    gt = get_ground_truth()
    if gt is None:
        return None
    t0 = time.perf_counter()
    with session_scope() as db:
        pairs = db.execute(select(m.IncidentAlert.alert_id, m.IncidentAlert.incident_id)).all()
        pred = {a: i for a, i in pairs}
        ranked = [{"incident_id": i, "severity": s} for i, s in db.execute(
            select(m.Incident.incident_id, m.Incident.severity).order_by(m.Incident.risk_score.desc()))]
        anomaly = dict(db.execute(select(m.Alert.alert_id, m.Alert.anomaly_score)).all())
        rule = dict(db.execute(select(m.Alert.alert_id, m.Alert.rule_anomaly_score)).all())
        run = db.get(m.PipelineRun, run_id)
        llm = db.execute(select(m.LlmRun.provider, m.LlmRun.status, m.LlmRun.validation)).all()
        decisions = db.scalars(select(m.DecisionRun)).all()
        metrics = {
            "correlation": ev.correlation_metrics(pred, gt["alerts"]),
            "priority": ev.priority_metrics(ranked, pred, gt["alerts"], gt["incidents"]),
            "detection": {
                "rules_only": ev.detection_metrics({k: v or 0 for k, v in rule.items()}, gt["alerts"],
                                                   gt["incidents"], 0.5),
                "rules_plus_isolation_forest": ev.detection_metrics({k: v or 0 for k, v in anomaly.items()},
                                                                    gt["alerts"], gt["incidents"], 0.5),
            },
            "llm": _llm_metrics(llm),
            "jev": {"decisions": len([d for d in decisions if d.status == "ok"]),
                    "errors": len([d for d in decisions if d.status == "error"]),
                    "median_latency_ms": _median([d.latency_ms for d in decisions if d.status == "ok"])},
            "runtime_ms": (run.timings_ms or {}) if run else {},
            "dataset": {"seed": gt.get("seed"), "dataset": gt.get("dataset"),
                        "ground_truth_incidents": len(gt["incidents"])},
        }
        db.add(m.EvaluationRun(run_id=run_id, config=run.config if run else {}, metrics=metrics,
                               runtime_ms=round((time.perf_counter() - t0) * 1000, 1)))
    return metrics


def _median(xs: list[float]) -> float | None:
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    return round(s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2, 1)


def _llm_metrics(rows: list[Any]) -> dict[str, Any]:
    model_runs = [r for r in rows if r.provider != "template"]
    total = len(rows)
    valid = sum(1 for r in rows if (r.validation or {}).get("schema_valid"))
    checked = sum((r.validation or {}).get("citations_checked", 0) for r in rows)
    bad = sum(len((r.validation or {}).get("invalid_citations", [])) for r in rows)
    return {"briefs": total, "model_briefs": len(model_runs),
            "template_fallbacks": sum(1 for r in rows if r.status == "fallback"),
            "structured_output_valid_rate": round(valid / total, 4) if total else None,
            "citation_validity_rate": round(1 - bad / checked, 4) if checked else None}
