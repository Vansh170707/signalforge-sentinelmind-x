from __future__ import annotations

import statistics
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.graph import build_graph
from app.config import get_settings
from app.db import models as m
from app.db import repository as repo
from app.db.session import get_db
from app.schemas.alerts import BatchIn
from app.services import runner
from app.services.ingestion import parse_payload
from app.services.mitre import get_catalog

router = APIRouter(prefix="/api/v1")


def trace(request: Request) -> str | None:
    return getattr(request.state, "trace_id", None)


def not_found(what: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{what} not found")


# ------------------------------------------------------------------ demo
class DemoLoadIn(BaseModel):
    seed: int = Field(default=7, ge=0, le=1_000_000)
    run_pipeline: bool = False


@router.post("/demo/reset")
def demo_reset(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    repo.reset_all(db)
    repo.audit(db, "demo.reset", trace_id=trace(request))
    db.commit()
    return {"status": "reset"}


@router.post("/demo/load")
def demo_load(body: DemoLoadIn, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    result = runner.load_demo(db, body.seed, trace(request))
    db.commit()
    if body.run_pipeline:
        result["run_id"] = runner.start_pipeline_run(trace(request))
    return result


# ------------------------------------------------------------------ alerts
@router.post("/alerts/batch")
def alerts_batch(body: BatchIn, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    if len(body.alerts) > get_settings().max_upload_alerts:
        raise HTTPException(413, f"batch exceeds {get_settings().max_upload_alerts} alerts")
    outcome = runner.ingest(db, body.alerts, "api-batch", trace(request))
    db.commit()
    return outcome.result.model_dump()


@router.post("/alerts/upload")
async def alerts_upload(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)
                        ) -> dict[str, Any]:
    raw = await file.read(20_000_001)
    if len(raw) > 20_000_000:
        raise HTTPException(413, "file larger than 20 MB")
    name = (file.filename or "upload.jsonl").lower()
    fmt = "csv" if name.endswith(".csv") else "json" if name.endswith(".json") else "jsonl"
    try:
        rows = parse_payload(raw.decode("utf-8", errors="replace"), fmt)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if len(rows) > get_settings().max_upload_alerts:
        raise HTTPException(413, f"file exceeds {get_settings().max_upload_alerts} alerts")
    outcome = runner.ingest(db, rows, file.filename, trace(request))
    db.commit()
    return outcome.result.model_dump()


def _alert_out(a: m.Alert, full: bool = False) -> dict[str, Any]:
    d = {"alert_id": a.alert_id, "timestamp": a.timestamp.isoformat(), "source": a.source, "vendor": a.vendor,
         "alert_type": a.alert_type, "title": a.title, "severity": a.severity, "severity_score": a.severity_score,
         "confidence": a.confidence, "user": a.user, "host": a.host, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
         "process": a.process, "resource": a.resource, "asset_criticality": a.asset_criticality,
         "user_privilege": a.user_privilege, "incident_id": a.incident_id, "anomaly_score": a.anomaly_score,
         "duplicate_count": a.duplicate_count, "attributes": a.attributes}
    if full:
        d |= {"user_display": a.user_display, "host_display": a.host_display, "raw": a.raw,
              "raw_event_ref": a.raw_event_ref, "content_hash": a.content_hash, "batch_id": a.batch_id,
              "rule_anomaly_score": a.rule_anomaly_score, "src_ip_internal": a.src_ip_internal,
              "dst_ip_internal": a.dst_ip_internal}
    return d


@router.get("/alerts")
def list_alerts(db: Session = Depends(get_db), q: str | None = None, severity: str | None = None,
                alert_type: str | None = None, user: str | None = None, host: str | None = None,
                src_ip: str | None = None, incident_id: str | None = None,
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    stmt = select(m.Alert)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(m.Alert.title).like(like), m.Alert.alert_id.like(f"%{q.upper()}%"),
                              func.lower(m.Alert.user).like(like), func.lower(m.Alert.host).like(like),
                              m.Alert.src_ip.like(f"%{q}%"), func.lower(m.Alert.alert_type).like(like)))
    for col, val in ((m.Alert.severity, severity), (m.Alert.alert_type, alert_type), (m.Alert.user, user),
                     (m.Alert.host, host.upper() if host else None), (m.Alert.src_ip, src_ip),
                     (m.Alert.incident_id, incident_id)):
        if val:
            stmt = stmt.where(col == val)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(m.Alert.timestamp.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"total": total, "page": page, "page_size": page_size, "items": [_alert_out(a) for a in rows]}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    a = db.get(m.Alert, alert_id)
    if a is None:
        raise not_found("alert")
    out = _alert_out(a, full=True)
    link = db.scalar(select(m.IncidentAlert).where(m.IncidentAlert.alert_id == alert_id))
    out["membership"] = ({"incident_id": link.incident_id, "edge_score": link.edge_score,
                          "linked_alert_id": link.linked_alert_id, "reasons": link.reasons} if link else None)
    return out


# ------------------------------------------------------------------ pipeline
@router.post("/pipeline/run")
def pipeline_run(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not db.scalar(select(func.count()).select_from(m.Alert)):
        raise HTTPException(409, "no alerts loaded; load the demo dataset first")
    run_id = runner.start_pipeline_run(trace(request))
    return {"run_id": run_id, "status": "queued"}


def _run_out(r: m.PipelineRun) -> dict[str, Any]:
    return {"run_id": r.run_id, "status": r.status, "stage": r.stage, "progress": r.progress,
            "started_at": r.started_at.isoformat(), "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "stats": r.stats, "timings_ms": r.timings_ms, "config": r.config, "error": r.error}


@router.get("/pipeline/latest")
def pipeline_latest(db: Session = Depends(get_db)) -> dict[str, Any] | None:
    r = repo.latest_run(db)
    return _run_out(r) if r else None


@router.get("/pipeline/{run_id}")
def pipeline_status(run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(m.PipelineRun, run_id)
    if r is None:
        raise not_found("pipeline run")
    return _run_out(r)


# ------------------------------------------------------------------ incidents
def _incident_row(i: m.Incident) -> dict[str, Any]:
    return {"incident_id": i.incident_id, "rank": i.rank, "title": i.title, "status": i.status,
            "severity": i.severity, "risk_score": i.risk_score, "correlation_confidence": i.correlation_confidence,
            "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat(),
            "alert_count": i.alert_count, "duplicate_count": i.duplicate_count,
            "primary_entities": i.primary_entities[:4], "mitre_ids": i.mitre_ids,
            "risk_formula": (i.risk or {}).get("formula"), "analyst_verdict": i.analyst_verdict,
            "chain_strength": i.chain_strength, "anomaly_score": i.anomaly_score}


@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db), severity: str | None = None, status: str | None = None,
                   q: str | None = None, min_risk: float = 0, technique: str | None = None,
                   sort: Literal["risk", "recent", "alerts"] = "risk",
                   page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    stmt = select(m.Incident).where(m.Incident.risk_score >= min_risk)
    if severity:
        stmt = stmt.where(m.Incident.severity.in_(severity.split(",")))
    if status:
        stmt = stmt.where(m.Incident.status.in_(status.split(",")))
    if q:
        stmt = stmt.where(or_(func.lower(m.Incident.title).like(f"%{q.lower()}%"),
                              m.Incident.incident_id.like(f"%{q.upper()}%")))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    order = {"risk": (m.Incident.risk_score.desc(), m.Incident.first_seen),
             "recent": (m.Incident.last_seen.desc(),), "alerts": (m.Incident.alert_count.desc(),)}[sort]
    rows = list(db.scalars(stmt.order_by(*order)))
    if technique:
        rows = [r for r in rows if technique in (r.mitre_ids or [])]
        total = len(rows)
    rows = rows[(page - 1) * page_size : page * page_size]
    return {"total": total, "page": page, "page_size": page_size, "items": [_incident_row(i) for i in rows]}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    view = runner.incident_view(db, incident_id)
    if view is None:
        raise not_found("incident")
    decision = db.scalar(select(m.DecisionRun).where(m.DecisionRun.evidence_hash == view["evidence_hash"])
                         .order_by(m.DecisionRun.created_at.desc()).limit(1))
    view["decision"] = ({"status": decision.status, "model": decision.model, "decision": decision.decision,
                         "latency_ms": decision.latency_ms, "error": decision.error,
                         "created_at": decision.created_at.isoformat()} if decision else None)
    view["feedback"] = [{"verdict": f.verdict, "corrected_severity": f.corrected_severity, "notes": f.notes,
                         "analyst": f.analyst, "created_at": f.created_at.isoformat()}
                        for f in db.scalars(select(m.AnalystFeedback).where(
                            m.AnalystFeedback.evidence_hash == view["evidence_hash"])
                            .order_by(m.AnalystFeedback.created_at.desc()))]
    view.pop("alert_ids", None)
    return view


@router.get("/incidents/{incident_id}/alerts")
def incident_alerts(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.get(m.Incident, incident_id) is None:
        raise not_found("incident")
    rows = db.execute(select(m.Alert, m.IncidentAlert).join(m.IncidentAlert, m.IncidentAlert.alert_id == m.Alert.alert_id)
                      .where(m.IncidentAlert.incident_id == incident_id).order_by(m.Alert.timestamp)).all()
    return {"incident_id": incident_id, "items": [
        _alert_out(a) | {"membership": {"edge_score": ia.edge_score, "linked_alert_id": ia.linked_alert_id,
                                        "reasons": ia.reasons}} for a, ia in rows]}


@router.get("/incidents/{incident_id}/graph")
def incident_graph(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    view = runner.incident_view(db, incident_id)
    if view is None:
        raise not_found("incident")
    return build_graph(view, runner.incident_alert_dicts(db, incident_id), runner.get_context())


@router.get("/incidents/{incident_id}/brief")
async def get_brief(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Cached model brief if one exists, otherwise the instant deterministic template."""
    inc = db.get(m.Incident, incident_id)
    if inc is None:
        raise not_found("incident")
    cached = db.scalar(select(m.LlmRun).where(m.LlmRun.evidence_hash == inc.evidence_hash,
                                              m.LlmRun.prompt_version == get_settings().prompt_version)
                       .order_by(m.LlmRun.created_at.desc()).limit(1))
    if cached is not None:
        return runner._brief_payload(cached, cached=True)
    return {"incident_id": incident_id, "provider": "template", "model": "deterministic-template", "status": "ok",
            "brief": inc.template_summary, "attempts": [], "cached": True,
            "validation": {"schema_valid": True, "citations_checked": sum(
                len(f["alert_ids"]) for f in (inc.template_summary or {}).get("observed_facts", [])),
                "invalid_citations": []},
            "generated_at": inc.created_at.isoformat(), "prompt_version": get_settings().prompt_version}


class BriefIn(BaseModel):
    refresh: bool = False
    providers: list[str] | None = None


@router.post("/incidents/{incident_id}/brief")
async def post_brief(incident_id: str, body: BriefIn | None = None) -> dict[str, Any]:
    body = body or BriefIn()
    result = await runner.brief_for_incident(incident_id, refresh=body.refresh, providers_order=body.providers)
    if result is None:
        raise not_found("incident")
    return result


@router.post("/incidents/{incident_id}/decision")
async def post_decision(incident_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not get_settings().typesafe_api_key:
        raise HTTPException(409, "Jev decision provider not configured (TYPESAFE_API_KEY)")
    inc = db.get(m.Incident, incident_id)
    if inc is None:
        raise not_found("incident")
    db.close()
    from app.db.session import session_scope

    with session_scope() as s:
        cached = s.scalar(select(m.DecisionRun).where(m.DecisionRun.evidence_hash == inc.evidence_hash,
                                                      m.DecisionRun.status == "ok"))
    if cached is None:
        await _decide_one(incident_id)
    with session_scope() as s:
        return get_incident(incident_id, s)["decision"] or {}


async def _decide_one(incident_id: str) -> None:
    from app.db.session import session_scope
    from app.llm.jev import JevDecisionProvider
    from app.services.agent import decision_state

    s = get_settings()
    with session_scope() as db:
        view = runner.incident_view(db, incident_id)
        pack = runner.evidence_pack_for(db, view)
    provider = JevDecisionProvider(s.typesafe_api_key, s.jev_model, s.jev_timeout_seconds)
    try:
        res = await provider.evaluate(decision_state(pack))
        row = m.DecisionRun(incident_id=incident_id, evidence_hash=view["evidence_hash"], provider="jev",
                            model=s.jev_model, status="ok", decision=res.decision | {"served_model": res.model},
                            raw_response=res.raw, latency_ms=res.latency_ms)
    except Exception as exc:  # noqa: BLE001
        row = m.DecisionRun(incident_id=incident_id, evidence_hash=view["evidence_hash"], provider="jev",
                            model=s.jev_model, status="error", error=str(exc)[:500])
    with session_scope() as db:
        old = db.scalar(select(m.DecisionRun).where(m.DecisionRun.evidence_hash == view["evidence_hash"],
                                                    m.DecisionRun.model == s.jev_model))
        if old is not None:
            db.delete(old)
            db.flush()
        db.add(row)
        db.flush()
        runner.apply_decisions(db)


class FeedbackIn(BaseModel):
    verdict: Literal["confirmed_malicious", "needs_investigation", "benign_true_positive", "false_positive"]
    corrected_severity: Literal["low", "medium", "high", "critical"] | None = None
    notes: str | None = Field(default=None, max_length=2000)
    analyst: str = Field(default="analyst", max_length=120)


@router.post("/incidents/{incident_id}/feedback")
def post_feedback(incident_id: str, body: FeedbackIn, request: Request, db: Session = Depends(get_db)
                  ) -> dict[str, Any]:
    inc = db.get(m.Incident, incident_id)
    if inc is None:
        raise not_found("incident")
    db.add(m.AnalystFeedback(incident_id=incident_id, evidence_hash=inc.evidence_hash, verdict=body.verdict,
                             corrected_severity=body.corrected_severity, notes=body.notes, analyst=body.analyst))
    inc.analyst_verdict = body.verdict
    inc.status = "closed" if body.verdict in ("false_positive", "benign_true_positive") else "triaged"
    repo.audit(db, "incident.feedback", actor=body.analyst, target_type="incident", target_id=incident_id,
               trace_id=trace(request), verdict=body.verdict, corrected_severity=body.corrected_severity)
    db.commit()
    return {"incident_id": incident_id, "verdict": body.verdict, "status": inc.status}


# ------------------------------------------------------------------ metrics
@router.get("/metrics/overview")
def metrics_overview(db: Session = Depends(get_db)) -> dict[str, Any]:
    c = repo.counts(db)
    run = repo.latest_run(db)
    hourly: dict[str, dict[str, int]] = {}
    for ts, sev in db.execute(select(m.Alert.timestamp, m.Alert.severity)):
        bucket = hourly.setdefault(f"{ts.hour:02d}", {})
        bucket[sev] = bucket.get(sev, 0) + 1
    top = db.scalars(select(m.Incident).order_by(m.Incident.risk_score.desc()).limit(5)).all()
    verdicts = dict(db.execute(select(m.AnalystFeedback.verdict, func.count())
                               .group_by(m.AnalystFeedback.verdict)).all())
    return {
        **c,
        "critical_high": c["incident_severity"].get("critical", 0) + c["incident_severity"].get("high", 0),
        "compression_ratio": round(c["alerts"] / c["incidents"], 2) if c["incidents"] else None,
        "alert_to_actionable_ratio": round(c["alerts"] / max(1, c["incident_severity"].get("critical", 0)
                                                             + c["incident_severity"].get("high", 0)), 1)
        if c["incidents"] else None,
        "pipeline": _run_out(run) if run else None,
        "hourly": [{"hour": h, **v} for h, v in sorted(hourly.items())],
        "top_incidents": [_incident_row(i) for i in top],
        "verdicts": verdicts,
    }


@router.get("/metrics/evaluation")
def metrics_evaluation(db: Session = Depends(get_db)) -> dict[str, Any]:
    er = db.scalar(select(m.EvaluationRun).order_by(m.EvaluationRun.created_at.desc()).limit(1))
    trials = _triage_summary(db)
    if er is None:
        return {"available": False, "reason": "run the pipeline on the demo dataset to compute metrics",
                "triage_experiment": trials}
    return {"available": True, "run_id": er.run_id, "created_at": er.created_at.isoformat(), "config": er.config,
            "metrics": er.metrics, "triage_experiment": trials}


@router.post("/metrics/evaluation/refresh")
def metrics_refresh(db: Session = Depends(get_db)) -> dict[str, Any]:
    run = repo.latest_run(db)
    if run is None:
        raise HTTPException(409, "no pipeline run yet")
    metrics = runner.compute_evaluation(run.run_id)
    return {"available": metrics is not None, "metrics": metrics}


class TriageTrialIn(BaseModel):
    participant: str = Field(max_length=120)
    mode: Literal["baseline", "assisted"]
    seconds: float = Field(gt=0, le=7200)
    correct: bool


@router.post("/experiments/triage")
def add_triage_trial(body: TriageTrialIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    db.add(m.TriageTrial(**body.model_dump()))
    db.commit()
    return _triage_summary(db)


def _triage_summary(db: Session) -> dict[str, Any]:
    trials = db.scalars(select(m.TriageTrial)).all()
    out: dict[str, Any] = {"trials": len(trials)}
    for mode in ("baseline", "assisted"):
        xs = [t.seconds for t in trials if t.mode == mode]
        out[mode] = {"n": len(xs), "median_seconds": statistics.median(xs) if xs else None,
                     "accuracy": round(sum(1 for t in trials if t.mode == mode and t.correct) / len(xs), 3)
                     if xs else None}
    b, a = out["baseline"]["median_seconds"], out["assisted"]["median_seconds"]
    out["triage_reduction_pct"] = round(100 * (b - a) / b, 1) if a is not None and b else None
    return out


# ------------------------------------------------------------------ misc
@router.get("/mitre/{technique_id}")
def mitre_lookup(technique_id: str) -> dict[str, Any]:
    cat = get_catalog()
    t = cat.get(technique_id.upper())
    if t is None:
        raise not_found("technique")
    return t | {"tactic_names": cat.tactic_names(technique_id.upper()), "attack_version": cat.version}


@router.get("/settings")
def settings_view(db: Session = Depends(get_db)) -> dict[str, Any]:
    s = get_settings()
    return {
        "providers": {
            "jev": {"configured": bool(s.typesafe_api_key), "model": s.jev_model,
                    "benchmark_model": s.jev_benchmark_model, "top_n": s.jev_top_n},
            "gemini": {"configured": bool(s.gemini_api_key), "model": s.gemini_model},
            "groq": {"configured": bool(s.groq_api_key), "fast_model": s.groq_fast_model,
                     "hard_model": s.groq_hard_model},
            "foundry": {"configured": bool(s.foundry_project_endpoint and s.foundry_api_key),
                        "deployment": s.foundry_model_deployment},
            "template": {"configured": True},
        },
        "narrative_order": s.narrative_order,
        "correlation": {"window_minutes": s.correlation_window_minutes,
                        "edge_threshold": s.correlation_edge_threshold,
                        "max_component": s.correlation_max_component, "version": s.correlation_config_version},
        "risk_config_version": s.risk_config_version, "prompt_version": s.prompt_version,
        "demo_seed": s.demo_seed, "attack_catalog_version": get_catalog().version,
        "database": db.bind.dialect.name,
    }


@router.get("/audit")
def audit_log(db: Session = Depends(get_db), limit: int = Query(100, le=1000)) -> list[dict[str, Any]]:
    rows = db.scalars(select(m.AuditEvent).order_by(m.AuditEvent.ts.desc()).limit(limit))
    return [{"ts": r.ts.isoformat(), "actor": r.actor, "action": r.action, "target_type": r.target_type,
             "target_id": r.target_id, "trace_id": r.trace_id, "details": r.details} for r in rows]


