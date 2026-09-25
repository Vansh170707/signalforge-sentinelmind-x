"""Persistence for ingestion + pipeline output, and read models for the API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session

from app.db import models as m
from app.schemas.alerts import BatchResult, CanonicalAlert
from app.services.entities import alert_entities, entity_key
from app.services.pipeline import IncidentDraft, PipelineOutput

CHUNK = 2000


def _chunks(rows: list[dict[str, Any]], size: int = CHUNK):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def audit(db: Session, action: str, *, actor: str = "system", target_type: str | None = None,
          target_id: str | None = None, trace_id: str | None = None, **details: Any) -> None:
    db.add(m.AuditEvent(actor=actor, action=action, target_type=target_type, target_id=target_id,
                        trace_id=trace_id, details=details))


def reset_all(db: Session, purge_ai_cache: bool = False) -> None:
    """Remove demo data and analyst feedback. Jev decisions and model briefs are caches keyed by evidence
    hash (+ model / prompt version), so they stay valid across reloads and are kept unless purged."""
    models = [m.IncidentAlert, m.IncidentEntity, m.AttackStage, m.IncidentMitre, m.Incident, m.AlertEntity,
              m.Alert, m.Entity, m.IngestBatch, m.PipelineRun, m.EvaluationRun, m.AnalystFeedback]
    if purge_ai_cache:
        models += [m.DecisionRun, m.LlmRun]
    for model in models:
        db.execute(delete(model))


def export_ai_cache(db: Session) -> dict[str, Any]:
    decisions = [{"evidence_hash": d.evidence_hash, "provider": d.provider, "model": d.model, "decision": d.decision,
                  "latency_ms": d.latency_ms, "created_at": d.created_at.isoformat()}
                 for d in db.scalars(select(m.DecisionRun).where(m.DecisionRun.status == "ok"))]
    briefs = [{"evidence_hash": r.evidence_hash, "provider": r.provider, "model": r.model,
               "prompt_version": r.prompt_version, "output": r.output, "output_hash": r.output_hash,
               "validation": r.validation, "latency_ms": r.latency_ms, "created_at": r.created_at.isoformat()}
              for r in db.scalars(select(m.LlmRun).where(m.LlmRun.status == "ok", m.LlmRun.provider != "template"))]
    return {"format": "sentinelmind-ai-cache/v1", "decisions": decisions, "briefs": briefs}


def import_ai_cache(db: Session, data: dict[str, Any]) -> dict[str, int]:
    """Idempotent upsert of cached decisions/briefs (only fills gaps; never overwrites fresher rows)."""
    have_d = set(db.execute(select(m.DecisionRun.evidence_hash, m.DecisionRun.model)).all())
    have_b = set(db.execute(select(m.LlmRun.evidence_hash, m.LlmRun.provider, m.LlmRun.model, m.LlmRun.prompt_version)
                            .where(m.LlmRun.status == "ok")).all())
    nd = nb = 0
    for d in data.get("decisions", []):
        if (d["evidence_hash"], d["model"]) in have_d:
            continue
        db.add(m.DecisionRun(evidence_hash=d["evidence_hash"], provider=d["provider"], model=d["model"], status="ok",
                             decision=d["decision"], latency_ms=d.get("latency_ms", 0),
                             created_at=datetime.fromisoformat(d["created_at"])))
        nd += 1
    for b in data.get("briefs", []):
        if (b["evidence_hash"], b["provider"], b["model"], b["prompt_version"]) in have_b:
            continue
        db.add(m.LlmRun(evidence_hash=b["evidence_hash"], provider=b["provider"], model=b["model"],
                        prompt_version=b["prompt_version"], status="ok", output=b["output"],
                        output_hash=b.get("output_hash"), validation=b.get("validation", {}),
                        attempts=[{"provider": b["provider"], "model": b["model"], "status": "ok", "cached": True}],
                        latency_ms=b.get("latency_ms", 0), created_at=datetime.fromisoformat(b["created_at"])))
        nb += 1
    db.flush()
    return {"decisions": nd, "briefs": nb}


# ---------------------------------------------------------------- ingestion
def existing_hashes(db: Session) -> dict[str, str]:
    return {h: a for h, a in db.execute(select(m.Alert.content_hash, m.Alert.alert_id))}


def alert_row(a: CanonicalAlert, batch_id: str) -> dict[str, Any]:
    return {
        "alert_id": a.alert_id, "batch_id": batch_id, "timestamp": a.timestamp, "source": a.source,
        "vendor": a.vendor, "alert_type": a.alert_type, "title": a.title, "severity": a.severity,
        "severity_score": a.severity_score, "confidence": a.confidence, "user": a.user,
        "user_display": a.user_display, "host": a.host, "host_display": a.host_display, "src_ip": a.src_ip,
        "src_ip_internal": a.src_ip_private, "dst_ip": a.dst_ip, "dst_ip_internal": a.dst_ip_private,
        "process": a.process, "resource": a.resource, "asset_criticality": a.asset_criticality,
        "user_privilege": a.user_privilege, "raw_event_ref": a.raw_event_ref, "attributes": a.attributes,
        "content_hash": a.content_hash, "duplicate_count": a.duplicate_count, "raw": a.raw,
    }


def save_batch(db: Session, result: BatchResult, alerts: list[CanonicalAlert], source_name: str | None,
               duplicate_of: dict[str, str]) -> None:
    db.add(m.IngestBatch(batch_id=result.batch_id, source_name=source_name, received=result.received,
                         accepted=result.accepted, duplicates=result.duplicates, rejected=result.rejected,
                         rejected_rows=[r.model_dump() for r in result.rejected_rows],
                         duration_ms=result.duration_ms))
    db.flush()
    rows = [alert_row(a, result.batch_id) for a in alerts]
    for chunk in _chunks(rows):
        db.execute(insert(m.Alert), chunk)
    # Duplicates that hit alerts from earlier batches increment the stored counter.
    new_ids = {a.alert_id for a in alerts}
    earlier: dict[str, int] = {}
    for kept in duplicate_of.values():
        if kept not in new_ids:
            earlier[kept] = earlier.get(kept, 0) + 1
    for alert_id, n in earlier.items():
        db.execute(update(m.Alert).where(m.Alert.alert_id == alert_id)
                   .values(duplicate_count=m.Alert.duplicate_count + n))
    links = []
    for a in alerts:
        seen = set()
        for etype, value, role in alert_entities(a):
            key = (a.alert_id, entity_key(etype, value), role)
            if key not in seen:
                seen.add(key)
                links.append({"alert_id": a.alert_id, "entity_key": key[1], "role": role})
    for chunk in _chunks(links):
        db.execute(insert(m.AlertEntity), chunk)


def load_alerts(db: Session) -> list[CanonicalAlert]:
    out = []
    for r in db.execute(select(m.Alert).order_by(m.Alert.timestamp)).scalars():
        out.append(CanonicalAlert(
            alert_id=r.alert_id, timestamp=r.timestamp, source=r.source, vendor=r.vendor, alert_type=r.alert_type,
            title=r.title, severity=r.severity, severity_score=r.severity_score, confidence=r.confidence,
            user=r.user, user_display=r.user_display, host=r.host, host_display=r.host_display, src_ip=r.src_ip,
            src_ip_private=r.src_ip_internal, dst_ip=r.dst_ip, dst_ip_private=r.dst_ip_internal,
            process=r.process, resource=r.resource, asset_criticality=r.asset_criticality,
            user_privilege=r.user_privilege, raw_event_ref=r.raw_event_ref, attributes=r.attributes or {},
            content_hash=r.content_hash, duplicate_count=r.duplicate_count, raw={},
        ))
    return out


# ---------------------------------------------------------------- pipeline output
def save_pipeline_output(db: Session, run_id: str, out: PipelineOutput, context_lookup: dict[str, Any]) -> None:
    for model in (m.IncidentAlert, m.IncidentEntity, m.AttackStage, m.IncidentMitre, m.Incident, m.Entity):
        db.execute(delete(model))

    feedback = {f.evidence_hash: f.verdict for f in db.execute(
        select(m.AnalystFeedback).order_by(m.AnalystFeedback.created_at)).scalars()}

    ents = [{"key": k, "type": k.split(":", 1)[0], "value": k.split(":", 1)[1],
             "alert_count": out.entity_stats[k]["alert_count"], "rarity": w,
             "first_seen": out.entity_stats[k]["first_seen"], "last_seen": out.entity_stats[k]["last_seen"],
             "context": context_lookup.get(k, {})} for k, w in out.entity_weights.items()]
    for chunk in _chunks(ents):
        db.execute(insert(m.Entity), chunk)

    inc_rows, ia_rows, ie_rows, st_rows, mi_rows = [], [], [], [], []
    alert_to_incident: dict[str, str] = {}
    for d in out.incidents:
        inc_rows.append(incident_row(d, run_id, feedback.get(d.evidence_hash)))
        for mem in d.memberships:
            alert_to_incident[mem["alert_id"]] = d.incident_id
            ia_rows.append({"incident_id": d.incident_id, **mem})
        for e in d.entities:
            ie_rows.append({"incident_id": d.incident_id, "entity_type": e["type"], "value": e["value"],
                            "role": e["role"], "alert_count": e["alert_count"], "rarity": e["rarity"],
                            "first_seen": None, "last_seen": None})
        for pos, s in enumerate(d.attack_stages):
            st_rows.append({"incident_id": d.incident_id, "stage": s["stage"], "label": s["label"],
                            "stage_order": s["order"], "position": pos, "first_seen": s["first_seen"],
                            "last_seen": s["last_seen"], "alert_ids": s["alert_ids"],
                            "alert_types": s["alert_types"], "confidence": s["confidence"]})
        for t in d.mitre:
            mi_rows.append({"incident_id": d.incident_id, **t})
    for model, rows in ((m.Incident, inc_rows), (m.IncidentAlert, ia_rows), (m.IncidentEntity, ie_rows),
                        (m.AttackStage, st_rows), (m.IncidentMitre, mi_rows)):
        for chunk in _chunks(rows):
            db.execute(insert(model), chunk)

    # Denormalized incident id + anomaly scores on alerts for the explorer.
    updates = [{"alert_id": a, "incident_id": alert_to_incident.get(a), "anomaly_score": s,
                "rule_anomaly_score": out.alert_rule_anomaly.get(a)} for a, s in out.alert_anomaly.items()]
    for chunk in _chunks(updates):
        db.execute(update(m.Alert), chunk)


def incident_row(d: IncidentDraft, run_id: str, verdict: str | None) -> dict[str, Any]:
    from app.services.agent import template_summary  # local import avoids cycle

    return {
        "incident_id": d.incident_id, "run_id": run_id, "rank": d.rank, "title": d.title,
        "status": "new" if not verdict else "triaged", "severity": d.severity, "risk_score": d.risk_score,
        "correlation_confidence": d.correlation_confidence,
        "first_seen": datetime.fromisoformat(d.first_seen), "last_seen": datetime.fromisoformat(d.last_seen),
        "alert_count": d.alert_count, "duplicate_count": d.duplicate_count, "chain_strength": d.chain_strength,
        "anomaly_score": d.anomaly_score, "anomaly_reasons": d.anomaly_reasons, "factors": d.factors,
        "risk": d.risk, "deterministic_risk": d.risk if d.risk.get("formula") == "v1-deterministic" else {},
        "primary_entities": d.primary_entities, "top_alert_types": [list(x) for x in d.top_alert_types],
        "mitre_ids": [t["technique_id"] for t in d.mitre], "evidence_hash": d.evidence_hash,
        "template_summary": template_summary(d), "analyst_verdict": verdict,
    }


# ---------------------------------------------------------------- reads
def counts(db: Session) -> dict[str, Any]:
    alerts = db.scalar(select(func.count()).select_from(m.Alert)) or 0
    received = db.scalar(select(func.coalesce(func.sum(m.IngestBatch.received), 0))) or 0
    duplicates = db.scalar(select(func.coalesce(func.sum(m.IngestBatch.duplicates), 0))) or 0
    rejected = db.scalar(select(func.coalesce(func.sum(m.IngestBatch.rejected), 0))) or 0
    incidents = db.scalar(select(func.count()).select_from(m.Incident)) or 0
    sev = dict(db.execute(select(m.Incident.severity, func.count()).group_by(m.Incident.severity)).all())
    alert_sev = dict(db.execute(select(m.Alert.severity, func.count()).group_by(m.Alert.severity)).all())
    return {"alerts": alerts, "received": received, "duplicates": duplicates, "rejected": rejected,
            "incidents": incidents, "incident_severity": sev, "alert_severity": alert_sev}


def latest_run(db: Session) -> m.PipelineRun | None:
    return db.execute(select(m.PipelineRun).order_by(m.PipelineRun.started_at.desc()).limit(1)).scalar()
