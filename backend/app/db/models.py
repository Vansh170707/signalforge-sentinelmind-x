from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

JSONType = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(TypeDecorator):
    """Timezone-aware datetimes on every backend (SQLite drops tzinfo; values are stored as UTC)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is not None and value.tzinfo is not None:
            value = value.astimezone(UTC)
            if dialect.name == "sqlite":
                value = value.replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONType, list[Any]: JSONType}


class IngestBatch(Base):
    __tablename__ = "ingest_batches"
    batch_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_name: Mapped[str | None] = mapped_column(String(200))
    received: Mapped[int] = mapped_column(Integer, default=0)
    accepted: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    rejected_rows: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    duration_ms: Mapped[float] = mapped_column(Float, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    batch_id: Mapped[str | None] = mapped_column(ForeignKey("ingest_batches.batch_id", ondelete="SET NULL"))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    source: Mapped[str] = mapped_column(String(40))
    vendor: Mapped[str] = mapped_column(String(80))
    alert_type: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    severity_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    user: Mapped[str | None] = mapped_column(String(200), index=True)
    user_display: Mapped[str | None] = mapped_column(String(200))
    host: Mapped[str | None] = mapped_column(String(200), index=True)
    host_display: Mapped[str | None] = mapped_column(String(200))
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    src_ip_internal: Mapped[bool | None] = mapped_column(Boolean)
    dst_ip: Mapped[str | None] = mapped_column(String(64))
    dst_ip_internal: Mapped[bool | None] = mapped_column(Boolean)
    process: Mapped[str | None] = mapped_column(String(200))
    resource: Mapped[str | None] = mapped_column(String(200))
    asset_criticality: Mapped[int] = mapped_column(Integer)
    user_privilege: Mapped[int] = mapped_column(Integer)
    raw_event_ref: Mapped[str | None] = mapped_column(String(200))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    rule_anomaly_score: Mapped[float | None] = mapped_column(Float)
    incident_id: Mapped[str | None] = mapped_column(String(32), index=True)


class Entity(Base):
    __tablename__ = "entities"
    key: Mapped[str] = mapped_column(String(300), primary_key=True)
    type: Mapped[str] = mapped_column(String(40))
    value: Mapped[str] = mapped_column(String(260))
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    rarity: Mapped[float] = mapped_column(Float, default=0)
    first_seen: Mapped[str | None] = mapped_column(String(40))
    last_seen: Mapped[str | None] = mapped_column(String(40))
    context: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    __table_args__ = (Index("ix_entities_type_value", "type", "value"),)


class AlertEntity(Base):
    __tablename__ = "alert_entities"
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True)
    entity_key: Mapped[str] = mapped_column(String(300), primary_key=True)
    role: Mapped[str] = mapped_column(String(40), primary_key=True)


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"
    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    stage: Mapped[str] = mapped_column(String(40), default="queued")
    progress: Mapped[float] = mapped_column(Float, default=0)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    timings_ms: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    trace_id: Mapped[str | None] = mapped_column(String(64))


class Incident(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    rank: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20), default="new")
    severity: Mapped[str] = mapped_column(String(20))
    risk_score: Mapped[float] = mapped_column(Float)
    correlation_confidence: Mapped[float] = mapped_column(Float)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    alert_count: Mapped[int] = mapped_column(Integer)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    chain_strength: Mapped[float] = mapped_column(Float, default=0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0)
    anomaly_reasons: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    factors: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    risk: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    deterministic_risk: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    primary_entities: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    top_alert_types: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    mitre_ids: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    evidence_hash: Mapped[str] = mapped_column(String(64), index=True)
    template_summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    analyst_verdict: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (Index("ix_incidents_risk_status", "risk_score", "status"),)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"),
                                             primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True)
    edge_score: Mapped[float] = mapped_column(Float)
    linked_alert_id: Mapped[str | None] = mapped_column(String(64))
    reasons: Mapped[list[Any]] = mapped_column(JSONType, default=list)


class IncidentEntity(Base):
    __tablename__ = "incident_entities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    value: Mapped[str] = mapped_column(String(260))
    role: Mapped[str] = mapped_column(String(40))
    alert_count: Mapped[int] = mapped_column(Integer)
    rarity: Mapped[float] = mapped_column(Float)
    first_seen: Mapped[str | None] = mapped_column(String(40))
    last_seen: Mapped[str | None] = mapped_column(String(40))


class AttackStage(Base):
    __tablename__ = "attack_stages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(80))
    stage_order: Mapped[int] = mapped_column(Integer)
    position: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40))
    alert_ids: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    alert_types: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    confidence: Mapped[float] = mapped_column(Float)


class IncidentMitre(Base):
    __tablename__ = "incident_mitre"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(200))
    tactics: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    confidence: Mapped[float] = mapped_column(Float)
    evidence_alert_ids: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    mapping_reason: Mapped[str] = mapped_column(Text)
    attack_catalog_version: Mapped[str] = mapped_column(String(20))


class DecisionRun(Base):
    """Cached Jev (or other decision provider) judgment; keyed by evidence hash + model."""

    __tablename__ = "decision_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str | None] = mapped_column(String(32), index=True)
    evidence_hash: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    model: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20))
    decision: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    raw_response: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    __table_args__ = (UniqueConstraint("evidence_hash", "model", name="uq_decision_hash_model"),)


class LlmRun(Base):
    __tablename__ = "llm_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str | None] = mapped_column(String(32), index=True)
    evidence_hash: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    model: Mapped[str] = mapped_column(String(80))
    prompt_version: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    output: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    output_hash: Mapped[str | None] = mapped_column(String(64))
    validation: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    attempts: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    latency_ms: Mapped[float] = mapped_column(Float, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(40))
    corrected_severity: Mapped[str | None] = mapped_column(String(20))
    notes: Mapped[str | None] = mapped_column(Text)
    analyst: Mapped[str] = mapped_column(String(120), default="analyst")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    trace_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    runtime_ms: Mapped[float] = mapped_column(Float, default=0)


class TriageTrial(Base):
    """Measured triage-time experiment entries (raw alert list vs incident view)."""

    __tablename__ = "triage_trials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant: Mapped[str] = mapped_column(String(120))
    mode: Mapped[str] = mapped_column(String(20))  # baseline | assisted
    seconds: Mapped[float] = mapped_column(Float)
    correct: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
