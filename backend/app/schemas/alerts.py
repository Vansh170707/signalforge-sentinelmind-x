from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CanonicalAlert(BaseModel):
    """Validated, normalized security alert. Display values are preserved next to canonical keys."""

    alert_id: str
    timestamp: datetime
    source: str
    vendor: str = "unknown"
    alert_type: str
    title: str
    severity: str
    severity_score: float = Field(ge=0, le=100)
    confidence: float = Field(default=0.7, ge=0, le=1)
    user: str | None = None
    user_display: str | None = None
    host: str | None = None
    host_display: str | None = None
    src_ip: str | None = None
    src_ip_private: bool | None = None
    dst_ip: str | None = None
    dst_ip_private: bool | None = None
    process: str | None = None
    resource: str | None = None
    asset_criticality: int = Field(default=1, ge=1, le=5)
    user_privilege: int = Field(default=1, ge=1, le=5)
    raw_event_ref: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    content_hash: str
    duplicate_count: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}


class RejectedRow(BaseModel):
    row_index: int
    alert_id: str | None = None
    errors: list[str]


class BatchIn(BaseModel):
    alerts: list[dict[str, Any]]


class BatchResult(BaseModel):
    batch_id: str
    received: int
    accepted: int
    duplicates: int
    rejected: int
    rejected_rows: list[RejectedRow] = Field(default_factory=list)
    duration_ms: float = 0.0
