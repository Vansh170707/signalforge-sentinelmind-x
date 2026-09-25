"""Alert normalization: UTC timestamps, severity label+score, canonical identities, validated IPs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

from app.schemas.alerts import CanonicalAlert
from app.services.catalog import ALERT_TYPES, SEVERITY_SCORES, severity_label
from app.services.context import ContextStore

SEVERITY_ALIASES = {
    "info": "informational", "informational": "informational", "low": "low", "medium": "medium",
    "moderate": "medium", "high": "high", "critical": "critical", "crit": "critical", "severe": "critical",
}
HOST_SUFFIXES = (".corp.local", ".corp.example", ".local")
HASH_FIELDS = ("timestamp", "source", "vendor", "alert_type", "title", "user", "host", "src_ip", "dst_ip",
               "process", "resource", "attributes")


class NormalizationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, int | float):
        # Epoch seconds or milliseconds.
        dt = datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=UTC)
    elif isinstance(value, str):
        v = value.strip()
        if v.isdigit():
            return parse_timestamp(int(v))
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    else:
        raise ValueError(f"unsupported timestamp type {type(value).__name__}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def canonical_user(value: str | None) -> str | None:
    if not value:
        return None
    v = str(value).strip()
    if "\\" in v:
        v = v.split("\\", 1)[1]
    if "@" in v:
        v = v.split("@", 1)[0]
    return v.lower() or None


def canonical_host(value: str | None) -> str | None:
    if not value:
        return None
    v = str(value).strip().lower()
    for suffix in HOST_SUFFIXES:
        if v.endswith(suffix):
            v = v[: -len(suffix)]
    return v.upper() or None


INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128")]


def parse_ip(value: Any) -> tuple[str | None, bool | None]:
    """Return (canonical ip, is_internal). Only RFC1918/loopback/link-local count as internal; the
    synthetic corpus uses documentation ranges (TEST-NET) to represent the public internet."""
    if value in (None, ""):
        return None, None
    ip = ipaddress.ip_address(str(value).strip())
    return str(ip), any(ip in net for net in INTERNAL_NETS if net.version == ip.version)


def normalize_severity(label: Any, score: Any) -> tuple[str, float]:
    if score is not None:
        s = float(score)
        if not 0 <= s <= 100:
            raise ValueError(f"severity_score {s} outside 0-100")
    else:
        s = None
    lab = SEVERITY_ALIASES.get(str(label).strip().lower()) if label is not None else None
    if label is not None and lab is None:
        raise ValueError(f"unknown severity label {label!r}")
    if s is None and lab is None:
        raise ValueError("missing severity and severity_score")
    if s is None:
        s = float(SEVERITY_SCORES[lab])  # type: ignore[index]
    if lab is None:
        lab = severity_label(s)
    return lab, s


def content_hash(fields: dict[str, Any]) -> str:
    payload = json.dumps({k: fields.get(k) for k in HASH_FIELDS}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def normalize_alert(raw: dict[str, Any], context: ContextStore | None = None) -> CanonicalAlert:
    errors: list[str] = []
    ctx = context or ContextStore()

    alert_id = raw.get("alert_id")
    if not alert_id:
        errors.append("missing alert_id")
    alert_type = (raw.get("alert_type") or "").strip()
    if not alert_type:
        errors.append("missing alert_type")
    try:
        ts = parse_timestamp(raw.get("timestamp"))
    except (ValueError, TypeError, OverflowError) as exc:
        errors.append(f"invalid timestamp: {exc}")
        ts = None
    try:
        sev_label, sev_score = normalize_severity(raw.get("severity"), raw.get("severity_score"))
    except (ValueError, TypeError) as exc:
        errors.append(str(exc))
        sev_label, sev_score = "low", 30.0
    try:
        src_ip, src_private = parse_ip(raw.get("src_ip"))
    except ValueError:
        errors.append(f"invalid src_ip {raw.get('src_ip')!r}")
        src_ip, src_private = None, None
    try:
        dst_ip, dst_private = parse_ip(raw.get("dst_ip"))
    except ValueError:
        errors.append(f"invalid dst_ip {raw.get('dst_ip')!r}")
        dst_ip, dst_private = None, None
    attributes = raw.get("attributes") or {}
    if not isinstance(attributes, dict):
        errors.append("attributes must be an object")
        attributes = {}
    if errors:
        raise NormalizationError(errors)

    spec = ALERT_TYPES.get(alert_type)
    user = canonical_user(raw.get("user"))
    host = canonical_host(raw.get("host"))
    resource = (str(raw["resource"]).strip().lower() or None) if raw.get("resource") else None
    process = (str(raw["process"]).strip().lower() or None) if raw.get("process") else None

    # Enrichment from the context store when the vendor omitted business context.
    crit = raw.get("asset_criticality")
    if crit is None:
        hc = ctx.host(host) or {}
        rc = ctx.resource(resource) or {}
        crit = max(hc.get("criticality", 1), rc.get("criticality", 1))
    priv = raw.get("user_privilege")
    if priv is None:
        priv = (ctx.user(user) or {}).get("privilege", 1)

    canon = {
        "timestamp": ts.isoformat() if ts else None, "source": raw.get("source"), "vendor": raw.get("vendor"),
        "alert_type": alert_type, "title": raw.get("title"), "user": user, "host": host, "src_ip": src_ip,
        "dst_ip": dst_ip, "process": process, "resource": resource, "attributes": attributes,
    }
    try:
        return CanonicalAlert(
            alert_id=str(alert_id),
            timestamp=ts,
            source=str(raw.get("source") or (spec.source if spec else "unknown")),
            vendor=str(raw.get("vendor") or "unknown"),
            alert_type=alert_type,
            title=str(raw.get("title") or (spec.title if spec else alert_type)),
            severity=sev_label,
            severity_score=sev_score,
            confidence=float(raw.get("confidence", 0.7)),
            user=user,
            user_display=raw.get("user"),
            host=host,
            host_display=raw.get("host"),
            src_ip=src_ip,
            src_ip_private=src_private,
            dst_ip=dst_ip,
            dst_ip_private=dst_private,
            process=process,
            resource=resource,
            asset_criticality=int(min(5, max(1, int(crit)))),
            user_privilege=int(min(5, max(1, int(priv)))),
            raw_event_ref=raw.get("raw_event_ref"),
            attributes=attributes,
            content_hash=content_hash(canon),
            raw=raw,
        )
    except (ValueError, TypeError) as exc:  # pydantic ValidationError subclasses ValueError
        raise NormalizationError([str(exc)]) from exc
