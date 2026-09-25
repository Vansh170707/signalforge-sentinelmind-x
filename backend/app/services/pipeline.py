"""Intelligence pipeline: entities -> correlation -> anomaly -> attack chain -> ATT&CK -> risk -> ranking.

Pure/in-memory so it is fast, testable and identical in API, scripts and tests. Persistence lives in
app.db.repository. Everything deterministic for a given input + config.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from app.schemas.alerts import CanonicalAlert
from app.services.anomaly import incident_anomaly, score_alerts
from app.services.attack_chain import build_chain
from app.services.context import ContextStore
from app.services.correlation import CorrelationConfig, correlate
from app.services.entities import alert_entities, compute_entity_stats, entity_key
from app.services.mitre import AttackCatalog, get_catalog, map_incident
from app.services.risk import base_factors, compute_risk

ProgressFn = Callable[[str, float], None]


@dataclass
class IncidentDraft:
    incident_id: str
    title: str
    severity: str
    risk_score: float
    correlation_confidence: float
    first_seen: str
    last_seen: str
    alert_ids: list[str]
    alert_count: int
    duplicate_count: int
    primary_entities: list[dict[str, Any]]
    entities: list[dict[str, Any]]
    attack_stages: list[dict[str, Any]]
    chain_strength: float
    mitre: list[dict[str, Any]]
    anomaly_score: float
    anomaly_reasons: list[str]
    factors: dict[str, float]
    risk: dict[str, Any]
    memberships: list[dict[str, Any]]
    top_alert_types: list[tuple[str, int]]
    evidence_hash: str
    rank: int = 0


@dataclass
class PipelineOutput:
    incidents: list[IncidentDraft]
    alert_anomaly: dict[str, float]
    alert_rule_anomaly: dict[str, float]
    entity_weights: dict[str, float]
    entity_stats: dict[str, dict[str, Any]]
    stats: dict[str, Any] = field(default_factory=dict)
    timings_ms: dict[str, float] = field(default_factory=dict)


def _incident_title(alerts: list[CanonicalAlert], stages: list[dict[str, Any]], mitre_ids: set[str],
                    primary: list[dict[str, Any]]) -> str:
    st = {s["stage"] for s in stages}
    users = Counter(a.user for a in alerts if a.user)
    hosts = Counter(a.host for a in alerts if a.host)
    user = users.most_common(1)[0][0] if users else None
    host = hosts.most_common(1)[0][0] if hosts else None
    priv = max((a.user_privilege for a in alerts if a.user == user), default=1)
    if "T1110.003" in mitre_ids:
        src = Counter(a.src_ip for a in alerts if a.alert_type == "failed_login").most_common(1)
        tail = " with successful sign-ins" if "valid_access" in st else ""
        return f"Password spray from {src[0][0] if src else 'external source'}{tail}"
    if "credential_theft" in st:
        extra = " and data exfiltration" if "exfiltration" in st else ""
        return f"Credential theft on {host}{extra}"
    if {"credential_attack", "valid_access"} <= st and st & {"execution", "privilege_persistence",
                                                             "resource_access"}:
        kind = "privileged account" if priv >= 4 else "account"
        return f"Possible {kind} compromise: {user}"
    if "T1078.004" in mitre_ids:
        return f"Impossible travel and suspicious mailbox access: {user}"
    if "initial_access" in st and "execution" in st:
        return f"Malicious document execution on {host}"
    if "exfiltration" in st:
        return f"Possible data exfiltration from {host}"
    top_type = Counter(a.title for a in alerts).most_common(1)[0][0]
    subject = user or host or (primary[0]["value"] if primary else "unknown")
    if len(alerts) == 1:
        return f"{top_type}: {subject}"
    return f"{top_type} ({len(alerts)} alerts): {subject}"


def evidence_hash(alert_ids: list[str], config: dict[str, Any]) -> str:
    payload = json.dumps({"alerts": sorted(alert_ids), "config": config}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:20]


def run_pipeline(alerts: list[CanonicalAlert], ctx: ContextStore, cfg: CorrelationConfig | None = None,
                 catalog: AttackCatalog | None = None, decisions: dict[str, dict[str, Any]] | None = None,
                 progress: ProgressFn | None = None) -> PipelineOutput:
    cfg = cfg or CorrelationConfig()
    cat = catalog or get_catalog()
    decisions = decisions or {}
    timings: dict[str, float] = {}

    def step(name: str, frac: float) -> float:
        if progress:
            progress(name, frac)
        return time.perf_counter()

    t = step("entities", 0.05)
    stats = compute_entity_stats(alerts)
    timings["entities"] = (time.perf_counter() - t) * 1000

    t = step("correlation", 0.15)
    corr = correlate(alerts, stats, cfg, ctx.ip_to_host)
    timings["correlation"] = (time.perf_counter() - t) * 1000

    t = step("anomaly", 0.55)
    anomaly = score_alerts(alerts, ctx)
    timings["anomaly"] = (time.perf_counter() - t) * 1000

    t = step("chain_mitre_risk", 0.75)
    config_fingerprint = {"correlation": cfg.version, "threshold": cfg.threshold, "window": cfg.window_minutes}
    drafts: list[IncidentDraft] = []
    for cluster in corr.clusters:
        members = [alerts[i] for i in cluster.members]
        stages_objs, strength = build_chain(members)
        stages = [asdict(s) for s in stages_objs]
        mappings = map_incident(members, cat)
        mitre = [asdict(m) for m in mappings]
        anom, anom_reasons = incident_anomaly(cluster.members, anomaly, alerts)
        factors = base_factors(members, strength, anom, cluster.confidence, [m.confidence for m in mappings])

        ent_counter: Counter[tuple[str, str, str]] = Counter()
        for a in members:
            for etype, value, role in alert_entities(a):
                ent_counter[(etype, value, role)] += 1
        entities = []
        for (etype, value, role), count in ent_counter.items():
            w = stats.weight(entity_key(etype, value))
            entities.append({"type": etype, "value": value, "role": role, "alert_count": count,
                             "rarity": round(w, 3), "score": round(w * count, 3)})
        entities.sort(key=lambda e: -e["score"])
        primary = [e for e in entities if e["rarity"] >= 0.2][:5] or entities[:3]

        memberships = []
        for i in cluster.members:
            m = cluster.memberships[i]
            memberships.append({
                "alert_id": alerts[i].alert_id,
                "edge_score": round(m.score, 4),
                "linked_alert_id": alerts[m.linked_index].alert_id if m.linked_index is not None else None,
                "reasons": m.reasons,
            })
        alert_ids = [a.alert_id for a in members]
        ehash = evidence_hash(alert_ids, config_fingerprint)
        risk = compute_risk(factors, decisions.get(ehash))
        drafts.append(IncidentDraft(
            incident_id="",
            title=_incident_title(members, stages, {m.technique_id for m in mappings}, primary),
            severity=risk.severity,
            risk_score=risk.score,
            correlation_confidence=cluster.confidence,
            first_seen=members[0].timestamp.isoformat(),
            last_seen=members[-1].timestamp.isoformat(),
            alert_ids=alert_ids,
            alert_count=len(members),
            duplicate_count=sum(a.duplicate_count for a in members),
            primary_entities=primary,
            entities=entities,
            attack_stages=stages,
            chain_strength=strength,
            mitre=mitre,
            anomaly_score=anom,
            anomaly_reasons=anom_reasons,
            factors=factors,
            risk=risk.as_dict(),
            memberships=memberships,
            top_alert_types=Counter(a.alert_type for a in members).most_common(5),
            evidence_hash=ehash,
        ))
    timings["chain_mitre_risk"] = (time.perf_counter() - t) * 1000

    # Rank: risk desc, then earlier first_seen; IDs follow rank so INC-0001 is the top of the queue.
    drafts.sort(key=lambda d: (-d.risk_score, d.first_seen))
    for rank, d in enumerate(drafts, start=1):
        d.rank = rank
        d.incident_id = f"INC-{rank:04d}"
    step("done", 1.0)

    sev_counts = Counter(d.severity for d in drafts)
    return PipelineOutput(
        incidents=drafts,
        alert_anomaly={a.alert_id: round(float(anomaly.score[i]), 4) for i, a in enumerate(alerts)},
        alert_rule_anomaly={a.alert_id: round(float(anomaly.rule_score[i]), 4) for i, a in enumerate(alerts)},
        entity_weights={k: round(stats.weight(k), 4) for k in stats.alert_counts},
        entity_stats={k: {"alert_count": stats.alert_counts[k], "first_seen": stats.first_seen.get(k),
                          "last_seen": stats.last_seen.get(k)} for k in stats.alert_counts},
        stats={**corr.stats, "incidents": len(drafts), "severity_counts": dict(sev_counts),
               "compression_ratio": round(len(alerts) / max(1, len(drafts)), 2)},
        timings_ms={k: round(v, 1) for k, v in timings.items()},
    )
