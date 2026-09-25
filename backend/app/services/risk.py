"""Explainable risk & priority engine (blueprint sections 17 and 19A.3).

Two published formulas, both fully decomposed:
  v1-deterministic (no decision model available)
    0.20 severity + 0.18 asset + 0.14 privilege + 0.16 chain + 0.10 anomaly + 0.10 correlation
    + 0.07 blast_radius + 0.05 threat_mapping
  v2-jev (a cached Jev decision exists; Jev capped at 15%)
    0.20 severity + 0.17 asset + 0.12 privilege + 0.14 anomaly + 0.12 chain + 0.10 correlation
    + 0.15 effective_jev_signal
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from app.schemas.alerts import CanonicalAlert

WEIGHTS_V1 = {
    "base_severity": 0.20, "asset_criticality": 0.18, "identity_privilege": 0.14,
    "attack_chain_strength": 0.16, "anomaly_score": 0.10, "correlation_confidence": 0.10,
    "blast_radius": 0.07, "threat_mapping_confidence": 0.05,
}
WEIGHTS_V2 = {
    "base_severity": 0.20, "asset_criticality": 0.17, "identity_privilege": 0.12,
    "anomaly_score": 0.14, "attack_chain_strength": 0.12, "correlation_confidence": 0.10,
    "jev_signal": 0.15,
}
FACTOR_LABELS = {
    "base_severity": "Alert severity",
    "asset_criticality": "Asset criticality",
    "identity_privilege": "Identity privilege",
    "attack_chain_strength": "Attack-chain strength",
    "anomaly_score": "Behavioral anomaly",
    "correlation_confidence": "Correlation confidence",
    "blast_radius": "Blast radius",
    "threat_mapping_confidence": "ATT&CK mapping confidence",
    "jev_signal": "Jev decision signal",
}
JEV_CONFIDENCE_GATE = 0.55


@dataclass
class RiskResult:
    score: float
    severity: str
    formula: str
    factors: dict[str, float]
    weights: dict[str, float]
    contributions: dict[str, float]
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score, "severity": self.severity, "formula": self.formula,
            "factors": self.factors, "weights": self.weights, "contributions": self.contributions,
            "labels": {k: FACTOR_LABELS[k] for k in self.factors}, "notes": self.notes,
        }


def risk_label(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def base_factors(alerts: list[CanonicalAlert], chain_strength: float, anomaly: float, correlation_conf: float,
                 mapping_confidences: list[float]) -> dict[str, float]:
    sev = sorted((a.severity_score for a in alerts), reverse=True)
    top = sev[: min(10, len(sev))]
    base_severity = 0.5 * sev[0] / 100 + 0.5 * (sum(top) / len(top)) / 100
    asset = max(a.asset_criticality for a in alerts) / 5
    with_user = [a.user_privilege for a in alerts if a.user]
    privilege = max(with_user) / 5 if with_user else 0.2
    distinct = {("u", a.user) for a in alerts if a.user} | {("h", a.host) for a in alerts if a.host} \
        | {("r", a.resource) for a in alerts if a.resource} \
        | {("ip", a.src_ip) for a in alerts if a.src_ip and a.src_ip_private is False}
    blast = min(1.0, math.log2(1 + len(distinct)) / math.log2(1 + 20))
    top_maps = sorted(mapping_confidences, reverse=True)[:3]
    threat = (sum(top_maps) / 3) if top_maps else 0.0
    return {
        "base_severity": round(base_severity, 4),
        "asset_criticality": round(asset, 4),
        "identity_privilege": round(privilege, 4),
        "attack_chain_strength": round(chain_strength, 4),
        "anomaly_score": round(anomaly, 4),
        "correlation_confidence": round(correlation_conf, 4),
        "blast_radius": round(blast, 4),
        "threat_mapping_confidence": round(threat, 4),
    }


def jev_signal(decision: dict[str, Any]) -> tuple[float, list[str]]:
    """effective signal from a cached Jev decision (see 19A.3); low disposition confidence shrinks it."""
    notes: list[str] = []
    p_mal = float(decision.get("p_malicious", 0.0))
    sev = float(decision.get("severity_normalized", 0.0))
    esc = float(decision.get("p_escalate", 0.0))
    raw = 0.55 * p_mal + 0.30 * sev + 0.15 * esc
    conf = float(decision.get("disposition_confidence", 1.0))
    if conf < JEV_CONFIDENCE_GATE:
        shrink = conf / JEV_CONFIDENCE_GATE
        notes.append(f"Jev disposition confidence {conf:.2f} below gate; influence reduced, human review flagged")
        raw = 0.5 + (raw - 0.5) * shrink
    return round(max(0.0, min(1.0, raw)), 4), notes


def compute_risk(factors: dict[str, float], decision: dict[str, Any] | None = None) -> RiskResult:
    notes: list[str] = []
    if decision:
        signal, notes = jev_signal(decision)
        f = {k: factors[k] for k in WEIGHTS_V2 if k != "jev_signal"}
        f["jev_signal"] = signal
        weights = WEIGHTS_V2
        formula = "v2-jev"
    else:
        f = dict(factors)
        weights = WEIGHTS_V1
        formula = "v1-deterministic"
    contributions = {k: round(100 * weights[k] * f[k], 2) for k in weights}
    score = round(max(0.0, min(100.0, sum(contributions.values()))), 1)
    return RiskResult(score=score, severity=risk_label(score), formula=formula, factors=f, weights=weights,
                      contributions=contributions, notes=notes)
