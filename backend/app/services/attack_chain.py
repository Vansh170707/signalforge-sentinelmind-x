"""Deterministic attack-chain construction (blueprint section 16).

Stages come from alert types (catalog), with context rules:
  * failed logins / lockouts only count as a credential attack when there are >= 5 inside the incident
  * an ordinary successful sign-in counts as valid access only when it follows a credential attack
Strength rewards stage coverage, canonical ordering, and an entry stage followed by post-compromise activity.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.alerts import CanonicalAlert
from app.services.catalog import ALERT_TYPES, STAGE_LABEL, STAGE_ORDER

ENTRY_STAGES = {"initial_access", "credential_attack", "valid_access"}
MIN_AUTH_FAILURES = 5


@dataclass
class Stage:
    stage: str
    label: str
    order: int
    first_seen: str
    last_seen: str
    alert_ids: list[str]
    alert_types: list[str]
    confidence: float


def build_chain(alerts: list[CanonicalAlert]) -> tuple[list[Stage], float]:
    ordered = sorted(alerts, key=lambda a: a.timestamp)
    fail_count = sum(1 for a in ordered if a.alert_type in ("failed_login", "account_lockout"))
    buckets: dict[str, list[CanonicalAlert]] = {}
    cred_seen = False
    for a in ordered:
        spec = ALERT_TYPES.get(a.alert_type)
        st = spec.stage if spec else None
        if a.alert_type in ("failed_login", "account_lockout") and fail_count < MIN_AUTH_FAILURES:
            st = None
        if a.alert_type == "login_success" and cred_seen:
            st = "valid_access"
        if st == "credential_attack":
            cred_seen = True
        if st:
            buckets.setdefault(st, []).append(a)

    stages: list[Stage] = []
    for st, items in buckets.items():
        conf = sum(x.confidence for x in items) / len(items)
        conf = min(0.99, conf * (0.85 + 0.15 * min(1.0, len(items) / 5)))
        stages.append(Stage(
            stage=st, label=STAGE_LABEL[st], order=STAGE_ORDER[st],
            first_seen=items[0].timestamp.isoformat(), last_seen=items[-1].timestamp.isoformat(),
            alert_ids=[x.alert_id for x in items], alert_types=sorted({x.alert_type for x in items}),
            confidence=round(conf, 3),
        ))
    stages.sort(key=lambda s: s.first_seen)
    return stages, chain_strength(stages)


def chain_strength(stages: list[Stage]) -> float:
    n = len(stages)
    if n == 0:
        return 0.0
    coverage = min(1.0, (n - 1) / 4)
    if n > 1:
        pairs = list(zip(stages, stages[1:], strict=False))
        coherence = sum(1 for x, y in pairs if y.order >= x.order) / len(pairs)
    else:
        coherence = 1.0
    entry_bonus = 0.0
    first_entry = min((s.first_seen for s in stages if s.stage in ENTRY_STAGES), default=None)
    if first_entry and any(s.stage not in ENTRY_STAGES and s.first_seen >= first_entry for s in stages):
        entry_bonus = 0.15
    return round(min(1.0, coverage * (0.7 + 0.3 * coherence) + entry_bonus), 4)
