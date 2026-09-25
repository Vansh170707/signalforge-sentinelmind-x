"""Entity intelligence: extraction + inverse-frequency weighting.

A shared entity is strong correlation evidence only if it is rare. Weight combines:
  * alert frequency  : log((N+1)/(n_e+1)) / log(N+1)          (blueprint 13.1)
  * temporal spread  : log((B+1)/(b_e+1)) / log(B+1)          B = 30-min buckets in the corpus
An always-on DNS resolver or jump host gets ~0; an attacker IP active for 40 minutes stays meaningful
even when it produced hundreds of alerts.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from app.schemas.alerts import CanonicalAlert

ENTITY_FIELDS: list[tuple[str, str, str]] = [
    # (alert field, entity type, role)
    ("user", "user", "actor"),
    ("host", "host", "device"),
    ("src_ip", "ip", "source"),
    ("dst_ip", "ip", "destination"),
    ("process", "process", "process"),
    ("resource", "resource", "target"),
]
BUCKET_MINUTES = 30


def entity_key(etype: str, value: str) -> str:
    return f"{etype}:{value}"


def alert_entities(alert: CanonicalAlert) -> list[tuple[str, str, str]]:
    """Return (entity_type, value, role) tuples for an alert."""
    out = []
    for fld, etype, role in ENTITY_FIELDS:
        v = getattr(alert, fld)
        if v:
            out.append((etype, v, role))
    return out


@dataclass
class EntityStats:
    n_alerts: int
    n_buckets: int
    alert_counts: dict[str, int] = field(default_factory=dict)
    bucket_counts: dict[str, int] = field(default_factory=dict)
    first_seen: dict[str, str] = field(default_factory=dict)
    last_seen: dict[str, str] = field(default_factory=dict)
    _cache: dict[str, float] = field(default_factory=dict)

    def weight(self, key: str) -> float:
        w = self._cache.get(key)
        if w is None:
            n = self.alert_counts.get(key, 0)
            b = self.bucket_counts.get(key, 0)
            a_idf = math.log((self.n_alerts + 1) / (n + 1)) / math.log(self.n_alerts + 1)
            t_idf = math.log((self.n_buckets + 1) / (b + 1)) / math.log(self.n_buckets + 1)
            w = max(0.0, min(1.0, 0.5 * a_idf + 0.5 * t_idf))
            self._cache[key] = w
        return w


def compute_entity_stats(alerts: list[CanonicalAlert]) -> EntityStats:
    if not alerts:
        return EntityStats(0, 1)
    t_min = min(a.timestamp for a in alerts)
    t_max = max(a.timestamp for a in alerts)
    n_buckets = max(1, int((t_max - t_min).total_seconds() // (BUCKET_MINUTES * 60)) + 1)
    counts: dict[str, int] = defaultdict(int)
    buckets: dict[str, set[int]] = defaultdict(set)
    first: dict[str, str] = {}
    last: dict[str, str] = {}
    for a in alerts:
        b = int((a.timestamp - t_min).total_seconds() // (BUCKET_MINUTES * 60))
        seen_here: set[str] = set()
        for etype, value, _ in alert_entities(a):
            k = entity_key(etype, value)
            if k in seen_here:
                continue
            seen_here.add(k)
            counts[k] += 1
            buckets[k].add(b)
            ts = a.timestamp.isoformat()
            if k not in first or ts < first[k]:
                first[k] = ts
            if k not in last or ts > last[k]:
                last[k] = ts
    return EntityStats(
        n_alerts=len(alerts), n_buckets=n_buckets, alert_counts=dict(counts),
        bucket_counts={k: len(v) for k, v in buckets.items()}, first_seen=first, last_seen=last,
    )
