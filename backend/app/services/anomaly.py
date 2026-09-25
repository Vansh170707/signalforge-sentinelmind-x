"""Behavioral anomaly scoring (blueprint section 15).

Interpretable per-alert features -> two scorers:
  * rules:  robust z-scores (median absolute deviation) on burst/breadth counts + novelty/time flags
  * model:  Isolation Forest over the same feature matrix (fixed seed)
alert_anomaly = 0.5 * rules + 0.5 * isolation_forest. Incident anomaly aggregates its alerts and keeps
the human-readable feature explanations that drove it.
"""

from __future__ import annotations

import bisect
import math
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest

from app.schemas.alerts import CanonicalAlert
from app.services.context import ContextStore

AUTH_FAIL_TYPES = {"failed_login", "account_lockout", "mfa_fatigue", "password_spray_detected"}
AUTH_SUCCESS_TYPES = {"login_success", "login_success_after_failures", "login_new_source", "new_device_login",
                      "impossible_travel"}
FEATURES = [
    "auth_fail_user_10m", "auth_fail_ip_10m", "distinct_users_ip_60m", "distinct_hosts_user_60m",
    "novel_src_ip", "off_hours", "process_rarity", "privileged", "asset_critical", "success_after_failures",
    "severity", "novel_process",
]
COUNT_FEATURES = FEATURES[:4]


@dataclass
class AnomalyResult:
    features: np.ndarray                     # (n, len(FEATURES))
    rule_score: np.ndarray                   # (n,) 0..1
    model_score: np.ndarray                  # (n,) 0..1
    score: np.ndarray                        # (n,) 0..1 combined
    explanations: list[list[str]] = field(default_factory=list)
    model: str = "isolation_forest"


def _trailing_count(times: list[float], t: float, window: float) -> int:
    lo = bisect.bisect_left(times, t - window)
    hi = bisect.bisect_right(times, t)
    return hi - lo


def compute_features(alerts: list[CanonicalAlert], ctx: ContextStore) -> tuple[np.ndarray, list[list[str]]]:
    n = len(alerts)
    t = [a.timestamp.timestamp() / 60.0 for a in alerts]
    order = sorted(range(n), key=lambda i: t[i])

    fail_user: dict[str, list[float]] = defaultdict(list)
    fail_ip: dict[str, list[float]] = defaultdict(list)
    ip_users: dict[str, list[tuple[float, str]]] = defaultdict(list)
    user_hosts: dict[str, list[tuple[float, str]]] = defaultdict(list)
    proc_count: dict[str, int] = defaultdict(int)
    for i in order:
        a = alerts[i]
        if a.alert_type in AUTH_FAIL_TYPES:
            if a.user:
                fail_user[a.user].append(t[i])
            if a.src_ip:
                fail_ip[a.src_ip].append(t[i])
        if a.src_ip and a.user:
            ip_users[a.src_ip].append((t[i], a.user))
        if a.user and a.host:
            user_hosts[a.user].append((t[i], a.host))
        if a.process:
            proc_count[a.process] += 1

    def distinct_trailing(seq: list[tuple[float, str]], now: float, window: float) -> int:
        times = [x[0] for x in seq]
        lo = bisect.bisect_left(times, now - window)
        hi = bisect.bisect_right(times, now)
        return len({x[1] for x in seq[lo:hi]})

    # Cache per-key time arrays for distinct lookups.
    X = np.zeros((n, len(FEATURES)))
    notes: list[list[str]] = [[] for _ in range(n)]
    for i in range(n):
        a = alerts[i]
        prof = ctx.user(a.user) or {}
        f_user = _trailing_count(fail_user[a.user], t[i], 10) if a.user in fail_user else 0
        f_ip = _trailing_count(fail_ip[a.src_ip], t[i], 10) if a.src_ip in fail_ip else 0
        d_users = distinct_trailing(ip_users[a.src_ip], t[i], 60) if a.src_ip in ip_users else 0
        d_hosts = distinct_trailing(user_hosts[a.user], t[i], 60) if a.user in user_hosts else 0
        novel = 0.0
        if a.src_ip and prof and a.alert_type in AUTH_SUCCESS_TYPES | AUTH_FAIL_TYPES:
            if a.src_ip not in prof.get("known_src_ips", []):
                novel = 0.5 if a.src_ip_private else 1.0
                if novel == 1.0:
                    notes[i].append(f"source {a.src_ip} never seen for {a.user}")
        off = 0.0
        hours = prof.get("baseline_hours")
        if hours and not (hours[0] == 0 and hours[1] >= 24):
            hr = a.timestamp.hour + a.timestamp.minute / 60
            if not hours[0] <= hr < hours[1]:
                off = 1.0
                notes[i].append(f"activity outside baseline hours for {a.user} "
                                f"({hours[0]:02d}:00-{hours[1]:02d}:00 UTC)")
        rarity = 0.0
        if a.process:
            rarity = math.log((n + 1) / (proc_count[a.process] + 1)) / math.log(n + 1)
            if rarity > 0.6:
                notes[i].append(f"rare process {a.process}")
        novel_proc = 0.0
        if a.process and prof.get("known_processes") is not None and a.process not in prof["known_processes"]:
            novel_proc = 1.0
            notes[i].append(f"{a.process} not in {a.user}'s known software baseline")
        success_after = 0.0
        if a.alert_type in AUTH_SUCCESS_TYPES and a.user in fail_user:
            if _trailing_count(fail_user[a.user], t[i], 30) >= 5:
                success_after = 1.0
                notes[i].append(f"successful sign-in after repeated failures for {a.user}")
        X[i] = [f_user, f_ip, d_users, d_hosts, novel, off, rarity, a.user_privilege / 5,
                a.asset_criticality / 5, success_after, a.severity_score / 100, novel_proc]
    return X, notes


def _robust_z(col: np.ndarray) -> np.ndarray:
    med = np.median(col)
    mad = np.median(np.abs(col - med))
    scale = 1.4826 * mad if mad > 0 else max(1.0, np.std(col))
    return (col - med) / scale


def score_alerts(alerts: list[CanonicalAlert], ctx: ContextStore, seed: int = 7) -> AnomalyResult:
    n = len(alerts)
    if n == 0:
        z = np.zeros(0)
        return AnomalyResult(np.zeros((0, len(FEATURES))), z, z, z)
    X, notes = compute_features(alerts, ctx)

    # Rules: robust z on count features, plus novelty / off-hours / sequence flags.
    zs = np.column_stack([_robust_z(np.log1p(X[:, k])) for k in range(len(COUNT_FEATURES))])
    burst = np.clip(zs.max(axis=1) / 6.0, 0, 1)
    rule = np.clip(0.40 * burst + 0.20 * X[:, 4] + 0.15 * X[:, 5] + 0.15 * X[:, 9] + 0.15 * X[:, 11]
                   + 0.10 * (X[:, 6] > 0.6), 0, 1)

    # Isolation Forest over behavioral features only (log-scaled counts + novelty/time/sequence flags).
    # Static business context (privilege, asset criticality, severity) is excluded on purpose: it
    # enters the risk score as separate factors and must not be double counted as "anomaly".
    behavioral = [k for k, name in enumerate(FEATURES) if name not in ("privileged", "asset_critical", "severity")]
    Xm = X[:, behavioral].copy()
    Xm[:, :4] = np.log1p(Xm[:, :4])
    if n >= 20:
        forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed)
        forest.fit(Xm)
        raw = -forest.score_samples(Xm)
        med = np.median(raw)
        top = np.percentile(raw, 99.5)
        model = np.clip((raw - med) / (top - med + 1e-9), 0, 1)
    else:
        model = rule.copy()
    score = np.clip(0.5 * rule + 0.5 * model, 0, 1)
    return AnomalyResult(features=X, rule_score=rule, model_score=model, score=score, explanations=notes)


def incident_anomaly(indices: list[int], res: AnomalyResult, alerts: list[CanonicalAlert]
                     ) -> tuple[float, list[str]]:
    if not indices:
        return 0.0, []
    s = np.sort(res.score[indices])[::-1]
    value = float(0.6 * s[0] + 0.4 * s[: min(5, len(s))].mean())
    notes: list[str] = []
    # Burst/breadth peaks, reported once at their maximum.
    for k, template, fld in (
        (0, "{v} failed logins for {e} within 10 min", "user"),
        (1, "{v} failed logins from {e} within 10 min", "src_ip"),
        (2, "{v} distinct users signing in from {e} within 60 min", "src_ip"),
    ):
        col = res.features[indices, k]
        j = int(np.argmax(col))
        if col[j] >= 10:
            notes.append(template.format(v=int(col[j]), e=getattr(alerts[indices[j]], fld)))
    counts: dict[str, int] = defaultdict(int)
    for i in indices:
        for note in res.explanations[i]:
            counts[note] += 1
    for note, _ in sorted(counts.items(), key=lambda kv: -kv[1]):
        if len(notes) >= 6:
            break
        notes.append(note)
    return round(value, 4), notes
