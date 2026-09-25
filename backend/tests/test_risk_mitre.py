from datetime import UTC, datetime, timedelta

from app.services.attack_chain import build_chain
from app.services.mitre import get_catalog, map_incident
from app.services.normalization import normalize_alert
from app.services.risk import base_factors, compute_risk, risk_label

T0 = datetime(2026, 9, 14, 2, 41, tzinfo=UTC)
STORY = [("failed_login", 12), ("login_success_after_failures", 1), ("powershell_execution", 4),
         ("privilege_group_change", 2), ("sensitive_resource_access", 5)]


def attack(host: str, crit: int, priv: int, prefix: str):
    out, n = [], 0
    for atype, count in STORY:
        for _ in range(count):
            n += 1
            out.append(normalize_alert({
                "alert_id": f"{prefix}{n}", "timestamp": (T0 + timedelta(seconds=30 * n)).isoformat(),
                "source": "identity", "alert_type": atype, "title": atype, "severity": "medium",
                "user": "finance-admin", "host": host, "src_ip": "203.0.113.27", "asset_criticality": crit,
                "user_privilege": priv, "process": "powershell.exe" if "powershell" in atype else None}))
    return out


def score(alerts):
    stages, strength = build_chain(alerts)
    maps = map_incident(alerts)
    return compute_risk(base_factors(alerts, strength, 0.7, 0.8, [m.confidence for m in maps]))


def test_same_attack_on_critical_asset_outranks_low_value_test_host():
    critical = score(attack("FINANCE-SRV-03", 5, 5, "C"))
    lab = score(attack("LAB-TEST-07", 1, 5, "L"))
    assert critical.score > lab.score
    assert critical.contributions["asset_criticality"] > lab.contributions["asset_criticality"]


def test_risk_exposes_every_factor_and_sums():
    r = score(attack("FINANCE-SRV-03", 5, 5, "C"))
    assert set(r.factors) == set(r.weights) == set(r.contributions)
    assert abs(sum(r.contributions.values()) - r.score) < 0.2
    assert r.formula == "v1-deterministic"


def test_jev_capped_at_15_percent_and_confidence_gated():
    factors = {"base_severity": 0.5, "asset_criticality": 0.5, "identity_privilege": 0.5,
               "attack_chain_strength": 0.5, "anomaly_score": 0.5, "correlation_confidence": 0.5,
               "blast_radius": 0.5, "threat_mapping_confidence": 0.5}
    hi = compute_risk(factors, {"p_malicious": 1, "severity_normalized": 1, "p_escalate": 1,
                                "disposition_confidence": 0.95})
    lo = compute_risk(factors, {"p_malicious": 0, "severity_normalized": 0, "p_escalate": 0,
                                "disposition_confidence": 0.95})
    assert hi.formula == "v2-jev" and hi.score - lo.score <= 15.0 + 1e-6
    gated = compute_risk(factors, {"p_malicious": 1, "severity_normalized": 1, "p_escalate": 1,
                                   "disposition_confidence": 0.2})
    assert gated.score < hi.score and gated.notes


def test_attack_chain_order_and_strength():
    stages, strength = build_chain(attack("FINANCE-SRV-03", 5, 5, "C"))
    assert [s.stage for s in stages] == ["credential_attack", "valid_access", "execution",
                                         "privilege_persistence", "resource_access"]
    assert strength >= 0.9
    assert all(s.alert_ids for s in stages)


def test_attack_ids_and_names_come_from_catalog():
    cat = get_catalog()
    maps = map_incident(attack("FINANCE-SRV-03", 5, 5, "C"))
    ids = {m.technique_id for m in maps}
    assert {"T1110", "T1078", "T1059.001", "T1098.007", "T1213"} <= ids
    for m in maps:
        assert cat.get(m.technique_id)["name"] == m.name
        assert m.evidence_alert_ids and m.attack_catalog_version == cat.version


def test_single_failed_login_is_not_brute_force():
    one = attack("WS-1", 1, 1, "S")[:1]
    assert "T1110" not in {m.technique_id for m in map_incident(one)}


def test_labels():
    assert [risk_label(x) for x in (10, 45, 70, 90)] == ["low", "medium", "high", "critical"]
