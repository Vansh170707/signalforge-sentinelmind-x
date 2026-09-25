from datetime import UTC, datetime, timedelta

from app.services.correlation import CorrelationConfig, correlate, edge_score
from app.services.embeddings import TitleSimilarity
from app.services.entities import compute_entity_stats
from app.services.normalization import normalize_alert

T0 = datetime(2026, 9, 14, 2, 0, tzinfo=UTC)


def mk(aid, minutes, **kw):
    base = {"alert_id": aid, "timestamp": (T0 + timedelta(minutes=minutes)).isoformat(), "source": "identity",
            "alert_type": "failed_login", "title": "Failed authentication", "severity": "medium"}
    return normalize_alert(base | kw)


def background(n=300):
    # Plenty of unrelated alerts so entity rarity is meaningful; a shared DNS server appears everywhere.
    return [mk(f"N{i}", i * 4, user=f"user{i}", host=f"WS-{i}", dst_ip="10.0.0.53",
               alert_type="file_share_access", title="File share accessed", severity="informational")
            for i in range(n)]


def test_rare_user_close_in_time_scores_higher_than_hours_apart():
    alerts = background() + [mk("P1", 0, user="finance-admin"), mk("P2", 2, user="finance-admin"),
                             mk("P3", 120, user="finance-admin")]
    stats = compute_entity_stats(alerts)
    sim = TitleSimilarity([a.title for a in alerts])
    near, _, _ = edge_score(alerts[-3], alerts[-2], stats, sim)
    far, _, _ = edge_score(alerts[-3], alerts[-1], stats, sim)
    assert near > far


def test_attack_chain_grouped_and_unrelated_kept_apart():
    chain = [mk(f"G{i}", i * 0.5, user="finance-admin", host="FINANCE-SRV-03", src_ip="203.0.113.27")
             for i in range(20)]
    chain.append(mk("G-S", 11, user="finance-admin", host="FINANCE-SRV-03", src_ip="203.0.113.27",
                    alert_type="login_success_after_failures", title="Successful login after repeated failures",
                    severity="high"))
    chain.append(mk("G-X", 14, user="finance-admin", host="FINANCE-SRV-03", source="endpoint",
                    alert_type="powershell_execution", title="PowerShell execution", process="powershell.exe"))
    alerts = background() + chain
    res = correlate(alerts, compute_entity_stats(alerts), CorrelationConfig())
    groups = [{alerts[i].alert_id for i in c.members} for c in res.clusters]
    golden = next(g for g in groups if "G0" in g)
    assert {a.alert_id for a in chain} <= golden
    assert not any(x.startswith("N") for x in golden)


def test_common_entity_does_not_megacluster():
    alerts = background(400)
    res = correlate(alerts, compute_entity_stats(alerts), CorrelationConfig())
    assert max(len(c.members) for c in res.clusters) <= 2  # the shared DNS server alone never groups alerts


def test_every_membership_has_reason():
    chain = [mk(f"G{i}", i, user="finance-admin", host="FINANCE-SRV-03") for i in range(5)]
    alerts = background(50) + chain
    res = correlate(alerts, compute_entity_stats(alerts), CorrelationConfig())
    for c in res.clusters:
        for mem in c.memberships.values():
            assert mem.reasons
