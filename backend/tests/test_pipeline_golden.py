"""Golden demo acceptance (blueprint 33.1) on the full seeded 10k corpus."""

from app.api.graph import build_graph
from app.services.evaluation import correlation_metrics, priority_metrics
from tests.conftest import incident_for_gt


def test_dataset_shape(demo):
    r = demo["outcome"].result
    assert r.received >= 10_000 and r.rejected == 4 and r.duplicates > 0


def test_golden_incident_grouped_with_high_purity_and_top3(demo):
    inc = incident_for_gt(demo, "GT-ATK-GOLDEN")
    truth = demo["gt"]["alerts"]
    golden_ids = {a for a, t in truth.items() if t == "GT-ATK-GOLDEN"}
    got = set(inc.alert_ids)
    assert len(got & golden_ids) / len(golden_ids) >= 0.95
    assert len(got & golden_ids) / len(got) >= 0.95
    assert inc.rank <= 3 and inc.severity == "critical"


def test_golden_timeline_order_and_attack_tags(demo):
    inc = incident_for_gt(demo, "GT-ATK-GOLDEN")
    order = [s["stage"] for s in inc.attack_stages]
    expected = demo["gt"]["incidents"]["GT-ATK-GOLDEN"]["stage_order"]
    assert [s for s in order if s in expected] == expected
    ids = {m["technique_id"] for m in inc.mitre}
    assert {"T1110", "T1078", "T1059.001", "T1213"} <= ids


def test_risk_driven_by_privilege_asset_chain(demo):
    inc = incident_for_gt(demo, "GT-ATK-GOLDEN")
    f = inc.factors
    assert f["identity_privilege"] == 1.0 and f["asset_criticality"] == 1.0 and f["attack_chain_strength"] >= 0.9


def test_golden_graph_path(demo):
    inc = incident_for_gt(demo, "GT-ATK-GOLDEN")
    alerts = {a.alert_id: a for a in demo["outcome"].alerts}
    rows = [alerts[i].model_dump(mode="json") for i in inc.alert_ids]
    from dataclasses import asdict
    g = build_graph(asdict(inc), rows, demo["ctx"])
    ids = {n["id"] for n in g["nodes"]}
    assert {"ip:203.0.113.27", "user:finance-admin", "host:FINANCE-SRV-03", "process:powershell.exe",
            "resource:finance-db"} <= ids
    rel = {(e["source"], e["target"]) for e in g["edges"]}
    assert ("ip:203.0.113.27", "user:finance-admin") in rel
    assert ("user:finance-admin", "host:FINANCE-SRV-03") in rel


def test_ground_truth_metrics(demo):
    m = correlation_metrics(demo["pred"], demo["gt"]["alerts"])
    assert m["pairwise_precision"] > 0.95 and m["pairwise_recall"] > 0.95 and m["incident_purity"] > 0.95
    ranked = [{"incident_id": d.incident_id, "severity": d.severity} for d in demo["out"].incidents]
    p = priority_metrics(ranked, demo["pred"], demo["gt"]["alerts"], demo["gt"]["incidents"])
    assert p["top3_critical_recall"] == 1.0 and p["false_high_rate"] < 0.01


def test_benign_maintenance_not_high(demo):
    inc = incident_for_gt(demo, "GT-BEN-MAINT")
    assert inc.severity not in ("high", "critical")


def test_duplicates_do_not_inflate_risk(demo):
    from app.services.ingestion import ingest_rows
    from app.services.pipeline import run_pipeline

    golden = incident_for_gt(demo, "GT-ATK-GOLDEN")
    ids = set(golden.alert_ids)
    extra = [dict(r, alert_id=r["alert_id"] + "-DUP") for r in demo["rows"] if r.get("alert_id") in ids][:40]
    dup_out = ingest_rows(demo["rows"] + extra, demo["ctx"])
    assert dup_out.result.duplicates == demo["outcome"].result.duplicates + 40
    rerun = run_pipeline(dup_out.alerts, demo["ctx"])
    again = next(d for d in rerun.incidents if golden.alert_ids[0] in d.alert_ids)
    assert again.risk_score == golden.risk_score  # risk unchanged ...
    assert again.duplicate_count == golden.duplicate_count + 40  # ... and duplicates stay visible
