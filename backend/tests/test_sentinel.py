"""Microsoft Sentinel connector: SecurityAlert import mapping, round trip on the demo corpus, incident export."""

import json

from app.services.ingestion import ingest_rows, parse_payload
from app.services.pipeline import run_pipeline
from app.services.sentinel import SENTINEL_NAMES, classify, from_sentinel, to_sentinel_alert_row
from tests.conftest import incident_for_gt

ROW = {
    "TimeGenerated": "2026-09-14T02:46:12Z", "StartTime": "2026-09-14T02:46:12Z",
    "SystemAlertId": "8f1c2a90-0000-4000-8000-000000000001",
    "AlertName": "Successful sign-in after multiple failed attempts", "AlertType": "",
    "AlertSeverity": "High", "ProductName": "Microsoft Entra ID Protection", "ConfidenceScore": 0.9,
    "CompromisedEntity": "CORP\\\\Finance-Admin",
    "Entities": json.dumps([
        {"$id": "2", "Type": "account", "Name": "finance-admin", "UPNSuffix": "corp.example"},
        {"$id": "3", "Type": "host", "HostName": "FINANCE-SRV-03", "DnsDomain": "corp.local"},
        {"$id": "4", "Type": "ip", "Address": "203.0.113.27"},
        {"$id": "5", "Type": "file", "Name": "powershell.exe"},
        {"$id": "6", "Type": "process", "CommandLine": "powershell -enc AAAA", "ImageFile": {"$ref": "5"}},
    ]),
    "ExtendedProperties": json.dumps({"prior_failures": 95}),
    "Techniques": json.dumps(["T1078"]), "Tactics": "InitialAccess",
}


def test_security_alert_row_maps_to_canonical_fields():
    raw = from_sentinel(ROW)
    assert raw["alert_type"] == "login_success_after_failures"
    assert (raw["user"], raw["host"], raw["src_ip"], raw["process"]) == (
        "finance-admin", "FINANCE-SRV-03", "203.0.113.27", "powershell.exe")
    assert raw["severity"] == "high" and raw["source"] == "identity"
    assert raw["attributes"]["vendor_techniques"] == ["T1078"]
    assert raw["attributes"]["command_line"] == "powershell -enc AAAA"
    assert raw["attributes"]["compromised_entity"] == "finance-admin"
    out = ingest_rows([ROW])
    assert out.result.accepted == 1 and out.result.converted_from_sentinel == 1
    assert out.alerts[0].raw["raw_original"]["SystemAlertId"] == ROW["SystemAlertId"]  # raw payload preserved


def test_alert_name_keyword_classification():
    for atype, name in SENTINEL_NAMES.items():
        assert classify(name, "", name) == atype, name
    assert classify("Something we have never seen", "", "") == "sentinel_alert"


def test_log_analytics_query_response_is_parsed():
    body = {"tables": [{"columns": [{"name": k} for k in ROW], "rows": [list(ROW.values())]}]}
    rows = parse_payload(json.dumps(body), "json")
    assert rows[0]["SystemAlertId"] == ROW["SystemAlertId"]


def test_demo_corpus_round_trip_through_connector(demo):
    srows = [to_sentinel_alert_row(r) for r in demo["rows"]]
    out = ingest_rows(srows, demo["ctx"])
    assert out.result.duplicates == demo["outcome"].result.duplicates
    assert out.result.converted_from_sentinel > 9_900
    res = run_pipeline(out.alerts, demo["ctx"])
    golden = incident_for_gt(demo, "GT-ATK-GOLDEN")
    again = next(d for d in res.incidents if golden.alert_ids[0] in d.alert_ids)
    assert again.rank <= 3 and len(set(again.alert_ids) & set(golden.alert_ids)) >= 155
    reported = [m for m in again.mitre if m["mapping_reason"].startswith("reported by")]
    assert reported and all(m["attack_catalog_version"] for m in reported)
