import pytest

from app.services.context import ContextStore
from app.services.ingestion import ingest_rows, parse_payload
from app.services.normalization import (
    NormalizationError,
    canonical_host,
    canonical_user,
    normalize_alert,
    parse_ip,
)

BASE = {"alert_id": "A1", "timestamp": "2026-09-14T10:21:03+02:00", "source": "identity",
        "alert_type": "failed_login", "title": "Failed authentication", "severity": "Medium",
        "user": "CORP\\Finance-Admin", "host": "finance-srv-03.corp.local", "src_ip": "203.0.113.27"}


def test_timestamp_converted_to_utc_and_identities_canonicalized():
    a = normalize_alert(BASE)
    assert a.timestamp.isoformat() == "2026-09-14T08:21:03+00:00"
    assert a.user == "finance-admin" and a.user_display == "CORP\\Finance-Admin"
    assert a.host == "FINANCE-SRV-03"
    assert a.severity == "medium" and a.severity_score == 55
    assert a.src_ip_private is False


def test_epoch_millis_and_score_only_severity():
    a = normalize_alert(BASE | {"timestamp": 1789381263000, "severity": None, "severity_score": 91})
    assert a.timestamp.year == 2026 and a.severity == "critical"


@pytest.mark.parametrize("patch,msg", [
    ({"timestamp": "yesterday"}, "invalid timestamp"),
    ({"alert_type": ""}, "missing alert_type"),
    ({"severity_score": 500}, "outside 0-100"),
    ({"src_ip": "999.1.1.1"}, "invalid src_ip"),
])
def test_malformed_rows_rejected_with_reason(patch, msg):
    with pytest.raises(NormalizationError) as exc:
        normalize_alert(BASE | patch)
    assert any(msg in e for e in exc.value.errors)


def test_batch_rejects_rows_individually_and_dedupes():
    rows = [BASE, dict(BASE, alert_id="A2"), BASE | {"alert_id": "A3", "timestamp": "bad"}]
    out = ingest_rows(rows)
    assert (out.result.accepted, out.result.duplicates, out.result.rejected) == (1, 1, 1)
    assert out.alerts[0].duplicate_count == 1
    assert out.duplicate_of == {"A2": "A1"}


def test_enrichment_from_context_store():
    ctx = ContextStore.from_dict({"users": {"finance-admin": {"privilege": 5}},
                                  "hosts": {"FINANCE-SRV-03": {"criticality": 5, "ip": "10.20.5.14"}}})
    a = normalize_alert(BASE, ctx)
    assert a.user_privilege == 5 and a.asset_criticality == 5


def test_csv_and_jsonl_parsing():
    csv_text = "alert_id,timestamp,alert_type,severity,user,attributes\nC1,2026-09-14T00:00:00Z,failed_login,low,bob,\"{\"\"k\"\": 1}\"\n"
    rows = parse_payload(csv_text, "csv")
    assert rows[0]["attributes"] == {"k": 1}
    assert parse_payload('{"a": 1}\nnot json\n', "jsonl")[1]["__parse_error__"].startswith("line 2")


def test_helpers():
    assert canonical_user("bob@corp.example") == "bob"
    assert canonical_host("ws-1001.local") == "WS-1001"
    assert parse_ip("10.1.2.3") == ("10.1.2.3", True)
