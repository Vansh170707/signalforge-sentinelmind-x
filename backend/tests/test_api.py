"""End-to-end: reset -> load -> pipeline -> open critical incident -> brief -> feedback -> evaluation."""

import time

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def loaded(client):
    assert client.post("/api/v1/demo/reset").status_code == 200
    r = client.post("/api/v1/demo/load", json={"seed": 7})
    assert r.status_code == 200 and r.json()["batch"]["rejected"] == 4
    run_id = client.post("/api/v1/pipeline/run").json()["run_id"]
    for _ in range(300):
        s = client.get(f"/api/v1/pipeline/{run_id}").json()
        if s["status"] in ("completed", "failed"):
            break
        time.sleep(0.2)
    assert s["status"] == "completed", s
    return s


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.headers["X-Trace-Id"]


def test_queue_and_detail(client, loaded):
    q = client.get("/api/v1/incidents", params={"page_size": 3}).json()
    assert q["total"] > 100
    top = q["items"][0]
    assert top["severity"] == "critical" and "finance-admin" in top["title"]
    d = client.get(f"/api/v1/incidents/{top['incident_id']}").json()
    assert d["risk"]["contributions"] and d["attack_stages"] and d["mitre"]
    g = client.get(f"/api/v1/incidents/{top['incident_id']}/graph").json()
    node = next(n for n in g["nodes"] if n["id"] == "user:finance-admin")
    alert = client.get(f"/api/v1/alerts/{node['alert_ids'][0]}").json()  # click node -> evidence
    assert alert["membership"]["incident_id"] == top["incident_id"] and alert["membership"]["reasons"]


def test_brief_template_without_llm_and_feedback(client, loaded):
    iid = client.get("/api/v1/incidents").json()["items"][0]["incident_id"]
    b = client.post(f"/api/v1/incidents/{iid}/brief", json={}).json()
    assert b["provider"] == "template" and b["brief"]["observed_facts"]
    assert b["evidence_pack_summary"]["instruction_like_text_alert_ids"]  # prompt-injection text flagged as data
    f = client.post(f"/api/v1/incidents/{iid}/feedback", json={"verdict": "confirmed_malicious", "notes": "demo"})
    assert f.status_code == 200
    d = client.get(f"/api/v1/incidents/{iid}").json()
    assert d["analyst_verdict"] == "confirmed_malicious" and d["feedback"]
    assert any(e["action"] == "incident.feedback" for e in client.get("/api/v1/audit").json())


def test_evaluation_computed(client, loaded):
    e = client.get("/api/v1/metrics/evaluation").json()
    assert e["available"] and e["metrics"]["priority"]["top3_critical_recall"] == 1.0
    o = client.get("/api/v1/metrics/overview").json()
    assert o["alerts"] > 9000 and o["incidents"] > 0 and o["compression_ratio"] > 1


def test_errors_and_limits(client, loaded):
    r = client.get("/api/v1/incidents/INC-9999")
    assert r.status_code == 404 and r.json()["error"]["trace_id"]
    bad = client.post("/api/v1/incidents/INC-0001/feedback", json={"verdict": "delete_everything"})
    assert bad.status_code == 422
    assert client.post("/api/v1/incidents/INC-0001/decision").status_code == 409  # Jev not configured


def test_malicious_string_displayed_as_data(client, loaded):
    items = client.get("/api/v1/alerts", params={"q": "encoded_command", "page_size": 200}).json()["items"]
    texts = [a["attributes"].get("command_line", "") for a in items]
    assert any("ignore all previous instructions" in t for t in texts)
