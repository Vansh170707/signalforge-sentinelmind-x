import asyncio

from app.llm.base import NarrativeResult, ProviderError, RateLimitError
from app.services.agent import generate_brief, template_summary, validate_brief

VIEW = {
    "incident_id": "INC-0001", "title": "Possible privileged account compromise: finance-admin",
    "severity": "critical", "risk_score": 90.0, "correlation_confidence": 0.8, "first_seen": "2026-09-14T02:41:00+00:00",
    "last_seen": "2026-09-14T03:20:00+00:00", "alert_count": 3, "duplicate_count": 0, "chain_strength": 0.9,
    "anomaly_score": 0.9, "anomaly_reasons": ["95 failed logins for finance-admin within 10 min"],
    "alert_ids": ["ALT-1", "ALT-2", "ALT-3"], "top_alert_types": [["failed_login", 2]],
    "primary_entities": [{"type": "user", "value": "finance-admin"}],
    "attack_stages": [{"stage": "credential_attack", "label": "Credential Attack", "first_seen": "2026-09-14T02:41:00+00:00",
                       "last_seen": "2026-09-14T02:45:00+00:00", "alert_ids": ["ALT-1", "ALT-2"],
                       "alert_types": ["failed_login"], "confidence": 0.9}],
    "mitre": [{"technique_id": "T1110", "name": "Brute Force", "confidence": 0.9, "evidence_alert_ids": ["ALT-1"],
               "mapping_reason": "95 failed logins"}],
    "risk": {"contributions": {"asset_criticality": 18.0}, "labels": {"asset_criticality": "Asset criticality"}},
}


def good_brief(**over):
    b = {"executive_summary": "Brute force against finance-admin followed by access.",
         "observed_facts": [{"fact": "95 failed logins", "alert_ids": ["ALT-1"]}],
         "hypotheses": [{"hypothesis": "Credentials guessed", "confidence": 0.7}],
         "why_high_risk": ["critical asset"], "affected_entities": ["finance-admin"],
         "mitre_explanation": [{"technique_id": "T1110", "reason": "burst of failures"}],
         "investigation_checks": ["Verify sign-in with owner"], "uncertainties": ["attribution unknown"],
         "overall_confidence": 0.7}
    return b | over


class Fake:
    def __init__(self, name, outputs):
        self.name, self.model, self.outputs, self.calls = name, f"{name}-model", list(outputs), 0

    def available(self):
        return True

    async def generate(self, system, user, schema):
        self.calls += 1
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            raise out
        return NarrativeResult(self.name, self.model, out, 5.0)


def run(providers):
    from app.services import agent

    agent._COOLDOWN.clear()
    return asyncio.run(generate_brief(VIEW, {"incident": {}}, providers))


def test_citation_outside_incident_rejected():
    brief, report = validate_brief(good_brief(observed_facts=[{"fact": "x fact", "alert_ids": ["ALT-999"]}]),
                                   set(VIEW["alert_ids"]), {"T1110"})
    assert brief is None and report["invalid_citations"] == ["ALT-999"]


def test_unknown_technique_rejected_and_names_from_catalog():
    brief, report = validate_brief(good_brief(mitre_explanation=[{"technique_id": "T9999", "reason": "x"}]),
                                   set(VIEW["alert_ids"]), {"T1110"})
    assert brief is None and "T9999" in report["unknown_techniques"]
    ok, _ = validate_brief(good_brief(), set(VIEW["alert_ids"]), {"T1110"})
    assert ok["mitre_explanation"][0]["technique_name"] == "Brute Force"


def test_failover_gemini_429_then_groq():
    gemini = Fake("gemini", [RateLimitError("HTTP 429")])
    groq = Fake("groq", [good_brief()])
    res = run([gemini, groq])
    assert res["provider"] == "groq" and res["status"] == "ok"
    assert [a["status"] for a in res["attempts"]] == ["rate_limited", "ok"]


def test_background_prewarm_waits_out_short_rate_limit():
    from app.services import agent

    agent._COOLDOWN.clear()
    groq = Fake("groq", [RateLimitError("HTTP 429", retry_after=0.01), good_brief()])
    res = asyncio.run(generate_brief(VIEW, {"incident": {}}, [groq], patient=True))
    assert res["provider"] == "groq" and groq.calls == 2 and len(res["attempts"]) == 1


def test_timeouts_everywhere_fall_back_to_template():
    res = run([Fake("gemini", [ProviderError("overall timeout")]), Fake("groq", [ProviderError("HTTP 500")])])
    assert res["provider"] == "template" and res["status"] == "fallback"
    assert res["brief"]["observed_facts"]


def test_one_retry_on_invalid_then_template():
    bad = good_brief(observed_facts=[{"fact": "made up", "alert_ids": ["ALT-404"]}])
    gemini = Fake("gemini", [bad, bad])
    groq = Fake("groq", [good_brief()])
    res = run([gemini, groq])
    assert gemini.calls == 2 and groq.calls == 0
    assert res["provider"] == "template"


def test_retry_can_succeed():
    bad = good_brief(observed_facts=[{"fact": "made up", "alert_ids": ["ALT-404"]}])
    res = run([Fake("gemini", [bad, good_brief()])])
    assert res["provider"] == "gemini" and len(res["attempts"]) == 2


def test_template_cites_only_incident_alerts_and_is_schema_valid():
    t = template_summary(VIEW)
    brief, report = validate_brief(t, set(VIEW["alert_ids"]), {"T1110"})
    assert brief is not None, report


def test_uncited_facts_dropped_not_invented():
    brief, report = validate_brief(good_brief(observed_facts=[{"fact": "95 failed logins", "alert_ids": ["ALT-1"]},
                                                              {"fact": "an uncited claim", "alert_ids": []}]),
                                   set(VIEW["alert_ids"]), {"T1110"})
    assert brief is not None and report["dropped_uncited_facts"] == 1
    assert [f["fact"] for f in brief["observed_facts"]] == ["95 failed logins"]


def test_failing_provider_is_skipped_during_cooldown():
    from app.services import agent

    agent._COOLDOWN.clear()
    gemini = Fake("gemini", [ProviderError("HTTP 503: overloaded")])
    groq = Fake("groq", [good_brief(), good_brief()])
    first = asyncio.run(generate_brief(VIEW, {"incident": {}}, [gemini, groq]))
    second = asyncio.run(generate_brief(VIEW, {"incident": {}}, [gemini, groq]))
    assert first["provider"] == second["provider"] == "groq"
    assert gemini.calls == 1 and second["attempts"][0]["status"] == "cooldown_skip"
    agent._COOLDOWN.clear()
