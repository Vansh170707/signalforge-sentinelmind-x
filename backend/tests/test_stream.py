"""Live stream mode: incidents assemble and escalate as alerts arrive; final state equals the batch pipeline."""

from app.services.stream import StreamEngine


def test_golden_story_escalates_while_streaming(demo):
    eng = StreamEngine(demo["rows"], demo["ctx"], seed=7, speed=900)
    eng.advance(2.75 * 3600)  # 02:45 - brute force under way
    early = eng.snapshot()
    top = early["board"][0]
    assert "finance-admin" in top["title"] and top["severity"] in ("high", "critical")
    eng.advance(0.5 * 3600)  # 03:15 - full chain visible
    mid = eng.snapshot()["board"][0]
    assert mid["severity"] == "critical" and len(mid["stages"]) >= 5 and mid["key"] == top["key"]
    kinds = {(e["key"], e["severity"]) for e in eng.snapshot()["events"]}
    assert (top["key"], "critical") in kinds


def test_stream_end_matches_batch(demo):
    eng = StreamEngine(demo["rows"], demo["ctx"], seed=7, speed=900)
    eng.advance(25 * 3600)
    s = eng.snapshot()
    assert s["status"] == "finished" and s["progress"] == 1.0
    assert s["alerts"] == demo["outcome"].result.accepted
    assert s["duplicates"] == demo["outcome"].result.duplicates and s["rejected"] == 4
    assert s["incidents"] == len(demo["out"].incidents)
    assert sum(b["alerts"] for b in s["buckets"]) == s["alerts"]
