"""Structured harvest metrics: summary + failure-rate derivation."""

from __future__ import annotations

from backend.collectors.harvest import build_harvest_metrics


def test_all_ok_zero_failure_rate():
    results = {
        "started_at": "2026-08-16T07:00:00+08:00",
        "finished_at": "2026-08-16T07:02:30+08:00",
        "steps": {
            "cisa_kev": {"ok": True, "count": 40},
            "epss_top": {"ok": True, "count": 12},
            "twcert": {"ok": True, "count": 18, "news": 10, "tvn": 8},
            "lifecycle": {"ok": True, "staled": 3},
        },
    }
    m = build_harvest_metrics(results)
    assert m["event"] == "harvest_complete"
    assert m["steps_total"] == 4
    assert m["steps_ok"] == 4
    assert m["steps_failed"] == 0
    assert m["failure_rate"] == 0.0
    assert m["items_collected"] == 40 + 12 + 18 + 3
    assert m["failed"] == []
    assert m["duration_sec"] == 150.0
    assert set(m["ok_steps"]) == {"cisa_kev", "epss_top", "twcert", "lifecycle"}


def test_top_level_failure_counted_in_rate():
    results = {
        "started_at": "2026-08-16T07:00:00+08:00",
        "finished_at": "2026-08-16T07:01:00+08:00",
        "steps": {
            "cisa_kev": {"ok": True, "count": 10},
            "otx": {"ok": False, "error": "401 unauthorized"},
            "hibp": {"ok": False, "error": "timeout"},
        },
    }
    m = build_harvest_metrics(results)
    assert m["steps_total"] == 3
    assert m["steps_failed"] == 2
    assert m["steps_ok"] == 1
    assert m["failure_rate"] == round(2 / 3, 4)
    assert {f["step"] for f in m["failed"]} == {"otx", "hibp"}
    assert any("401" in f["error"] for f in m["failed"])


def test_nested_intel_feed_failures_are_surfaced_but_not_in_headline_rate():
    """A flaky single RSS must not inflate the top-level failure rate when the
    aggregate step itself is still considered successful."""
    results = {
        "started_at": "2026-08-16T15:00:00+08:00",
        "finished_at": "2026-08-16T15:03:00+08:00",
        "steps": {
            "cisa_kev": {"ok": True, "count": 5},
            "intel_feeds": {
                "unit42_rss": {"ok": True, "count": 8, "name": "Unit 42"},
                "dragos_ot_rss": {"ok": False, "error": "403 Forbidden", "name": "Dragos"},
                "_total": 8,
            },
        },
    }
    m = build_harvest_metrics(results)
    assert m["steps_total"] == 2
    assert m["steps_failed"] == 0  # intel_feeds aggregate has no top-level ok=False
    assert m["failure_rate"] == 0.0
    assert m["nested_feed_failures"] == 1
    assert any(f["step"] == "intel_feeds.dragos_ot_rss" for f in m["failed"])
    assert m["items_collected"] == 5 + 8


def test_empty_steps():
    m = build_harvest_metrics({"started_at": None, "finished_at": None, "steps": {}})
    assert m["steps_total"] == 0
    assert m["failure_rate"] == 0.0
    assert m["items_collected"] == 0
    assert m["duration_sec"] is None
