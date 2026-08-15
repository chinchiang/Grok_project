"""Dashboard adapter for the preemptive daily brief."""

from __future__ import annotations

from backend.preemptive import build_preemptive_brief


def test_build_brief_from_intel_kev():
    items = [
        {
            "id": "x",
            "cve_id": "CVE-2026-48027",
            "title": "[KEV] CVE-2026-48027",
            "source_name": "CISA KEV",
            "verification": "confirmed",
            "layer_id": "L1",
            "in_kev": True,
            "product": "Nx Console",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2026-48027",
        }
    ]
    brief = build_preemptive_brief(items)
    assert brief["stats"]["p0"] == 1
    assert brief["must_do"]
    assert "先制式資安日報" in brief["markdown"]
    assert "CVE-2026-48027" in brief["markdown"]


def test_ot_item_never_recommends_active_scan():
    items = [
        {
            "id": "ot",
            "title": "Siemens SIMATIC advisory",
            "source_name": "CISA ICS",
            "product": "SIMATIC S7-1500",
            "vendor": "Siemens",
            "tags": ["ics"],
            "verification": "confirmed",
        }
    ]
    brief = build_preemptive_brief(items)
    blob = brief["markdown"]
    assert "OT/ICS" in blob
    assert "主動掃描" in blob  # the prohibition
    assert "禁止主動掃描" in blob
