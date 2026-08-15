"""Three-signal priority + asset mapping + evidence grade."""

from __future__ import annotations

from preemptive_daily_brief.lib.classify import (
    classify_item,
    evidence_grade,
    match_assets,
    three_signal_priority,
)


def test_kev_is_p0_even_without_epss():
    assert (
        three_signal_priority(in_kev=True, epss=0.01, cvss=4.0, org_asset=False) == "P0"
    )


def test_mass_exploitation_is_p0():
    assert three_signal_priority(mass_exploitation=True) == "P0"


def test_p1_requires_epss_cvss_and_org():
    assert (
        three_signal_priority(epss=0.71, cvss=8.8, org_asset=True) == "P1"
    )
    # missing org asset → not P1
    assert (
        three_signal_priority(epss=0.71, cvss=8.8, org_asset=False) == "P3"
    )


def test_p1_from_epss_jump():
    assert (
        three_signal_priority(epss=0.3, epss_delta=0.25, cvss=7.5, org_asset=True)
        == "P1"
    )


def test_critical_cvss_low_epss_is_p2():
    assert three_signal_priority(epss=0.05, cvss=9.8, org_asset=False) == "P2"


def test_org_hit_promotes_p3_to_p2():
    assert three_signal_priority(epss=0.01, cvss=5.0, org_asset=True) == "P2"


def test_match_fortigate_and_siemens():
    hits = match_assets("FortiGate SSL-VPN and Siemens SIMATIC S7-1500 advisory")
    keys = {h["key"] for h in hits}
    assert "fortigate" in keys
    assert "siemens" in keys
    owners = {h["owner"] for h in hits}
    assert "IT" in owners and "OT" in owners


def test_official_source_is_confirmed():
    assert evidence_grade(source_name="CISA KEV", layer_id="L1") == "confirmed"
    assert evidence_grade(source_name="Siemens ProductCERT") == "confirmed"


def test_media_is_third_party():
    assert evidence_grade(source_name="The Hacker News", source_count=1) == "third_party"


def test_classify_does_not_invent_cve():
    item = classify_item(
        {
            "title": "Random blog post about phishing",
            "source_name": "some tweet",
            "verification": "unverified",
        }
    )
    assert item.get("cve_id") in (None, "")
    assert item["brief_priority"] == "P3"
    assert item["evidence_grade"] == "unverified"
