"""Three-signal priority + asset mapping + evidence grade."""

from __future__ import annotations

from preemptive_daily_brief.lib.classify import (
    classify_item,
    evidence_grade,
    match_assets,
    three_signal_priority,
)


def test_kev_plus_mass_exploitation_is_p0():
    assert (
        three_signal_priority(
            in_kev=True, mass_exploitation=True, epss=0.01, cvss=4.0, org_asset=False
        )
        == "P0"
    )


def test_kev_alone_is_p1_not_p0():
    """Same rule as the dashboard: KEV without mass exploitation is P1."""
    assert (
        three_signal_priority(in_kev=True, epss=0.01, cvss=4.0, org_asset=False) == "P1"
    )
    # An org-asset hit must not manufacture a P0 out of a KEV-only item.
    assert (
        three_signal_priority(in_kev=True, epss=0.01, cvss=4.0, org_asset=True) == "P1"
    )


def test_mass_exploitation_without_kev_is_p1():
    assert three_signal_priority(mass_exploitation=True) == "P1"


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


def test_asset_keywords_are_word_anchored():
    """Regressions from the naive `kw in blob` form — each promoted a priority."""
    # "ICS" inside "forensics" claimed the SCADA/OT asset on 54 of 400 rows.
    assert match_assets("cisa forensics triage requirements") == []
    # "Exchange" inside "IKEv1 key exchange" claimed Microsoft on a Check Point CVE.
    assert match_assets("vulnerability in ikev1 key exchange handling") == []
    # "Gateway" attributed "Check Point Security Gateway" to Citrix.
    assert match_assets("check point security gateway rce") == []
    # "Spring"/"Apache" as bare words claimed the SBOM asset from prose.
    assert match_assets("spring cleaning for your apache helicopter fleet") == []
    # A bare Taiwan ticker needs market context, not any 4-digit run.
    assert match_assets("cve-2026-2356 out-of-bounds write") == []
    assert {h["key"] for h in match_assets("twse 2356 英業達 公告")} == {"inventec"}


def test_qualified_keywords_still_match():
    assert {h["key"] for h in match_assets("citrix netscaler adc session hijack")} == {"citrix"}
    assert "microsoft" in {h["key"] for h in match_assets("microsoft exchange server rce")}
    assert "open_source" in {h["key"] for h in match_assets("apache tomcat path traversal")}
    assert "scada" in {h["key"] for h in match_assets("hmi and plc firmware advisory")}


def test_official_source_is_confirmed():
    assert evidence_grade(source_name="CISA KEV", layer_id="L1") == "confirmed"
    assert evidence_grade(source_name="Siemens ProductCERT") == "confirmed"


def test_media_is_third_party():
    assert evidence_grade(source_name="The Hacker News", source_count=1) == "third_party"


def test_section_hints_are_word_anchored():
    """'ot ' used to match 'as root on ' and route Chromium CVEs to OT/ICS."""
    item = classify_item(
        {
            "title": "Chromium use-after-free lets code run as root on the host",
            "summary": "Including, but not limited to, sandbox escape.",
            "source_name": "Chrome Releases",
            "verification": "credible",
        }
    )
    assert item["section"] != "ot_ics"
    # 'eap' inside 'heap-based' filed CVEs under the先制式市場動態 section.
    market = classify_item(
        {
            "title": "Heap-based buffer overflow with improper input validation",
            "source_name": "NVD",
            "verification": "confirmed",
        }
    )
    assert market["section"] != "market"


def test_kev_detection_needs_kev_as_a_word():
    """`'kev' in source_name` treated any source spelling 'kev' as a KEV listing."""
    item = classify_item({"title": "x", "source_name": "Kevlar Security Blog"})
    assert item["in_kev"] is False
    assert classify_item({"title": "x", "source_name": "CISA KEV"})["in_kev"] is True


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
