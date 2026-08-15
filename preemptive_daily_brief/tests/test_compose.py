"""Brief composer: 8 sections, Traditional Chinese, no invented CVEs, no OT scans."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from preemptive_daily_brief.lib.compose import compose_brief

TZ = ZoneInfo("Asia/Taipei")


SAMPLE = [
    {
        "id": "kev-1",
        "cve_id": "CVE-2026-48027",
        "title": "[KEV] CVE-2026-48027 — Nx Console",
        "summary": "Embedded malicious code",
        "vendor": "Nx",
        "product": "Nx Console",
        "source_name": "CISA KEV",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2026-48027",
        "in_kev": True,
        "verification": "confirmed",
        "layer_id": "L1",
        "epss": 0.018,
        "cvss": 8.8,
    },
    {
        "id": "ot-1",
        "cve_id": "CVE-2026-11111",
        "title": "Siemens SIMATIC S7-1500 advisory",
        "summary": "ICS advisory for SIMATIC PLC",
        "vendor": "Siemens",
        "product": "SIMATIC S7-1500",
        "source_name": "CISA ICS",
        "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-26-000-01",
        "verification": "confirmed",
        "cvss": 7.5,
        "epss": 0.02,
        "tags": ["ics"],
    },
    {
        "id": "media-1",
        "title": "Gartner names a new CTEM category",
        "summary": "Vendor marketing around continuous threat exposure management",
        "source_name": "Gartner Newsroom",
        "url": "https://www.gartner.com/en/newsroom/example",
        "verification": "unverified",
    },
]


def test_compose_has_eight_sections_and_zh():
    brief = compose_brief(SAMPLE, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    md = brief["markdown"]
    assert "先制式資安日報" in md
    assert "一、管理階層摘要" in md
    assert "二、今日必辦" in md
    assert "三、新增 KEV" in md
    assert "四、曝險" in md
    assert "五、OT/ICS" in md
    assert "六、產品資安" in md
    assert "七、先制式技術" in md
    assert "八、觀察" in md
    assert "附錄" in md
    assert brief["date"] == "2026-08-15"
    assert brief["weekday_zh"] == "週六"


def test_kev_lands_in_must_do_as_p0():
    brief = compose_brief(SAMPLE, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    assert brief["stats"]["p0"] >= 1
    assert any(i.get("cve_id") == "CVE-2026-48027" for i in brief["must_do"])
    assert any(i.get("evidence") == "confirmed" for i in brief["must_do"])


def test_ot_action_forbids_active_scan():
    brief = compose_brief(SAMPLE, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    ot = brief["ot_ics"]
    assert ot, "Siemens item must route to OT section"
    joined = " ".join(i.get("action") or "" for i in ot)
    assert "禁止主動掃描" in joined
    assert "CAB" in joined
    assert "主動掃描產線" not in joined


def test_no_invented_cve_in_output():
    brief = compose_brief(SAMPLE, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    md = brief["markdown"]
    assert "CVE-2024-99999" not in md
    # only CVEs we fed in
    assert "CVE-2026-48027" in md
    assert "CVE-2026-11111" in md


def test_failed_source_is_recorded():
    brief = compose_brief(
        [],
        failed_sources=[{"id": "nvd", "name": "NVD", "url": "https://nvd.nist.gov", "error": "timeout"}],
        now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ),
    )
    assert "來源今日無法存取" in brief["markdown"]
    assert brief["must_do"] == []
    assert "本日無重大更新" in brief["markdown"]


def test_gartner_marked_third_party_or_unverified():
    brief = compose_brief(SAMPLE, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    market = brief["market"]
    assert market
    assert market[0]["evidence"] in ("third_party", "unverified")
    assert "【第三方評論】" in brief["markdown"] or "【尚未證實】" in brief["markdown"]
