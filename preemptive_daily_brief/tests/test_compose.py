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


def test_kev_lands_in_must_do_as_p1():
    """KEV alone is P1 (see CLAUDE.md §3.4) but still reaches 今日必辦."""
    brief = compose_brief(SAMPLE, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    assert brief["stats"]["p0"] == 0
    assert brief["stats"]["p1"] >= 1
    lead = next(i for i in brief["must_do"] if i.get("cve_id") == "CVE-2026-48027")
    assert lead["priority"] == "P1"
    assert lead["deadline"] == "72 小時"
    assert any(i.get("evidence") == "confirmed" for i in brief["must_do"])


def test_kev_plus_ransomware_campaign_is_p0_in_24h():
    brief = compose_brief(
        [{**SAMPLE[0], "known_ransomware_campaign": True}],
        now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ),
    )
    assert brief["stats"]["p0"] == 1
    assert brief["must_do"][0]["priority"] == "P0"
    assert brief["must_do"][0]["deadline"] == "24 小時"


def test_ot_p0_gets_emergency_cab_not_the_routine_window():
    """Section must not override priority: a P0 on an OT asset cannot wait 7 days."""
    brief = compose_brief(
        [
            {
                "id": "ot-p0",
                "cve_id": "CVE-2026-22222",
                "title": "Siemens SIMATIC S7-1500 exploited in the wild",
                "summary": "ICS advisory; ransomware crews are abusing it.",
                "vendor": "Siemens",
                "product": "SIMATIC S7-1500",
                "source_name": "CISA KEV",
                "in_kev": True,
                "known_ransomware_campaign": True,
                "verification": "confirmed",
                "layer_id": "L1",
            }
        ],
        now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ),
    )
    lead = brief["must_do"][0]
    assert lead["priority"] == "P0"
    assert lead["section"] == "ot_ics"
    assert lead["owner"] == "OT"
    assert "24 小時" in lead["deadline"]
    assert "7 日" not in lead["deadline"]
    # The OT safety constraint survives the reordering.
    assert "禁止主動掃描" in lead["action"]
    assert "CAB" in lead["action"]


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


def test_unscored_item_is_reachable_not_routed_into_the_kev_table():
    """An IOC bundle with no CVE / KEV / EPSS must still be renderable somewhere.

    assign_section used to fall through to "kev_epss", whose section 3 is a table
    keyed on a scored vulnerability — 72 of 400 real rows were counted in
    stats.total and then rendered nowhere.
    """
    ioc = {
        "id": "tf-1",
        "title": "ThreatFox IOC bundle｜Remcos",
        "summary": "297 indicators for Remcos RAT infrastructure",
        "source_name": "ThreatFox",
        "verification": "unverified",
    }
    brief = compose_brief([ioc], now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    assert brief["kev_epss"] == []
    assert [i["id"] for i in brief["watch"]] == ["tf-1"]
    assert brief["stats"]["rendered"] == 1
    assert brief["stats"]["truncated"] == 0
    assert "Remcos" in brief["markdown"]


def test_every_truncation_point_reports_shown_and_total():
    items = [
        {
            "id": f"w-{n}",
            "title": f"Unscored observation {n}",
            "source_name": "Dark Reading",
            "verification": "unverified",
        }
        for n in range(30)
    ]
    brief = compose_brief(items, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    watch = brief["section_counts"]["watch"]
    assert watch == {"shown": 20, "total": 30, "cap": 20}
    assert brief["stats"]["rendered"] == 20
    assert brief["stats"]["truncated"] == 10
    # Both layers are disclosed: the payload caps at 20, the Markdown at 12.
    assert "顯示 12／共 30 件" in brief["markdown"]
    assert "本日分類 30 件，其中 20 件列入本報告" in brief["markdown"]


def test_kev_table_keeps_cves_without_an_epss_score():
    """EPSS is null on ~97% of real rows; a `epss >= 0.1` gate emptied section 3."""
    item = {
        "id": "cve-only",
        "cve_id": "CVE-2026-70001",
        "title": "CVE-2026-70001 — unscored but published",
        "source_name": "NVD",
        "verification": "confirmed",
    }
    brief = compose_brief([item], now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    assert [i["cve_id"] for i in brief["kev_epss"]] == ["CVE-2026-70001"]


def test_gartner_marked_third_party_or_unverified():
    brief = compose_brief(SAMPLE, now=datetime(2026, 8, 15, 16, 0, tzinfo=TZ))
    market = brief["market"]
    assert market
    assert market[0]["evidence"] in ("third_party", "unverified")
    assert "【第三方評論】" in brief["markdown"] or "【尚未證實】" in brief["markdown"]
