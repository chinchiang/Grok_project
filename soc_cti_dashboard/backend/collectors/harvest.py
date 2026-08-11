"""Full harvest orchestration: every collector, then aggregation and ageing."""

from __future__ import annotations

from typing import Any
from ..config import (
    TWCERT_NEWS_RSS,
    TWCERT_NEWS_EN_RSS,
    TWCERT_NEWS_GNEWS_RSS,
    TWCERT_TVN_RSS,
    TWCERT_TVN_EN_RSS,
    TWCERT_TVN_GNEWS_RSS,
    LAYERS,
)
from ..database import now_iso

from ._base import _mark
from .breaches import collect_hibp_breaches
from .easm import collect_censys_easm, collect_shodan_easm
from .ics import collect_cisa_ics
from .iocs import collect_otx_pulses, collect_threatfox
from .kev import collect_cisa_kev, collect_epss_top_scores
from .osint import collect_x_darkweb_accounts, dual_source_darkweb_verify
from .ransom import collect_ransomlook, collect_ransomware_live, dual_source_ransom_trackers
from .rss import collect_registered_intel_feeds, collect_rss_layer


async def run_full_harvest() -> dict[str, Any]:
    """Run all configured collectors; return summary."""
    results: dict[str, Any] = {"started_at": now_iso(), "steps": {}}

    # L1 KEV + EPSS enrichment + EPSS top-score feed
    try:
        n = await collect_cisa_kev()
        results["steps"]["cisa_kev"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["cisa_kev"] = {"ok": False, "error": str(e)}

    try:
        n = await collect_epss_top_scores()
        results["steps"]["epss_top"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["epss_top"] = {"ok": False, "error": str(e)}

    # L2 TWCERT/CC official RSS (news + Taiwan Vulnerability Notes)
    # Primary zh feeds; EN RSS + Google News fallbacks for Actions/WAF blocks
    n_news = await collect_rss_layer(
        source_id="twcert_news_rss",
        layer_id="L2",
        name="TWCERT/CC 資安新聞 RSS",
        url=TWCERT_NEWS_RSS,
        fallback_url=TWCERT_NEWS_EN_RSS,
        darkweb_indirect=False,
        force_ransomware_scan=True,
        max_items=25,
        extra_tags=["ot-it", "ot-gov", "official-gov", "twcert", "tw"],
        title_prefix="🇹🇼 TWCERT",
    )
    if n_news == 0:
        n_news = await collect_rss_layer(
            source_id="twcert_news_rss",
            layer_id="L2",
            name="TWCERT/CC 資安新聞 RSS",
            url=TWCERT_NEWS_GNEWS_RSS,
            darkweb_indirect=False,
            force_ransomware_scan=True,
            max_items=25,
            extra_tags=["ot-it", "ot-gov", "official-gov", "twcert", "tw"],
            title_prefix="🇹🇼 TWCERT",
        )
    n_tvn = await collect_rss_layer(
        source_id="twcert_tvn_rss",
        layer_id="L2",
        name="TWCERT/CC TVN 漏洞公告 RSS",
        url=TWCERT_TVN_RSS,
        fallback_url=TWCERT_TVN_EN_RSS,
        darkweb_indirect=False,
        force_ransomware_scan=True,
        max_items=25,
        extra_tags=["ot-it", "ot-gov", "official-gov", "twcert", "tw", "tvn"],
        title_prefix="🇹🇼 TWCERT TVN",
    )
    if n_tvn == 0:
        n_tvn = await collect_rss_layer(
            source_id="twcert_tvn_rss",
            layer_id="L2",
            name="TWCERT/CC TVN 漏洞公告 RSS",
            url=TWCERT_TVN_GNEWS_RSS,
            darkweb_indirect=False,
            force_ransomware_scan=True,
            max_items=25,
            extra_tags=["ot-it", "ot-gov", "official-gov", "twcert", "tw", "tvn"],
            title_prefix="🇹🇼 TWCERT TVN",
        )
    # Keep legacy source_id healthy for existing dashboards that still list it
    await _mark(
        "twcert_rss",
        "L2",
        "TWCERT/CC RSS (legacy id → news+TVN)",
        ok=True,
        count=n_news + n_tvn,
        detail=f"news={n_news}, tvn={n_tvn}; feeds rss-104-1 + rss-132-1",
    )
    results["steps"]["twcert"] = {
        "ok": True,
        "count": n_news + n_tvn,
        "news": n_news,
        "tvn": n_tvn,
    }

    # L3 — ThreatFox (free export) + OTX pulses (optional key)
    try:
        n = await collect_threatfox()
        results["steps"]["abusech"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["abusech"] = {"ok": False, "error": str(e)}
    try:
        n = await collect_otx_pulses()
        results["steps"]["otx"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["otx"] = {"ok": False, "error": str(e)}

    # Multi-layer news / research / PSIRT feeds (Unit42, Fortinet, news, Dragos, …)
    try:
        feed_stats = await collect_registered_intel_feeds()
        results["steps"]["intel_feeds"] = feed_stats
    except Exception as e:
        results["steps"]["intel_feeds"] = {"ok": False, "error": str(e)}

    # L4 EASM — Shodan InternetDB (free) + optional Shodan/Censys keys
    try:
        n_sh = await collect_shodan_easm()
        results["steps"]["shodan"] = {"ok": True, "count": n_sh}
    except Exception as e:
        results["steps"]["shodan"] = {"ok": False, "error": str(e)}
    try:
        n_ce = await collect_censys_easm()
        results["steps"]["censys"] = {"ok": True, "count": n_ce}
    except Exception as e:
        results["steps"]["censys"] = {"ok": False, "error": str(e)}
    results["steps"]["easm"] = {
        "ok": True,
        "shodan": results["steps"].get("shodan"),
        "censys": results["steps"].get("censys"),
    }

    # L5 HIBP public breach catalog (free) + optional paid domain watch
    try:
        n = await collect_hibp_breaches()
        results["steps"]["hibp"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["hibp"] = {"ok": False, "error": str(e)}

    # L6 ransomware trackers + X dark-web accounts + news dual-verify
    try:
        n_live = await collect_ransomware_live()
        results["steps"]["ransomware_live"] = {"ok": True, "count": n_live}
    except Exception as e:
        results["steps"]["ransomware_live"] = {"ok": False, "error": str(e)}

    try:
        n_look = await collect_ransomlook()
        results["steps"]["ransomlook"] = {"ok": True, "count": n_look}
    except Exception as e:
        results["steps"]["ransomlook"] = {"ok": False, "error": str(e)}

    try:
        n_dual = await dual_source_ransom_trackers()
        results["steps"]["ransom_dual"] = {"ok": True, "elevated": n_dual}
    except Exception as e:
        results["steps"]["ransom_dual"] = {"ok": False, "error": str(e)}

    try:
        n_x = await collect_x_darkweb_accounts()
        results["steps"]["x_darkweb"] = {"ok": True, "count": n_x}
    except Exception as e:
        results["steps"]["x_darkweb"] = {"ok": False, "error": str(e)}

    try:
        n = await dual_source_darkweb_verify()
        results["steps"]["darkweb_dual"] = {"ok": True, "dual_elevated": n}
    except Exception as e:
        results["steps"]["darkweb_dual"] = {"ok": False, "error": str(e)}

    # L7 ICS
    try:
        n = await collect_cisa_ics()
        results["steps"]["cisa_ics"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["cisa_ics"] = {"ok": False, "error": str(e)}

    # Post-ingest: recognise the same event reported by several feeds, then
    # age out anything that stopped being observed. Both must run after every
    # collector, since either can change an item's evidence count.
    try:
        from ..aggregate import aggregate_cross_source_events

        results["steps"]["cross_source"] = await aggregate_cross_source_events()
    except Exception as e:
        results["steps"]["cross_source"] = {"ok": False, "error": str(e)}

    try:
        from ..database import mark_stale_items

        results["steps"]["lifecycle"] = {"ok": True, "staled": await mark_stale_items()}
    except Exception as e:
        results["steps"]["lifecycle"] = {"ok": False, "error": str(e)}

    results["finished_at"] = now_iso()
    results["layers"] = LAYERS
    return results
