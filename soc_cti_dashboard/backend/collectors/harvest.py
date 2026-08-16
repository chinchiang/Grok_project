"""Full harvest orchestration: every collector, then aggregation and ageing."""

from __future__ import annotations

import json
import logging
from datetime import datetime
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
from ..database import now_iso, set_meta

from ._base import _mark
from .breaches import collect_hibp_breaches
from .easm import collect_censys_easm, collect_shodan_easm
from .ics import collect_cisa_ics
from .iocs import collect_otx_pulses, collect_threatfox
from .kev import collect_cisa_kev, collect_epss_top_scores
from .osint import collect_x_darkweb_accounts, dual_source_darkweb_verify
from .ransom import collect_ransomlook, collect_ransomware_live, dual_source_ransom_trackers
from .rss import collect_registered_intel_feeds, collect_rss_layer

log = logging.getLogger("soc_cti.harvest")


def _step_ok(step: Any) -> bool:
    """Treat a step as successful when it reports ok=True or (legacy) has a count."""
    if not isinstance(step, dict):
        return False
    if "ok" in step:
        return bool(step.get("ok"))
    # Nested aggregates (e.g. easm, intel_feeds) without a top-level ok flag:
    # success if no explicit error and at least one child looks healthy.
    if step.get("error"):
        return False
    return True


def _step_item_count(step: Any) -> int:
    if not isinstance(step, dict):
        return 0
    for key in ("count", "elevated", "dual_elevated", "staled", "_total"):
        val = step.get(key)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return int(val)
    # Nested feed map: sum child counts
    total = 0
    for k, v in step.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(v.get("count"), (int, float)):
            total += int(v["count"])
    return total


def build_harvest_metrics(results: dict[str, Any]) -> dict[str, Any]:
    """Derive a compact, structured harvest summary for logs and scan_meta.

    Designed to be one JSON object per harvest — easy to grep in Actions logs
    or ship to a log aggregator. Failure rate is over *top-level steps* (not
    every nested feed), so a single flaky RSS does not drown the headline
    figure when intel_feeds still reports overall success.
    """
    steps = results.get("steps") or {}
    if not isinstance(steps, dict):
        steps = {}

    failed: list[dict[str, str]] = []
    ok_names: list[str] = []
    items_collected = 0

    for name, step in steps.items():
        if not isinstance(step, dict):
            continue
        items_collected += _step_item_count(step)
        if _step_ok(step):
            ok_names.append(name)
            # Surface nested feed failures inside an otherwise-ok aggregate
            if name == "intel_feeds":
                for feed_id, feed in step.items():
                    if feed_id.startswith("_"):
                        continue
                    if isinstance(feed, dict) and feed.get("ok") is False:
                        failed.append(
                            {
                                "step": f"intel_feeds.{feed_id}",
                                "error": str(feed.get("error") or "unknown")[:300],
                            }
                        )
        else:
            failed.append(
                {
                    "step": name,
                    "error": str(step.get("error") or step.get("detail") or "unknown")[:300],
                }
            )

    steps_total = len([k for k, v in steps.items() if isinstance(v, dict)])
    steps_failed = len([f for f in failed if not f["step"].startswith("intel_feeds.")])
    # Count nested feed failures separately so the headline rate stays stable
    nested_feed_failures = len([f for f in failed if f["step"].startswith("intel_feeds.")])
    steps_ok = max(0, steps_total - steps_failed)
    failure_rate = round(steps_failed / steps_total, 4) if steps_total else 0.0

    duration_sec: float | None = None
    started = results.get("started_at")
    finished = results.get("finished_at")
    if started and finished:
        try:
            t0 = datetime.fromisoformat(str(started))
            t1 = datetime.fromisoformat(str(finished))
            duration_sec = round((t1 - t0).total_seconds(), 2)
        except (TypeError, ValueError):
            duration_sec = None

    return {
        "event": "harvest_complete",
        "started_at": started,
        "finished_at": finished,
        "duration_sec": duration_sec,
        "steps_total": steps_total,
        "steps_ok": steps_ok,
        "steps_failed": steps_failed,
        "nested_feed_failures": nested_feed_failures,
        "failure_rate": failure_rate,
        "items_collected": items_collected,
        "failed": failed,
        "ok_steps": ok_names,
    }


def log_harvest_metrics(metrics: dict[str, Any]) -> None:
    """Emit one structured JSON line. Actions / journald can parse it as-is."""
    # Prefer a pure JSON line so log shippers do not need a custom formatter.
    payload = json.dumps(metrics, ensure_ascii=False, default=str, separators=(",", ":"))
    if metrics.get("steps_failed") or metrics.get("nested_feed_failures"):
        log.warning(payload)
    else:
        log.info(payload)


async def persist_harvest_metrics(metrics: dict[str, Any]) -> None:
    """Store the last run in scan_meta for API / static export consumers."""
    await set_meta("last_harvest_metrics", json.dumps(metrics, ensure_ascii=False, default=str))
    await set_meta(
        "last_harvest_failure_rate",
        str(metrics.get("failure_rate", 0)),
    )
    await set_meta(
        "last_harvest_failed_steps",
        str(metrics.get("steps_failed", 0)),
    )


async def run_full_harvest() -> dict[str, Any]:
    """Run all configured collectors; return summary with structured metrics."""
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

    metrics = build_harvest_metrics(results)
    results["metrics"] = metrics
    log_harvest_metrics(metrics)
    try:
        await persist_harvest_metrics(metrics)
    except Exception:
        # Logging must not fail the harvest; meta write is best-effort.
        log.exception("could not persist harvest metrics to scan_meta")

    return results
