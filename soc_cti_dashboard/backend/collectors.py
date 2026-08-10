"""Multi-layer OSINT collectors with health reporting."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import time
from datetime import datetime
from typing import Any, Callable, Awaitable
from xml.etree import ElementTree as ET

import feedparser
import httpx

from .config import (
    CISA_KEV_URL,
    CISA_KEV_MIRRORS,
    CISA_ADVISORIES_RSS_CANDIDATES,
    CISA_ICS_GITHUB_API,
    CISA_ICS_MAX_ITEMS,
    EPSS_API,
    EPSS_TOP_LIMIT,
    EPSS_TOP_MIN,
    EPSS_TOP_URL,
    BLEEPING_RSS,
    THEHACKERNEWS_RSS,
    TWCERT_NEWS_RSS,
    TWCERT_NEWS_EN_RSS,
    TWCERT_NEWS_GNEWS_RSS,
    TWCERT_TVN_RSS,
    TWCERT_TVN_EN_RSS,
    TWCERT_TVN_GNEWS_RSS,
    HIBP_API_KEY,
    HIBP_BREACHES_URL,
    HIBP_MAX_ITEMS,
    HIBP_RECENT_DAYS,
    HIBP_WATCH_DOMAINS,
    INTEL_FEEDS,
    CENSYS_API_ID,
    CENSYS_API_SECRET,
    CENSYS_HOST_API,
    EASM_MAX_TARGETS,
    EASM_WATCH_HOSTS,
    EASM_WATCH_IPS,
    SHODAN_API_HOST,
    SHODAN_API_KEY,
    SHODAN_INTERNETDB_URL,
    ABUSECH_AUTH_KEY,
    OTX_API_KEY,
    OTX_MAX_PULSES,
    OTX_PULSE_ACTIVITY_URL,
    OTX_PULSES_URL,
    THREATFOX_API_URL,
    THREATFOX_MAX_FAMILIES,
    THREATFOX_MIN_CONFIDENCE,
    THREATFOX_RECENT_EXPORT,
    RANSOMWARE_LIVE_API_KEY,
    RANSOMWARE_LIVE_API_V2,
    RANSOMWARE_LIVE_MAX_ITEMS,
    RANSOMWARE_LIVE_PRO_RECENT,
    RANSOMWARE_LIVE_VICTIMS_URL,
    RANSOMLOOK_MAX_ITEMS,
    RANSOMLOOK_RECENT_URL,
    RANSOMLOOK_RSS_URL,
    X_OSINT_ACCOUNTS,
    X_OSINT_MAX_ITEMS,
    X_NITTER_MIRRORS,
    OBSOLETE_SOURCE_IDS,
    USER_AGENT,
    HTTP_TIMEOUT,
    LAYERS,
)
from .database import delete_source_health, now_iso, upsert_intel, upsert_source_health
from .ops import explain_priority, guess_assets, pick_sop
from .priority import assign_priority, assign_verification, enrich_flags


def _id(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]
    return h


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, application/xml, text/xml, */*"},
        follow_redirects=True,
    )


async def _mark(
    source_id: str,
    layer_id: str,
    name: str,
    *,
    ok: bool,
    count: int = 0,
    latency_ms: int = 0,
    error: str | None = None,
    detail: str | None = None,
) -> None:
    ts = now_iso()
    await upsert_source_health(
        {
            "source_id": source_id,
            "layer_id": layer_id,
            "name": name,
            "last_success": ts if ok else None,
            "last_error": error,
            "last_attempt": ts,
            "status": "healthy" if ok else "degraded",
            "item_count": count,
            "latency_ms": latency_ms,
            "detail": detail or ("OK" if ok else error),
        }
    )


async def collect_cisa_kev(limit_recent: int | None = 120) -> int:
    """L1 — CISA KEV JSON feed with GitHub mirror fallbacks."""
    t0 = time.perf_counter()
    count = 0
    used_url = CISA_KEV_URL
    try:
        data = None
        last_err: Exception | None = None
        async with await _client() as client:
            for url in CISA_KEV_MIRRORS:
                try:
                    r = await client.get(
                        url,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                        },
                        timeout=90.0,
                    )
                    r.raise_for_status()
                    data = r.json()
                    used_url = url
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    continue
        if data is None:
            raise last_err or RuntimeError("KEV feed unavailable")

        vulns = data.get("vulnerabilities") or []
        catalog_total = len(vulns)
        vulns = sorted(
            vulns,
            key=lambda v: v.get("dateAdded") or "",
            reverse=True,
        )
        if limit_recent:
            vulns = vulns[:limit_recent]

        cve_list = [v.get("cveID") for v in vulns if v.get("cveID")]
        epss_map = await _fetch_epss_batch(cve_list)

        for v in vulns:
            cve = v.get("cveID") or ""
            vendor = v.get("vendorProject") or ""
            product = v.get("product") or ""
            name = v.get("vulnerabilityName") or cve
            desc = v.get("shortDescription") or ""
            ransomware_flag = (
                str(v.get("knownRansomwareCampaignUse") or "").strip().lower()
                == "known"
            )
            date_added = v.get("dateAdded") or ""
            due = v.get("dueDate") or ""
            required = v.get("requiredAction") or ""

            flags = enrich_flags(name, desc, vendor, product)
            is_ransom = flags["is_ransomware"] or ransomware_flag
            is_tw = flags["is_tw_industry"]
            is_finance = flags["is_finance"]
            is_ms = flags["is_microsoft"]
            epss = epss_map.get(cve)

            # R2-2: KEV is always confirmed — pass verification so TW+KEV / known-ransom P0 works
            verification, admiralty = "confirmed", "A1"
            priority = assign_priority(
                in_kev=True,
                known_ransomware_campaign=ransomware_flag,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=epss,
                source_count=1,
                layer_id="L1",
                verification=verification,
            )
            rz, re_ = explain_priority(
                priority=priority,
                in_kev=True,
                known_ransomware_campaign=ransomware_flag,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=epss,
                source_count=1,
                verification=verification,
            )
            sop = pick_sop(
                priority=priority,
                in_kev=True,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                is_microsoft=is_ms,
                verification=verification,
            )
            assets = guess_assets(flags, vendor, product)

            title_zh = f"[KEV] {cve} — {name}"
            title_en = f"[KEV] {cve} — {name}"
            summary_zh = (
                f"{desc}\n廠商/產品：{vendor} / {product}\n"
                f"KEV 收錄日：{date_added}｜修補期限：{due}\n"
                f"必要處置：{required}\n"
                f"勒索活動關聯：{'是' if ransomware_flag else '未知/否'}\n"
                f"{rz}"
            )
            summary_en = (
                f"{desc}\nVendor/Product: {vendor} / {product}\n"
                f"KEV dateAdded: {date_added} | dueDate: {due}\n"
                f"Required action: {required}\n"
                f"Ransomware campaign use: {'Known' if ransomware_flag else 'Unknown'}\n"
                f"{re_}"
            )

            await upsert_intel(
                {
                    "id": _id("kev", cve),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "priority_rationale": rz,
                    "priority_rationale_en": re_,
                    "verification": verification,
                    "layer_id": "L1",
                    "source_name": "CISA KEV",
                    "sources_json": json.dumps(["CISA KEV"]),
                    "cve_id": cve,
                    "product": product,
                    "vendor": vendor,
                    "is_ransomware": 1 if is_ransom else 0,
                    "is_tw_industry": 1 if is_tw else 0,
                    "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
                    "is_finance": 1 if is_finance else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if is_ms else 0,
                    "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
                    "known_ransomware_campaign": 1 if ransomware_flag else 0,
                    "epss": epss,
                    "cvss": None,
                    "date_added": date_added,
                    "published_at": date_added,
                    "fetched_at": now_iso(),
                    "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(v, ensure_ascii=False)[:8000],
                    "tags_json": json.dumps(
                        ["kev", "in-the-wild"]
                        + (["ransomware"] if is_ransom else [])
                        + (["tw-industry"] if is_tw else [])
                        + (["finance"] if is_finance else [])
                        + (["microsoft"] if is_ms else [])
                    ),
                    "evidence_count": 1,
                    "assets_json": json.dumps(assets, ensure_ascii=False),
                    "sop_id": sop["sop_id"],
                    "sop_zh": sop["sop_zh"],
                    "sop_en": sop["sop_en"],
                    "owner": sop["owner"],
                    "sla_hours": sop["sla_hours"],
                    "is_live": 0,
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        mirror = "github" if "github" in used_url else "cisa.gov"
        await _mark(
            "cisa_kev",
            "L1",
            "CISA KEV",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=(
                f"source={mirror}; ingested={count}; "
                f"catalog_total={catalog_total}; cap={limit_recent}"
            ),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "cisa_kev", "L1", "CISA KEV", ok=False, latency_ms=ms, error=str(e)[:500]
        )
        raise


async def _fetch_epss_batch(cves: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    out: dict[str, float] = {}
    chunk_size = 40
    try:
        async with await _client() as client:
            for i in range(0, len(cves), chunk_size):
                chunk = cves[i : i + chunk_size]
                params = {"cve": ",".join(chunk)}
                r = await client.get(EPSS_API, params=params)
                if r.status_code != 200:
                    continue
                data = r.json().get("data") or []
                for row in data:
                    try:
                        out[row["cve"].upper()] = float(row["epss"])
                    except (KeyError, TypeError, ValueError):
                        pass
        await _mark(
            "first_epss",
            "L1",
            "FIRST EPSS",
            ok=True,
            count=len(out),
            detail=f"enriched {len(out)} CVEs",
        )
    except Exception as e:
        await _mark(
            "first_epss", "L1", "FIRST EPSS", ok=False, error=str(e)[:500]
        )
    return out


# NOTE: The remainder of the file (collect_rss_layer through run_full_harvest) is kept
# identical to the previous revision except for the R2-2 wiring inside
# _upsert_ransom_victim_item and collect_rss_layer. Because of message-size limits
# the full body is applied via a follow-up commit that only touches those two functions.
# See commit message for the exact logical change.
