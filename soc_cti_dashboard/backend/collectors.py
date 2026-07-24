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
        epss_map = await _fetch_epss_batch(cve_list[:80])

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

            priority = assign_priority(
                in_kev=True,
                known_ransomware_campaign=ransomware_flag,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=epss,
                source_count=1,
                layer_id="L1",
            )
            rz, re_ = explain_priority(
                priority=priority,
                in_kev=True,
                known_ransomware_campaign=ransomware_flag,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=epss,
                source_count=1,
            )
            verification, admiralty = assign_verification(
                in_kev=True,
                layer_id="L1",
                source_count=1,
                is_darkweb_indirect=False,
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
    # API accepts comma-separated cve list; chunk to be safe
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


async def collect_rss_layer(
    *,
    source_id: str,
    layer_id: str,
    name: str,
    url: str,
    darkweb_indirect: bool = False,
    force_ransomware_scan: bool = True,
    max_items: int = 40,
    fallback_url: str | None = None,
    fallback_urls: list[str] | None = None,
    extra_tags: list[str] | None = None,
    title_prefix: str | None = None,
) -> int:
    t0 = time.perf_counter()
    count = 0
    used_url = url
    try:
        content = ""
        async with await _client() as client:
            last_err: Exception | None = None
            # Primary → single fallback_url → extra fallback_urls (deduped, order kept)
            candidates: list[str] = []
            for u in [url, fallback_url, *(fallback_urls or [])]:
                if u and u not in candidates:
                    candidates.append(u)
            for candidate in candidates:
                if not candidate:
                    continue
                try:
                    r = await client.get(
                        candidate,
                        headers={
                            "User-Agent": (
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/128.0.0.0 Safari/537.36"
                            ),
                            "Accept": "application/rss+xml, application/xml, text/xml, */*",
                            "Accept-Language": "en-US,en;q=0.9",
                        },
                        timeout=HTTP_TIMEOUT,
                    )
                    r.raise_for_status()
                    body = r.content or b""
                    # Skip empty / non-feed HTML bodies and try next candidate
                    text_head = body[:400].lstrip().lower()
                    if b"<html" in text_head[:200] and b"<rss" not in text_head and b"<feed" not in text_head:
                        last_err = RuntimeError(
                            f"HTML not RSS from {candidate} (HTTP {r.status_code})"
                        )
                        continue
                    parsed = feedparser.parse(body)
                    if not parsed.entries:
                        last_err = RuntimeError(
                            f"no RSS entries from {candidate} (HTTP {r.status_code})"
                        )
                        continue
                    content = r.text
                    used_url = candidate
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    continue
            if last_err and not content:
                raise last_err
        feed = feedparser.parse(content)
        entries = feed.entries[:max_items]

        # Dual-source map for dark web: title fingerprint across runs handled via sources list
        for e in entries:
            title = (e.get("title") or "").strip()
            summary = (e.get("summary") or e.get("description") or "").strip()
            # strip html tags lightly
            summary = re.sub(r"<[^>]+>", " ", summary)
            summary = re.sub(r"\s+", " ", summary).strip()[:1200]
            link = e.get("link") or ""
            published = e.get("published") or e.get("updated") or ""
            cve_m = re.findall(r"CVE-\d{4}-\d{4,7}", f"{title} {summary}", flags=re.I)
            cve_id = cve_m[0].upper() if cve_m else None

            # Include source name so MS Security Blog / MSRC / Defender TI classify correctly
            flags = enrich_flags(title, f"{summary} {name}")
            is_ransom = flags["is_ransomware"]
            is_tw = flags["is_tw_industry"]
            is_finance = flags["is_finance"]
            is_ms = flags["is_microsoft"]
            # Force Microsoft flag for dedicated MS official feeds
            if not is_ms and any(
                k in name.lower()
                for k in ("microsoft", "msrc", "defender ti")
            ):
                is_ms = True
                flags = {
                    **flags,
                    "is_microsoft": True,
                    "ms_entities": flags.get("ms_entities")
                    or [{"key": "microsoft", "matched": name, "tier": "source"}],
                }
            if (
                not force_ransomware_scan
                and not is_ransom
                and not is_tw
                and not is_finance
                and not is_ms
                and not cve_id
            ):
                # keep general news volume down unless relevant
                if layer_id == "L6" and not is_ransom:
                    continue

            # Dual-source heuristic: if ransomware + another vendor name in same item
            sources = [name]
            source_count = 1
            if darkweb_indirect:
                # Require dual-source for elevated trust: check if article cites multiple orgs
                cite_markers = [
                    "cisa",
                    "fbi",
                    "ncsc",
                    "microsoft",
                    "mandiant",
                    "crowdstrike",
                    "recorded future",
                    "bleepingcomputer",
                    "krebsonsecurity",
                    "the record",
                    "twcert",
                ]
                cites = sum(1 for m in cite_markers if m in f"{title} {summary}".lower())
                if cites >= 1:
                    sources.append("secondary-media-citation")
                    source_count = 2

            # Dark-web-indirect single source → forced P3 (no watchlist auto-P0)
            force_p3 = bool(darkweb_indirect and source_count < 2)
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=None,
                source_count=source_count,
                layer_id=layer_id,
                force_p3_review=force_p3,
            )
            verification, admiralty = assign_verification(
                in_kev=False,
                layer_id=layer_id,
                source_count=source_count,
                is_darkweb_indirect=darkweb_indirect,
            )
            if darkweb_indirect and source_count < 2:
                verification = "unverified"
                admiralty = "C3"

            title_zh = title
            title_en = title
            if title_prefix:
                # Avoid double-prefix on re-ingest of already-tagged titles
                if not title.startswith(title_prefix):
                    title_zh = f"{title_prefix}｜{title}"
                    title_en = f"{title_prefix}｜{title}"
            if is_ransom:
                title_zh = f"🔐 勒索相關｜{title_zh}"
                title_en = f"🔐 Ransomware｜{title_en}"
            if is_tw:
                title_zh = f"🇹🇼 台灣電子／半導體｜{title_zh}"
                title_en = f"🇹🇼 TW Electronics/Semi｜{title_en}"
            if is_finance:
                title_zh = f"💰 金融相關｜{title_zh}"
                title_en = f"💰 Finance｜{title_en}"
            if is_ms:
                title_zh = f"🪟 微軟相關｜{title_zh}"
                title_en = f"🪟 Microsoft｜{title_en}"

            tags_raw = (
                (["ransomware"] if is_ransom else [])
                + (["tw-industry"] if is_tw else [])
                + (["finance"] if is_finance else [])
                + (["microsoft"] if is_ms else [])
                + (["darkweb-indirect"] if darkweb_indirect else [])
                + (["unverified"] if verification == "unverified" else [])
                + list(extra_tags or [])
            )
            # Deduplicate tags while preserving order
            seen_t: set[str] = set()
            tags: list[str] = []
            for tg in tags_raw:
                if tg and tg not in seen_t:
                    seen_t.add(tg)
                    tags.append(tg)

            await upsert_intel(
                {
                    "id": _id(source_id, title, link),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary or title,
                    "summary_en": summary or title,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": layer_id,
                    "source_name": name,
                    "sources_json": json.dumps(sources),
                    "cve_id": cve_id,
                    "product": "",
                    "vendor": "",
                    "is_ransomware": 1 if is_ransom else 0,
                    "is_tw_industry": 1 if is_tw else 0,
                    "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
                    "is_finance": 1 if is_finance else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if is_ms else 0,
                    "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
                    "known_ransomware_campaign": 0,
                    "epss": None,
                    "cvss": None,
                    "date_added": None,
                    "published_at": published,
                    "fetched_at": now_iso(),
                    "url": link,
                    "admiralty": admiralty,
                    "raw_json": json.dumps(
                        {"title": title, "link": link}, ensure_ascii=False
                    )[:4000],
                    "tags_json": json.dumps(tags),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        detail = f"url={used_url}"
        if used_url != url:
            detail += " (fallback)"
        await _mark(
            source_id,
            layer_id,
            name,
            ok=True,
            count=count,
            latency_ms=ms,
            detail=detail,
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            source_id, layer_id, name, ok=False, latency_ms=ms, error=str(e)[:500]
        )
        return 0


async def collect_registered_intel_feeds() -> dict[str, Any]:
    """Harvest all INTEL_FEEDS (Unit 42, news, Fortinet PSIRT, Dragos, gov CERTs, …)."""
    out: dict[str, Any] = {}
    total = 0
    for feed in INTEL_FEEDS:
        try:
            n = await collect_rss_layer(
                source_id=feed["source_id"],
                layer_id=feed["layer_id"],
                name=feed["name"],
                url=feed["url"],
                fallback_url=feed.get("fallback_url"),
                fallback_urls=feed.get("fallback_urls"),
                darkweb_indirect=bool(feed.get("darkweb_indirect")),
                force_ransomware_scan=bool(feed.get("force_all", True)),
                max_items=int(feed.get("max_items") or 20),
                extra_tags=list(feed.get("extra_tags") or []),
                title_prefix=feed.get("title_prefix"),
            )
            out[feed["source_id"]] = {"ok": True, "count": n, "name": feed["name"]}
            total += n
        except Exception as e:
            out[feed["source_id"]] = {
                "ok": False,
                "error": str(e)[:300],
                "name": feed["name"],
            }
    out["_total"] = total
    return out


async def collect_epss_top_scores(
    *, limit: int | None = None, min_epss: float | None = None
) -> int:
    """
    L1 — FIRST EPSS highest exploit-probability CVEs (public API).
    Complements KEV enrichment with predictive scores.
    """
    t0 = time.perf_counter()
    lim = limit if limit is not None else EPSS_TOP_LIMIT
    thr = min_epss if min_epss is not None else EPSS_TOP_MIN
    count = 0
    try:
        async with await _client() as client:
            r = await client.get(
                EPSS_TOP_URL,
                params={"order": "!epss", "limit": str(min(lim * 2, 100))},
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            r.raise_for_status()
            rows = r.json().get("data") or []

        rows = [x for x in rows if float(x.get("epss") or 0) >= thr][:lim]
        for row in rows:
            cve = (row.get("cve") or "").upper()
            if not cve:
                continue
            try:
                epss = float(row.get("epss") or 0)
            except (TypeError, ValueError):
                continue
            percentile = row.get("percentile")
            try:
                pct = float(percentile) if percentile is not None else None
            except (TypeError, ValueError):
                pct = None

            title_zh = f"[EPSS] {cve} — 利用機率 {epss * 100:.1f}%"
            title_en = f"[EPSS] {cve} — exploit probability {epss * 100:.1f}%"
            summary_zh = (
                f"FIRST EPSS 公開評分\n"
                f"CVE：{cve}\n"
                f"EPSS：{epss:.5f}（{epss * 100:.2f}%）\n"
                f"百分位：{f'{pct * 100:.1f}%' if pct is not None else '—'}\n"
                f"用途：預測在野利用可能性（非等同 KEV 已證實利用）"
            )
            summary_en = (
                f"FIRST EPSS public score\n"
                f"CVE: {cve}\n"
                f"EPSS: {epss:.5f} ({epss * 100:.2f}%)\n"
                f"Percentile: {f'{pct * 100:.1f}%' if pct is not None else '—'}\n"
                f"Note: predictive exploit likelihood — not the same as KEV confirmation"
            )
            flags = enrich_flags(title_en, summary_en, "", "")
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=flags["is_ransomware"],
                is_tw_industry=flags["is_tw_industry"],
                epss=epss,
                source_count=1,
                layer_id="L1",
            )
            verification, admiralty = "confirmed", "A2"

            await upsert_intel(
                {
                    "id": _id("epss-top", cve),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L1",
                    "source_name": "FIRST EPSS",
                    "sources_json": json.dumps(["FIRST EPSS"]),
                    "cve_id": cve,
                    "product": "",
                    "vendor": "",
                    "is_ransomware": 1 if flags["is_ransomware"] else 0,
                    "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                    "tw_entities_json": json.dumps(
                        flags["tw_entities"], ensure_ascii=False
                    ),
                    "is_finance": 1 if flags["is_finance"] else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if flags["is_microsoft"] else 0,
                    "ms_entities_json": json.dumps(
                        flags["ms_entities"], ensure_ascii=False
                    ),
                    "known_ransomware_campaign": 0,
                    "epss": epss,
                    "cvss": None,
                    "date_added": now_iso()[:10],
                    "published_at": now_iso()[:10],
                    "fetched_at": now_iso(),
                    "url": f"https://api.first.org/data/v1/epss?cve={cve}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(row, ensure_ascii=False)[:2000],
                    "tags_json": json.dumps(
                        ["epss", "predictive", "exploit-probability"]
                        + (["high-epss"] if epss >= 0.5 else [])
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "first_epss_top",
            "L1",
            "FIRST EPSS (top scores)",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"min_epss>={thr}; ingested={count}",
        )
        # Keep legacy source_id used by KEV enrichment healthy if top scores OK
        await _mark(
            "first_epss",
            "L1",
            "FIRST EPSS",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"top-score feed; min>={thr}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "first_epss_top",
            "L1",
            "FIRST EPSS (top scores)",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


async def collect_otx_pulses(max_items: int | None = None) -> int:
    """
    L3 — AlienVault OTX pulses.
    Requires OTX_API_KEY (free account at otx.alienvault.com).
    """
    t0 = time.perf_counter()
    limit = max_items if max_items is not None else OTX_MAX_PULSES

    if not OTX_API_KEY:
        await upsert_source_health(
            {
                "source_id": "otx_pulse",
                "layer_id": "L3",
                "name": "AlienVault OTX Pulse",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "需免費 OTX_API_KEY（https://otx.alienvault.com → Settings → API Key）"
                ),
            }
        )
        return 0

    count = 0
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "X-OTX-API-KEY": OTX_API_KEY,
        }
        pulses: list[dict] = []
        async with await _client() as client:
            # Prefer subscribed pulses; fall back to activity
            for url in (OTX_PULSES_URL, OTX_PULSE_ACTIVITY_URL):
                try:
                    r = await client.get(
                        url, headers=headers, params={"limit": str(limit)}
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if isinstance(data, dict):
                            pulses = data.get("results") or data.get("pulses") or []
                        elif isinstance(data, list):
                            pulses = data
                        if pulses:
                            break
                except Exception:
                    continue

        for p in pulses[:limit]:
            name = (p.get("name") or p.get("title") or "OTX Pulse").strip()
            desc = (p.get("description") or "")[:1200]
            author = ""
            if isinstance(p.get("author_name"), str):
                author = p["author_name"]
            elif isinstance(p.get("author"), dict):
                author = p["author"].get("username") or ""
            tags = p.get("tags") or []
            if isinstance(tags, list):
                tag_s = ", ".join(str(t) for t in tags[:15])
            else:
                tag_s = str(tags)
            created = p.get("created") or p.get("modified") or ""
            pulse_id = str(p.get("id") or p.get("pulse_id") or name)
            indicators = p.get("indicators") or []
            ind_n = len(indicators) if isinstance(indicators, list) else 0
            ind_sample = []
            if isinstance(indicators, list):
                for ind in indicators[:8]:
                    if isinstance(ind, dict):
                        ind_sample.append(
                            f"{ind.get('type') or '?'}:{ind.get('indicator') or ''}"
                        )

            title_zh = f"[OTX] {name}"
            title_en = title_zh
            summary_zh = (
                f"{desc}\n"
                f"作者：{author or '—'}\n"
                f"標籤：{tag_s or '—'}\n"
                f"IOC 數：{ind_n}\n"
                f"樣本：{'; '.join(ind_sample) if ind_sample else '—'}\n"
                f"建立：{created or '—'}"
            )
            summary_en = summary_zh
            flags = enrich_flags(name, desc + " " + tag_s)
            cve_m = re.findall(r"CVE-\d{4}-\d{4,7}", f"{name} {desc}", re.I)
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=flags["is_ransomware"],
                is_tw_industry=flags["is_tw_industry"],
                epss=None,
                source_count=1,
                layer_id="L3",
            )
            verification, admiralty = assign_verification(
                in_kev=False,
                layer_id="L3",
                source_count=1,
                is_darkweb_indirect=False,
            )

            await upsert_intel(
                {
                    "id": _id("otx", pulse_id),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L3",
                    "source_name": "AlienVault OTX",
                    "sources_json": json.dumps(["AlienVault OTX"]),
                    "cve_id": cve_m[0].upper() if cve_m else None,
                    "product": "",
                    "vendor": author or "",
                    "is_ransomware": 1 if flags["is_ransomware"] else 0,
                    "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                    "tw_entities_json": json.dumps(
                        flags["tw_entities"], ensure_ascii=False
                    ),
                    "is_finance": 1 if flags["is_finance"] else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if flags["is_microsoft"] else 0,
                    "ms_entities_json": json.dumps(
                        flags["ms_entities"], ensure_ascii=False
                    ),
                    "known_ransomware_campaign": 0,
                    "epss": None,
                    "cvss": None,
                    "date_added": (created or "")[:10] or None,
                    "published_at": created or None,
                    "fetched_at": now_iso(),
                    "url": f"https://otx.alienvault.com/pulse/{pulse_id}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(
                        {"id": pulse_id, "name": name, "tags": tags[:20]},
                        ensure_ascii=False,
                    )[:4000],
                    "tags_json": json.dumps(
                        ["otx", "ioc", "pulse"]
                        + (["ransomware"] if flags["is_ransomware"] else [])
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "otx_pulse",
            "L3",
            "AlienVault OTX Pulse",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"pulses={count}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "otx_pulse",
            "L3",
            "AlienVault OTX Pulse",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


async def collect_cisa_ics(max_items: int | None = None) -> int:
    """
    L7 — CISA ICS / cybersecurity advisories.

    Prefer official RSS; if blocked (common 403 from Akamai/WAF), fall back to the
    community ICS Advisory Project CSV mirror on GitHub (derived from CISA ICS-CERT).
    """
    limit = max_items if max_items is not None else CISA_ICS_MAX_ITEMS
    t0 = time.perf_counter()
    errors: list[str] = []

    # 1) Official RSS candidates (browser-like headers help on some networks)
    browser_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        ),
        "Accept": "application/rss+xml, application/xml, text/xml, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.cisa.gov/news-events/cybersecurity-advisories",
    }
    for url in CISA_ADVISORIES_RSS_CANDIDATES:
        try:
            n = await collect_rss_layer(
                source_id="cisa_ics_rss",
                layer_id="L7",
                name="CISA Advisories RSS",
                url=url,
                darkweb_indirect=False,
                force_ransomware_scan=False,
                max_items=limit,
                extra_tags=["ot", "ot-gov", "official-gov", "ot-it", "cisa", "ics"],
                title_prefix="🏭 CISA ICS",
            )
            if n > 0:
                return n
            errors.append(f"{url} -> 0 entries")
        except Exception as e:
            errors.append(f"{url} -> {e}")

    # 2) GitHub CSV mirror of CISA ICS advisories
    try:
        n = await _collect_cisa_ics_from_github_csv(limit=limit)
        if n > 0:
            ms = int((time.perf_counter() - t0) * 1000)
            await _mark(
                "cisa_ics_rss",
                "L7",
                "CISA ICS Advisories",
                ok=True,
                count=n,
                latency_ms=ms,
                detail=(
                    f"source=ICS-Advisory-Project CSV mirror; "
                    f"official RSS blocked ({'; '.join(errors)[:180]})"
                ),
            )
            return n
        errors.append("github csv mirror -> 0")
    except Exception as e:
        errors.append(f"github csv -> {e}")

    ms = int((time.perf_counter() - t0) * 1000)
    await _mark(
        "cisa_ics_rss",
        "L7",
        "CISA ICS Advisories",
        ok=False,
        latency_ms=ms,
        error="; ".join(errors)[:500],
    )
    return 0


async def _collect_cisa_ics_from_github_csv(*, limit: int = 40) -> int:
    """Ingest recent CISA ICS advisories from icsadvprj/ICS-Advisory-Project CSV."""
    year = datetime.utcnow().year
    async with await _client() as client:
        api = await client.get(
            CISA_ICS_GITHUB_API,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/vnd.github+json",
            },
        )
        api.raise_for_status()
        listing = api.json()
        if not isinstance(listing, list):
            raise ValueError("unexpected GitHub contents payload")

        # Prefer current year CISA_ICS_ADV_YYYY_*.csv, then previous year
        def pick(y: int) -> dict | None:
            cands = [
                f
                for f in listing
                if f.get("name", "").startswith(f"CISA_ICS_ADV_{y}_")
                and f.get("name", "").endswith(".csv")
                and f.get("download_url")
            ]
            if not cands:
                return None
            # Newest filename last (date suffix)
            cands.sort(key=lambda x: x["name"])
            return cands[-1]

        chosen = pick(year) or pick(year - 1)
        if not chosen:
            # fall back to any CISA_ICS_ADV_*.csv
            cands = [
                f
                for f in listing
                if f.get("name", "").startswith("CISA_ICS_ADV_")
                and f.get("name", "").endswith(".csv")
                and "Master" not in f.get("name", "")
                and f.get("download_url")
            ]
            cands.sort(key=lambda x: x["name"])
            chosen = cands[-1] if cands else None
        if not chosen:
            raise FileNotFoundError("no CISA_ICS_ADV_*.csv in GitHub mirror")

        csv_url = chosen["download_url"]
        r = await client.get(
            csv_url, headers={"User-Agent": USER_AGENT, "Accept": "text/csv,*/*"}
        )
        r.raise_for_status()
        text = r.text

    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)

    def parse_date(s: str) -> datetime | None:
        s = (s or "").strip()
        for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%m/%d/%y"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None

    # Sort by release date desc
    rows.sort(
        key=lambda row: parse_date(row.get("Original_Release_Date") or "")
        or parse_date(row.get("Last_Updated") or "")
        or datetime.min,
        reverse=True,
    )

    count = 0
    for row in rows[:limit]:
        icsa = (row.get("ICS-CERT_Number") or "").strip()
        title = (row.get("ICS-CERT_Advisory_Title") or icsa or "ICS Advisory").strip()
        vendor = (row.get("Vendor") or "").strip()
        product = (row.get("Product") or row.get("Products_Affected") or "").strip()
        cve_raw = (row.get("CVE_Number") or "").strip()
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", cve_raw, flags=re.I)
        cve_id = cves[0].upper() if cves else None
        cvss_s = (row.get("Cumulative_CVSS") or "").strip()
        try:
            cvss = float(cvss_s) if cvss_s else None
        except ValueError:
            cvss = None
        severity = (row.get("CVSS_Severity") or "").strip()
        sector = (row.get("Critical_Infrastructure_Sector") or "").strip()
        cwe = (row.get("CWE_Number") or "").strip()
        released = (row.get("Original_Release_Date") or "").strip()
        updated = (row.get("Last_Updated") or "").strip()

        slug = icsa.lower() if icsa else ""
        url = (
            f"https://www.cisa.gov/news-events/ics-advisories/{slug}"
            if slug
            else "https://www.cisa.gov/news-events/ics-advisories"
        )

        title_zh = f"[CISA ICS] {icsa} — {title}" if icsa else f"[CISA ICS] {title}"
        title_en = title_zh
        summary_zh = (
            f"廠商/產品：{vendor} / {product}\n"
            f"CVSS：{cvss_s or '—'} ({severity or '—'})\n"
            f"CVE：{cve_raw or '—'}\n"
            f"CWE：{cwe or '—'}\n"
            f"關鍵基礎設施領域：{sector or '—'}\n"
            f"發布/更新：{released or '—'} / {updated or '—'}\n"
            f"來源：CISA ICS Advisory（GitHub ICS Advisory Project 鏡像）"
        )
        summary_en = (
            f"Vendor/Product: {vendor} / {product}\n"
            f"CVSS: {cvss_s or '—'} ({severity or '—'})\n"
            f"CVE: {cve_raw or '—'}\n"
            f"CWE: {cwe or '—'}\n"
            f"Critical infrastructure sector: {sector or '—'}\n"
            f"Released/Updated: {released or '—'} / {updated or '—'}\n"
            f"Source: CISA ICS Advisory (ICS Advisory Project CSV mirror)"
        )

        flags = enrich_flags(title, summary_en, vendor, product)
        is_ransom = flags["is_ransomware"]
        # OT critical manufacturing + high CVSS is elevated monitoring
        priority = assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=is_ransom,
            is_tw_industry=flags["is_tw_industry"],
            epss=None,
            source_count=1,
            layer_id="L7",
        )
        if priority == "P3" and cvss is not None and cvss >= 9.0:
            priority = "P2"
        elif priority == "P3" and (severity or "").lower() == "critical":
            priority = "P2"

        verification, admiralty = assign_verification(
            in_kev=False,
            layer_id="L7",
            source_count=1,
            is_darkweb_indirect=False,
        )
        # Official ICS advisory content (via trusted community mirror of CISA data)
        verification, admiralty = "confirmed", "A2"

        # Normalize release date to ISO-ish
        pub_dt = parse_date(released) or parse_date(updated)
        published_at = pub_dt.date().isoformat() if pub_dt else released or None

        await upsert_intel(
            {
                "id": _id("cisa-ics", icsa or title, cve_id or ""),
                "title": title_zh,
                "title_en": title_en,
                "summary": summary_zh,
                "summary_en": summary_en,
                "priority": priority,
                "verification": verification,
                "layer_id": "L7",
                "source_name": "CISA ICS Advisories",
                "sources_json": json.dumps(
                    ["CISA ICS", "ICS Advisory Project mirror"]
                ),
                "cve_id": cve_id,
                "product": product[:200],
                "vendor": vendor[:200],
                "is_ransomware": 1 if is_ransom else 0,
                "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                "tw_entities_json": json.dumps(
                    flags["tw_entities"], ensure_ascii=False
                ),
                "is_finance": 1 if flags["is_finance"] else 0,
                "finance_entities_json": json.dumps(
                    flags["finance_entities"], ensure_ascii=False
                ),
                "is_microsoft": 1 if flags["is_microsoft"] else 0,
                "ms_entities_json": json.dumps(
                    flags["ms_entities"], ensure_ascii=False
                ),
                "known_ransomware_campaign": 0,
                "epss": None,
                "cvss": cvss,
                "date_added": published_at,
                "published_at": published_at,
                "fetched_at": now_iso(),
                "url": url,
                "admiralty": admiralty,
                "raw_json": json.dumps(row, ensure_ascii=False)[:4000],
                "tags_json": json.dumps(
                    ["cisa", "ics", "ot", "ot-gov", "official-gov", "ot-it"]
                    + (["critical"] if (severity or "").lower() == "critical" else [])
                    + (["tw-industry"] if flags["is_tw_industry"] else [])
                    + (["finance"] if flags["is_finance"] else [])
                    + (["microsoft"] if flags["is_microsoft"] else [])
                ),
            }
        )
        count += 1

    return count


def _resolve_easm_targets() -> list[str]:
    """Merge configured IPs + DNS-resolved hostnames (unique, capped)."""
    import socket

    targets: list[str] = []
    seen: set[str] = set()

    def add(ip: str) -> None:
        ip = (ip or "").strip()
        if not ip or ip in seen:
            return
        # basic IPv4/IPv6 sanity
        if re.match(r"^[\d.:a-fA-F]+$", ip) is None:
            return
        seen.add(ip)
        targets.append(ip)

    for ip in EASM_WATCH_IPS:
        add(ip)

    for host in EASM_WATCH_HOSTS:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                add(info[4][0])
        except Exception:
            continue

    return targets[:EASM_MAX_TARGETS]


async def _upsert_easm_finding(
    *,
    source_id: str,
    source_name: str,
    ip: str,
    ports: list[Any],
    hostnames: list[str],
    vulns: list[str],
    cpes: list[str],
    tags: list[str],
    extra_summary: str = "",
    url: str = "",
) -> None:
    ports_s = ", ".join(str(p) for p in ports[:40]) if ports else "—"
    host_s = ", ".join(hostnames[:12]) if hostnames else "—"
    vuln_s = ", ".join(vulns[:20]) if vulns else "—"
    cpe_s = ", ".join(cpes[:12]) if cpes else "—"
    tag_s = ", ".join(tags[:12]) if tags else "—"

    title_zh = f"[EASM] {ip} 對外暴露端口 {len(ports) if ports else 0}"
    if vulns:
        title_zh = f"[EASM] {ip} 暴露且關聯 {len(vulns)} 個 CVE"
    title_en = title_zh

    summary_zh = (
        f"IP：{ip}\n主機名：{host_s}\n端口：{ports_s}\n"
        f"CVE/漏洞：{vuln_s}\nCPE：{cpe_s}\n標籤：{tag_s}\n"
        f"{extra_summary}"
    )
    summary_en = (
        f"IP: {ip}\nHostnames: {host_s}\nPorts: {ports_s}\n"
        f"Vulns: {vuln_s}\nCPEs: {cpe_s}\nTags: {tag_s}\n"
        f"{extra_summary}"
    )

    flags = enrich_flags(title_zh, summary_en, " ".join(hostnames), " ".join(cpes))
    cve_id = None
    if vulns:
        m = re.findall(r"CVE-\d{4}-\d{4,7}", " ".join(vulns), re.I)
        cve_id = m[0].upper() if m else None

    priority = assign_priority(
        in_kev=False,
        known_ransomware_campaign=False,
        is_ransomware=flags["is_ransomware"],
        is_tw_industry=flags["is_tw_industry"],
        epss=None,
        source_count=1,
        layer_id="L4",
    )
    # Open risky ports or known vulns → at least P2
    risky_ports = {21, 23, 445, 3389, 5900, 6379, 9200, 27017}
    open_set = {int(p) for p in ports if str(p).isdigit()}
    if vulns or (open_set & risky_ports):
        if priority == "P3":
            priority = "P2"

    verification, admiralty = assign_verification(
        in_kev=False,
        layer_id="L4",
        source_count=1,
        is_darkweb_indirect=False,
    )
    verification, admiralty = "credible", "B2"

    await upsert_intel(
        {
            "id": _id("easm", source_id, ip, ",".join(str(p) for p in (ports or [])[:8])),
            "title": title_zh,
            "title_en": title_en,
            "summary": summary_zh,
            "summary_en": summary_en,
            "priority": priority,
            "verification": verification,
            "layer_id": "L4",
            "source_name": source_name,
            "sources_json": json.dumps([source_name]),
            "cve_id": cve_id,
            "product": host_s if host_s != "—" else ip,
            "vendor": "EASM",
            "is_ransomware": 1 if flags["is_ransomware"] else 0,
            "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
            "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
            "is_finance": 1 if flags["is_finance"] else 0,
            "finance_entities_json": json.dumps(
                flags["finance_entities"], ensure_ascii=False
            ),
            "is_microsoft": 1 if flags["is_microsoft"] else 0,
            "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
            "known_ransomware_campaign": 0,
            "epss": None,
            "cvss": None,
            "date_added": now_iso()[:10],
            "published_at": now_iso()[:10],
            "fetched_at": now_iso(),
            "url": url or f"https://www.shodan.io/host/{ip}",
            "admiralty": admiralty,
            "raw_json": json.dumps(
                {
                    "ip": ip,
                    "ports": ports[:50] if ports else [],
                    "vulns": vulns[:30] if vulns else [],
                    "hostnames": hostnames[:20] if hostnames else [],
                },
                ensure_ascii=False,
            )[:4000],
            "tags_json": json.dumps(
                ["easm", "attack-surface"]
                + (["has-vulns"] if vulns else [])
                + (["tw-industry"] if flags["is_tw_industry"] else [])
            ),
        }
    )


async def collect_shodan_easm() -> int:
    """
    L4 Shodan:
      1) Free InternetDB (no key) for EASM_WATCH_IPS / resolved EASM_WATCH_HOSTS
      2) Optional SHODAN_API_KEY for deeper host enrichment
    """
    t0 = time.perf_counter()
    targets = _resolve_easm_targets()
    count = 0

    if not targets and not SHODAN_API_KEY:
        await upsert_source_health(
            {
                "source_id": "shodan",
                "layer_id": "L4",
                "name": "Shodan InternetDB / API",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "免金鑰可用 InternetDB：設定 EASM_WATCH_IPS=x.x.x.x "
                    "或 EASM_WATCH_HOSTS=edge.example.com；"
                    "進階可設 SHODAN_API_KEY"
                ),
            }
        )
        return 0

    try:
        async with await _client() as client:
            # Prefer InternetDB for each target (free)
            for ip in targets:
                try:
                    r = await client.get(
                        f"{SHODAN_INTERNETDB_URL}/{ip}",
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                        },
                    )
                    if r.status_code == 404:
                        # no data in InternetDB
                        continue
                    r.raise_for_status()
                    data = r.json()
                    ports = data.get("ports") or []
                    hostnames = data.get("hostnames") or []
                    vulns = data.get("vulns") or []
                    cpes = data.get("cpes") or []
                    tags = data.get("tags") or []
                    if not ports and not vulns and not hostnames:
                        continue
                    await _upsert_easm_finding(
                        source_id="shodan-idb",
                        source_name="Shodan InternetDB",
                        ip=ip,
                        ports=ports,
                        hostnames=hostnames,
                        vulns=vulns,
                        cpes=cpes,
                        tags=tags,
                        extra_summary="來源：Shodan InternetDB（免 API 金鑰）\n",
                        url=f"https://www.shodan.io/host/{ip}",
                    )
                    count += 1
                except Exception:
                    continue

                # Optional API enrichment
                if SHODAN_API_KEY:
                    try:
                        hr = await client.get(
                            f"{SHODAN_API_HOST}/{ip}",
                            params={"key": SHODAN_API_KEY},
                            headers={"User-Agent": USER_AGENT},
                        )
                        if hr.status_code == 200:
                            h = hr.json()
                            ports2 = h.get("ports") or ports
                            hostnames2 = h.get("hostnames") or hostnames
                            vulns2 = list(h.get("vulns") or vulns or [])
                            await _upsert_easm_finding(
                                source_id="shodan-api",
                                source_name="Shodan API",
                                ip=ip,
                                ports=ports2,
                                hostnames=hostnames2,
                                vulns=vulns2,
                                cpes=cpes,
                                tags=tags,
                                extra_summary=(
                                    f"org={h.get('org') or '—'}; "
                                    f"isp={h.get('isp') or '—'}; "
                                    f"os={h.get('os') or '—'}\n"
                                    "來源：Shodan Host API\n"
                                ),
                                url=f"https://www.shodan.io/host/{ip}",
                            )
                            count += 1
                    except Exception:
                        pass

        ms = int((time.perf_counter() - t0) * 1000)
        mode = []
        mode.append("internetdb")
        if SHODAN_API_KEY:
            mode.append("api-key")
        await _mark(
            "shodan",
            "L4",
            "Shodan InternetDB / API",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=(
                f"targets={len(targets)}; modes={'+'.join(mode)}; findings={count}"
            ),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "shodan",
            "L4",
            "Shodan InternetDB / API",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


async def collect_censys_easm() -> int:
    """
    L4 Censys host lookup for watch IPs.
    Requires CENSYS_API_ID + CENSYS_API_SECRET (free tier host lookup supported).
    """
    t0 = time.perf_counter()
    targets = _resolve_easm_targets()

    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        await upsert_source_health(
            {
                "source_id": "censys",
                "layer_id": "L4",
                "name": "Censys host lookup",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "需 CENSYS_API_ID + CENSYS_API_SECRET（免費帳號可申請），"
                    "並設定 EASM_WATCH_IPS 或 EASM_WATCH_HOSTS"
                ),
            }
        )
        return 0

    if not targets:
        await upsert_source_health(
            {
                "source_id": "censys",
                "layer_id": "L4",
                "name": "Censys host lookup",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "金鑰已設定，但未設定監控目標："
                    "EASM_WATCH_IPS / EASM_WATCH_HOSTS"
                ),
            }
        )
        return 0

    count = 0
    try:
        auth = (CENSYS_API_ID, CENSYS_API_SECRET)
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        ) as client:
            for ip in targets:
                try:
                    r = await client.get(f"{CENSYS_HOST_API}/{ip}", auth=auth)
                    if r.status_code in (404, 422):
                        continue
                    if r.status_code == 401:
                        raise RuntimeError("Censys auth failed (check API ID/Secret)")
                    r.raise_for_status()
                    body = r.json()
                    result = body.get("result") or body
                    services = result.get("services") or []
                    ports = []
                    for s in services:
                        p = s.get("port")
                        if p is not None:
                            ports.append(p)
                    dns = result.get("dns") or {}
                    hostnames = []
                    if isinstance(dns, dict):
                        names = dns.get("names") or dns.get("reverse_dns") or []
                        if isinstance(names, dict):
                            hostnames = list(names.keys())[:20]
                        elif isinstance(names, list):
                            hostnames = [str(n) for n in names[:20]]
                    # Censys v2 may put names at top-level
                    for n in result.get("name") and [result.get("name")] or []:
                        if n and n not in hostnames:
                            hostnames.append(n)

                    vulns: list[str] = []
                    for s in services:
                        for v in s.get("vulns") or []:
                            if isinstance(v, str):
                                vulns.append(v)
                            elif isinstance(v, dict) and v.get("id"):
                                vulns.append(str(v["id"]))

                    await _upsert_easm_finding(
                        source_id="censys",
                        source_name="Censys",
                        ip=ip,
                        ports=ports,
                        hostnames=hostnames,
                        vulns=vulns,
                        cpes=[],
                        tags=[],
                        extra_summary=(
                            f"services={len(services)}; "
                            f"autonomous_system="
                            f"{(result.get('autonomous_system') or {}).get('name') or '—'}\n"
                            "來源：Censys Host API\n"
                        ),
                        url=f"https://search.censys.io/hosts/{ip}",
                    )
                    count += 1
                except Exception:
                    continue

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "censys",
            "L4",
            "Censys host lookup",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"targets={len(targets)}; findings={count}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "censys",
            "L4",
            "Censys host lookup",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


def _strip_html(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", s).strip()


async def collect_hibp_breaches(
    *,
    recent_days: int | None = None,
    max_items: int | None = None,
) -> int:
    """
    L5 — Have I Been Pwned public breach catalog (no API key required).

    Paid HIBP_API_KEY + HIBP_WATCH_DOMAINS enable optional domain search
    (breacheddomain) which surfaces corporate email exposure.
    """
    t0 = time.perf_counter()
    days = recent_days if recent_days is not None else HIBP_RECENT_DAYS
    limit = max_items if max_items is not None else HIBP_MAX_ITEMS
    count = 0
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }
        if HIBP_API_KEY:
            headers["hibp-api-key"] = HIBP_API_KEY

        async with await _client() as client:
            r = await client.get(HIBP_BREACHES_URL, headers=headers)
            r.raise_for_status()
            breaches = r.json()
            if not isinstance(breaches, list):
                raise ValueError("unexpected HIBP breaches payload")

            # Optional paid: domain email breach presence
            domain_hits: list[dict[str, Any]] = []
            if HIBP_API_KEY and HIBP_WATCH_DOMAINS:
                for domain in HIBP_WATCH_DOMAINS[:10]:
                    try:
                        dr = await client.get(
                            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                            headers=headers,
                        )
                        if dr.status_code == 200:
                            data = dr.json() or {}
                            domain_hits.append(
                                {"domain": domain, "aliases": len(data), "raw": data}
                            )
                        elif dr.status_code == 404:
                            # no breached emails for domain
                            domain_hits.append(
                                {"domain": domain, "aliases": 0, "raw": {}}
                            )
                    except Exception:
                        continue

        cutoff = datetime.utcnow().date()
        from datetime import timedelta

        min_date = cutoff - timedelta(days=max(1, days))

        # Sort by AddedDate desc (when HIBP cataloged the breach)
        def added_key(b: dict) -> str:
            return b.get("AddedDate") or b.get("BreachDate") or ""

        breaches = sorted(breaches, key=added_key, reverse=True)

        recent: list[dict] = []
        for b in breaches:
            added = (b.get("AddedDate") or "")[:10]
            try:
                ad = datetime.strptime(added, "%Y-%m-%d").date()
            except ValueError:
                ad = None
            if ad is not None and ad < min_date:
                # list is sorted; can stop early once past window... but ModifiedDate
                # may vary; keep scanning a bit for safety
                continue
            recent.append(b)
            if len(recent) >= limit:
                break

        # Always ensure latest few if window empty (catalog edge cases)
        if not recent:
            recent = breaches[: min(10, limit)]

        for b in recent:
            name = b.get("Name") or b.get("Title") or "unknown"
            title = b.get("Title") or name
            domain = b.get("Domain") or ""
            desc = _strip_html(b.get("Description") or "")[:1200]
            breach_date = (b.get("BreachDate") or "")[:10]
            added_date = (b.get("AddedDate") or "")[:10]
            pwn = b.get("PwnCount")
            data_classes = b.get("DataClasses") or []
            is_verified = bool(b.get("IsVerified"))
            is_sensitive = bool(b.get("IsSensitive"))
            is_spam = bool(b.get("IsSpamList"))

            # Skip pure spam lists for SOC signal-to-noise
            if is_spam and not is_verified:
                continue

            title_zh = f"[HIBP 外洩] {title}" + (f" ({domain})" if domain else "")
            title_en = f"[HIBP Breach] {title}" + (f" ({domain})" if domain else "")
            summary_zh = (
                f"{desc}\n"
                f"網域：{domain or '—'}｜外洩日：{breach_date}｜目錄收錄：{added_date}\n"
                f"影響筆數：{pwn if pwn is not None else '—'}｜"
                f"驗證：{'是' if is_verified else '否'}｜敏感：{'是' if is_sensitive else '否'}\n"
                f"資料類型：{', '.join(data_classes[:12])}"
            )
            summary_en = (
                f"{desc}\n"
                f"Domain: {domain or '—'} | BreachDate: {breach_date} | Added: {added_date}\n"
                f"PwnCount: {pwn if pwn is not None else '—'} | "
                f"Verified: {is_verified} | Sensitive: {is_sensitive}\n"
                f"Data classes: {', '.join(data_classes[:12])}"
            )

            # Match categories on name/domain primarily (HIBP HTML often cites
            # many third parties and "data leak", which would false-positive).
            flags = enrich_flags(title, domain, domain, "")
            # Credential catalog ≠ ransomware unless text explicitly says so
            ransom_blob = f"{title} {desc}".lower()
            is_ransom = any(
                k in ransom_blob
                for k in (
                    "ransomware",
                    "勒索軟體",
                    "勒索病毒",
                    "lockbit",
                    "double extortion",
                    "雙重勒索",
                )
            )
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=is_ransom,
                is_tw_industry=flags["is_tw_industry"],
                epss=None,
                source_count=1,
                layer_id="L5",
            )
            # Large recent public breaches with passwords elevate monitoring
            if (
                priority == "P3"
                and isinstance(pwn, int)
                and pwn >= 1_000_000
                and any(
                    dc.lower() in ("passwords", "password hints", "email addresses")
                    for dc in data_classes
                )
            ):
                priority = "P2"

            verification, admiralty = assign_verification(
                in_kev=False,
                layer_id="L5",
                source_count=1,
                is_darkweb_indirect=False,
            )
            # HIBP catalog is a trusted public authority for breach existence
            if is_verified:
                verification, admiralty = "confirmed", "A2"
            else:
                verification, admiralty = "credible", "B2"

            await upsert_intel(
                {
                    "id": _id("hibp", name, added_date or breach_date),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L5",
                    "source_name": "Have I Been Pwned",
                    "sources_json": json.dumps(["Have I Been Pwned"]),
                    "cve_id": None,
                    "product": domain,
                    "vendor": title,
                    "is_ransomware": 1 if is_ransom else 0,
                    "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                    "tw_entities_json": json.dumps(
                        flags["tw_entities"], ensure_ascii=False
                    ),
                    "is_finance": 1 if flags["is_finance"] else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if flags["is_microsoft"] else 0,
                    "ms_entities_json": json.dumps(
                        flags["ms_entities"], ensure_ascii=False
                    ),
                    "known_ransomware_campaign": 0,
                    "epss": None,
                    "cvss": None,
                    "date_added": added_date or None,
                    "published_at": breach_date or added_date,
                    "fetched_at": now_iso(),
                    "url": f"https://haveibeenpwned.com/Breach/{name}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(
                        {
                            "Name": name,
                            "Domain": domain,
                            "PwnCount": pwn,
                            "DataClasses": data_classes,
                        },
                        ensure_ascii=False,
                    )[:4000],
                    "tags_json": json.dumps(
                        ["hibp", "breach", "credentials"]
                        + (["sensitive"] if is_sensitive else [])
                        + (["tw-industry"] if flags["is_tw_industry"] else [])
                        + (["finance"] if flags["is_finance"] else [])
                        + (["microsoft"] if flags["is_microsoft"] else [])
                    ),
                }
            )
            count += 1

        # Surface domain-watch results as intel when paid key is active
        for hit in domain_hits:
            if hit.get("aliases", 0) <= 0:
                continue
            domain = hit["domain"]
            title_zh = f"[HIBP 網域監控] {domain} 出現外洩信箱別名"
            title_en = f"[HIBP Domain Watch] {domain} has breached email aliases"
            summary = (
                f"Paid HIBP breacheddomain API: {domain} has "
                f"{hit['aliases']} alias entries in breach corpus. "
                f"Review corporate credential hygiene / MFA / password resets."
            )
            await upsert_intel(
                {
                    "id": _id("hibp-domain", domain, now_iso()[:10]),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary,
                    "summary_en": summary,
                    "priority": "P1",
                    "verification": "confirmed",
                    "layer_id": "L5",
                    "source_name": "Have I Been Pwned (domain)",
                    "sources_json": json.dumps(["Have I Been Pwned domain search"]),
                    "cve_id": None,
                    "product": domain,
                    "vendor": domain,
                    "is_ransomware": 0,
                    "is_tw_industry": 0,
                    "tw_entities_json": "[]",
                    "is_finance": 0,
                    "finance_entities_json": "[]",
                    "is_microsoft": 0,
                    "ms_entities_json": "[]",
                    "known_ransomware_campaign": 0,
                    "epss": None,
                    "cvss": None,
                    "date_added": now_iso()[:10],
                    "published_at": now_iso()[:10],
                    "fetched_at": now_iso(),
                    "url": "https://haveibeenpwned.com/DomainSearch",
                    "admiralty": "A2",
                    "raw_json": json.dumps(
                        {"domain": domain, "alias_count": hit["aliases"]},
                        ensure_ascii=False,
                    )[:2000],
                    "tags_json": json.dumps(
                        ["hibp", "breach", "domain-watch", "credentials"]
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        detail_parts = [
            f"recent_days={days}",
            f"ingested={count}",
            "mode=public_catalog",
        ]
        if HIBP_API_KEY:
            detail_parts.append("api_key=set")
            if HIBP_WATCH_DOMAINS:
                detail_parts.append(
                    f"domains={','.join(HIBP_WATCH_DOMAINS[:5])}"
                )
            else:
                detail_parts.append("domains=none (set HIBP_WATCH_DOMAINS)")
        else:
            detail_parts.append(
                "api_key=none (catalog free; domain search optional via HIBP_API_KEY)"
            )

        await _mark(
            "hibp",
            "L5",
            "Have I Been Pwned",
            ok=True,
            count=count,
            latency_ms=ms,
            detail="; ".join(detail_parts),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "hibp",
            "L5",
            "Have I Been Pwned",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


async def collect_threatfox(
    *,
    max_families: int | None = None,
    min_confidence: int | None = None,
) -> int:
    """
    L3 — abuse.ch ThreatFox community IOCs.

    Free path: public recent JSON export (no key).
    Optional ABUSECH_AUTH_KEY / THREATFOX_API_KEY for POST API get_iocs.
    Aggregates by malware family to avoid flooding the dashboard.
    """
    t0 = time.perf_counter()
    fam_cap = max_families if max_families is not None else THREATFOX_MAX_FAMILIES
    min_conf = (
        min_confidence if min_confidence is not None else THREATFOX_MIN_CONFIDENCE
    )
    count = 0
    mode = "export"

    try:
        rows: list[dict[str, Any]] = []
        async with await _client() as client:
            # Optional authenticated API (last N days)
            if ABUSECH_AUTH_KEY:
                try:
                    r = await client.post(
                        THREATFOX_API_URL,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "Auth-Key": ABUSECH_AUTH_KEY,
                        },
                        json={"query": "get_iocs", "days": 3},
                        timeout=90.0,
                    )
                    if r.status_code == 200:
                        payload = r.json()
                        if payload.get("query_status") == "ok" and payload.get("data"):
                            rows = list(payload["data"])
                            mode = "api+auth"
                except Exception:
                    rows = []

            # Free public recent export
            if not rows:
                r = await client.get(
                    THREATFOX_RECENT_EXPORT,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "application/json",
                    },
                    timeout=120.0,
                )
                r.raise_for_status()
                payload = r.json()
                if isinstance(payload, dict):
                    for tf_key, items in payload.items():
                        if isinstance(items, list):
                            for it in items:
                                if isinstance(it, dict):
                                    it = {**it, "id": it.get("id") or tf_key}
                                    rows.append(it)
                        elif isinstance(items, dict):
                            rows.append({**items, "id": items.get("id") or tf_key})
                elif isinstance(payload, list):
                    rows = payload
                mode = "export/json/recent"

        # Filter by confidence
        filtered: list[dict[str, Any]] = []
        for row in rows:
            try:
                conf = int(row.get("confidence_level") or 0)
            except (TypeError, ValueError):
                conf = 0
            if conf < min_conf:
                continue
            filtered.append(row)

        # Aggregate by malware family
        families: dict[str, dict[str, Any]] = {}
        for row in filtered:
            fam = (
                row.get("malware_printable")
                or row.get("malware")
                or "Unknown malware"
            )
            fam = str(fam).strip() or "Unknown malware"
            bucket = families.setdefault(
                fam,
                {
                    "family": fam,
                    "malware_id": row.get("malware") or "",
                    "count": 0,
                    "max_conf": 0,
                    "threat_types": set(),
                    "ioc_types": set(),
                    "samples": [],
                    "tags": set(),
                    "first_seen": row.get("first_seen_utc") or "",
                    "references": [],
                },
            )
            bucket["count"] += 1
            try:
                conf = int(row.get("confidence_level") or 0)
            except (TypeError, ValueError):
                conf = 0
            bucket["max_conf"] = max(bucket["max_conf"], conf)
            if row.get("threat_type"):
                bucket["threat_types"].add(str(row["threat_type"]))
            if row.get("ioc_type"):
                bucket["ioc_types"].add(str(row["ioc_type"]))
            tags = row.get("tags") or ""
            if isinstance(tags, str) and tags:
                for t in tags.replace(";", ",").split(","):
                    t = t.strip()
                    if t:
                        bucket["tags"].add(t)
            elif isinstance(tags, list):
                for t in tags:
                    if t:
                        bucket["tags"].add(str(t))
            if len(bucket["samples"]) < 6:
                val = row.get("ioc_value") or row.get("ioc") or ""
                typ = row.get("ioc_type") or "?"
                if val:
                    bucket["samples"].append(f"{typ}:{val}")
            ref = row.get("reference") or ""
            if ref and ref not in bucket["references"] and len(bucket["references"]) < 3:
                bucket["references"].append(str(ref))
            fs = row.get("first_seen_utc") or ""
            if fs and (not bucket["first_seen"] or fs > bucket["first_seen"]):
                bucket["first_seen"] = fs

        # Prioritize ransomware-ish + volume
        def fam_score(b: dict[str, Any]) -> tuple:
            tags_l = " ".join(b["tags"]).lower()
            ransom = 1 if any(
                k in tags_l or k in b["family"].lower()
                for k in ("ransom", "locker", "lockbit", "blackcat", "akira")
            ) else 0
            return (ransom, b["count"], b["max_conf"])

        ranked = sorted(families.values(), key=fam_score, reverse=True)[:fam_cap]

        for b in ranked:
            fam = b["family"]
            threat_s = ", ".join(sorted(b["threat_types"])) or "—"
            ioc_s = ", ".join(sorted(b["ioc_types"])) or "—"
            tag_s = ", ".join(sorted(b["tags"])[:12]) or "—"
            samples = "\n".join(f"  - {s}" for s in b["samples"]) or "  —"
            refs = b["references"][0] if b["references"] else "https://threatfox.abuse.ch/"

            title_zh = f"[ThreatFox] {fam} — {b['count']} IOCs (max conf {b['max_conf']})"
            title_en = title_zh
            summary_zh = (
                f"abuse.ch ThreatFox 社群 IOC 彙整\n"
                f"惡意程式家族：{fam} ({b.get('malware_id') or '—'})\n"
                f"IOC 數量（近期匯出，conf≥{min_conf}）：{b['count']}\n"
                f"最高信心：{b['max_conf']}\n"
                f"威脅類型：{threat_s}\n"
                f"IOC 類型：{ioc_s}\n"
                f"標籤：{tag_s}\n"
                f"最新觀察：{b['first_seen'] or '—'}\n"
                f"樣本 IOC：\n{samples}\n"
                f"來源模式：{mode}"
            )
            summary_en = (
                f"abuse.ch ThreatFox community IOC rollup\n"
                f"Malware family: {fam} ({b.get('malware_id') or '—'})\n"
                f"IOC count (recent export, conf≥{min_conf}): {b['count']}\n"
                f"Max confidence: {b['max_conf']}\n"
                f"Threat types: {threat_s}\n"
                f"IOC types: {ioc_s}\n"
                f"Tags: {tag_s}\n"
                f"Latest seen: {b['first_seen'] or '—'}\n"
                f"Sample IOCs:\n{samples}\n"
                f"Mode: {mode}"
            )

            flags = enrich_flags(fam, tag_s + " " + threat_s)
            # ThreatFox is malware/IOC — ransomware if tag/family suggests
            is_ransom = flags["is_ransomware"] or any(
                k in (tag_s + " " + fam).lower()
                for k in ("ransom", "locker", "lockbit", "blackcat", "akira", "clop")
            )
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=is_ransom,
                is_tw_industry=flags["is_tw_industry"],
                epss=None,
                source_count=1,
                layer_id="L3",
            )
            if priority == "P3" and (b["count"] >= 50 or b["max_conf"] >= 90):
                priority = "P2"

            verification, admiralty = "credible", "B2"

            await upsert_intel(
                {
                    "id": _id("threatfox", fam, str(b["count"]), b["first_seen"][:10]),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L3",
                    "source_name": "abuse.ch ThreatFox",
                    "sources_json": json.dumps(["abuse.ch ThreatFox"]),
                    "cve_id": None,
                    "product": fam,
                    "vendor": "ThreatFox",
                    "is_ransomware": 1 if is_ransom else 0,
                    "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                    "tw_entities_json": json.dumps(
                        flags["tw_entities"], ensure_ascii=False
                    ),
                    "is_finance": 1 if flags["is_finance"] else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if flags["is_microsoft"] else 0,
                    "ms_entities_json": json.dumps(
                        flags["ms_entities"], ensure_ascii=False
                    ),
                    "known_ransomware_campaign": 1 if is_ransom else 0,
                    "epss": None,
                    "cvss": None,
                    "date_added": (b["first_seen"] or "")[:10] or now_iso()[:10],
                    "published_at": b["first_seen"] or None,
                    "fetched_at": now_iso(),
                    "url": refs if refs.startswith("http") else "https://threatfox.abuse.ch/",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(
                        {
                            "family": fam,
                            "count": b["count"],
                            "max_conf": b["max_conf"],
                            "samples": b["samples"],
                        },
                        ensure_ascii=False,
                    )[:4000],
                    "tags_json": json.dumps(
                        ["threatfox", "ioc", "malware"]
                        + (["ransomware"] if is_ransom else [])
                        + list(sorted(b["tags"]))[:8]
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "abusech_threatfox",
            "L3",
            "abuse.ch ThreatFox",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=(
                f"mode={mode}; raw_iocs={len(rows)}; "
                f"conf>={min_conf}; families={count}"
                + ("; auth=set" if ABUSECH_AUTH_KEY else "; auth=none(free export)")
            ),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "abusech_threatfox",
            "L3",
            "abuse.ch ThreatFox",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


async def _upsert_ransom_victim_item(
    *,
    source_id: str,
    source_name: str,
    victim: str,
    group: str,
    description: str = "",
    country: str = "",
    website: str = "",
    activity: str = "",
    discovered: str = "",
    published: str = "",
    url: str = "",
    extra_sources: list[str] | None = None,
    dual_verified: bool = False,
) -> None:
    """Shared L6 ransomware-victim card builder (leak-site indirect)."""
    victim = (victim or "").strip() or "unknown-victim"
    group = (group or "").strip() or "unknown-group"
    blob_parts = [victim, group, description, country, website, activity]
    flags = enrich_flags(victim, " ".join(blob_parts), website, "")
    is_ransom = True  # victim listing from ransomware tracker
    is_tw = flags["is_tw_industry"]
    is_finance = flags["is_finance"]
    is_ms = flags["is_microsoft"]
    # Country TW is industry-adjacent for Taiwan SOC
    if (country or "").upper() in ("TW", "TWN") or "taiwan" in (country or "").lower():
        # keep is_tw only if watchlist hit; still tag country in summary
        pass

    sources = [source_name] + (extra_sources or [])
    source_count = len(sources) if dual_verified else 1
    if dual_verified:
        source_count = max(2, source_count)
    # Spec: single-source leak-site → P3 human review queue only
    force_p3 = not dual_verified

    priority = assign_priority(
        in_kev=False,
        known_ransomware_campaign=False,
        is_ransomware=is_ransom,
        is_tw_industry=is_tw and dual_verified,
        epss=None,
        source_count=source_count,
        layer_id="L6",
        force_p3_review=force_p3,
    )
    rz, re_ = explain_priority(
        priority=priority,
        is_ransomware=is_ransom,
        is_tw_industry=is_tw,
        source_count=source_count,
        dual_verified=dual_verified,
        forced_p3_review=force_p3,
    )
    verification, admiralty = assign_verification(
        in_kev=False,
        layer_id="L6",
        source_count=source_count,
        is_darkweb_indirect=True,
    )
    if dual_verified:
        verification, admiralty = "credible", "B2"
    else:
        verification, admiralty = "unverified", "C3"

    sop = pick_sop(
        priority=priority,
        is_ransomware=is_ransom,
        is_tw_industry=is_tw,
        is_microsoft=is_ms,
        verification=verification,
        is_darkweb=True,
        is_breach=True,
    )
    assets = guess_assets(flags, group, website)

    title_core = f"{victim} — claimed by {group}"
    title_zh = f"🔐 勒索受駭｜{title_core}"
    title_en = f"🔐 Ransom victim｜{title_core}"
    if is_tw:
        title_zh = f"🇹🇼 台灣電子／半導體｜{title_zh}"
        title_en = f"🇹🇼 TW Electronics/Semi｜{title_en}"
    if is_finance:
        title_zh = f"💰 金融相關｜{title_zh}"
        title_en = f"💰 Finance｜{title_en}"
    if not dual_verified:
        title_zh = f"[未核實 Unverified] {title_zh}"
        title_en = f"[Unverified] {title_en}"

    summary_zh = (
        f"受駭組織：{victim}\n"
        f"勒索集團：{group}\n"
        f"國家：{country or '—'}｜產業：{activity or '—'}\n"
        f"網站：{website or '—'}\n"
        f"發現/公布：{discovered or '—'} / {published or '—'}\n"
        f"{(description or '')[:800]}\n"
        f"來源：{', '.join(sources)}（暗網洩漏站間接 — "
        f"{'雙源可信' if dual_verified else '單源未核實 → P3 複核佇列'}）\n"
        f"{rz}"
    )
    summary_en = (
        f"Victim: {victim}\n"
        f"Group: {group}\n"
        f"Country: {country or '—'} | Sector: {activity or '—'}\n"
        f"Website: {website or '—'}\n"
        f"Discovered/Published: {discovered or '—'} / {published or '—'}\n"
        f"{(description or '')[:800]}\n"
        f"Source: {', '.join(sources)} (indirect leak-site — "
        f"{'dual-source credible' if dual_verified else 'single-source → P3 review'})\n"
        f"{re_}"
    )

    link = url or (
        f"https://www.ransomware.live/"
        if "ransomware.live" in source_name.lower()
        else "https://www.ransomlook.io/"
    )

    await upsert_intel(
        {
            "id": _id(source_id, victim, group, discovered or published or ""),
            "title": title_zh,
            "title_en": title_en,
            "summary": summary_zh,
            "summary_en": summary_en,
            "priority": priority,
            "priority_rationale": rz,
            "priority_rationale_en": re_,
            "verification": verification,
            "layer_id": "L6",
            "source_name": source_name,
            "sources_json": json.dumps(sources),
            "cve_id": None,
            "product": website or "",
            "vendor": group,
            "is_ransomware": 1,
            "is_tw_industry": 1 if is_tw else 0,
            "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
            "is_finance": 1 if is_finance else 0,
            "finance_entities_json": json.dumps(
                flags["finance_entities"], ensure_ascii=False
            ),
            "is_microsoft": 1 if is_ms else 0,
            "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
            "known_ransomware_campaign": 1,
            "epss": None,
            "cvss": None,
            "date_added": (discovered or published or "")[:10] or None,
            "published_at": published or discovered or None,
            "fetched_at": now_iso(),
            "url": link,
            "admiralty": admiralty,
            "evidence_count": source_count,
            "assets": assets,
            "sop_id": sop["sop_id"],
            "sop_zh": sop["sop_zh"],
            "sop_en": sop["sop_en"],
            "owner": sop["owner"],
            "sla_hours": sop["sla_hours"],
            "is_live": 0,
            "raw_json": json.dumps(
                {
                    "victim": victim,
                    "group": group,
                    "country": country,
                    "website": website,
                    "activity": activity,
                },
                ensure_ascii=False,
            )[:4000],
            "tags_json": json.dumps(
                ["ransomware", "leak-site", "darkweb-indirect"]
                + (["dual-source"] if dual_verified else ["unverified"])
                + (["tw-industry"] if is_tw else [])
                + (["finance"] if is_finance else [])
                + ([f"country:{(country or '').upper()}"] if country else [])
            ),
        }
    )


async def collect_ransomware_live(max_items: int | None = None) -> int:
    """L6 — Ransomware.live recent victims (data dump or optional PRO API)."""
    t0 = time.perf_counter()
    limit = max_items if max_items is not None else RANSOMWARE_LIVE_MAX_ITEMS
    count = 0
    detail = ""
    try:
        rows: list[dict[str, Any]] = []
        async with await _client() as client:
            # Prefer free PRO recent if key set
            if RANSOMWARE_LIVE_API_KEY:
                try:
                    pr = await client.get(
                        RANSOMWARE_LIVE_PRO_RECENT,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                            "X-API-KEY": RANSOMWARE_LIVE_API_KEY,
                        },
                    )
                    if pr.status_code == 200:
                        payload = pr.json()
                        if isinstance(payload, list):
                            rows = payload
                        elif isinstance(payload, dict):
                            rows = (
                                payload.get("victims")
                                or payload.get("data")
                                or payload.get("items")
                                or []
                            )
                        detail = "source=api-pro"
                except Exception:
                    rows = []

            # Try free v2 REST
            if not rows:
                try:
                    vr = await client.get(
                        RANSOMWARE_LIVE_API_V2,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                        },
                    )
                    if vr.status_code == 200 and "json" in (
                        vr.headers.get("content-type") or ""
                    ):
                        payload = vr.json()
                        if isinstance(payload, list):
                            rows = payload
                            detail = "source=api-v2"
                except Exception:
                    pass

            # Reliable public dump
            if not rows:
                dr = await client.get(
                    RANSOMWARE_LIVE_VICTIMS_URL,
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                    timeout=120.0,
                )
                dr.raise_for_status()
                payload = dr.json()
                if not isinstance(payload, list):
                    raise ValueError("unexpected victims.json payload")
                rows = payload
                detail = "source=data.ransomware.live/victims.json"

        def sort_key(x: dict) -> str:
            return (
                str(x.get("discovered") or "")
                or str(x.get("published") or "")
                or str(x.get("attackdate") or "")
            )

        rows = sorted(rows, key=sort_key, reverse=True)[:limit]

        for row in rows:
            victim = (
                row.get("post_title")
                or row.get("victim")
                or row.get("name")
                or row.get("website")
                or ""
            )
            group = row.get("group_name") or row.get("group") or ""
            await _upsert_ransom_victim_item(
                source_id="ransomlive",
                source_name="Ransomware.live",
                victim=str(victim),
                group=str(group),
                description=str(row.get("description") or "")[:900],
                country=str(row.get("country") or ""),
                website=str(row.get("website") or ""),
                activity=str(row.get("activity") or row.get("sector") or ""),
                discovered=str(row.get("discovered") or ""),
                published=str(row.get("published") or row.get("attackdate") or ""),
                url=str(
                    row.get("post_url")
                    or row.get("url")
                    or "https://www.ransomware.live/"
                ),
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "ransomware_live",
            "L6",
            "Ransomware.live",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"{detail}; ingested={count}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "ransomware_live",
            "L6",
            "Ransomware.live",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


async def collect_ransomlook(max_items: int | None = None) -> int:
    """L6 — RansomLook recent posts (open API)."""
    t0 = time.perf_counter()
    limit = max_items if max_items is not None else RANSOMLOOK_MAX_ITEMS
    count = 0
    try:
        rows: list[dict[str, Any]] = []
        async with await _client() as client:
            r = await client.get(
                RANSOMLOOK_RECENT_URL,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            if r.status_code == 200:
                payload = r.json()
                if isinstance(payload, list):
                    rows = payload
                elif isinstance(payload, dict):
                    rows = payload.get("posts") or payload.get("data") or []

            # RSS fallback
            if not rows:
                rr = await client.get(
                    RANSOMLOOK_RSS_URL,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "application/rss+xml,application/xml,text/xml,*/*",
                    },
                )
                rr.raise_for_status()
                feed = feedparser.parse(rr.text)
                for e in feed.entries[:limit]:
                    title = (e.get("title") or "").strip()
                    # Typical "victim - group" or free text
                    group = ""
                    victim = title
                    if " - " in title:
                        parts = title.split(" - ", 1)
                        victim, group = parts[0].strip(), parts[1].strip()
                    rows.append(
                        {
                            "post_title": victim,
                            "group_name": group,
                            "discovered": e.get("published") or "",
                            "description": re.sub(
                                r"<[^>]+>", " ", e.get("summary") or ""
                            )[:900],
                            "link": e.get("link") or "",
                        }
                    )

        rows = rows[:limit]
        for row in rows:
            victim = str(
                row.get("post_title") or row.get("title") or row.get("victim") or ""
            )
            group = str(
                row.get("group_name") or row.get("group") or row.get("gang") or ""
            )
            await _upsert_ransom_victim_item(
                source_id="ransomlook",
                source_name="RansomLook",
                victim=victim,
                group=group,
                description=str(row.get("description") or "")[:900],
                country=str(row.get("country") or ""),
                website=str(row.get("website") or row.get("link") or ""),
                activity=str(row.get("activity") or ""),
                discovered=str(row.get("discovered") or ""),
                published=str(row.get("published") or row.get("discovered") or ""),
                url=str(
                    row.get("link")
                    or row.get("url")
                    or (
                        f"https://www.ransomlook.io/group/{group}"
                        if group
                        else "https://www.ransomlook.io/"
                    )
                ),
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "ransomlook",
            "L6",
            "RansomLook",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"api/recent; ingested={count}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "ransomlook",
            "L6",
            "RansomLook",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


def _parse_rss_entries(
    content: bytes | str, *, profile: str, limit: int
) -> list[dict[str, str]]:
    feed = feedparser.parse(content)
    out: list[dict[str, str]] = []
    for e in feed.entries[:limit]:
        title = (e.get("title") or "").strip()
        if not title:
            continue
        # Drop non-intel Google News noise (privacy policy, about, etc.)
        tl = title.lower()
        if any(
            bad in tl
            for bad in ("privacy policy", "terms of service", "cookie policy", "about us")
        ):
            continue
        out.append(
            {
                "title": title,
                "summary": re.sub(
                    r"<[^>]+>",
                    " ",
                    e.get("summary") or e.get("description") or "",
                ).strip()[:1200],
                "link": e.get("link") or profile,
                "published": e.get("published") or "",
            }
        )
    return out


async def collect_x_darkweb_accounts(max_items: int | None = None) -> int:
    """Alias — X OSINT account collector (darkweb + news handles)."""
    return await collect_x_osint_accounts(max_items=max_items)


async def collect_x_osint_accounts(max_items: int | None = None) -> int:
    """
    L6 — Curated X OSINT handles (no X API key).

    Order per account: Nitter mirrors → official blog RSS → Google News.
    Health rows are per-handle only (no aggregate line).

    Skips handles already covered by primary RSS/API (see config comments).
    In-run title fingerprint de-dupes cross-handle reposts.
    """
    t0 = time.perf_counter()
    default_per = max_items if max_items is not None else X_OSINT_MAX_ITEMS
    total = 0
    seen_fp: set[str] = set()

    rss_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        ),
        "Accept": "application/rss+xml, application/xml, text/xml, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }

    threat_kw = (
        "ransom",
        "勒索",
        "breach",
        "leak",
        "dark web",
        "darkweb",
        "data dump",
        "stolen",
        "hack",
        "malware",
        "phishing",
        "cve-",
        "extortion",
        "infostealer",
        "initial access",
        "compromised",
        "threat",
        "actor",
        "forum",
        "market",
        "cyber",
        "database",
        "credential",
        "exploit",
        "vulnerability",
        "zero-day",
        "0day",
        "dfir",
        "ioc",
        "apt",
        "sigma",
        "detection",
    )

    # Always remove obsolete aggregate row first
    for obsolete in OBSOLETE_SOURCE_IDS:
        try:
            await delete_source_health(obsolete)
        except Exception:
            pass

    for acct in X_OSINT_ACCOUNTS:
        handle = acct["handle"]
        category = (acct.get("category") or "darkweb").lower()
        source_id = f"x_{handle.lower()}"
        name = f"@{handle} (X)"
        per = int(acct.get("max_items") or default_per)
        count = 0
        used = ""
        errors: list[str] = []
        entries: list[dict[str, str]] = []

        # Candidate feed URLs in priority order
        candidates: list[tuple[str, str]] = []
        for mirror in X_NITTER_MIRRORS:
            candidates.append((f"{mirror}/{handle}/rss", f"nitter:{mirror}"))
        if acct.get("blog_rss"):
            candidates.append((acct["blog_rss"], "blog-rss"))
        if acct.get("gnews_rss"):
            candidates.append((acct["gnews_rss"], "gnews"))

        try:
            async with await _client() as client:
                for url, label in candidates:
                    try:
                        r = await client.get(
                            url, headers=rss_headers, timeout=HTTP_TIMEOUT
                        )
                        if r.status_code != 200:
                            errors.append(f"{label}:HTTP{r.status_code}")
                            continue
                        ct = (r.headers.get("content-type") or "").lower()
                        body = r.content
                        text_head = r.text.lstrip()[:200].lower()
                        if not (
                            "xml" in ct
                            or text_head.startswith("<?xml")
                            or "<rss" in text_head
                            or "<feed" in text_head
                        ):
                            errors.append(f"{label}:not-xml")
                            continue
                        parsed = _parse_rss_entries(
                            body, profile=acct["profile"], limit=per
                        )
                        if not parsed:
                            errors.append(f"{label}:0-entries")
                            continue
                        entries = parsed
                        used = label
                        break
                    except Exception as e:
                        errors.append(f"{label}:{type(e).__name__}")
                        continue

            for e in entries:
                title = e["title"]
                summary = e["summary"]
                blob = f"{title} {summary}".lower()
                # Curated intel accounts: keep most posts; only drop ultra-short noise
                if len(title) < 8:
                    continue
                if not any(k in blob for k in threat_kw) and used.startswith("gnews"):
                    # GNews can be noisy — require threat keywords
                    continue

                # Cross-handle de-dupe (strip URLs / handles / punctuation)
                fp_raw = re.sub(r"https?://\S+", " ", title.lower())
                fp_raw = re.sub(r"@\w+", " ", fp_raw)
                fp_raw = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", " ", fp_raw)
                fp_raw = re.sub(r"\s+", " ", fp_raw).strip()[:160]
                if fp_raw and fp_raw in seen_fp:
                    continue
                if fp_raw:
                    seen_fp.add(fp_raw)

                flags = enrich_flags(title, summary)
                is_ransom = flags["is_ransomware"] or any(
                    k in blob for k in ("ransom", "勒索", "extortion", "lockbit")
                )
                # Spec: single-source X OSINT is always Unverified → P3 review only.
                # Watchlist + ransomware keywords must NOT auto-elevate to P0.
                priority = assign_priority(
                    in_kev=False,
                    known_ransomware_campaign=False,
                    is_ransomware=is_ransom,
                    is_tw_industry=flags["is_tw_industry"],
                    epss=None,
                    source_count=1,
                    layer_id="L6",
                    force_p3_review=True,
                )
                rz, re_ = explain_priority(
                    priority=priority,
                    is_ransomware=is_ransom,
                    is_tw_industry=flags["is_tw_industry"],
                    source_count=1,
                    forced_p3_review=True,
                )
                verification, admiralty = "unverified", "C3"
                sop = pick_sop(
                    priority=priority,
                    is_ransomware=is_ransom,
                    is_tw_industry=flags["is_tw_industry"],
                    is_microsoft=flags["is_microsoft"],
                    verification=verification,
                    is_darkweb=True,
                )

                title_zh = f"[X @{handle}] {title}"
                title_en = title_zh
                if is_ransom:
                    title_zh = f"🔐 {title_zh}"
                    title_en = f"🔐 {title_en}"
                title_zh = f"[未核實 Unverified] {title_zh}"
                title_en = f"[Unverified] {title_en}"

                is_dark = category == "darkweb" or any(
                    k in blob
                    for k in ("dark web", "darkweb", "leak site", "ransom", "extortion")
                )
                note_zh = (
                    f"[單來源] @{handle} via {used or 'rss'}"
                    + (" — 暗網間接，標示未核實 → P3 複核" if is_dark else " — OSINT 社群，標示未核實 → P3 複核")
                    + f"\n{rz}"
                )
                note_en = (
                    f"[Single source] @{handle} via {used or 'rss'}"
                    + (
                        " — indirect dark-web intel, Unverified → P3 review"
                        if is_dark
                        else " — OSINT community post, Unverified → P3 review"
                    )
                    + f"\n{re_}"
                )

                tags = [
                    "x-twitter",
                    "unverified",
                    "p3-review",
                    handle.lower(),
                    f"cat-{category}",
                ]
                if is_dark:
                    tags.append("darkweb-indirect")
                if is_ransom:
                    tags.append("ransomware")
                if flags["is_tw_industry"]:
                    tags.append("tw-industry")
                if category in ("ot-research", "ot", "ics") or handle.lower() in (
                    "sansics",
                    "dragos",
                ):
                    tags.extend(["ot", "ot-research"])

                await upsert_intel(
                    {
                        "id": _id("x", handle, title, e["link"]),
                        "title": title_zh,
                        "title_en": title_en,
                        "summary": f"{summary}\n\n{note_zh}",
                        "summary_en": f"{summary}\n\n{note_en}",
                        "priority": priority,
                        "priority_rationale": rz,
                        "priority_rationale_en": re_,
                        "verification": verification,
                        "layer_id": "L6",
                        "source_name": name,
                        "sources_json": json.dumps([f"@{handle}"]),
                        "cve_id": (
                            re.findall(r"CVE-\d{4}-\d{4,7}", f"{title} {summary}", re.I)
                            or [None]
                        )[0],
                        "product": "",
                        "vendor": "",
                        "is_ransomware": 1 if is_ransom else 0,
                        "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                        "tw_entities_json": json.dumps(
                            flags["tw_entities"], ensure_ascii=False
                        ),
                        "is_finance": 1 if flags["is_finance"] else 0,
                        "finance_entities_json": json.dumps(
                            flags["finance_entities"], ensure_ascii=False
                        ),
                        "is_microsoft": 1 if flags["is_microsoft"] else 0,
                        "ms_entities_json": json.dumps(
                            flags["ms_entities"], ensure_ascii=False
                        ),
                        "known_ransomware_campaign": 0,
                        "epss": None,
                        "cvss": None,
                        "date_added": None,
                        "published_at": e["published"] or None,
                        "fetched_at": now_iso(),
                        "url": e["link"] or acct["profile"],
                        "admiralty": admiralty,
                        "raw_json": json.dumps(e, ensure_ascii=False)[:3000],
                        "tags_json": json.dumps(tags),
                        "sop_id": sop["sop_id"],
                        "sop_zh": sop["sop_zh"],
                        "sop_en": sop["sop_en"],
                        "owner": sop["owner"],
                        "sla_hours": sop["sla_hours"],
                    }
                )
                count += 1

            total += count
            ms = int((time.perf_counter() - t0) * 1000)
            if count > 0:
                await _mark(
                    source_id,
                    "L6",
                    name,
                    ok=True,
                    count=count,
                    latency_ms=ms,
                    detail=f"via={used}; cat={category}; tried={len(candidates)}",
                )
            else:
                await _mark(
                    source_id,
                    "L6",
                    name,
                    ok=False,
                    latency_ms=ms,
                    error=("no feed worked: " + "; ".join(errors))[:500],
                )
        except Exception as ex:
            await _mark(
                source_id,
                "L6",
                name,
                ok=False,
                error=str(ex)[:400],
            )

    return total


async def dual_source_ransom_trackers() -> int:
    """
    Elevate victims seen on both Ransomware.live and RansomLook to credible.
    Runs after both collectors; re-upserts dual-verified cards.
    """
    # Lightweight: fetch recent titles from both APIs and cross-match
    t0 = time.perf_counter()
    elevated = 0
    try:
        async with await _client() as client:
            rl_rows: list[dict] = []
            try:
                r = await client.get(
                    RANSOMLOOK_RECENT_URL,
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                )
                if r.status_code == 200:
                    p = r.json()
                    rl_rows = p if isinstance(p, list) else []
            except Exception:
                rl_rows = []

            live_rows: list[dict] = []
            try:
                # Use only first chunk via streaming would be better; dump is large —
                # reuse API if possible, else skip dual and rely on single ingest.
                r = await client.get(
                    RANSOMWARE_LIVE_API_V2,
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                )
                if r.status_code == 200 and "json" in (
                    r.headers.get("content-type") or ""
                ):
                    p = r.json()
                    live_rows = p if isinstance(p, list) else []
            except Exception:
                live_rows = []

            # If live API empty, match against what we just stored is hard;
            # instead normalize RansomLook set and re-fetch a small slice of dump.
            if not live_rows:
                try:
                    # Only compare against RansomLook victims by re-querying
                    # data dump is huge; dual-check using token overlap on RL list
                    # against recent live already ingested is skippable.
                    pass
                except Exception:
                    pass

        def norm(s: str) -> str:
            s = (s or "").lower()
            s = re.sub(r"https?://", "", s)
            s = re.sub(r"^www\.", "", s)
            s = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", s)
            return s

        look_map: dict[str, dict] = {}
        for row in rl_rows[:120]:
            v = norm(
                str(row.get("post_title") or row.get("title") or row.get("victim") or "")
            )
            if len(v) >= 4:
                look_map[v] = row

        # Pull recent live dump slice only when needed
        if not live_rows:
            try:
                async with await _client() as client:
                    dr = await client.get(
                        RANSOMWARE_LIVE_VICTIMS_URL,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                        },
                        timeout=120.0,
                    )
                    if dr.status_code == 200:
                        allv = dr.json()
                        if isinstance(allv, list):
                            live_rows = sorted(
                                allv,
                                key=lambda x: str(x.get("discovered") or ""),
                                reverse=True,
                            )[:150]
            except Exception:
                live_rows = []

        for row in live_rows[:150]:
            victim = str(
                row.get("post_title") or row.get("victim") or row.get("website") or ""
            )
            key = norm(victim)
            if not key or key not in look_map:
                # try website
                key2 = norm(str(row.get("website") or ""))
                if key2 not in look_map:
                    continue
                key = key2
            partner = look_map[key]
            group = str(
                row.get("group_name")
                or row.get("group")
                or partner.get("group_name")
                or ""
            )
            await _upsert_ransom_victim_item(
                source_id="ransom-dual",
                source_name="Ransomware.live + RansomLook",
                victim=victim,
                group=group,
                description=str(row.get("description") or "")[:900],
                country=str(row.get("country") or ""),
                website=str(row.get("website") or ""),
                activity=str(row.get("activity") or ""),
                discovered=str(row.get("discovered") or ""),
                published=str(row.get("published") or ""),
                url=str(row.get("post_url") or "https://www.ransomware.live/"),
                extra_sources=["RansomLook"],
                dual_verified=True,
            )
            elevated += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "ransom_dual_verify",
            "L6",
            "Ransom dual-source (Live∩Look)",
            ok=True,
            count=elevated,
            latency_ms=ms,
            detail=f"elevated={elevated}",
        )
        return elevated
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "ransom_dual_verify",
            "L6",
            "Ransom dual-source (Live∩Look)",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0


async def dual_source_darkweb_verify() -> int:
    """
    L6 dual-source: pull two independent news feeds and elevate items
    that appear in both (title similarity) as credible ransomware intel.
    """
    t0 = time.perf_counter()
    items_a: list[dict[str, str]] = []
    items_b: list[dict[str, str]] = []

    async def load(url: str) -> list[dict[str, str]]:
        async with await _client() as client:
            r = await client.get(url)
            r.raise_for_status()
            feed = feedparser.parse(r.text)
        out = []
        for e in feed.entries[:50]:
            title = (e.get("title") or "").strip()
            summary = re.sub(
                r"<[^>]+>", " ", e.get("summary") or e.get("description") or ""
            )
            summary = re.sub(r"\s+", " ", summary).strip()
            out.append(
                {
                    "title": title,
                    "summary": summary,
                    "link": e.get("link") or "",
                    "published": e.get("published") or "",
                }
            )
        return out

    try:
        items_a = await load(BLEEPING_RSS)
        items_b = await load(THEHACKERNEWS_RSS)
    except Exception as e:
        await _mark(
            "darkweb_dual",
            "L6",
            "Dark Web Dual-Source Verify",
            ok=False,
            error=str(e)[:500],
        )
        # still try single-source harvests
        n1 = await collect_rss_layer(
            source_id="bleeping_rss",
            layer_id="L6",
            name="BleepingComputer (indirect DW)",
            url=BLEEPING_RSS,
            darkweb_indirect=True,
            max_items=35,
        )
        n2 = await collect_rss_layer(
            source_id="thn_rss",
            layer_id="L6",
            name="The Hacker News (indirect DW)",
            url=THEHACKERNEWS_RSS,
            darkweb_indirect=True,
            max_items=35,
        )
        return n1 + n2

    def tokens(s: str) -> set[str]:
        return {w for w in re.findall(r"[a-z0-9\u4e00-\u9fff]{4,}", s.lower())}

    elevated = 0
    # Ingest A with dual check against B
    for a in items_a:
        ta = tokens(a["title"])
        dual = False
        partner = None
        for b in items_b:
            tb = tokens(b["title"])
            if not ta or not tb:
                continue
            inter = len(ta & tb)
            fa = enrich_flags(a["title"], a["summary"])
            if inter >= 3 and (
                fa["is_ransomware"]
                or "ransomware" in a["title"].lower()
                or fa["is_tw_industry"]
                or fa["is_finance"]
                or fa["is_microsoft"]
            ):
                dual = True
                partner = b
                break

        flags = enrich_flags(a["title"], a["summary"])
        is_ransom = flags["is_ransomware"]
        is_tw = flags["is_tw_industry"]
        is_finance = flags["is_finance"]
        is_ms = flags["is_microsoft"]
        # only keep ransomware / category / CVE related to control noise
        cve_m = re.findall(r"CVE-\d{4}-\d{4,7}", f"{a['title']} {a['summary']}", re.I)
        if not (is_ransom or is_tw or is_finance or is_ms or cve_m or dual):
            continue

        sources = ["BleepingComputer"]
        source_count = 1
        if dual and partner:
            sources.append("The Hacker News")
            source_count = 2
            elevated += 1

        # Single-source dual-track news → P3 review; dual-source may elevate.
        force_p3 = source_count < 2
        priority = assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=is_ransom,
            is_tw_industry=is_tw,
            epss=None,
            source_count=source_count,
            layer_id="L6",
            force_p3_review=force_p3,
        )
        verification, admiralty = assign_verification(
            in_kev=False,
            layer_id="L6",
            source_count=source_count,
            is_darkweb_indirect=True,
        )
        if source_count < 2:
            verification = "unverified"
            admiralty = "C3"

        title = a["title"]
        title_zh = title
        title_en = title
        if is_ransom:
            title_zh = f"🔐 勒索相關｜{title}"
            title_en = f"🔐 Ransomware｜{title}"
        if is_tw:
            title_zh = f"🇹🇼 台灣電子／半導體｜{title_zh}"
            title_en = f"🇹🇼 TW Electronics/Semi｜{title_en}"
        if is_finance:
            title_zh = f"💰 金融相關｜{title_zh}"
            title_en = f"💰 Finance｜{title_en}"
        if is_ms:
            title_zh = f"🪟 微軟相關｜{title_zh}"
            title_en = f"🪟 Microsoft｜{title_en}"
        if source_count < 2:
            title_zh = f"[未核實 Unverified] {title_zh}"
            title_en = f"[Unverified] {title_en}"

        await upsert_intel(
            {
                "id": _id("dw", a["title"], a["link"]),
                "title": title_zh,
                "title_en": title_en,
                "summary": a["summary"][:1200]
                + (
                    f"\n\n[雙來源核實] 第二來源：{partner['title']}"
                    if partner
                    else "\n\n[單來源] 暗網間接情資 — 標示為未核實"
                ),
                "summary_en": a["summary"][:1200]
                + (
                    f"\n\n[Dual-source verified] Partner: {partner['title']}"
                    if partner
                    else "\n\n[Single source] Indirect dark-web intel — Unverified"
                ),
                "priority": priority,
                "verification": verification,
                "layer_id": "L6",
                "source_name": "Indirect Dark Web (news dual-track)",
                "sources_json": json.dumps(sources),
                "cve_id": cve_m[0].upper() if cve_m else None,
                "product": "",
                "vendor": "",
                "is_ransomware": 1 if is_ransom else 0,
                "is_tw_industry": 1 if is_tw else 0,
                "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
                "is_finance": 1 if is_finance else 0,
                "finance_entities_json": json.dumps(
                    flags["finance_entities"], ensure_ascii=False
                ),
                "is_microsoft": 1 if is_ms else 0,
                "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
                "known_ransomware_campaign": 0,
                "epss": None,
                "cvss": None,
                "date_added": None,
                "published_at": a["published"],
                "fetched_at": now_iso(),
                "url": a["link"],
                "admiralty": admiralty,
                "raw_json": json.dumps(a, ensure_ascii=False)[:4000],
                "tags_json": json.dumps(
                    ["darkweb-indirect"]
                    + (["dual-source"] if source_count >= 2 else ["unverified"])
                    + (["ransomware"] if is_ransom else [])
                    + (["tw-industry"] if is_tw else [])
                    + (["finance"] if is_finance else [])
                    + (["microsoft"] if is_ms else [])
                ),
            }
        )

    # Also ingest THN-only ransomware / category items as unverified
    for b in items_b:
        flags = enrich_flags(b["title"], b["summary"])
        if not (
            flags["is_ransomware"]
            or flags["is_tw_industry"]
            or flags["is_finance"]
            or flags["is_microsoft"]
        ):
            continue
        # skip if already dual-elevated via A
        tags = ["darkweb-indirect", "unverified"]
        if flags["is_ransomware"]:
            tags.append("ransomware")
        if flags["is_tw_industry"]:
            tags.append("tw-industry")
        if flags["is_finance"]:
            tags.append("finance")
        if flags["is_microsoft"]:
            tags.append("microsoft")
        await upsert_intel(
            {
                "id": _id("dwthn", b["title"], b["link"]),
                "title": f"[未核實 Unverified] 🔐 {b['title']}"
                if flags["is_ransomware"]
                else f"[未核實 Unverified] {b['title']}",
                "title_en": f"[Unverified] 🔐 {b['title']}"
                if flags["is_ransomware"]
                else f"[Unverified] {b['title']}",
                "summary": (
                    b["summary"][:1200]
                    + "\n\n[單來源] The Hacker News — 未核實 → P3 複核佇列"
                ),
                "summary_en": (
                    b["summary"][:1200]
                    + "\n\n[Single source] The Hacker News — Unverified → P3 review"
                ),
                "priority": assign_priority(
                    in_kev=False,
                    known_ransomware_campaign=False,
                    is_ransomware=flags["is_ransomware"],
                    is_tw_industry=flags["is_tw_industry"],
                    epss=None,
                    source_count=1,
                    layer_id="L6",
                    force_p3_review=True,
                ),
                "verification": "unverified",
                "layer_id": "L6",
                "source_name": "The Hacker News (indirect DW)",
                "sources_json": json.dumps(["The Hacker News"]),
                "cve_id": None,
                "product": "",
                "vendor": "",
                "is_ransomware": 1 if flags["is_ransomware"] else 0,
                "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
                "is_finance": 1 if flags["is_finance"] else 0,
                "finance_entities_json": json.dumps(
                    flags["finance_entities"], ensure_ascii=False
                ),
                "is_microsoft": 1 if flags["is_microsoft"] else 0,
                "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
                "known_ransomware_campaign": 0,
                "epss": None,
                "cvss": None,
                "date_added": None,
                "published_at": b["published"],
                "fetched_at": now_iso(),
                "url": b["link"],
                "admiralty": "C3",
                "raw_json": json.dumps(b, ensure_ascii=False)[:4000],
                "tags_json": json.dumps(tags),
            }
        )

    ms = int((time.perf_counter() - t0) * 1000)
    total = elevated  # health metric focus on dual elevations
    await _mark(
        "darkweb_dual",
        "L6",
        "Dark Web Dual-Source Verify",
        ok=True,
        count=total,
        latency_ms=ms,
        detail=f"dual-elevated={elevated}; feeds A={len(items_a)} B={len(items_b)}",
    )
    await _mark(
        "bleeping_rss",
        "L6",
        "BleepingComputer (indirect DW)",
        ok=True,
        count=len(items_a),
        latency_ms=ms,
    )
    await _mark(
        "thn_rss",
        "L6",
        "The Hacker News (indirect DW)",
        ok=True,
        count=len(items_b),
        latency_ms=ms,
    )
    return elevated


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

    results["finished_at"] = now_iso()
    results["layers"] = LAYERS
    return results
