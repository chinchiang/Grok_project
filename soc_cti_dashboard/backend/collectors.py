"""Multi-layer OSINT collectors with health reporting."""

from __future__ import annotations

import hashlib
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
    CISA_ICS_RSS,
    EPSS_API,
    BLEEPING_RSS,
    THEHACKERNEWS_RSS,
    TWCERT_RSS,
    USER_AGENT,
    HTTP_TIMEOUT,
    LAYERS,
)
from .database import now_iso, upsert_intel, upsert_source_health
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
    """L1 — CISA KEV real-time JSON feed."""
    t0 = time.perf_counter()
    count = 0
    try:
        async with await _client() as client:
            r = await client.get(CISA_KEV_URL)
            r.raise_for_status()
            data = r.json()
        vulns = data.get("vulnerabilities") or []
        # Sort by dateAdded desc
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
            verification, admiralty = assign_verification(
                in_kev=True,
                layer_id="L1",
                source_count=1,
                is_darkweb_indirect=False,
            )

            title_zh = f"[KEV] {cve} — {name}"
            title_en = f"[KEV] {cve} — {name}"
            summary_zh = (
                f"{desc}\n廠商/產品：{vendor} / {product}\n"
                f"KEV 收錄日：{date_added}｜修補期限：{due}\n"
                f"必要處置：{required}\n"
                f"勒索活動關聯：{'是' if ransomware_flag else '未知/否'}"
            )
            summary_en = (
                f"{desc}\nVendor/Product: {vendor} / {product}\n"
                f"KEV dateAdded: {date_added} | dueDate: {due}\n"
                f"Required action: {required}\n"
                f"Ransomware campaign use: {'Known' if ransomware_flag else 'Unknown'}"
            )

            await upsert_intel(
                {
                    "id": _id("kev", cve),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
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
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "cisa_kev",
            "L1",
            "CISA KEV",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"catalog entries ingested (cap={limit_recent})",
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
) -> int:
    t0 = time.perf_counter()
    count = 0
    try:
        async with await _client() as client:
            r = await client.get(url)
            r.raise_for_status()
            content = r.text
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

            flags = enrich_flags(title, summary)
            is_ransom = flags["is_ransomware"]
            is_tw = flags["is_tw_industry"]
            if not force_ransomware_scan and not is_ransom and not is_tw and not cve_id:
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

            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=None,
                source_count=source_count,
                layer_id=layer_id,
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
            if is_ransom:
                title_zh = f"🔐 勒索相關｜{title}"
                title_en = f"🔐 Ransomware｜{title}"
            if is_tw:
                title_zh = f"🇹🇼 台灣電子／半導體｜{title_zh}"
                title_en = f"🇹🇼 TW Electronics/Semi｜{title_en}"

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
                    "tags_json": json.dumps(
                        ([ "ransomware"] if is_ransom else [])
                        + (["tw-industry"] if is_tw else [])
                        + (["darkweb-indirect"] if darkweb_indirect else [])
                        + (["unverified"] if verification == "unverified" else [])
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            source_id, layer_id, name, ok=True, count=count, latency_ms=ms
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            source_id, layer_id, name, ok=False, latency_ms=ms, error=str(e)[:500]
        )
        return 0


async def collect_cisa_ics() -> int:
    """L7 — CISA cybersecurity advisories RSS (includes ICS)."""
    return await collect_rss_layer(
        source_id="cisa_ics_rss",
        layer_id="L7",
        name="CISA Advisories RSS",
        url=CISA_ICS_RSS,
        darkweb_indirect=False,
        force_ransomware_scan=False,
        max_items=30,
    )


async def mark_easm_placeholder() -> None:
    """L4 requires API keys — report scheduled-but-not-configured."""
    await upsert_source_health(
        {
            "source_id": "shodan",
            "layer_id": "L4",
            "name": "Shodan (API key required)",
            "last_success": None,
            "last_error": "SHODAN_API_KEY not configured",
            "last_attempt": now_iso(),
            "status": "not_configured",
            "item_count": 0,
            "latency_ms": 0,
            "detail": "Set SHODAN_API_KEY to enable external attack surface monitoring",
        }
    )
    await upsert_source_health(
        {
            "source_id": "censys",
            "layer_id": "L4",
            "name": "Censys (API key required)",
            "last_success": None,
            "last_error": "CENSYS_API_ID/SECRET not configured",
            "last_attempt": now_iso(),
            "status": "not_configured",
            "item_count": 0,
            "latency_ms": 0,
            "detail": "Set Censys credentials to enable ASM delta alerts",
        }
    )


async def mark_hibp_placeholder() -> None:
    await upsert_source_health(
        {
            "source_id": "hibp",
            "layer_id": "L5",
            "name": "Have I Been Pwned (API key required)",
            "last_success": None,
            "last_error": "HIBP_API_KEY not configured",
            "last_attempt": now_iso(),
            "status": "not_configured",
            "item_count": 0,
            "latency_ms": 0,
            "detail": "Domain search requires paid HIBP key",
        }
    )


async def mark_abusech_placeholder() -> None:
    await upsert_source_health(
        {
            "source_id": "abusech_threatfox",
            "layer_id": "L3",
            "name": "abuse.ch ThreatFox (optional Auth-Key)",
            "last_success": None,
            "last_error": "optional — configure ABUSECH_AUTH_KEY for full IOC feed",
            "last_attempt": now_iso(),
            "status": "not_configured",
            "item_count": 0,
            "latency_ms": 0,
            "detail": "Community IOC layer ready for API key",
        }
    )


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
            if inter >= 3 and (
                enrich_flags(a["title"], a["summary"])["is_ransomware"]
                or "ransomware" in a["title"].lower()
                or enrich_flags(a["title"], a["summary"])["is_tw_industry"]
            ):
                dual = True
                partner = b
                break

        flags = enrich_flags(a["title"], a["summary"])
        is_ransom = flags["is_ransomware"]
        is_tw = flags["is_tw_industry"]
        # only keep ransomware / TW / CVE related to control noise
        cve_m = re.findall(r"CVE-\d{4}-\d{4,7}", f"{a['title']} {a['summary']}", re.I)
        if not (is_ransom or is_tw or cve_m or dual):
            continue

        sources = ["BleepingComputer"]
        source_count = 1
        if dual and partner:
            sources.append("The Hacker News")
            source_count = 2
            elevated += 1

        priority = assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=is_ransom,
            is_tw_industry=is_tw,
            epss=None,
            source_count=source_count,
            layer_id="L6",
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
                ),
            }
        )

    # Also ingest THN-only ransomware items as unverified
    for b in items_b:
        flags = enrich_flags(b["title"], b["summary"])
        if not (flags["is_ransomware"] or flags["is_tw_industry"]):
            continue
        # skip if already dual-elevated via A
        await upsert_intel(
            {
                "id": _id("dwthn", b["title"], b["link"]),
                "title": f"[未核實 Unverified] 🔐 {b['title']}"
                if flags["is_ransomware"]
                else f"[未核實 Unverified] {b['title']}",
                "title_en": f"[Unverified] 🔐 {b['title']}"
                if flags["is_ransomware"]
                else f"[Unverified] {b['title']}",
                "summary": (b["summary"][:1200] + "\n\n[單來源] The Hacker News"),
                "summary_en": (b["summary"][:1200] + "\n\n[Single source] The Hacker News"),
                "priority": assign_priority(
                    in_kev=False,
                    known_ransomware_campaign=False,
                    is_ransomware=flags["is_ransomware"],
                    is_tw_industry=flags["is_tw_industry"],
                    epss=None,
                    source_count=1,
                    layer_id="L6",
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
                "known_ransomware_campaign": 0,
                "epss": None,
                "cvss": None,
                "date_added": None,
                "published_at": b["published"],
                "fetched_at": now_iso(),
                "url": b["link"],
                "admiralty": "C3",
                "raw_json": json.dumps(b, ensure_ascii=False)[:4000],
                "tags_json": json.dumps(["darkweb-indirect", "unverified", "ransomware"]),
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

    # L1 KEV + EPSS
    try:
        n = await collect_cisa_kev()
        results["steps"]["cisa_kev"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["cisa_kev"] = {"ok": False, "error": str(e)}

    # L2 TWCERT best-effort
    n = await collect_rss_layer(
        source_id="twcert_rss",
        layer_id="L2",
        name="TWCERT/CC RSS",
        url=TWCERT_RSS,
        darkweb_indirect=False,
        force_ransomware_scan=False,
        max_items=25,
    )
    results["steps"]["twcert"] = {"ok": True, "count": n}

    # L3 placeholder
    await mark_abusech_placeholder()
    results["steps"]["abusech"] = {"ok": True, "count": 0, "status": "not_configured"}

    # L4 placeholder
    await mark_easm_placeholder()
    results["steps"]["easm"] = {"ok": True, "status": "not_configured"}

    # L5 placeholder + public breach news via THN/Bleeping already in L6
    await mark_hibp_placeholder()
    results["steps"]["hibp"] = {"ok": True, "status": "not_configured"}

    # L6 dual dark web
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
