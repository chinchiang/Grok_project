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
    CISA_ADVISORIES_RSS_CANDIDATES,
    CISA_ICS_GITHUB_API,
    CISA_ICS_MAX_ITEMS,
    EPSS_API,
    BLEEPING_RSS,
    THEHACKERNEWS_RSS,
    TWCERT_NEWS_RSS,
    TWCERT_TVN_RSS,
    HIBP_API_KEY,
    HIBP_BREACHES_URL,
    HIBP_MAX_ITEMS,
    HIBP_RECENT_DAYS,
    HIBP_WATCH_DOMAINS,
    RANSOMWARE_LIVE_API_KEY,
    RANSOMWARE_LIVE_API_V2,
    RANSOMWARE_LIVE_MAX_ITEMS,
    RANSOMWARE_LIVE_PRO_RECENT,
    RANSOMWARE_LIVE_VICTIMS_URL,
    RANSOMLOOK_MAX_ITEMS,
    RANSOMLOOK_RECENT_URL,
    RANSOMLOOK_RSS_URL,
    X_DARKWEB_ACCOUNTS,
    X_DARKWEB_MAX_ITEMS,
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
            is_finance = flags["is_finance"]
            is_ms = flags["is_microsoft"]
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
            if is_finance:
                title_zh = f"💰 金融相關｜{title_zh}"
                title_en = f"💰 Finance｜{title_en}"
            if is_ms:
                title_zh = f"🪟 微軟相關｜{title_zh}"
                title_en = f"🪟 Microsoft｜{title_en}"

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
                    "tags_json": json.dumps(
                        (["ransomware"] if is_ransom else [])
                        + (["tw-industry"] if is_tw else [])
                        + (["finance"] if is_finance else [])
                        + (["microsoft"] if is_ms else [])
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
                    ["cisa", "ics", "ot"]
                    + (["critical"] if (severity or "").lower() == "critical" else [])
                    + (["tw-industry"] if flags["is_tw_industry"] else [])
                    + (["finance"] if flags["is_finance"] else [])
                    + (["microsoft"] if flags["is_microsoft"] else [])
                ),
            }
        )
        count += 1

    return count


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
    if dual_verified:
        verification, admiralty = "credible", "B2"
    else:
        verification, admiralty = "unverified", "C3"

    title_core = f"{victim} — claimed by {group}"
    title_zh = f"🔐 勒索受害｜{title_core}"
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
        f"受害組織：{victim}\n"
        f"勒索集團：{group}\n"
        f"國家：{country or '—'}｜產業：{activity or '—'}\n"
        f"網站：{website or '—'}\n"
        f"發現/公布：{discovered or '—'} / {published or '—'}\n"
        f"{(description or '')[:800]}\n"
        f"來源：{', '.join(sources)}（暗網洩漏站間接 — "
        f"{'雙源可信' if dual_verified else '單源未核實'}）"
    )
    summary_en = (
        f"Victim: {victim}\n"
        f"Group: {group}\n"
        f"Country: {country or '—'} | Sector: {activity or '—'}\n"
        f"Website: {website or '—'}\n"
        f"Discovered/Published: {discovered or '—'} / {published or '—'}\n"
        f"{(description or '')[:800]}\n"
        f"Source: {', '.join(sources)} (indirect leak-site — "
        f"{'dual-source credible' if dual_verified else 'single-source unverified'})"
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


async def collect_x_darkweb_accounts(max_items: int | None = None) -> int:
    """
    L6 — @DailyDarkWeb / @DarkWebInformer via Nitter RSS (no X API key).
    Falls back to each account's public blog RSS when Nitter is down.
    """
    t0 = time.perf_counter()
    per = max_items if max_items is not None else X_DARKWEB_MAX_ITEMS
    total = 0
    details: list[str] = []

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
    )

    for acct in X_DARKWEB_ACCOUNTS:
        handle = acct["handle"]
        source_id = f"x_{handle.lower()}"
        name = f"@{handle} (X)"
        count = 0
        used = ""
        try:
            entries: list[dict[str, str]] = []
            async with await _client() as client:
                # 1) Nitter
                try:
                    nr = await client.get(
                        acct["nitter_rss"],
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/rss+xml,application/xml,text/xml,*/*",
                        },
                    )
                    if nr.status_code == 200 and (
                        "xml" in (nr.headers.get("content-type") or "")
                        or nr.text.lstrip().startswith("<?xml")
                    ):
                        feed = feedparser.parse(nr.text)
                        for e in feed.entries[:per]:
                            entries.append(
                                {
                                    "title": (e.get("title") or "").strip(),
                                    "summary": re.sub(
                                        r"<[^>]+>",
                                        " ",
                                        e.get("summary") or e.get("description") or "",
                                    ).strip()[:1200],
                                    "link": e.get("link") or acct["profile"],
                                    "published": e.get("published") or "",
                                }
                            )
                        used = "nitter"
                except Exception:
                    entries = []

                # 2) Blog RSS fallback
                if not entries and acct.get("blog_rss"):
                    br = await client.get(
                        acct["blog_rss"],
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/rss+xml,application/xml,text/xml,*/*",
                        },
                    )
                    br.raise_for_status()
                    feed = feedparser.parse(br.text)
                    for e in feed.entries[:per]:
                        entries.append(
                            {
                                "title": (e.get("title") or "").strip(),
                                "summary": re.sub(
                                    r"<[^>]+>",
                                    " ",
                                    e.get("summary") or e.get("description") or "",
                                ).strip()[:1200],
                                "link": e.get("link") or acct["profile"],
                                "published": e.get("published") or "",
                            }
                        )
                    used = "blog-rss"

            for e in entries:
                title = e["title"]
                summary = e["summary"]
                blob = f"{title} {summary}".lower()
                if not any(k in blob for k in threat_kw):
                    # keep account signal if title is non-empty (intel accounts are curated)
                    if len(title) < 12:
                        continue

                flags = enrich_flags(title, summary)
                is_ransom = flags["is_ransomware"] or any(
                    k in blob for k in ("ransom", "勒索", "extortion", "lockbit")
                )
                priority = assign_priority(
                    in_kev=False,
                    known_ransomware_campaign=False,
                    is_ransomware=is_ransom,
                    is_tw_industry=flags["is_tw_industry"],
                    epss=None,
                    source_count=1,
                    layer_id="L6",
                )
                # X is always single-source unverified for dark-web claims
                verification, admiralty = "unverified", "C3"

                title_zh = f"[X @{handle}] {title}"
                title_en = title_zh
                if is_ransom:
                    title_zh = f"🔐 {title_zh}"
                    title_en = f"🔐 {title_en}"
                title_zh = f"[未核實 Unverified] {title_zh}"
                title_en = f"[Unverified] {title_en}"

                await upsert_intel(
                    {
                        "id": _id("x", handle, title, e["link"]),
                        "title": title_zh,
                        "title_en": title_en,
                        "summary": (
                            f"{summary}\n\n"
                            f"[單來源] X/@{handle} via {used or 'rss'} — 暗網間接，標示未核實"
                        ),
                        "summary_en": (
                            f"{summary}\n\n"
                            f"[Single source] X/@{handle} via {used or 'rss'} — "
                            "indirect dark-web intel, Unverified"
                        ),
                        "priority": priority,
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
                        "tags_json": json.dumps(
                            [
                                "x-twitter",
                                "darkweb-indirect",
                                "unverified",
                                handle.lower(),
                            ]
                            + (["ransomware"] if is_ransom else [])
                        ),
                    }
                )
                count += 1

            total += count
            details.append(f"@{handle}:{count}:{used or 'none'}")
            await _mark(
                source_id,
                "L6",
                name,
                ok=True,
                count=count,
                detail=f"via={used or 'none'}",
            )
        except Exception as ex:
            details.append(f"@{handle}:err")
            await _mark(
                source_id,
                "L6",
                name,
                ok=False,
                error=str(ex)[:400],
            )

    ms = int((time.perf_counter() - t0) * 1000)
    await _mark(
        "x_darkweb_accounts",
        "L6",
        "@DailyDarkWeb / @DarkWebInformer (X)",
        ok=total > 0 or any("err" not in d for d in details),
        count=total,
        latency_ms=ms,
        detail="; ".join(details),
        error=None if total > 0 else ("all sources failed: " + "; ".join(details))[:500],
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

    # L1 KEV + EPSS
    try:
        n = await collect_cisa_kev()
        results["steps"]["cisa_kev"] = {"ok": True, "count": n}
    except Exception as e:
        results["steps"]["cisa_kev"] = {"ok": False, "error": str(e)}

    # L2 TWCERT/CC official RSS (news + Taiwan Vulnerability Notes)
    n_news = await collect_rss_layer(
        source_id="twcert_news_rss",
        layer_id="L2",
        name="TWCERT/CC 資安新聞 RSS",
        url=TWCERT_NEWS_RSS,
        darkweb_indirect=False,
        force_ransomware_scan=False,
        max_items=25,
    )
    n_tvn = await collect_rss_layer(
        source_id="twcert_tvn_rss",
        layer_id="L2",
        name="TWCERT/CC TVN 漏洞公告 RSS",
        url=TWCERT_TVN_RSS,
        darkweb_indirect=False,
        force_ransomware_scan=False,
        max_items=25,
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

    # L3 placeholder
    await mark_abusech_placeholder()
    results["steps"]["abusech"] = {"ok": True, "count": 0, "status": "not_configured"}

    # L4 placeholder
    await mark_easm_placeholder()
    results["steps"]["easm"] = {"ok": True, "status": "not_configured"}

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
