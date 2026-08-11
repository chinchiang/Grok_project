"""L7 — CISA ICS advisories, via official RSS or the community CSV mirror."""

from __future__ import annotations

import csv
import io
import json
import re
import time
from datetime import datetime
from ..config import (
    CISA_ADVISORIES_RSS_CANDIDATES,
    CISA_ICS_GITHUB_API,
    CISA_ICS_MAX_ITEMS,
    USER_AGENT,
)
from ..database import now_iso, upsert_intel
from ..priority import assign_priority, enrich_flags

from ._base import _client, _id, _mark
from .rss import collect_rss_layer


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
        # Official ICS advisory content (via trusted community mirror of CISA data)
        verification, admiralty = "confirmed", "A2"
        # OT critical manufacturing + high CVSS is elevated monitoring
        priority = assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=is_ransom,
            is_tw_industry=flags["is_tw_industry"],
            epss=None,
            source_count=1,
            layer_id="L7",
            verification=verification,
        )
        if priority == "P3" and cvss is not None and cvss >= 9.0:
            priority = "P2"
        elif priority == "P3" and (severity or "").lower() == "critical":
            priority = "P2"

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
