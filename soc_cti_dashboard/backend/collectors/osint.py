"""L6 — X/Nitter OSINT accounts and dual-source news cross-verification."""

from __future__ import annotations

import json
import re
import time
from ..config import (
    X_OSINT_ACCOUNTS,
    X_OSINT_MAX_ITEMS,
    X_NITTER_MIRRORS,
    OBSOLETE_SOURCE_IDS,
    HTTP_TIMEOUT,
)
from ..database import delete_source_health, now_iso, upsert_intel
from ..ops import explain_priority, pick_sop
from ..priority import assign_priority, enrich_flags

from ._base import _client, _id, _mark, _parse_rss_entries


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
                verification, admiralty = "unverified", "C3"
                priority = assign_priority(
                    in_kev=False,
                    known_ransomware_campaign=False,
                    is_ransomware=is_ransom,
                    is_tw_industry=flags["is_tw_industry"],
                    epss=None,
                    source_count=1,
                    layer_id="L6",
                    force_p3_review=True,
                    verification=verification,
                )
                rz, re_ = explain_priority(
                    priority=priority,
                    is_ransomware=is_ransom,
                    is_tw_industry=flags["is_tw_industry"],
                    source_count=1,
                    forced_p3_review=True,
                    verification=verification,
                )
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

async def collect_x_darkweb_accounts(max_items: int | None = None) -> int:
    """Alias — X OSINT account collector (darkweb + news handles)."""
    return await collect_x_osint_accounts(max_items=max_items)

async def dual_source_darkweb_verify() -> int:
    """BC × THN corroboration belongs in aggregate.py.

    Re-ingesting those feeds here as darkweb-indirect and elevating on a
    3-token title overlap duplicated INTEL_FEEDS rows and produced false
    dual-source P0s. Harvest still calls this name.
    """
    await _mark(
        "darkweb_dual",
        "L6",
        "Dark Web Dual-Source Verify",
        ok=True,
        count=0,
        detail="deferred to aggregate_cross_source_events (feeds already in INTEL_FEEDS)",
    )
    return 0
