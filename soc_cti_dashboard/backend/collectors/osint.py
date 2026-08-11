"""L6 — X/Nitter OSINT accounts and dual-source news cross-verification."""

from __future__ import annotations

import json
import re
import time
import feedparser
from ..config import (
    SOURCE_CLASS_OSINT,
    BLEEPING_RSS,
    THEHACKERNEWS_RSS,
    X_OSINT_ACCOUNTS,
    X_OSINT_MAX_ITEMS,
    X_NITTER_MIRRORS,
    OBSOLETE_SOURCE_IDS,
    HTTP_TIMEOUT,
)
from ..database import delete_source_health, now_iso, upsert_intel
from ..ops import explain_priority, pick_sop
from ..priority import assign_priority, assign_verification, enrich_flags

from ._base import _client, _id, _mark, _parse_rss_entries
from .rss import collect_rss_layer


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
        # R2-2: verification before priority (dual-source TW + ransom → P0)
        verification, admiralty = assign_verification(
            in_kev=False,
            layer_id="L6",
            source_count=source_count,
            is_darkweb_indirect=True,
            source_class=SOURCE_CLASS_OSINT,
        )
        if source_count < 2:
            verification = "unverified"
            admiralty = "C3"
        priority = assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=is_ransom,
            is_tw_industry=is_tw,
            epss=None,
            source_count=source_count,
            layer_id="L6",
            force_p3_review=force_p3,
            verification=verification,
        )

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
                    verification="unverified",
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
