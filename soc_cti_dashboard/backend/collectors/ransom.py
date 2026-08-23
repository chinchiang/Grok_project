"""L6 — ransomware leak-site trackers and their dual-source cross-check.

Dual-source rule (T5/T6 agent spec, 2026-08-11):
  Primary path — ALL of:
    1. victim name normalised similarity ≥ 85%
    2. group name normalised similarity ≥ 90% (or known alias)
    3. discovery/attack date gap ≤ 7 days (default; hard cap 14)
  Strong path — shared registrable domain (equivalent corroboration).

Single-source (only one of Ransomware.live / RansomLook, or any X /
media-indirect T6 feed) → unverified + forced P3. Never auto-elevate.
"""

from __future__ import annotations

import json
import re
import time
from datetime import date as _date, datetime
from difflib import SequenceMatcher
from typing import Any
import feedparser
from ..config import (
    RANSOMWARE_LIVE_API_KEY,
    RANSOMWARE_LIVE_API_V2,
    RANSOMWARE_LIVE_MAX_ITEMS,
    RANSOMWARE_LIVE_PRO_RECENT,
    RANSOMWARE_LIVE_VICTIMS_URL,
    RANSOMLOOK_MAX_ITEMS,
    RANSOMLOOK_RECENT_URL,
    RANSOMLOOK_RSS_URL,
    USER_AGENT,
)
from ..database import mark_superseded_ransom_rows, now_iso, upsert_intel
from ..dates import day_bucket
from ..ops import explain_priority, guess_assets, pick_sop
from ..priority import assign_priority, enrich_flags

from ._base import _client, _id, _mark, _strip_html


# ---------------------------------------------------------------------------
# Normalisation & dual-source matching (spec §一／§二)
# ---------------------------------------------------------------------------

# Default date window per agent spec; hard cap remains 14 days.
DEFAULT_DAY_GAP = 7
MAX_DAY_GAP = 14

# Victim-name similarity threshold (≥ 85%).
NAME_SIM_THRESHOLD = 0.85
# Group-name similarity threshold (≥ 90%), unless alias table hits.
GROUP_SIM_THRESHOLD = 0.90

_LEGAL_SUFFIXES = (
    # EN / international
    "incorporated", "corporation", "limited", "holdings", "holding", "group",
    "company", "gmbh", "llc", "ltd", "inc", "corp", "plc", "pte", "pty", "bv",
    "nv", "ag", "sa", "srl", "spa", "oy", "ab", "as", "kk", "co",
    # TW / CJK corporate forms
    "股份有限公司", "有限公司", "台灣", "臺灣", "株式会社", "株式會社",
)

# Canonical group aliases → single key. Extend as trackers introduce variants.
_GROUP_ALIASES: dict[str, str] = {
    "lockbit": "lockbit",
    "lockbit3": "lockbit",
    "lockbit30": "lockbit",
    "lockbitblack": "lockbit",
    "clop": "clop",
    "cl0p": "clop",
    "clopransomware": "clop",
    "alphv": "alphv",
    "blackcat": "alphv",
    "blackcatalphv": "alphv",
    "play": "play",
    "playransomware": "play",
    "akira": "akira",
    "ransomhub": "ransomhub",
    "8base": "8base",
    "bianlian": "bianlian",
    "medusa": "medusa",
    "medusalocker": "medusa",
    "qilin": "qilin",
    "agenda": "qilin",
    "fog": "fog",
    "hunters": "hunters",
    "huntersinternational": "hunters",
}


def _victim_domain(*values: str) -> str:
    """Registrable-ish domain from a website/URL field — the strongest join key."""
    for value in values:
        s = (value or "").strip().lower()
        if not s or "." not in s:
            continue
        s = re.sub(r"^[a-z]+://", "", s)
        s = s.split("/")[0].split("?")[0].split("@")[-1]
        s = re.sub(r"^www\d?\.", "", s).strip(".")
        parts = [p for p in s.split(".") if p]
        if len(parts) < 2 or not re.fullmatch(r"[a-z0-9.\-]+", s or ""):
            continue
        # keep last three labels for co.uk / com.tw style suffixes
        return ".".join(parts[-3:]) if len(parts[-2]) <= 3 and len(parts) >= 3 else ".".join(parts[-2:])
    return ""


# The token filter below splits on whitespace, which CJK names do not have:
# "鴻海精密工業股份有限公司" is a single token and can never equal a suffix
# entry, so the CJK forms in _LEGAL_SUFFIXES were unreachable. They are stripped
# from the end of the name instead, longest form first. Only true legal forms
# are listed — a geographic word like 台灣 is part of the name (台灣大哥大)
# and removing it would merge unrelated victims.
_CJK_LEGAL_SUFFIX_RE = re.compile(
    r"(?:股份有限公司|有限責任公司|有限公司|股份公司|"
    r"株式会社|株式會社|控股集團|控股|集團)+$"
)


def _victim_name_key(value: str) -> str:
    """Normalised company name with legal suffixes removed (spec §二)."""
    s = (value or "").lower()
    s = re.sub(r"^[a-z]+://", " ", s)
    s = re.sub(r"[^a-z0-9一-鿿]+", " ", s).strip()
    tokens = [t for t in s.split() if t and t not in _LEGAL_SUFFIXES]
    return _CJK_LEGAL_SUFFIX_RE.sub("", "".join(tokens))


def _group_key(value: str) -> str:
    """Normalised ransomware group name + alias fold (spec §二)."""
    s = (value or "").lower()
    s = re.sub(r"[^a-z0-9]+", "", s)
    s = re.sub(r"\d+(\.\d+)*$", "", s)  # trailing version numbers
    return _GROUP_ALIASES.get(s, s)


def _similarity(a: str, b: str) -> float:
    """SequenceMatcher ratio on already-normalised strings."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def _victim_day(*values: str) -> _date | None:
    """First parseable date among the given tracker fields.

    Trackers are inconsistent: ISO timestamps, bare dates, and US-style slashes
    all appear, sometimes with a trailing timezone.
    """
    for value in values:
        s = (value or "").strip()
        if not s:
            continue
        iso = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
        if iso:
            try:
                return _date(int(iso.group(1)), int(iso.group(2)), int(iso.group(3)))
            except ValueError:
                pass
        for fmt in ("%m/%d/%Y", "%d/%m/%Y", "%m/%d/%y", "%Y/%m/%d"):
            try:
                return datetime.strptime(s[:10], fmt).date()
            except ValueError:
                continue
    return None


def _ransom_match(
    live: dict[str, Any],
    look: dict[str, Any],
    *,
    max_day_gap: int = DEFAULT_DAY_GAP,
) -> str | None:
    """Decide whether two tracker rows describe the same victim (spec §一).

    Returns evidence string, or None when not dual-confirmed.

    Paths (either is enough):
      A. Shared domain — strongest join key; still recorded as dual-source.
      B. name_sim ≥ 0.85 AND group_sim ≥ 0.90 (or alias) AND date gap ≤ window.

    Window defaults to 7 days; callers must not exceed MAX_DAY_GAP (14).
    Short/generic names (< 5 normalised chars) cannot pass path B alone.
    """
    gap = min(max(1, max_day_gap), MAX_DAY_GAP)

    live_domain = _victim_domain(
        str(live.get("website") or ""), str(live.get("post_url") or "")
    )
    look_domain = _victim_domain(
        str(look.get("website") or ""),
        str(look.get("link") or ""),
        str(look.get("post_url") or ""),
    )
    if live_domain and live_domain == look_domain:
        return f"domain={live_domain}"

    live_name = _victim_name_key(
        str(live.get("post_title") or live.get("victim") or "")
    )
    look_name = _victim_name_key(
        str(look.get("post_title") or look.get("title") or look.get("victim") or "")
    )
    if not live_name or not look_name or len(live_name) < 5 or len(look_name) < 5:
        return None

    name_sim = _similarity(live_name, look_name)
    if name_sim < NAME_SIM_THRESHOLD:
        return None

    live_group = _group_key(str(live.get("group_name") or live.get("group") or ""))
    look_group = _group_key(str(look.get("group_name") or look.get("group") or ""))
    if not live_group or not look_group:
        return None

    if live_group == look_group:
        group_ok = True
        group_sim = 1.0
    else:
        group_sim = _similarity(live_group, look_group)
        group_ok = group_sim >= GROUP_SIM_THRESHOLD
    if not group_ok:
        return None

    live_day = _victim_day(
        str(live.get("discovered") or ""), str(live.get("published") or "")
    )
    look_day = _victim_day(
        str(look.get("discovered") or ""), str(look.get("published") or "")
    )
    if not live_day or not look_day:
        return None
    if abs((live_day - look_day).days) > gap:
        return None

    return (
        f"name={name_sim:.2f}+group={group_sim:.2f}+within{gap}d"
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
) -> str:
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

    # R2-2: resolve verification first — dual-source TW ransomware → P0
    # only when verification is credible/confirmed (see assign_priority).
    if dual_verified:
        verification, admiralty = "credible", "B2"
    else:
        verification, admiralty = "unverified", "C3"

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
    rz, re_ = explain_priority(
        priority=priority,
        is_ransomware=is_ransom,
        is_tw_industry=is_tw,
        source_count=source_count,
        dual_verified=dual_verified,
        forced_p3_review=force_p3,
        verification=verification,
    )

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
        f"{'雙源確認' if dual_verified else '單源未核實 → P3 複核佇列'}）\n"
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
        f"{'dual-source confirmed' if dual_verified else 'single-source → P3 review'})\n"
        f"{re_}"
    )

    link = url or (
        f"https://www.ransomware.live/"
        if "ransomware.live" in source_name.lower()
        else "https://www.ransomlook.io/"
    )

    item_id = _id(source_id, victim, group, discovered or published or "")
    await upsert_intel(
        {
            "id": item_id,
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
            # day_bucket, not a [:10] slice: RansomLook's RSS fallback dates its
            # posts in RFC-822, which sliced to 'Mon, 20 Ju' — and date_added is
            # the first COALESCE key, so it decided the sparkline bucket.
            # (upsert_intel would drop that to NULL now; bucketing here keeps the
            # real post date instead of falling back to the harvest time.)
            "date_added": day_bucket(discovered or published) or None,
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
                    "dual_verified": dual_verified,
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
    return item_id


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
                            "description": _strip_html(e.get("summary") or "")[:900],
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


async def dual_source_ransom_trackers() -> int:
    """
    Elevate victims seen on both Ransomware.live and RansomLook to credible.
    Runs after both collectors; re-upserts dual-verified cards.

    Matching follows the T5/T6 agent spec: domain share, or
    name≥85% + group≥90%/alias + date≤7d (see _ransom_match).
    """
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

        # Candidate buckets: exact domain, else name key for fuzzy pass
        look_by_domain: dict[str, list[dict]] = {}
        look_by_name: dict[str, list[dict]] = {}
        for row in rl_rows[:120]:
            dom = _victim_domain(
                str(row.get("website") or ""),
                str(row.get("link") or ""),
                str(row.get("post_url") or ""),
            )
            if dom:
                look_by_domain.setdefault(dom, []).append(row)
            nm = _victim_name_key(
                str(row.get("post_title") or row.get("title") or row.get("victim") or "")
            )
            if len(nm) >= 5:
                look_by_name.setdefault(nm, []).append(row)

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

        rejected = 0
        for row in live_rows[:150]:
            victim = str(
                row.get("post_title") or row.get("victim") or row.get("website") or ""
            )
            # Broad candidate set: same domain, exact name key, plus near-key
            # neighbours are not pre-indexed — fuzzy is applied in _ransom_match.
            candidates = look_by_domain.get(
                _victim_domain(
                    str(row.get("website") or ""), str(row.get("post_url") or "")
                ),
                [],
            ) + look_by_name.get(_victim_name_key(victim), [])
            # Also try other name-bucket keys that share a long prefix (≥4)
            # so 85% similarity can still fire without O(n²) on all rows.
            vn = _victim_name_key(victim)
            if len(vn) >= 5:
                prefix = vn[:4]
                for key, rows in look_by_name.items():
                    if key.startswith(prefix) or vn.startswith(key[:4]):
                        for cand in rows:
                            if cand not in candidates:
                                candidates.append(cand)

            partner = None
            evidence = ""
            for cand in candidates:
                why = _ransom_match(row, cand)  # default 7-day window
                if why:
                    partner, evidence = cand, why
                    break
            if partner is None:
                if candidates:
                    rejected += 1
                continue
            group = str(
                row.get("group_name")
                or row.get("group")
                or partner.get("group_name")
                or ""
            )
            dual_id = await _upsert_ransom_victim_item(
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
                extra_sources=[f"RansomLook ({evidence})"],
                dual_verified=True,
            )
            await mark_superseded_ransom_rows(
                victim=victim,
                group=group,
                dual_id=dual_id,
                website=str(row.get("website") or ""),
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
            detail=(
                f"elevated={elevated}; rejected_near={rejected}; "
                f"rule=domain OR name≥{NAME_SIM_THRESHOLD}+group≥{GROUP_SIM_THRESHOLD}+≤{DEFAULT_DAY_GAP}d"
            ),
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
