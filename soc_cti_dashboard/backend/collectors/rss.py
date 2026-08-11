"""Generic RSS/Atom layer collector and the registered feed sweep."""

from __future__ import annotations

import json
import re
import time
from typing import Any
import feedparser
from ..config import derive_source_class, INTEL_FEEDS, HTTP_TIMEOUT
from ..database import now_iso, upsert_intel
from ..priority import assign_priority, assign_verification, enrich_flags

from ._base import _client, _id, _mark


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
    source_class: str | None = None,
) -> int:
    t0 = time.perf_counter()
    count = 0
    used_url = url
    # R3-1: reliability class drives single-source credibility (media needs 2 sources)
    src_class = source_class or derive_source_class(source_id, extra_tags)
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
            # R2-2: verification MUST be resolved before assign_priority so that
            # dual-source TW + ransomware can elevate to P0 (credible gate).
            verification, admiralty = assign_verification(
                in_kev=False,
                layer_id=layer_id,
                source_count=source_count,
                is_darkweb_indirect=darkweb_indirect,
                source_class=src_class,
            )
            if darkweb_indirect and source_count < 2:
                verification = "unverified"
                admiralty = "C3"
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=None,
                source_count=source_count,
                layer_id=layer_id,
                force_p3_review=force_p3,
                verification=verification,
            )

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
                + [f"src:{src_class}"]
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
                source_class=feed.get("source_class"),
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
