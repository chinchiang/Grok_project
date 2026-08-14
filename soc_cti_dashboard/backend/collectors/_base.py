"""Shared plumbing: stable ids, the HTTP client, and source-health reporting."""

from __future__ import annotations

import hashlib
import feedparser
import httpx
from ..config import USER_AGENT, HTTP_TIMEOUT
from ..database import now_iso, upsert_source_health
from ..textclean import clean_text


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

def _strip_html(s: str) -> str:
    """Turn feed markup into the plain text the UI shows."""
    return clean_text(s)

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
                # _strip_html, not an inline tag strip: the summary is raw feed
                # markup and needs entity decoding too, or `&nbsp;` survives all
                # the way to the analyst's screen.
                "summary": _strip_html(
                    e.get("summary") or e.get("description") or ""
                )[:1200],
                "link": e.get("link") or profile,
                "published": e.get("published") or "",
            }
        )
    return out
