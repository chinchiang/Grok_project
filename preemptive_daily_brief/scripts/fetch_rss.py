"""Tier 2–4 RSS harvest. Each feed is independently fault-tolerant."""

from __future__ import annotations

import re
from email.utils import parsedate_to_datetime
from typing import Any
from xml.etree import ElementTree as ET

from preemptive_daily_brief.lib.io_yaml import load_yaml
from preemptive_daily_brief.lib.paths import CONFIG_DIR
from preemptive_daily_brief.scripts._http import try_urls

_TAG = re.compile(r"<[^>]+>")


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return _TAG.sub("", el.text).strip()


def _parse_rss(xml_text: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    items: list[dict[str, str]] = []
    # RSS 2.0
    for it in root.findall("./channel/item"):
        items.append(
            {
                "title": _text(it.find("title")),
                "summary": _text(it.find("description")),
                "url": _text(it.find("link")),
                "published_at": _text(it.find("pubDate")),
            }
        )
    # Atom
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for it in root.findall("a:entry", ns):
        link = ""
        for lk in it.findall("a:link", ns):
            href = lk.attrib.get("href") or ""
            if href:
                link = href
                break
        items.append(
            {
                "title": _text(it.find("a:title", ns)),
                "summary": _text(it.find("a:summary", ns)) or _text(it.find("a:content", ns)),
                "url": link,
                "published_at": _text(it.find("a:updated", ns)) or _text(it.find("a:published", ns)),
            }
        )
    return items


def _norm_date(raw: str) -> str:
    if not raw:
        return ""
    try:
        return parsedate_to_datetime(raw).isoformat()
    except (TypeError, ValueError, IndexError):
        return raw


def fetch_rss_tier(tiers: tuple[str, ...] = ("tier2", "tier3", "tier4")) -> dict[str, Any]:
    cfg = load_yaml(CONFIG_DIR / "sources.yaml") or {}
    items: list[dict[str, Any]] = []
    failed: list[dict[str, str]] = []
    ok_feeds: list[str] = []
    for tier in tiers:
        for src in cfg.get(tier) or []:
            if src.get("kind") not in ("rss", "json") and src.get("kind") == "web":
                failed.append(
                    {
                        "id": src.get("id") or "",
                        "name": src.get("name") or "",
                        "url": src.get("url") or "",
                        "error": "web-only source skipped (no structured feed)",
                    }
                )
                continue
            if src.get("kind") != "rss":
                continue
            url = src.get("url") or ""
            payload, used, err = try_urls([url], as_json=False, cache_name=f"rss_{src.get('id')}")
            if err or not isinstance(payload, str):
                failed.append(
                    {
                        "id": str(src.get("id") or ""),
                        "name": str(src.get("name") or ""),
                        "url": url,
                        "error": err or "empty",
                    }
                )
                continue
            ok_feeds.append(str(src.get("id")))
            klass = src.get("class") or src.get("vendor") or tier
            for row in _parse_rss(payload)[:12]:
                items.append(
                    {
                        "id": f"rss-{src.get('id')}-{row.get('url') or row.get('title')}",
                        "title": row.get("title") or src.get("name"),
                        "summary": (row.get("summary") or "")[:600],
                        "source_name": src.get("name"),
                        "url": row.get("url"),
                        "published_at": _norm_date(row.get("published_at") or ""),
                        "verification": "unverified" if klass in ("media", "early", "analyst") else "credible",
                        "layer_id": "L2" if tier == "tier2" else "L7" if "ics" in str(src.get("id")) else "L6",
                        "tags": [tier, klass],
                    }
                )
    return {
        "ok": True,
        "items": items,
        "failed": failed,
        "ok_feeds": ok_feeds,
        "source": "rss",
    }
