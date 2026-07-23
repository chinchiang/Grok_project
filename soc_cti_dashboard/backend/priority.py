"""
P0–P3 exclusive priority assignment.

Rules (mutually exclusive — P1 never mixed into other buckets):
  P0  KEV + known ransomware campaign use
      OR Taiwan electronics/semi manufacturing victim + ransomware
      OR dual-confirmed critical exploit against TW manufacturing stack
  P1  In CISA KEV (confirmed in-the-wild) and NOT already P0
  P2  Not KEV; high EPSS (>= 0.5) OR multi-source credible non-KEV alert
  P3  Everything else under monitoring

Verification:
  confirmed   — official authority (CISA KEV, ICS official)
  credible    — >= 2 independent sources OR official non-KEV
  unverified  — single source / dark-web indirect without second source

Category flags (orthogonal to priority):
  is_tw_industry / is_finance / is_microsoft — tab filtering only
"""

from __future__ import annotations

import re
from typing import Any

from .config import (
    FINANCE_WATCHLIST,
    MICROSOFT_WATCHLIST,
    RANSOMWARE_KEYWORDS,
    TW_ELECTRONICS_WATCHLIST,
)


def text_blob(*parts: str | None) -> str:
    return " ".join(p for p in parts if p).lower()


def _match_watchlist(text: str, watchlist: list[dict[str, Any]]) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    t = text.lower()
    for ent in watchlist:
        for alias in ent["aliases"]:
            alias_l = alias.lower()
            if alias_l in t:
                hits.append(
                    {"key": ent["key"], "matched": alias, "tier": ent.get("tier", "")}
                )
                break
    return hits


def match_tw_entities(text: str) -> list[dict[str, str]]:
    return _match_watchlist(text, TW_ELECTRONICS_WATCHLIST)


def match_finance_entities(text: str) -> list[dict[str, str]]:
    return _match_watchlist(text, FINANCE_WATCHLIST)


def match_microsoft_entities(text: str, vendor: str = "", product: str = "") -> list[dict[str, str]]:
    """
    Microsoft-related matching with vendor/product boost.

    Rules for correctness:
    - Vendor Microsoft → always classify (KEV catalog).
    - Known non-Microsoft vendor → only match product/title (first ~220 chars),
      never full multi-browser descriptions that casually mention Edge.
    - Empty vendor (news RSS) → full text match with specific product strings.
    """
    v = (vendor or "").strip().lower()
    p = (product or "").strip().lower()
    is_ms_vendor = v in ("microsoft", "microsoft corporation") or v.startswith(
        "microsoft "
    )

    if is_ms_vendor:
        blob = text_blob(text, vendor, product)
        hits = _match_watchlist(blob, MICROSOFT_WATCHLIST)
        if not any(h["key"] == "microsoft" for h in hits):
            hits.append(
                {
                    "key": "microsoft",
                    "matched": vendor or "Microsoft",
                    "tier": "vendor",
                }
            )
        return hits

    # Non-MS vendor (e.g. Google Chromium notes "including Microsoft Edge")
    if v:
        short = text_blob(product, (text or "")[:220])
        hits = _match_watchlist(short, MICROSOFT_WATCHLIST)
        weak_aliases = {"microsoft", "microsoft edge", "微軟"}
        strong_keys = {
            "exchange",
            "azure",
            "m365",
            "identity",
            "windows",
            "security_stack",
            "server_apps",
        }
        filtered: list[dict[str, str]] = []
        for h in hits:
            matched = (h.get("matched") or "").lower()
            if matched in weak_aliases:
                continue
            if h.get("key") == "microsoft":
                continue
            if h.get("key") in strong_keys:
                filtered.append(h)
        return filtered

    # News / no vendor: full-text specific product watchlist
    hits = _match_watchlist(text_blob(text, product), MICROSOFT_WATCHLIST)
    if p and not hits:
        ms_product = re.search(
            r"\b(exchange|sharepoint|azure|windows server|sql server|active directory|office 365|microsoft 365)\b",
            p,
        )
        if ms_product:
            hits.append(
                {
                    "key": "server_apps",
                    "matched": ms_product.group(0),
                    "tier": "product",
                }
            )
    return hits


def is_ransomware_text(text: str) -> bool:
    t = text.lower()
    return any(k.lower() in t for k in RANSOMWARE_KEYWORDS)


def assign_priority(
    *,
    in_kev: bool,
    known_ransomware_campaign: bool,
    is_ransomware: bool,
    is_tw_industry: bool,
    epss: float | None,
    source_count: int,
    layer_id: str,
) -> str:
    """Return exactly one of P0|P1|P2|P3 — exclusive, no mixing."""
    # P0 first
    if in_kev and known_ransomware_campaign:
        return "P0"
    if is_tw_industry and is_ransomware:
        return "P0"
    if is_tw_industry and in_kev:
        return "P0"

    # P1: pure KEV without P0 elevation
    if in_kev:
        return "P1"

    # P2: predictive / multi-source
    if epss is not None and epss >= 0.5:
        return "P2"
    if source_count >= 2 and layer_id in ("L2", "L3", "L6", "L7"):
        return "P2"
    if is_ransomware and source_count >= 2:
        return "P2"

    return "P3"


def assign_verification(
    *,
    in_kev: bool,
    layer_id: str,
    source_count: int,
    is_darkweb_indirect: bool,
) -> tuple[str, str]:
    """
    Returns (verification, admiralty_hint)
    verification: confirmed | credible | unverified
    """
    if in_kev or layer_id == "L1" and source_count >= 1 and not is_darkweb_indirect:
        if in_kev:
            return "confirmed", "A1"
        return "confirmed", "A2"

    if is_darkweb_indirect:
        if source_count >= 2:
            return "credible", "B2"
        return "unverified", "C3"

    if source_count >= 2:
        return "credible", "B2"
    if layer_id in ("L2", "L7"):
        return "credible", "B2"
    return "unverified", "C3"


def enrich_flags(
    title: str, summary: str, vendor: str = "", product: str = ""
) -> dict[str, Any]:
    blob = text_blob(title, summary, vendor, product)
    tw = match_tw_entities(blob)
    finance = match_finance_entities(blob)
    ms = match_microsoft_entities(blob, vendor=vendor, product=product)
    ransomware = is_ransomware_text(blob)
    return {
        "is_ransomware": ransomware,
        "is_tw_industry": len(tw) > 0,
        "tw_entities": tw,
        "is_finance": len(finance) > 0,
        "finance_entities": finance,
        "is_microsoft": len(ms) > 0,
        "ms_entities": ms,
    }
