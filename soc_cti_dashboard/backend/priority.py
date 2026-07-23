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
"""

from __future__ import annotations

from typing import Any

from .config import RANSOMWARE_KEYWORDS, TW_ELECTRONICS_WATCHLIST


def text_blob(*parts: str | None) -> str:
    return " ".join(p for p in parts if p).lower()


def match_tw_entities(text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    t = text.lower()
    for ent in TW_ELECTRONICS_WATCHLIST:
        for alias in ent["aliases"]:
            if alias.lower() in t:
                hits.append(
                    {"key": ent["key"], "matched": alias, "tier": ent["tier"]}
                )
                break
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


def enrich_flags(title: str, summary: str, vendor: str = "", product: str = "") -> dict[str, Any]:
    blob = text_blob(title, summary, vendor, product)
    tw = match_tw_entities(blob)
    ransomware = is_ransomware_text(blob)
    return {
        "is_ransomware": ransomware,
        "is_tw_industry": len(tw) > 0,
        "tw_entities": tw,
    }
