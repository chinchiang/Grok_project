"""
P0–P3 exclusive priority assignment (first match wins, no mixing).

  P0  KEV + known ransomware campaign
      OR TW electronics/semi watchlist + ransomware
      OR TW industry + KEV
  P1  In CISA KEV and not already P0  (never mixed into P2/P3)
  P2  Not KEV; EPSS >= 0.5 OR multi-source credible
  P3  Everything else (incl. single-source dark-web review queue)

Verification:
  confirmed / credible / unverified + Admiralty hint
"""

from __future__ import annotations

import re
from typing import Any

from .config import (
    FINANCE_WATCHLIST,
    FINANCE_WORD_PATTERNS,
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


def _scrub_finance_false_positives(text: str) -> str:
    """Strip CISA-style critical-infrastructure sector laundry lists.

    ICS advisories often enumerate sectors like
    ``…; Healthcare and Public Health; Financial Services; Government…``
    which must not flag every ICS advisory as finance intel.
    """
    t = text
    # Semicolon / slash separated "Financial Services" in multi-sector lists
    t = re.sub(r"(?<=[;/|])\s*Financial Services\b", " ", t, flags=re.I)
    t = re.sub(r"\bFinancial Services\s*(?=[;/|])", " ", t, flags=re.I)
    t = re.sub(
        r"\b(?:Commercial Facilities|Communications|Critical Manufacturing|"
        r"Dams|Defense Industrial Base|Emergency Services|Energy|"
        r"Financial Services|Food and Agriculture|Government Facilities|"
        r"Healthcare and Public Health|Information Technology|"
        r"Nuclear Reactors|Transportation Systems|Water and Wastewater)\b",
        " ",
        t,
        flags=re.I,
    )
    # 中文關鍵基礎設施領域列舉中的「金融服務」
    t = re.sub(r"關鍵基礎設施領域[：:][^\n]{0,200}", " ", t)
    t = re.sub(r"金融服務[；;、,/]", " ", t)
    return t


def match_finance_entities(text: str) -> list[dict[str, str]]:
    cleaned = _scrub_finance_false_positives(text)
    # Drop leak-dump boilerplate that is not a finance-sector victim signal
    cleaned = re.sub(
        r"\bfinancial\s+(documents?|data|information|records?|files?|"
        r"reporting|accounting|planning|statements?)\b",
        " ",
        cleaned,
        flags=re.I,
    )
    hits = _match_watchlist(cleaned, FINANCE_WATCHLIST)
    seen = {h["key"] for h in hits}
    low = cleaned.lower()
    for pat, key, tier in FINANCE_WORD_PATTERNS:
        m = re.search(pat, low, flags=re.I)
        if not m:
            continue
        if key in seen:
            continue
        hits.append({"key": key, "matched": m.group(0), "tier": tier})
        seen.add(key)
    return hits


def match_microsoft_entities(
    text: str, vendor: str = "", product: str = ""
) -> list[dict[str, str]]:
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
            "threat_intel",
        }
        filtered: list[dict[str, str]] = []
        for h in hits:
            matched = (h.get("matched") or "").lower()
            if matched in weak_aliases or h.get("key") == "microsoft":
                continue
            if h.get("key") in strong_keys:
                filtered.append(h)
        return filtered

    hits = _match_watchlist(text_blob(text, product), MICROSOFT_WATCHLIST)
    if p and not hits:
        ms_product = re.search(
            r"\b(exchange|sharepoint|azure|windows server|sql server|active directory|office 365|microsoft 365|entra)\b",
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
    force_p3_review: bool = False,
) -> str:
    """Return exactly one of P0|P1|P2|P3 — exclusive, first match wins."""
    # Spec: single-source dark-web → P3 review queue only
    if force_p3_review:
        return "P3"

    # P0 first
    if in_kev and known_ransomware_campaign:
        return "P0"
    if is_tw_industry and is_ransomware:
        return "P0"
    if is_tw_industry and in_kev:
        return "P0"

    # P1: pure KEV without P0 elevation — never mixed into P2
    if in_kev:
        return "P1"

    # P2: predictive / multi-source
    if epss is not None and epss >= 0.5:
        return "P2"
    if source_count >= 2 and layer_id in ("L2", "L3", "L6", "L7", "T2", "T3", "T6", "T7"):
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
    if in_kev:
        return "confirmed", "A1"
    if layer_id in ("L1", "T1") and source_count >= 1 and not is_darkweb_indirect:
        return "confirmed", "A2"

    if is_darkweb_indirect:
        if source_count >= 2:
            return "credible", "B2"
        return "unverified", "C3"

    if source_count >= 2:
        return "credible", "B2"
    if layer_id in ("L2", "L7", "T2", "T7"):
        return "credible", "B2"
    return "unverified", "C3"


def enrich_flags(
    title: str, summary: str, vendor: str = "", product: str = ""
) -> dict[str, Any]:
    # Ignore UI classification prefixes so re-tagging is not self-reinforcing
    title_clean = re.sub(
        r"^(?:💰\s*金融相關｜|🪟\s*微軟相關｜|🇹🇼\s*)+",
        "",
        title or "",
    )
    blob = text_blob(title_clean, summary, vendor, product)
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
