"""Three-signal priority, org-asset mapping, evidence grade, section routing."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .io_yaml import load_yaml
from .paths import CONFIG_DIR

PRIO_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

OFFICIAL_HINTS = (
    "cisa",
    "nvd",
    "msrc",
    "psirt",
    "productcert",
    "twcert",
    "ncsc",
    "jpcert",
    "enisa",
    "nukib",
    "siemens productcert",
    "fortiguard",
)
MEDIA_HINTS = (
    "hacker news",
    "bleeping",
    "dark reading",
    "securityweek",
    "recorded future",
    "infosecurity",
    "gartner",
    "third-party",
)
UNVERIFIED_HINTS = (
    "twitter",
    "x.com",
    "rumor",
    "unconfirmed",
    "alleged",
    "osint",
    "leak site",
    "telegram",
)

OT_HINTS = (
    "ics",
    # Bare "OT". The trailing space this used to carry was a hand-rolled word
    # boundary that still matched "as root on " and "but not lim…"; matches_keyword
    # anchors it properly, so the space is now noise.
    "ot",
    "scada",
    "plc",
    "siemens",
    "rockwell",
    "schneider",
    "modbus",
    "profinet",
    "opc ua",
    "industrial",
    "icsa-",
    "icsma",
    "dragos",
    "claroty",
    "nozomi",
)
EXPOSURE_HINTS = (
    "easm",
    "certificate",
    "憑證",
    "typosquat",
    "lookalike",
    "brand",
    "leak",
    "breach",
    "hibp",
    "stealer",
    "credential",
    "shodan",
    "censys",
    "exposed",
    "supply chain",
    "供應鏈",
)
PSIRT_HINTS = (
    "sbom",
    "cra",
    "psirt",
    "product security",
    "component",
    "openssl",
    "log4j",
    "upstream",
    "firmware",
    "out-of-bounds",
    "library",
)
MARKET_HINTS = (
    "ctem",
    "aev",
    "eap",
    "amtd",
    "deception",
    "breach and attack",
    # Qualified: a bare "validation" filed every "Improper Input Validation" CVE
    # under 先制式技術與市場動態, and word boundaries cannot fix that on their own.
    "security validation",
    "attack simulation",
    "continuous threat",
    "adversarial exposure",
    "picus",
    "cymulate",
    "safebreach",
    "horizon3",
    "xm cyber",
    "morphisec",
    "acalvio",
    "bforeai",
    "watchtowr",
    "predictive dns",
    "gartner",
)


@lru_cache(maxsize=1)
def load_assets(config_dir: str | None = None) -> dict[str, Any]:
    path = Path(config_dir) / "assets.yaml" if config_dir else CONFIG_DIR / "assets.yaml"
    data = load_yaml(path) or {}
    return data


def _blob(*parts: Any) -> str:
    return " ".join(str(p) for p in parts if p).lower()


_CJK_RE = re.compile(r"[㐀-䶿一-鿿豈-﫿]")

# Market context required before a bare Taiwan ticker counts as a company hit.
_TICKER_CONTEXT = (
    r"twse|tpex|tse|otc|taiex|"
    r"台股|臺股|股票代號|股票代碼|股號|代號|代碼|上市|上櫃|股價|台證|臺證"
)

_KEYWORD_RE_CACHE: dict[str, re.Pattern[str]] = {}


def keyword_regex(keyword: str) -> re.Pattern[str]:
    """Compile one config keyword into a false-positive-resistant matcher.

    The rules mirror ``soc_cti_dashboard/backend/priority.py::_alias_regex``,
    which remains the canonical implementation. They are restated rather than
    imported because this package is deliberately standalone (see io_yaml.py) —
    importing the dashboard's priority module would drag in backend.config and
    its environment lookups, and generate_brief.py must run without them.

    * numeric  — a Taiwan ticker. A bare 4-digit run matches CVE ids, dates and
      byte counts far more often than a listed company, so it only counts next
      to market context ("TWSE 2356", "2356.TW", "(2356)").
    * CJK      — substring. Word boundaries are meaningless between Han
      characters and CJK names are distinctive on their own.
    * trailing hyphen ("icsa-") — prefix match, for enumerated advisory ids.
    * otherwise — boundary-anchored, so "ICS" no longer fires on "forensics",
      "OT" on "as root on", "EAP" on "heap-based buffer overflow", or
      "Gateway" without a Citrix/NetScaler qualifier.
    """
    kw = (keyword or "").strip()
    cached = _KEYWORD_RE_CACHE.get(kw)
    if cached is not None:
        return cached

    if not kw:
        pattern = re.compile(r"(?!)")  # never matches
    elif kw.isdigit():
        esc = re.escape(kw)
        pattern = re.compile(
            rf"(?:{_TICKER_CONTEXT})[^0-9a-z]{{0,8}}{esc}(?![0-9])"
            rf"|(?<![0-9]){esc}\s*\.\s*tw(?![a-z])"
            rf"|[（(]\s*{esc}\s*[）)]",
            re.I,
        )
    elif _CJK_RE.search(kw):
        pattern = re.compile(re.escape(kw))
    elif kw.endswith("-"):
        pattern = re.compile(rf"(?<![0-9a-z]){re.escape(kw)}", re.I)
    else:
        pattern = re.compile(rf"(?<![0-9a-z]){re.escape(kw)}(?![0-9a-z])", re.I)

    _KEYWORD_RE_CACHE[kw] = pattern
    return pattern


def matches_keyword(text: str, keyword: str) -> bool:
    return bool(keyword_regex(keyword).search(text or ""))


def _first_hint(blob: str, hints: tuple[str, ...]) -> str | None:
    """First hint word that appears in blob as a word, not as a substring."""
    return next((h for h in hints if matches_keyword(blob, h)), None)


def match_assets(text: str, config_dir: str | None = None) -> list[dict[str, str]]:
    """Return asset hits from config/assets.yaml (word-anchored, case-insensitive).

    Every hit here promotes the item one priority level and stamps
    〔本組織相關〕, so a false positive is not cosmetic. The previous naive
    ``kw in blob`` form attributed "forensics triage" to the SCADA asset via
    "ICS", "IKEv1 key exchange" to Microsoft Exchange, and "Check Point
    Security Gateway" to Citrix — see keyword_regex for the matching rules.
    """
    data = load_assets(config_dir)
    hits: list[dict[str, str]] = []
    blob = (text or "").lower()
    for asset in data.get("assets") or []:
        kws = asset.get("keywords") or []
        matched = next((kw for kw in kws if matches_keyword(blob, str(kw))), None)
        if matched:
            hits.append(
                {
                    "key": str(asset.get("key") or ""),
                    "matched": str(matched),
                    "owner": str(asset.get("owner") or ""),
                    "kind": str(asset.get("kind") or ""),
                    "iec62443": str(asset.get("iec62443") or ""),
                    "cra": "1" if asset.get("cra") else "",
                }
            )
    return hits


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def three_signal_priority(
    *,
    in_kev: bool = False,
    mass_exploitation: bool = False,
    epss: float | None = None,
    epss_delta: float | None = None,
    cvss: float | None = None,
    org_asset: bool = False,
) -> str:
    """KEV / EPSS / CVSS three-signal ranking (prompt §3.4).

    P0  KEV AND confirmed mass exploitation / known ransomware campaign
    P1  KEV alone; or confirmed mass exploitation without a KEV listing;
        or (EPSS ≥ 0.5 or 24h jump ≥ 0.2) AND CVSS ≥ 7.0 AND org asset type
    P2  CVSS ≥ 9.0 but EPSS low (watch, not must-do)
    P3  everything else
    Org-asset hits then promote one level (P3→P2, P2→P1; P0/P1 stay).

    P0 requires both signals so that this scale means the same thing as the
    dashboard's (soc_cti_dashboard/backend/priority.py::assign_priority: "P0
    KEV + known ransomware campaign", "P1 in KEV and not already P0"). Treating
    a KEV listing alone as P0 put 191 of 400 rows at a 24-hour deadline while
    the same rows showed as 14 P0 + 106 P1 on the dashboard — two contradictory
    P0 counts for one definition, and a must-do list too long to act on.
    """
    if in_kev and mass_exploitation:
        base = "P0"
    elif in_kev or mass_exploitation:
        base = "P1"
    else:
        epss_hot = (epss is not None and epss >= 0.5) or (
            epss_delta is not None and epss_delta >= 0.2
        )
        cvss_hi = cvss is not None and cvss >= 7.0
        if epss_hot and cvss_hi and org_asset:
            base = "P1"
        elif cvss is not None and cvss >= 9.0 and not epss_hot:
            base = "P2"
        else:
            base = "P3"

    if org_asset and base not in ("P0", "P1"):
        base = "P2" if base == "P3" else "P1"
    return base


def evidence_grade(
    *,
    source_name: str = "",
    verification: str = "",
    source_count: int = 1,
    layer_id: str = "",
) -> str:
    """confirmed | third_party | unverified  (maps to 【已證實】／【第三方評論】／【尚未證實】)."""
    if verification == "confirmed" or layer_id == "L1":
        return "confirmed"
    blob = source_name.lower()
    if any(h in blob for h in OFFICIAL_HINTS) or verification == "credible":
        return "confirmed" if any(h in blob for h in OFFICIAL_HINTS) else "third_party"
    if any(h in blob for h in UNVERIFIED_HINTS) or (source_count <= 1 and verification == "unverified"):
        if any(h in blob for h in MEDIA_HINTS):
            return "third_party"
        return "unverified"
    if any(h in blob for h in MEDIA_HINTS) or source_count >= 2:
        return "third_party"
    if verification == "unverified":
        return "unverified"
    return "third_party"


def assign_section(item: dict[str, Any], assets: list[dict[str, str]]) -> str:
    """Route one item into a brief section key."""
    blob = _blob(
        item.get("title"),
        item.get("summary"),
        item.get("source_name"),
        item.get("vendor"),
        item.get("product"),
        " ".join(str(t) for t in (item.get("tags") or [])),
    )
    kinds = {a.get("kind") for a in assets}
    owners = {a.get("owner") for a in assets}
    if _first_hint(blob, OT_HINTS) or owners & {"OT"} or kinds & {"plc", "protocol", "ics"}:
        return "ot_ics"
    if _first_hint(blob, EXPOSURE_HINTS) or item.get("is_ransomware"):
        return "exposure"
    if _first_hint(blob, MARKET_HINTS):
        return "market"
    if _first_hint(blob, PSIRT_HINTS) or kinds & {"sbom", "brand", "supply_chain"} or any(
        a.get("cra") for a in assets
    ):
        return "psirt"
    if item.get("cve_id") or item.get("in_kev") or item.get("epss") is not None:
        return "kev_epss"
    # Fallback is 追蹤清單, not kev_epss. Section 3 renders a KEV/EPSS table keyed
    # on a scored vulnerability, so anything without a CVE, a KEV listing or an
    # EPSS score that landed there was counted in stats.total and then rendered
    # nowhere -- 72 of 400 rows (ThreatFox IOC bundles for Remcos, AdaptixC2,
    # Vidar, Havoc …) vanished from the brief entirely.
    return "watch"


def classify_item(raw: dict[str, Any], config_dir: str | None = None) -> dict[str, Any]:
    """Annotate a raw intel-like dict with brief fields. Never invents CVE / scores."""
    blob = _blob(
        raw.get("title"),
        raw.get("summary"),
        raw.get("vendor"),
        raw.get("product"),
        raw.get("source_name"),
        raw.get("cve_id"),
    )
    assets = match_assets(blob, config_dir)
    tags = raw.get("tags") if isinstance(raw.get("tags"), list) else []
    in_kev = bool(
        raw.get("in_kev")
        or matches_keyword(str(raw.get("source_name") or ""), "kev")
        or any(matches_keyword(str(t), "kev") for t in tags)
    )
    mass = bool(raw.get("mass_exploitation"))
    if not mass and raw.get("known_ransomware_campaign"):
        # The dashboard sets known_ransomware_campaign for two different things:
        # CISA's knownRansomwareCampaignUse on a KEV row (a real mass-exploitation
        # signal), and every leak-site victim listing, where it only means "a crew
        # posted a victim" — an unverified attacker claim with no CVE attached.
        # Only the former is a three-signal input; counting the latter put 67
        # leak-site posts on the must-do list.
        mass = bool(raw.get("cve_id") or in_kev)
    epss = _as_float(raw.get("epss"))
    epss_delta = _as_float(raw.get("epss_delta"))
    cvss = _as_float(raw.get("cvss") if raw.get("cvss") is not None else raw.get("cvss_score"))
    org = bool(assets)
    prio = three_signal_priority(
        in_kev=in_kev,
        mass_exploitation=mass,
        epss=epss,
        epss_delta=epss_delta,
        cvss=cvss,
        org_asset=org,
    )
    grade = evidence_grade(
        source_name=str(raw.get("source_name") or ""),
        verification=str(raw.get("verification") or ""),
        source_count=int(raw.get("evidence_count") or raw.get("source_count") or 1),
        layer_id=str(raw.get("layer_id") or ""),
    )
    section = assign_section({**raw, "in_kev": in_kev}, assets)
    if prio == "P3" and grade == "unverified" and section != "ot_ics":
        section = "watch"

    owner = next((a["owner"] for a in assets if a.get("owner")), None)
    if not owner:
        owner = "OT" if section == "ot_ics" else "PSIRT" if section == "psirt" else "IT"

    out = dict(raw)
    out.update(
        {
            "brief_priority": prio,
            "in_kev": in_kev,
            "epss": epss,
            "epss_delta": epss_delta,
            "cvss": cvss,
            "cvss_version": raw.get("cvss_version") or ("v3.1" if cvss is not None else None),
            "org_related": org,
            "org_assets": assets,
            "evidence_grade": grade,
            "section": section,
            "owner_unit": owner,
            "iec62443": next((a["iec62443"] for a in assets if a.get("iec62443")), ""),
        }
    )
    return out


def promote_if_upgrade(item: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    """Mark ⬆ status upgrade when an already-reported item crosses a gate."""
    if not previous:
        item["status_upgrade"] = False
        return item
    reasons: list[str] = []
    if item.get("in_kev") and not previous.get("in_kev"):
        reasons.append("進入 KEV")
    prev_epss = _as_float(previous.get("epss"))
    now_epss = _as_float(item.get("epss"))
    if now_epss is not None and prev_epss is not None and now_epss >= 0.5 > prev_epss:
        reasons.append("EPSS 跨越 0.5")
    if item.get("poc") and not previous.get("poc"):
        reasons.append("PoC 公開")
    if item.get("mass_exploitation") and not previous.get("mass_exploitation"):
        reasons.append("開始大規模利用")
    item["status_upgrade"] = bool(reasons)
    item["upgrade_reason"] = "；".join(reasons)
    return item
