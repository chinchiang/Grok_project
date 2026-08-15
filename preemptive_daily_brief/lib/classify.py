"""Three-signal priority, org-asset mapping, evidence grade, section routing."""

from __future__ import annotations

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
    "ot ",
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
    "validation",
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


def match_assets(text: str, config_dir: str | None = None) -> list[dict[str, str]]:
    """Return asset hits from config/assets.yaml (keyword substring, case-insensitive)."""
    data = load_assets(config_dir)
    hits: list[dict[str, str]] = []
    blob = (text or "").lower()
    for asset in data.get("assets") or []:
        kws = asset.get("keywords") or []
        matched = next((kw for kw in kws if str(kw).lower() in blob), None)
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

    P0  KEV or confirmed mass exploitation
    P1  (EPSS ≥ 0.5 or 24h jump ≥ 0.2) AND CVSS ≥ 7.0 AND org asset type
    P2  CVSS ≥ 9.0 but EPSS low (watch, not must-do)
    P3  everything else
    Org-asset hits then promote one level (P3→P2, P2→P1; P0/P1 stay).
    """
    if in_kev or mass_exploitation:
        base = "P0"
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
    if any(h in blob for h in OT_HINTS) or owners & {"OT"} or kinds & {"plc", "protocol", "ics"}:
        return "ot_ics"
    if any(h in blob for h in EXPOSURE_HINTS) or item.get("is_ransomware"):
        return "exposure"
    if any(h in blob for h in MARKET_HINTS):
        return "market"
    if any(h in blob for h in PSIRT_HINTS) or kinds & {"sbom", "brand", "supply_chain"} or any(
        a.get("cra") for a in assets
    ):
        return "psirt"
    if item.get("cve_id") or item.get("in_kev") or item.get("epss") is not None:
        return "kev_epss"
    if item.get("verification") == "unverified":
        return "watch"
    return "kev_epss"


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
    in_kev = bool(
        raw.get("in_kev")
        or "kev" in str(raw.get("source_name") or "").lower()
        or (isinstance(raw.get("tags"), list) and any("kev" in str(t).lower() for t in raw["tags"]))
    )
    mass = bool(raw.get("mass_exploitation") or raw.get("known_ransomware_campaign"))
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
