"""Microsoft-focused dashboard payload builder."""

from __future__ import annotations

from typing import Any

from .config import MICROSOFT_WATCHLIST

# Entity keys → product buckets
_WINDOWS_KEYS = frozenset({"windows"})
_ENTERPRISE_KEYS = frozenset(
    {"exchange", "azure", "m365", "identity", "security_stack", "server_apps"}
)
_TI_KEYS = frozenset({"threat_intel"})

_WINDOWS_HINTS = (
    "windows server",
    "windows 10",
    "windows 11",
    "windows 7",
    "win32k",
    "print spooler",
    "rdp",
    "remote desktop",
    "smbv",
    "ntoskrnl",
    "windows kernel",
)
_ENTERPRISE_HINTS = (
    "exchange",
    "sharepoint",
    "entra",
    "azure ad",
    "azure active directory",
    "defender",
    "intune",
    "office 365",
    "microsoft 365",
    "m365",
    "active directory",
    "outlook",
    "teams",
    "onedrive",
    "sql server",
    "iis ",
    "hyper-v",
    "sentinel",
    "dynamics",
)
_TI_HINTS = (
    "threat intelligence",
    "threat actor",
    "campaign",
    "ioc",
    "indicators of compromise",
    "nation-state",
    "storm-",
    "midnight blizzard",
    "nobelium",
    "apt",
    "attack chain",
    "ttPs",
    "ttp",
)
_MS_OFFICIAL_SOURCES = (
    "microsoft security blog",
    "msrc",
    "microsoft defender",
    "cisa kev",
)


def _blob(item: dict[str, Any]) -> str:
    parts = [
        item.get("title") or "",
        item.get("title_en") or "",
        item.get("summary") or "",
        item.get("product") or "",
        item.get("vendor") or "",
        item.get("source_name") or "",
    ]
    for ent in item.get("ms_entities") or []:
        parts.append(ent.get("key") or "")
        parts.append(ent.get("matched") or "")
    return " ".join(parts).lower()


def _entity_keys(item: dict[str, Any]) -> set[str]:
    return {
        (e.get("key") or "").lower()
        for e in (item.get("ms_entities") or [])
        if e.get("key")
    }


def is_kev_item(item: dict[str, Any]) -> bool:
    src = (item.get("source_name") or "").lower()
    tags = [str(t).lower() for t in (item.get("tags") or [])]
    return "kev" in src or "kev" in tags or "in-the-wild" in tags


def is_official_corroborated(item: dict[str, Any]) -> bool:
    """Official / high-trust corroboration: confirmed verification or MSRC/KEV/MS blog."""
    if item.get("verification") == "confirmed":
        return True
    src = (item.get("source_name") or "").lower()
    return any(s in src for s in _MS_OFFICIAL_SOURCES)


def ms_buckets(item: dict[str, Any]) -> set[str]:
    """
    Return product/theme buckets for Microsoft dashboard sections.
    Possible: windows_os, enterprise_platform, threat_intel, ransomware, other
    """
    keys = _entity_keys(item)
    text = _blob(item)
    buckets: set[str] = set()

    if keys & _WINDOWS_KEYS or any(h in text for h in _WINDOWS_HINTS):
        buckets.add("windows_os")
    if keys & _ENTERPRISE_KEYS or any(h in text for h in _ENTERPRISE_HINTS):
        buckets.add("enterprise_platform")
    if keys & _TI_KEYS or any(h in text for h in _TI_HINTS):
        buckets.add("threat_intel")
    src = (item.get("source_name") or "").lower()
    if "microsoft security blog" in src or "microsoft defender ti" in src:
        buckets.add("threat_intel")
    if "msrc" in src:
        # MSRC CVEs often OS or enterprise — already covered by product hints
        pass
    if item.get("is_ransomware"):
        buckets.add("ransomware")

    if not buckets:
        buckets.add("other")
    return buckets


def _entity_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    by_entity: dict[str, int] = {}
    for item in items:
        for ent in item.get("ms_entities") or []:
            k = ent.get("key") or "unknown"
            by_entity[k] = by_entity.get(k, 0) + 1
    return by_entity


def build_microsoft_dashboard(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble Microsoft tab payload from classified intel items."""
    windows: list[dict] = []
    enterprise: list[dict] = []
    threat_intel: list[dict] = []
    ransomware: list[dict] = []
    p1_items: list[dict] = []
    kev_items: list[dict] = []
    confirmed_items: list[dict] = []
    other: list[dict] = []

    seen_win: set[str] = set()
    seen_ent: set[str] = set()
    seen_ti: set[str] = set()

    for item in items:
        iid = item.get("id") or ""
        buckets = ms_buckets(item)

        if item.get("priority") == "P1":
            p1_items.append(item)
        if is_kev_item(item):
            kev_items.append(item)
        if is_official_corroborated(item):
            confirmed_items.append(item)
        if "ransomware" in buckets:
            ransomware.append(item)

        if "windows_os" in buckets and iid not in seen_win:
            windows.append(item)
            seen_win.add(iid)
        if "enterprise_platform" in buckets and iid not in seen_ent:
            enterprise.append(item)
            seen_ent.add(iid)
        if "threat_intel" in buckets and iid not in seen_ti:
            threat_intel.append(item)
            seen_ti.add(iid)

        if buckets <= {"other", "ransomware"} and "ransomware" not in buckets:
            other.append(item)
        elif buckets == {"other"}:
            other.append(item)

    # Deduplicate "other" from already sectioned items
    sectioned = seen_win | seen_ent | seen_ti | {i.get("id") for i in ransomware}
    other = [i for i in other if i.get("id") not in sectioned]

    # Sort priority within lists (already roughly ordered from query_intel)
    def prio_key(i: dict) -> int:
        return {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(i.get("priority") or "P3", 3)

    for lst in (
        windows,
        enterprise,
        threat_intel,
        ransomware,
        p1_items,
        kev_items,
        confirmed_items,
        other,
    ):
        lst.sort(key=prio_key)

    return {
        "watchlist": MICROSOFT_WATCHLIST,
        "items": items,
        "windows_os": windows[:50],
        "enterprise_platform": enterprise[:50],
        "threat_intel": threat_intel[:40],
        "ransomware": ransomware[:40],
        "p1_items": p1_items[:40],
        "kev_items": kev_items[:60],
        "confirmed_items": confirmed_items[:50],
        "other": other[:40],
        "entity_counts": _entity_counts(items),
        "stats": {
            "total": len(items),
            "windows_os": len(windows),
            "enterprise_platform": len(enterprise),
            "threat_intel": len(threat_intel),
            "ransomware": len(ransomware),
            "p1": len(p1_items),
            "p0": sum(1 for i in items if i.get("priority") == "P0"),
            "kev": len(kev_items),
            "confirmed": len(confirmed_items),
            "other": len(other),
        },
        "sections": {
            "windows_os": "Windows 作業系統重大漏洞",
            "enterprise_platform": "Defender／SharePoint／Exchange／Entra 等企業平台",
            "threat_intel": "Microsoft Threat Intelligence 預警／攻擊活動／IOC",
            "p1": "P1 優先（KEV 在野利用路徑）",
            "kev": "CISA KEV／已遭利用",
            "confirmed": "官方旁證（Confirmed／MSRC／MS Blog）",
            "ransomware": "微軟生態＋勒索",
        },
    }
