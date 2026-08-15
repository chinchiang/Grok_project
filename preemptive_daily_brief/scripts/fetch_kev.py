"""KEV JSON delta vs reported state — new / newly-KEV entries only."""

from __future__ import annotations

from typing import Any

from preemptive_daily_brief.lib.io_yaml import load_yaml
from preemptive_daily_brief.lib.paths import CONFIG_DIR
from preemptive_daily_brief.lib.state import ReportedState
from preemptive_daily_brief.scripts._http import try_urls


def kev_urls() -> list[str]:
    cfg = load_yaml(CONFIG_DIR / "sources.yaml") or {}
    for src in cfg.get("tier1") or []:
        if src.get("id") == "cisa_kev":
            return [src["url"], *(src.get("mirrors") or [])]
    return [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    ]


def fetch_kev(state: ReportedState | None = None) -> dict[str, Any]:
    payload, url, err = try_urls(kev_urls(), as_json=True, cache_name="kev")
    if err or not isinstance(payload, dict):
        return {"ok": False, "error": err or "invalid payload", "items": [], "source": "cisa_kev"}
    vulns = payload.get("vulnerabilities") or []
    items: list[dict[str, Any]] = []
    for v in vulns:
        cve = v.get("cveID") or v.get("cve_id")
        if not cve:
            continue
        item = {
            "id": f"kev-{cve}",
            "cve_id": cve,
            "title": f"[KEV] {cve} — {v.get('vulnerabilityName') or v.get('product') or ''}".strip(),
            "summary": v.get("shortDescription") or "",
            "vendor": v.get("vendorProject") or "",
            "product": v.get("product") or "",
            "source_name": "CISA KEV",
            "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            "date_added": v.get("dateAdded") or "",
            "published_at": v.get("dateAdded") or "",
            "in_kev": True,
            "known_ransomware_campaign": str(v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "verification": "confirmed",
            "layer_id": "L1",
        }
        if state and state.is_duplicate(item) and not item["known_ransomware_campaign"]:
            # still keep if we need upgrade detection later
            prev = state.lookup(item)
            if prev and prev.get("in_kev"):
                continue
        items.append(item)
    # newest first; keep a bounded working set for the daily brief
    items.sort(key=lambda i: i.get("date_added") or "", reverse=True)
    return {
        "ok": True,
        "error": None,
        "items": items[:80],
        "source": "cisa_kev",
        "used_url": url,
        "catalog_count": len(vulns),
    }
