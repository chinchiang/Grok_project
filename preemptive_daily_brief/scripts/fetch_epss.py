"""FIRST EPSS — high percentile today and optional per-CVE enrich."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from preemptive_daily_brief.scripts._http import try_urls

EPSS_BASE = "https://api.first.org/data/v1/epss"


def fetch_epss_high() -> dict[str, Any]:
    url = f"{EPSS_BASE}?{urlencode({'days': 1, 'percentile-gt': 0.9})}"
    payload, used, err = try_urls([url], as_json=True, cache_name="epss_high")
    if err or not isinstance(payload, dict):
        return {"ok": False, "error": err or "invalid payload", "items": [], "source": "first_epss"}
    rows = payload.get("data") or []
    items: list[dict[str, Any]] = []
    for row in rows:
        cve = row.get("cve")
        if not cve:
            continue
        try:
            epss = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        try:
            pct = float(row.get("percentile"))
        except (TypeError, ValueError):
            pct = None
        items.append(
            {
                "id": f"epss-{cve}",
                "cve_id": cve,
                "title": f"[EPSS] {cve}",
                "summary": f"EPSS {epss:.3f}" + (f"（百分位 {pct:.3f}）" if pct is not None else ""),
                "source_name": "FIRST EPSS",
                "url": f"https://api.first.org/data/v1/epss?cve={cve}",
                "epss": epss,
                "epss_percentile": pct,
                "verification": "confirmed",
                "layer_id": "L1",
            }
        )
    items.sort(key=lambda i: i.get("epss") or 0, reverse=True)
    return {
        "ok": True,
        "error": None,
        "items": items[:60],
        "source": "first_epss",
        "used_url": used,
    }


def enrich_epss(cves: list[str]) -> dict[str, dict[str, float]]:
    """Map CVE → {epss, percentile}. Empty dict on failure (never invent scores)."""
    out: dict[str, dict[str, float]] = {}
    uniq = [c for c in dict.fromkeys(cves) if c]
    # FIRST allows comma-separated CVE query; batch to stay polite
    for i in range(0, len(uniq), 20):
        batch = uniq[i : i + 20]
        url = f"{EPSS_BASE}?cve={','.join(batch)}"
        payload, _, err = try_urls([url], as_json=True)
        if err or not isinstance(payload, dict):
            continue
        for row in payload.get("data") or []:
            cve = row.get("cve")
            if not cve:
                continue
            try:
                out[cve] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row.get("percentile") or 0),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return out
