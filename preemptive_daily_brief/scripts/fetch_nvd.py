"""NVD 2.0 incremental CVE pull (lastModStartDate). Rate-limit friendly, no key required."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from preemptive_daily_brief.scripts._http import try_urls

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cvss_from(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key, ver in (("cvssMetricV40", "v4.0"), ("cvssMetricV31", "v3.1"), ("cvssMetricV30", "v3.0")):
        rows = metrics.get(key) or []
        if not rows:
            continue
        data = (rows[0] or {}).get("cvssData") or {}
        score = data.get("baseScore")
        try:
            return float(score), ver
        except (TypeError, ValueError):
            continue
    return None, None


def fetch_nvd(hours: int = 48) -> dict[str, Any]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    # NVD wants offset-naive ISO with Z
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "resultsPerPage": 50,
    }
    url = f"{NVD}?{urlencode(params)}"
    # unauthenticated NVD: be polite even on the first call
    time.sleep(0.8)
    payload, used, err = try_urls([url], as_json=True, cache_name="nvd")
    if err or not isinstance(payload, dict):
        return {"ok": False, "error": err or "invalid payload", "items": [], "source": "nvd"}
    items: list[dict[str, Any]] = []
    for wrap in payload.get("vulnerabilities") or []:
        cve = (wrap or {}).get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = cve.get("descriptions") or []
        summary = ""
        for d in descs:
            if d.get("lang") == "en":
                summary = d.get("value") or ""
                break
        if not summary and descs:
            summary = descs[0].get("value") or ""
        cvss, ver = _cvss_from(cve.get("metrics") or {})
        vendor = product = ""
        configs = cve.get("configurations") or []
        try:
            nodes = (configs[0] or {}).get("nodes") or []
            cpe = ((nodes[0] or {}).get("cpeMatch") or [{}])[0].get("criteria") or ""
            parts = cpe.split(":")
            if len(parts) > 5:
                vendor, product = parts[3], parts[4]
        except (IndexError, TypeError, AttributeError):
            pass
        items.append(
            {
                "id": f"nvd-{cve_id}",
                "cve_id": cve_id,
                "title": f"[NVD] {cve_id}",
                "summary": summary[:600],
                "vendor": vendor.replace("_", " "),
                "product": product.replace("_", " "),
                "source_name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published_at": cve.get("published") or "",
                "cvss": cvss,
                "cvss_version": ver,
                "verification": "confirmed",
                "layer_id": "L1",
            }
        )
    return {
        "ok": True,
        "error": None,
        "items": items[:80],
        "source": "nvd",
        "used_url": used,
        "total_results": payload.get("totalResults"),
    }
