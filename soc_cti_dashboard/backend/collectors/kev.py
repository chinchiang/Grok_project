"""L1 — CISA KEV catalog and FIRST EPSS enrichment/top scores."""

from __future__ import annotations

import json
import time
from ..config import (
    CISA_KEV_URL,
    CISA_KEV_MIRRORS,
    EPSS_API,
    EPSS_TOP_LIMIT,
    EPSS_TOP_MIN,
    EPSS_TOP_URL,
    SOURCE_CLASS_OFFICIAL_GOV,
    USER_AGENT,
)
from ..database import now_iso, upsert_intel
from ..ops import explain_priority, guess_assets, pick_sop
from ..priority import assign_priority, assign_verification, enrich_flags

from ._base import _client, _id, _mark


async def collect_cisa_kev(limit_recent: int | None = 120) -> int:
    """L1 — CISA KEV JSON feed with GitHub mirror fallbacks."""
    t0 = time.perf_counter()
    count = 0
    used_url = CISA_KEV_URL
    try:
        data = None
        last_err: Exception | None = None
        async with await _client() as client:
            for url in CISA_KEV_MIRRORS:
                try:
                    r = await client.get(
                        url,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                        },
                        timeout=90.0,
                    )
                    r.raise_for_status()
                    data = r.json()
                    used_url = url
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    continue
        if data is None:
            raise last_err or RuntimeError("KEV feed unavailable")

        vulns = data.get("vulnerabilities") or []
        catalog_total = len(vulns)
        vulns = sorted(
            vulns,
            key=lambda v: v.get("dateAdded") or "",
            reverse=True,
        )
        if limit_recent:
            vulns = vulns[:limit_recent]

        cve_list = [v.get("cveID") for v in vulns if v.get("cveID")]
        epss_map = await _fetch_epss_batch(cve_list)

        for v in vulns:
            cve = v.get("cveID") or ""
            vendor = v.get("vendorProject") or ""
            product = v.get("product") or ""
            name = v.get("vulnerabilityName") or cve
            desc = v.get("shortDescription") or ""
            ransomware_flag = (
                str(v.get("knownRansomwareCampaignUse") or "").strip().lower()
                == "known"
            )
            date_added = v.get("dateAdded") or ""
            due = v.get("dueDate") or ""
            required = v.get("requiredAction") or ""

            flags = enrich_flags(name, desc, vendor, product)
            is_ransom = flags["is_ransomware"] or ransomware_flag
            is_tw = flags["is_tw_industry"]
            is_finance = flags["is_finance"]
            is_ms = flags["is_microsoft"]
            epss = epss_map.get(cve)

            verification, admiralty = assign_verification(
                in_kev=True,
                layer_id="L1",
                source_count=1,
                is_darkweb_indirect=False,
                source_class=SOURCE_CLASS_OFFICIAL_GOV,
            )
            priority = assign_priority(
                in_kev=True,
                known_ransomware_campaign=ransomware_flag,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=epss,
                source_count=1,
                layer_id="L1",
                verification=verification,
            )
            rz, re_ = explain_priority(
                priority=priority,
                in_kev=True,
                known_ransomware_campaign=ransomware_flag,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                epss=epss,
                source_count=1,
                verification=verification,
            )
            sop = pick_sop(
                priority=priority,
                in_kev=True,
                is_ransomware=is_ransom,
                is_tw_industry=is_tw,
                is_microsoft=is_ms,
                verification=verification,
            )
            assets = guess_assets(flags, vendor, product)

            title_zh = f"[KEV] {cve} — {name}"
            title_en = f"[KEV] {cve} — {name}"
            summary_zh = (
                f"{desc}\n廠商/產品：{vendor} / {product}\n"
                f"KEV 收錄日：{date_added}｜修補期限：{due}\n"
                f"必要處置：{required}\n"
                f"勒索活動關聯：{'是' if ransomware_flag else '未知/否'}\n"
                f"{rz}"
            )
            summary_en = (
                f"{desc}\nVendor/Product: {vendor} / {product}\n"
                f"KEV dateAdded: {date_added} | dueDate: {due}\n"
                f"Required action: {required}\n"
                f"Ransomware campaign use: {'Known' if ransomware_flag else 'Unknown'}\n"
                f"{re_}"
            )

            await upsert_intel(
                {
                    "id": _id("kev", cve),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "priority_rationale": rz,
                    "priority_rationale_en": re_,
                    "verification": verification,
                    "layer_id": "L1",
                    "source_name": "CISA KEV",
                    "sources_json": json.dumps(["CISA KEV"]),
                    "cve_id": cve,
                    "product": product,
                    "vendor": vendor,
                    "is_ransomware": 1 if is_ransom else 0,
                    "is_tw_industry": 1 if is_tw else 0,
                    "tw_entities_json": json.dumps(flags["tw_entities"], ensure_ascii=False),
                    "is_finance": 1 if is_finance else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if is_ms else 0,
                    "ms_entities_json": json.dumps(flags["ms_entities"], ensure_ascii=False),
                    "known_ransomware_campaign": 1 if ransomware_flag else 0,
                    "epss": epss,
                    "cvss": None,
                    "date_added": date_added,
                    "published_at": date_added,
                    "fetched_at": now_iso(),
                    "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(v, ensure_ascii=False)[:8000],
                    "tags_json": json.dumps(
                        ["kev", "in-the-wild"]
                        + (["ransomware"] if is_ransom else [])
                        + (["tw-industry"] if is_tw else [])
                        + (["finance"] if is_finance else [])
                        + (["microsoft"] if is_ms else [])
                    ),
                    "evidence_count": 1,
                    "assets_json": json.dumps(assets, ensure_ascii=False),
                    "sop_id": sop["sop_id"],
                    "sop_zh": sop["sop_zh"],
                    "sop_en": sop["sop_en"],
                    "owner": sop["owner"],
                    "sla_hours": sop["sla_hours"],
                    "is_live": 0,
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        mirror = "github" if "github" in used_url else "cisa.gov"
        await _mark(
            "cisa_kev",
            "L1",
            "CISA KEV",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=(
                f"source={mirror}; ingested={count}; "
                f"catalog_total={catalog_total}; cap={limit_recent}"
            ),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "cisa_kev", "L1", "CISA KEV", ok=False, latency_ms=ms, error=str(e)[:500]
        )
        raise

async def _fetch_epss_batch(cves: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    out: dict[str, float] = {}
    # API accepts comma-separated cve list; chunk to be safe
    chunk_size = 40
    try:
        async with await _client() as client:
            for i in range(0, len(cves), chunk_size):
                chunk = cves[i : i + chunk_size]
                params = {"cve": ",".join(chunk)}
                r = await client.get(EPSS_API, params=params)
                if r.status_code != 200:
                    continue
                data = r.json().get("data") or []
                for row in data:
                    try:
                        out[row["cve"].upper()] = float(row["epss"])
                    except (KeyError, TypeError, ValueError):
                        pass
        await _mark(
            "first_epss",
            "L1",
            "FIRST EPSS",
            ok=True,
            count=len(out),
            detail=f"enriched {len(out)} CVEs",
        )
    except Exception as e:
        await _mark(
            "first_epss", "L1", "FIRST EPSS", ok=False, error=str(e)[:500]
        )
    return out

async def collect_epss_top_scores(
    *, limit: int | None = None, min_epss: float | None = None
) -> int:
    """
    L1 — FIRST EPSS highest exploit-probability CVEs (public API).
    Complements KEV enrichment with predictive scores.
    """
    t0 = time.perf_counter()
    lim = limit if limit is not None else EPSS_TOP_LIMIT
    thr = min_epss if min_epss is not None else EPSS_TOP_MIN
    count = 0
    try:
        async with await _client() as client:
            r = await client.get(
                EPSS_TOP_URL,
                params={"order": "!epss", "limit": str(min(lim * 2, 100))},
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            r.raise_for_status()
            rows = r.json().get("data") or []

        rows = [x for x in rows if float(x.get("epss") or 0) >= thr][:lim]
        for row in rows:
            cve = (row.get("cve") or "").upper()
            if not cve:
                continue
            try:
                epss = float(row.get("epss") or 0)
            except (TypeError, ValueError):
                continue
            percentile = row.get("percentile")
            try:
                pct = float(percentile) if percentile is not None else None
            except (TypeError, ValueError):
                pct = None

            title_zh = f"[EPSS] {cve} — 利用機率 {epss * 100:.1f}%"
            title_en = f"[EPSS] {cve} — exploit probability {epss * 100:.1f}%"
            summary_zh = (
                f"FIRST EPSS 公開評分\n"
                f"CVE：{cve}\n"
                f"EPSS：{epss:.5f}（{epss * 100:.2f}%）\n"
                f"百分位：{f'{pct * 100:.1f}%' if pct is not None else '—'}\n"
                f"用途：預測在野利用可能性（非等同 KEV 已證實利用）"
            )
            summary_en = (
                f"FIRST EPSS public score\n"
                f"CVE: {cve}\n"
                f"EPSS: {epss:.5f} ({epss * 100:.2f}%)\n"
                f"Percentile: {f'{pct * 100:.1f}%' if pct is not None else '—'}\n"
                f"Note: predictive exploit likelihood — not the same as KEV confirmation"
            )
            flags = enrich_flags(title_en, summary_en, "", "")
            verification, admiralty = "confirmed", "A2"
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=flags["is_ransomware"],
                is_tw_industry=flags["is_tw_industry"],
                epss=epss,
                source_count=1,
                layer_id="L1",
                verification=verification,
            )

            await upsert_intel(
                {
                    "id": _id("epss-top", cve),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L1",
                    "source_name": "FIRST EPSS",
                    "sources_json": json.dumps(["FIRST EPSS"]),
                    "cve_id": cve,
                    "product": "",
                    "vendor": "",
                    "is_ransomware": 1 if flags["is_ransomware"] else 0,
                    "is_tw_industry": 1 if flags["is_tw_industry"] else 0,
                    "tw_entities_json": json.dumps(
                        flags["tw_entities"], ensure_ascii=False
                    ),
                    "is_finance": 1 if flags["is_finance"] else 0,
                    "finance_entities_json": json.dumps(
                        flags["finance_entities"], ensure_ascii=False
                    ),
                    "is_microsoft": 1 if flags["is_microsoft"] else 0,
                    "ms_entities_json": json.dumps(
                        flags["ms_entities"], ensure_ascii=False
                    ),
                    "known_ransomware_campaign": 0,
                    "epss": epss,
                    "cvss": None,
                    "date_added": now_iso()[:10],
                    "published_at": now_iso()[:10],
                    "fetched_at": now_iso(),
                    "url": f"https://api.first.org/data/v1/epss?cve={cve}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(row, ensure_ascii=False)[:2000],
                    "tags_json": json.dumps(
                        ["epss", "predictive", "exploit-probability"]
                        + (["high-epss"] if epss >= 0.5 else [])
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "first_epss_top",
            "L1",
            "FIRST EPSS (top scores)",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"min_epss>={thr}; ingested={count}",
        )
        # Keep legacy source_id used by KEV enrichment healthy if top scores OK
        await _mark(
            "first_epss",
            "L1",
            "FIRST EPSS",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"top-score feed; min>={thr}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "first_epss_top",
            "L1",
            "FIRST EPSS (top scores)",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0
