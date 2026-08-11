"""L5 — Have I Been Pwned public breach catalog and domain watch."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any
from ..config import (
    HIBP_API_KEY,
    HIBP_BREACHES_URL,
    HIBP_MAX_ITEMS,
    HIBP_RECENT_DAYS,
    HIBP_WATCH_DOMAINS,
    USER_AGENT,
)
from ..database import now_iso, upsert_intel
from ..priority import assign_priority, enrich_flags

from ._base import _client, _id, _mark, _strip_html


async def collect_hibp_breaches(
    *,
    recent_days: int | None = None,
    max_items: int | None = None,
) -> int:
    """
    L5 — Have I Been Pwned public breach catalog (no API key required).

    Paid HIBP_API_KEY + HIBP_WATCH_DOMAINS enable optional domain search
    (breacheddomain) which surfaces corporate email exposure.
    """
    t0 = time.perf_counter()
    days = recent_days if recent_days is not None else HIBP_RECENT_DAYS
    limit = max_items if max_items is not None else HIBP_MAX_ITEMS
    count = 0
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }
        if HIBP_API_KEY:
            headers["hibp-api-key"] = HIBP_API_KEY

        async with await _client() as client:
            r = await client.get(HIBP_BREACHES_URL, headers=headers)
            r.raise_for_status()
            breaches = r.json()
            if not isinstance(breaches, list):
                raise ValueError("unexpected HIBP breaches payload")

            # Optional paid: domain email breach presence
            domain_hits: list[dict[str, Any]] = []
            if HIBP_API_KEY and HIBP_WATCH_DOMAINS:
                for domain in HIBP_WATCH_DOMAINS[:10]:
                    try:
                        dr = await client.get(
                            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                            headers=headers,
                        )
                        if dr.status_code == 200:
                            data = dr.json() or {}
                            domain_hits.append(
                                {"domain": domain, "aliases": len(data), "raw": data}
                            )
                        elif dr.status_code == 404:
                            # no breached emails for domain
                            domain_hits.append(
                                {"domain": domain, "aliases": 0, "raw": {}}
                            )
                    except Exception:
                        continue

        cutoff = datetime.utcnow().date()
        from datetime import timedelta

        min_date = cutoff - timedelta(days=max(1, days))

        # Sort by AddedDate desc (when HIBP cataloged the breach)
        def added_key(b: dict) -> str:
            return b.get("AddedDate") or b.get("BreachDate") or ""

        breaches = sorted(breaches, key=added_key, reverse=True)

        recent: list[dict] = []
        for b in breaches:
            added = (b.get("AddedDate") or "")[:10]
            try:
                ad = datetime.strptime(added, "%Y-%m-%d").date()
            except ValueError:
                ad = None
            if ad is not None and ad < min_date:
                # list is sorted; can stop early once past window... but ModifiedDate
                # may vary; keep scanning a bit for safety
                continue
            recent.append(b)
            if len(recent) >= limit:
                break

        # Always ensure latest few if window empty (catalog edge cases)
        if not recent:
            recent = breaches[: min(10, limit)]

        for b in recent:
            name = b.get("Name") or b.get("Title") or "unknown"
            title = b.get("Title") or name
            domain = b.get("Domain") or ""
            desc = _strip_html(b.get("Description") or "")[:1200]
            breach_date = (b.get("BreachDate") or "")[:10]
            added_date = (b.get("AddedDate") or "")[:10]
            pwn = b.get("PwnCount")
            data_classes = b.get("DataClasses") or []
            is_verified = bool(b.get("IsVerified"))
            is_sensitive = bool(b.get("IsSensitive"))
            is_spam = bool(b.get("IsSpamList"))

            # Skip pure spam lists for SOC signal-to-noise
            if is_spam and not is_verified:
                continue

            title_zh = f"[HIBP 外洩] {title}" + (f" ({domain})" if domain else "")
            title_en = f"[HIBP Breach] {title}" + (f" ({domain})" if domain else "")
            summary_zh = (
                f"{desc}\n"
                f"網域：{domain or '—'}｜外洩日：{breach_date}｜目錄收錄：{added_date}\n"
                f"影響筆數：{pwn if pwn is not None else '—'}｜"
                f"驗證：{'是' if is_verified else '否'}｜敏感：{'是' if is_sensitive else '否'}\n"
                f"資料類型：{', '.join(data_classes[:12])}"
            )
            summary_en = (
                f"{desc}\n"
                f"Domain: {domain or '—'} | BreachDate: {breach_date} | Added: {added_date}\n"
                f"PwnCount: {pwn if pwn is not None else '—'} | "
                f"Verified: {is_verified} | Sensitive: {is_sensitive}\n"
                f"Data classes: {', '.join(data_classes[:12])}"
            )

            # Match categories on name/domain primarily (HIBP HTML often cites
            # many third parties and "data leak", which would false-positive).
            flags = enrich_flags(title, domain, domain, "")
            # Credential catalog ≠ ransomware unless text explicitly says so
            ransom_blob = f"{title} {desc}".lower()
            is_ransom = any(
                k in ransom_blob
                for k in (
                    "ransomware",
                    "勒索軟體",
                    "勒索病毒",
                    "lockbit",
                    "double extortion",
                    "雙重勒索",
                )
            )
            # HIBP catalog is a trusted public authority for breach existence
            if is_verified:
                verification, admiralty = "confirmed", "A2"
            else:
                verification, admiralty = "credible", "B2"
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=is_ransom,
                is_tw_industry=flags["is_tw_industry"],
                epss=None,
                source_count=1,
                layer_id="L5",
                verification=verification,
            )
            # Large recent public breaches with passwords elevate monitoring
            if (
                priority == "P3"
                and isinstance(pwn, int)
                and pwn >= 1_000_000
                and any(
                    dc.lower() in ("passwords", "password hints", "email addresses")
                    for dc in data_classes
                )
            ):
                priority = "P2"

            await upsert_intel(
                {
                    "id": _id("hibp", name, added_date or breach_date),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L5",
                    "source_name": "Have I Been Pwned",
                    "sources_json": json.dumps(["Have I Been Pwned"]),
                    "cve_id": None,
                    "product": domain,
                    "vendor": title,
                    "is_ransomware": 1 if is_ransom else 0,
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
                    "epss": None,
                    "cvss": None,
                    "date_added": added_date or None,
                    "published_at": breach_date or added_date,
                    "fetched_at": now_iso(),
                    "url": f"https://haveibeenpwned.com/Breach/{name}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(
                        {
                            "Name": name,
                            "Domain": domain,
                            "PwnCount": pwn,
                            "DataClasses": data_classes,
                        },
                        ensure_ascii=False,
                    )[:4000],
                    "tags_json": json.dumps(
                        ["hibp", "breach", "credentials"]
                        + (["sensitive"] if is_sensitive else [])
                        + (["tw-industry"] if flags["is_tw_industry"] else [])
                        + (["finance"] if flags["is_finance"] else [])
                        + (["microsoft"] if flags["is_microsoft"] else [])
                    ),
                }
            )
            count += 1

        # Surface domain-watch results as intel when paid key is active
        for hit in domain_hits:
            if hit.get("aliases", 0) <= 0:
                continue
            domain = hit["domain"]
            title_zh = f"[HIBP 網域監控] {domain} 出現外洩信箱別名"
            title_en = f"[HIBP Domain Watch] {domain} has breached email aliases"
            summary = (
                f"Paid HIBP breacheddomain API: {domain} has "
                f"{hit['aliases']} alias entries in breach corpus. "
                f"Review corporate credential hygiene / MFA / password resets."
            )
            await upsert_intel(
                {
                    "id": _id("hibp-domain", domain, now_iso()[:10]),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary,
                    "summary_en": summary,
                    "priority": "P1",
                    "verification": "confirmed",
                    "layer_id": "L5",
                    "source_name": "Have I Been Pwned (domain)",
                    "sources_json": json.dumps(["Have I Been Pwned domain search"]),
                    "cve_id": None,
                    "product": domain,
                    "vendor": domain,
                    "is_ransomware": 0,
                    "is_tw_industry": 0,
                    "tw_entities_json": "[]",
                    "is_finance": 0,
                    "finance_entities_json": "[]",
                    "is_microsoft": 0,
                    "ms_entities_json": "[]",
                    "known_ransomware_campaign": 0,
                    "epss": None,
                    "cvss": None,
                    "date_added": now_iso()[:10],
                    "published_at": now_iso()[:10],
                    "fetched_at": now_iso(),
                    "url": "https://haveibeenpwned.com/DomainSearch",
                    "admiralty": "A2",
                    "raw_json": json.dumps(
                        {"domain": domain, "alias_count": hit["aliases"]},
                        ensure_ascii=False,
                    )[:2000],
                    "tags_json": json.dumps(
                        ["hibp", "breach", "domain-watch", "credentials"]
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        detail_parts = [
            f"recent_days={days}",
            f"ingested={count}",
            "mode=public_catalog",
        ]
        if HIBP_API_KEY:
            detail_parts.append("api_key=set")
            if HIBP_WATCH_DOMAINS:
                detail_parts.append(
                    f"domains={','.join(HIBP_WATCH_DOMAINS[:5])}"
                )
            else:
                detail_parts.append("domains=none (set HIBP_WATCH_DOMAINS)")
        else:
            detail_parts.append(
                "api_key=none (catalog free; domain search optional via HIBP_API_KEY)"
            )

        await _mark(
            "hibp",
            "L5",
            "Have I Been Pwned",
            ok=True,
            count=count,
            latency_ms=ms,
            detail="; ".join(detail_parts),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "hibp",
            "L5",
            "Have I Been Pwned",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0
