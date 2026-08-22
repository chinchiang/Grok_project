"""L3 — community IOC feeds: abuse.ch ThreatFox and AlienVault OTX."""

from __future__ import annotations

import json
import re
import time
from typing import Any
from ..config import (
    SOURCE_CLASS_COMMUNITY,
    ABUSECH_AUTH_KEY,
    OTX_API_KEY,
    OTX_MAX_PULSES,
    OTX_PULSE_ACTIVITY_URL,
    OTX_PULSES_URL,
    THREATFOX_API_URL,
    THREATFOX_MAX_FAMILIES,
    THREATFOX_MIN_CONFIDENCE,
    THREATFOX_RECENT_EXPORT,
    USER_AGENT,
)
from ..database import now_iso, upsert_intel, upsert_source_health
from ..priority import assign_priority, assign_verification, enrich_flags

from ._base import _client, _id, _mark


async def collect_threatfox(
    *,
    max_families: int | None = None,
    min_confidence: int | None = None,
) -> int:
    """
    L3 — abuse.ch ThreatFox community IOCs.

    Free path: public recent JSON export (no key).
    Optional ABUSECH_AUTH_KEY / THREATFOX_API_KEY for POST API get_iocs.
    Aggregates by malware family to avoid flooding the dashboard.
    """
    t0 = time.perf_counter()
    fam_cap = max_families if max_families is not None else THREATFOX_MAX_FAMILIES
    min_conf = (
        min_confidence if min_confidence is not None else THREATFOX_MIN_CONFIDENCE
    )
    count = 0
    mode = "export"

    try:
        rows: list[dict[str, Any]] = []
        async with await _client() as client:
            # Optional authenticated API (last N days)
            if ABUSECH_AUTH_KEY:
                try:
                    r = await client.post(
                        THREATFOX_API_URL,
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "Auth-Key": ABUSECH_AUTH_KEY,
                        },
                        json={"query": "get_iocs", "days": 3},
                        timeout=90.0,
                    )
                    if r.status_code == 200:
                        payload = r.json()
                        if payload.get("query_status") == "ok" and payload.get("data"):
                            rows = list(payload["data"])
                            mode = "api+auth"
                except Exception:
                    rows = []

            # Free public recent export
            if not rows:
                r = await client.get(
                    THREATFOX_RECENT_EXPORT,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept": "application/json",
                    },
                    timeout=120.0,
                )
                r.raise_for_status()
                payload = r.json()
                if isinstance(payload, dict):
                    for tf_key, items in payload.items():
                        if isinstance(items, list):
                            for it in items:
                                if isinstance(it, dict):
                                    it = {**it, "id": it.get("id") or tf_key}
                                    rows.append(it)
                        elif isinstance(items, dict):
                            rows.append({**items, "id": items.get("id") or tf_key})
                elif isinstance(payload, list):
                    rows = payload
                mode = "export/json/recent"

        # Filter by confidence
        filtered: list[dict[str, Any]] = []
        for row in rows:
            try:
                conf = int(row.get("confidence_level") or 0)
            except (TypeError, ValueError):
                conf = 0
            if conf < min_conf:
                continue
            filtered.append(row)

        # Aggregate by malware family
        families: dict[str, dict[str, Any]] = {}
        for row in filtered:
            fam = (
                row.get("malware_printable")
                or row.get("malware")
                or "Unknown malware"
            )
            fam = str(fam).strip() or "Unknown malware"
            bucket = families.setdefault(
                fam,
                {
                    "family": fam,
                    "malware_id": row.get("malware") or "",
                    "count": 0,
                    "max_conf": 0,
                    "threat_types": set(),
                    "ioc_types": set(),
                    "samples": [],
                    "tags": set(),
                    "first_seen": row.get("first_seen_utc") or "",
                    "references": [],
                },
            )
            bucket["count"] += 1
            try:
                conf = int(row.get("confidence_level") or 0)
            except (TypeError, ValueError):
                conf = 0
            bucket["max_conf"] = max(bucket["max_conf"], conf)
            if row.get("threat_type"):
                bucket["threat_types"].add(str(row["threat_type"]))
            if row.get("ioc_type"):
                bucket["ioc_types"].add(str(row["ioc_type"]))
            tags = row.get("tags") or ""
            if isinstance(tags, str) and tags:
                for t in tags.replace(";", ",").split(","):
                    t = t.strip()
                    if t:
                        bucket["tags"].add(t)
            elif isinstance(tags, list):
                for t in tags:
                    if t:
                        bucket["tags"].add(str(t))
            if len(bucket["samples"]) < 6:
                val = row.get("ioc_value") or row.get("ioc") or ""
                typ = row.get("ioc_type") or "?"
                if val:
                    bucket["samples"].append(f"{typ}:{val}")
            ref = row.get("reference") or ""
            if ref and ref not in bucket["references"] and len(bucket["references"]) < 3:
                bucket["references"].append(str(ref))
            fs = row.get("first_seen_utc") or ""
            if fs and (not bucket["first_seen"] or fs > bucket["first_seen"]):
                bucket["first_seen"] = fs

        # Prioritize ransomware-ish + volume
        def fam_score(b: dict[str, Any]) -> tuple:
            tags_l = " ".join(b["tags"]).lower()
            ransom = 1 if any(
                k in tags_l or k in b["family"].lower()
                for k in ("ransom", "locker", "lockbit", "blackcat", "akira")
            ) else 0
            return (ransom, b["count"], b["max_conf"])

        ranked = sorted(families.values(), key=fam_score, reverse=True)[:fam_cap]

        for b in ranked:
            fam = b["family"]
            threat_s = ", ".join(sorted(b["threat_types"])) or "—"
            ioc_s = ", ".join(sorted(b["ioc_types"])) or "—"
            tag_s = ", ".join(sorted(b["tags"])[:12]) or "—"
            samples = "\n".join(f"  - {s}" for s in b["samples"]) or "  —"
            refs = b["references"][0] if b["references"] else "https://threatfox.abuse.ch/"

            title_zh = f"[ThreatFox] {fam} — {b['count']} IOCs (max conf {b['max_conf']})"
            title_en = title_zh
            summary_zh = (
                f"abuse.ch ThreatFox 社群 IOC 彙整\n"
                f"惡意程式家族：{fam} ({b.get('malware_id') or '—'})\n"
                f"IOC 數量（近期匯出，conf≥{min_conf}）：{b['count']}\n"
                f"最高信心：{b['max_conf']}\n"
                f"威脅類型：{threat_s}\n"
                f"IOC 類型：{ioc_s}\n"
                f"標籤：{tag_s}\n"
                f"最新觀察：{b['first_seen'] or '—'}\n"
                f"樣本 IOC：\n{samples}\n"
                f"來源模式：{mode}"
            )
            summary_en = (
                f"abuse.ch ThreatFox community IOC rollup\n"
                f"Malware family: {fam} ({b.get('malware_id') or '—'})\n"
                f"IOC count (recent export, conf≥{min_conf}): {b['count']}\n"
                f"Max confidence: {b['max_conf']}\n"
                f"Threat types: {threat_s}\n"
                f"IOC types: {ioc_s}\n"
                f"Tags: {tag_s}\n"
                f"Latest seen: {b['first_seen'] or '—'}\n"
                f"Sample IOCs:\n{samples}\n"
                f"Mode: {mode}"
            )

            flags = enrich_flags(fam, tag_s + " " + threat_s)
            # ThreatFox is malware/IOC — ransomware if tag/family suggests
            is_ransom = flags["is_ransomware"] or any(
                k in (tag_s + " " + fam).lower()
                for k in ("ransom", "locker", "lockbit", "blackcat", "akira", "clop")
            )
            verification, admiralty = assign_verification(
                in_kev=False,
                layer_id="L3",
                source_count=1,
                is_darkweb_indirect=False,
                source_class=SOURCE_CLASS_COMMUNITY,
            )
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=is_ransom,
                is_tw_industry=flags["is_tw_industry"],
                epss=None,
                source_count=1,
                layer_id="L3",
                verification=verification,
            )
            if priority == "P3" and (b["count"] >= 50 or b["max_conf"] >= 90):
                priority = "P2"

            await upsert_intel(
                {
                    "id": _id("threatfox", fam, str(b["count"]), b["first_seen"][:10]),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L3",
                    "source_name": "abuse.ch ThreatFox",
                    "sources_json": json.dumps(["abuse.ch ThreatFox"]),
                    "cve_id": None,
                    "product": fam,
                    "vendor": "ThreatFox",
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
                    "date_added": (b["first_seen"] or "")[:10] or now_iso()[:10],
                    "published_at": b["first_seen"] or None,
                    "fetched_at": now_iso(),
                    "url": refs if refs.startswith("http") else "https://threatfox.abuse.ch/",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(
                        {
                            "family": fam,
                            "count": b["count"],
                            "max_conf": b["max_conf"],
                            "samples": b["samples"],
                        },
                        ensure_ascii=False,
                    )[:4000],
                    "tags_json": json.dumps(
                        ["threatfox", "ioc", "malware"]
                        + (["ransomware"] if is_ransom else [])
                        + list(sorted(b["tags"]))[:8]
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "abusech_threatfox",
            "L3",
            "abuse.ch ThreatFox",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=(
                f"mode={mode}; raw_iocs={len(rows)}; "
                f"conf>={min_conf}; families={count}"
                + ("; auth=set" if ABUSECH_AUTH_KEY else "; auth=none(free export)")
            ),
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "abusech_threatfox",
            "L3",
            "abuse.ch ThreatFox",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0

async def collect_otx_pulses(max_items: int | None = None) -> int:
    """
    L3 — AlienVault OTX pulses.
    Requires OTX_API_KEY (free account at otx.alienvault.com).
    """
    t0 = time.perf_counter()
    limit = max_items if max_items is not None else OTX_MAX_PULSES

    if not OTX_API_KEY:
        await upsert_source_health(
            {
                "source_id": "otx_pulse",
                "layer_id": "L3",
                "name": "AlienVault OTX Pulse",
                "last_success": None,
                "last_error": None,
                "last_attempt": now_iso(),
                "status": "not_configured",
                "item_count": 0,
                "latency_ms": 0,
                "detail": (
                    "需免費 OTX_API_KEY（https://otx.alienvault.com → Settings → API Key）"
                ),
            }
        )
        return 0

    count = 0
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "X-OTX-API-KEY": OTX_API_KEY,
        }
        pulses: list[dict] = []
        async with await _client() as client:
            # Prefer subscribed pulses; fall back to activity
            for url in (OTX_PULSES_URL, OTX_PULSE_ACTIVITY_URL):
                try:
                    r = await client.get(
                        url, headers=headers, params={"limit": str(limit)}
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if isinstance(data, dict):
                            pulses = data.get("results") or data.get("pulses") or []
                        elif isinstance(data, list):
                            pulses = data
                        if pulses:
                            break
                except Exception:
                    continue

        for p in pulses[:limit]:
            name = (p.get("name") or p.get("title") or "OTX Pulse").strip()
            desc = (p.get("description") or "")[:1200]
            author = ""
            if isinstance(p.get("author_name"), str):
                author = p["author_name"]
            elif isinstance(p.get("author"), dict):
                author = p["author"].get("username") or ""
            tags = p.get("tags") or []
            if isinstance(tags, list):
                tag_s = ", ".join(str(t) for t in tags[:15])
            else:
                tag_s = str(tags)
            created = p.get("created") or p.get("modified") or ""
            pulse_id = str(p.get("id") or p.get("pulse_id") or name)
            indicators = p.get("indicators") or []
            ind_n = len(indicators) if isinstance(indicators, list) else 0
            ind_sample = []
            if isinstance(indicators, list):
                for ind in indicators[:8]:
                    if isinstance(ind, dict):
                        ind_sample.append(
                            f"{ind.get('type') or '?'}:{ind.get('indicator') or ''}"
                        )

            title_zh = f"[OTX] {name}"
            title_en = title_zh
            summary_zh = (
                f"{desc}\n"
                f"作者：{author or '—'}\n"
                f"標籤：{tag_s or '—'}\n"
                f"IOC 數：{ind_n}\n"
                f"樣本：{'; '.join(ind_sample) if ind_sample else '—'}\n"
                f"建立：{created or '—'}"
            )
            summary_en = summary_zh
            flags = enrich_flags(name, desc + " " + tag_s)
            cve_m = re.findall(r"CVE-\d{4}-\d{4,7}", f"{name} {desc}", re.I)
            verification, admiralty = assign_verification(
                in_kev=False,
                layer_id="L3",
                source_count=1,
                is_darkweb_indirect=False,
                source_class=SOURCE_CLASS_COMMUNITY,
            )
            priority = assign_priority(
                in_kev=False,
                known_ransomware_campaign=False,
                is_ransomware=flags["is_ransomware"],
                is_tw_industry=flags["is_tw_industry"],
                epss=None,
                source_count=1,
                layer_id="L3",
                verification=verification,
            )

            await upsert_intel(
                {
                    "id": _id("otx", pulse_id),
                    "title": title_zh,
                    "title_en": title_en,
                    "summary": summary_zh,
                    "summary_en": summary_en,
                    "priority": priority,
                    "verification": verification,
                    "layer_id": "L3",
                    "source_name": "AlienVault OTX",
                    "sources_json": json.dumps(["AlienVault OTX"]),
                    "cve_id": cve_m[0].upper() if cve_m else None,
                    "product": "",
                    "vendor": author or "",
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
                    "epss": None,
                    "cvss": None,
                    "date_added": (created or "")[:10] or None,
                    "published_at": created or None,
                    "fetched_at": now_iso(),
                    "url": f"https://otx.alienvault.com/pulse/{pulse_id}",
                    "admiralty": admiralty,
                    "raw_json": json.dumps(
                        {"id": pulse_id, "name": name, "tags": tags[:20]},
                        ensure_ascii=False,
                    )[:4000],
                    "tags_json": json.dumps(
                        ["otx", "ioc", "pulse"]
                        + (["ransomware"] if flags["is_ransomware"] else [])
                    ),
                }
            )
            count += 1

        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "otx_pulse",
            "L3",
            "AlienVault OTX Pulse",
            ok=True,
            count=count,
            latency_ms=ms,
            detail=f"pulses={count}",
        )
        return count
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        await _mark(
            "otx_pulse",
            "L3",
            "AlienVault OTX Pulse",
            ok=False,
            latency_ms=ms,
            error=str(e)[:500],
        )
        return 0
