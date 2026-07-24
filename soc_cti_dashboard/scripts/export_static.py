"""
Harvest intel and export JSON snapshots for GitHub Pages (no live API).

Usage (from soc_cti_dashboard/):
  python scripts/export_static.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Allow running as script: python scripts/export_static.py
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.collectors import run_full_harvest
from backend.config import (
    FINANCE_WATCHLIST,
    MANUAL_SCAN_COOLDOWN_SEC,
    OBSOLETE_SOURCE_IDS,
    OT_IT_SOURCE_CATALOG,
    SCHEDULE_HOURS,
    TW_ELECTRONICS_WATCHLIST,
)
from backend.ms_dashboard import build_microsoft_dashboard
from backend.database import (
    get_kpis,
    get_meta,
    get_source_health,
    init_db,
    now_iso,
    query_intel,
    set_meta,
)
from backend.config import LAYERS

OUT_DIR = ROOT / "frontend" / "data"


def _entity_counts(items: list, entities_key: str) -> dict[str, int]:
    by_entity: dict[str, int] = {}
    for item in items:
        for ent in item.get(entities_key) or []:
            k = ent.get("key") or "unknown"
            by_entity[k] = by_entity.get(k, 0) + 1
    return by_entity


def _split_ransom(items: list) -> tuple[list, list]:
    ransom = [i for i in items if i.get("is_ransomware")]
    other = [i for i in items if not i.get("is_ransomware")]
    return ransom, other


async def export() -> None:
    await init_db()
    print("[export] running harvest…")
    summary = await run_full_harvest()
    await set_meta("last_scheduled_scan", now_iso())
    print("[export] harvest done:", json.dumps(summary.get("steps", {}), ensure_ascii=False)[:500])

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    kpis = await get_kpis()
    kpis["last_scheduled_scan"] = await get_meta("last_scheduled_scan")
    kpis["last_manual_scan"] = await get_meta("last_manual_scan")
    kpis["static_export"] = True
    kpis["exported_at"] = now_iso()

    items = await query_intel(limit=400)
    by_priority = {
        "P0": [i for i in items if i.get("priority") == "P0"],
        "P1": [i for i in items if i.get("priority") == "P1"],
        "P2": [i for i in items if i.get("priority") == "P2"],
        "P3": [i for i in items if i.get("priority") == "P3"],
    }

    all_tw = await query_intel(tw_only=True, limit=200)
    ransom, non_ransom = _split_ransom(all_tw)
    global_ransom = await query_intel(ransomware_only=True, limit=80)

    finance_items = await query_intel(finance_only=True, limit=200)
    fin_ransom, fin_other = _split_ransom(finance_items)
    fin_kev = [i for i in finance_items if i.get("source_name") and "KEV" in i["source_name"]]

    ms_items = await query_intel(microsoft_only=True, limit=300)
    ms_payload = build_microsoft_dashboard(ms_items)

    health = await get_source_health()
    by_layer: dict[str, list] = {L["id"]: [] for L in LAYERS}
    for h in health:
        if h.get("source_id") in OBSOLETE_SOURCE_IDS:
            continue
        by_layer.setdefault(h["layer_id"], []).append(h)
    layers_out = []
    for L in LAYERS:
        srcs = by_layer.get(L["id"], [])
        statuses = [s.get("status") for s in srcs]
        if not srcs:
            overall = "unknown"
        elif all(s == "healthy" for s in statuses):
            overall = "healthy"
        elif any(s == "healthy" for s in statuses):
            overall = "partial"
        elif all(s == "not_configured" for s in statuses):
            overall = "not_configured"
        else:
            overall = "degraded"
        layers_out.append({**L, "overall": overall, "sources": srcs})

    payloads = {
        "kpis.json": kpis,
        "intel.json": {"count": len(items), "items": items, "by_priority": by_priority},
        "tw-dashboard.json": {
            "watchlist": TW_ELECTRONICS_WATCHLIST,
            "tw_items": all_tw,
            "tw_ransomware": ransom,
            "tw_other": non_ransom,
            "global_ransomware_highlight": [
                g for g in global_ransom if g.get("priority") in ("P0", "P1")
            ][:40],
            "entity_counts": _entity_counts(all_tw, "tw_entities"),
            "stats": {
                "tw_total": len(all_tw),
                "tw_ransomware": len(ransom),
                "tw_other": len(non_ransom),
            },
        },
        "finance-dashboard.json": {
            "watchlist": FINANCE_WATCHLIST,
            "items": finance_items,
            "ransomware": fin_ransom,
            "other": fin_other,
            "kev_items": fin_kev[:40],
            "entity_counts": _entity_counts(finance_items, "finance_entities"),
            "stats": {
                "total": len(finance_items),
                "ransomware": len(fin_ransom),
                "other": len(fin_other),
                "kev": len(fin_kev),
            },
        },
        "microsoft-dashboard.json": ms_payload,
        "layers.json": {
            "layers": layers_out,
            "schedule": {
                "timezone": "Asia/Taipei",
                "hours": list(SCHEDULE_HOURS),
                "description_zh": "每日 07:00、15:00（臺灣時間）由 GitHub Actions 自動更新",
                "description_en": "Auto-updated daily at 07:00 & 15:00 Asia/Taipei via GitHub Actions",
            },
            "last_scheduled_scan": await get_meta("last_scheduled_scan"),
            "last_manual_scan": await get_meta("last_manual_scan"),
        },
        "scan-status.json": {
            "manual_scan_allowed": False,
            "cooldown_remaining_sec": 0,
            "cooldown_sec": MANUAL_SCAN_COOLDOWN_SEC,
            "last_manual_scan": await get_meta("last_manual_scan"),
            "last_scheduled_scan": await get_meta("last_scheduled_scan"),
            "harvest_running": False,
            "static_mode": True,
            "note_zh": "GitHub Pages 為靜態站，請用 GitHub Actions「Run workflow」觸發更新",
            "note_en": "Static GitHub Pages site — trigger update via Actions workflow_dispatch",
        },
        "meta.json": {
            "exported_at": now_iso(),
            "timezone": "Asia/Taipei",
            "mode": "static",
            "harvest_summary": summary.get("steps"),
        },
        "ot-catalog.json": {
            "categories": [
                {
                    "id": 1,
                    "name_zh": "官方與政府級預警（優先訂閱）",
                    "name_en": "Official / government early-warning (priority)",
                    "note_zh": "CISA ICS Advisory 為全球最權威公開 OT／ICS 漏洞預警；建議每日必查，並與 KEV 交叉比對。",
                    "note_en": "CISA ICS Advisories are the most authoritative public OT/ICS vuln feed; daily must-check; cross-check KEV.",
                },
                {
                    "id": 2,
                    "name_zh": "專業 OT／ICS 威脅研究機構",
                    "name_en": "Specialist OT/ICS threat research",
                    "note_zh": "公開部落格與年度報告適合作為威脅建模與 ATT&CK for ICS mapping 輸入。",
                    "note_en": "Public blogs/annual reports feed threat modeling & ATT&CK for ICS mapping.",
                },
                {
                    "id": 3,
                    "name_zh": "產業新聞與專題媒體",
                    "name_en": "Industry news & specialist media",
                    "note_zh": "高頻 ICS／OT 新聞、會議與事件追蹤。",
                    "note_en": "High-cadence ICS/OT news, events, and conferences.",
                },
                {
                    "id": 4,
                    "name_zh": "框架與知識庫（非即時，但極重要）",
                    "name_en": "Frameworks & knowledge bases (not live news)",
                    "note_zh": "MITRE ATT&CK for ICS 等為威脅建模／偵測對照基準，非 RSS 新聞流。",
                    "note_en": "MITRE ATT&CK for ICS etc. are modeling/detection baselines, not RSS streams.",
                },
            ],
            "sources": OT_IT_SOURCE_CATALOG,
            "by_category": {
                str(c): [s for s in OT_IT_SOURCE_CATALOG if s.get("cat") == c]
                for c in (1, 2, 3, 4)
            },
        },
    }

    for name, obj in payloads.items():
        path = OUT_DIR / name
        path.write_text(
            json.dumps(obj, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"[export] wrote {path} ({path.stat().st_size} bytes)")

    print("[export] complete")


if __name__ == "__main__":
    asyncio.run(export())
