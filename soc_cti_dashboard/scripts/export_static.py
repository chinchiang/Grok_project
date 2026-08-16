"""
Harvest intel and export JSON snapshots for GitHub Pages (no live API).

Usage (from soc_cti_dashboard/):
  python scripts/export_static.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

# Allow running as script: python scripts/export_static.py
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)

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
from backend.preemptive import build_preemptive_brief
from backend.database import (
    VALID_VERDICTS,
    get_kpis,
    get_rule_accuracy,
    get_meta,
    get_source_health,
    init_db,
    now_iso,
    query_intel,
    set_meta,
)
from backend.config import LAYERS

OUT_DIR = ROOT / "frontend" / "data"

# Fields that exist only for server-side processing. raw_json alone was up to
# 8 KB per item, which is what made intel.json multi-megabyte on a dashboard
# that advertises mobile support.
_DROP_FIELDS = ("raw_json", "extras_json", "summary_en", "title_en")
_SUMMARY_MAX = 600


def slim(item: dict, *, keep_translation: bool = True) -> dict:
    """Strip an item down to what the UI actually renders."""
    out = {k: v for k, v in item.items() if k not in _DROP_FIELDS}
    if keep_translation:
        for k in ("title_en", "summary_en"):
            if item.get(k) and item.get(k) != item.get(k.replace("_en", "")):
                out[k] = item[k]
    for k in ("summary", "summary_en"):
        if isinstance(out.get(k), str) and len(out[k]) > _SUMMARY_MAX:
            out[k] = out[k][:_SUMMARY_MAX].rstrip() + "…"
    return out


def slim_all(items: list) -> list:
    return [slim(i) for i in items]


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

    metrics = summary.get("metrics") or {}
    # Human-readable line for Actions logs; the structured JSON line is already
    # emitted by log_harvest_metrics() inside run_full_harvest.
    print(
        "[export] harvest metrics:",
        json.dumps(
            {
                "failure_rate": metrics.get("failure_rate"),
                "steps_ok": metrics.get("steps_ok"),
                "steps_failed": metrics.get("steps_failed"),
                "nested_feed_failures": metrics.get("nested_feed_failures"),
                "items_collected": metrics.get("items_collected"),
                "duration_sec": metrics.get("duration_sec"),
                "failed": metrics.get("failed"),
            },
            ensure_ascii=False,
        ),
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    kpis = await get_kpis()
    kpis["last_scheduled_scan"] = await get_meta("last_scheduled_scan")
    kpis["last_manual_scan"] = await get_meta("last_manual_scan")
    kpis["static_export"] = True
    kpis["exported_at"] = now_iso()
    # Surface last harvest observability on the KPI payload for operators
    kpis["last_harvest"] = {
        "failure_rate": metrics.get("failure_rate"),
        "steps_failed": metrics.get("steps_failed"),
        "nested_feed_failures": metrics.get("nested_feed_failures"),
        "items_collected": metrics.get("items_collected"),
        "duration_sec": metrics.get("duration_sec"),
        "finished_at": metrics.get("finished_at"),
    }

    items = slim_all(await query_intel(limit=400))
    by_priority = {
        "P0": [i for i in items if i.get("priority") == "P0"],
        "P1": [i for i in items if i.get("priority") == "P1"],
        "P2": [i for i in items if i.get("priority") == "P2"],
        "P3": [i for i in items if i.get("priority") == "P3"],
    }
    high_risk = by_priority["P0"] + by_priority["P1"]

    all_tw = slim_all(await query_intel(tw_only=True, limit=200))
    ransom, non_ransom = _split_ransom(all_tw)
    global_ransom = slim_all(await query_intel(ransomware_only=True, limit=80))

    finance_items = slim_all(await query_intel(finance_only=True, limit=200))
    fin_ransom, fin_other = _split_ransom(finance_items)
    fin_kev = [i for i in finance_items if i.get("source_name") and "KEV" in i["source_name"]]

    ms_items = slim_all(await query_intel(microsoft_only=True, limit=300))
    ms_payload = build_microsoft_dashboard(ms_items)

    review_queue = slim_all(
        await query_intel(
            priority="P3",
            verification="unverified",
            status="open",
            unreviewed_only=True,
            limit=150,
        )
    )
    rule_accuracy = await get_rule_accuracy()

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
        # Split so the first paint only needs the high-risk slice; the full
        # stream is fetched lazily by the views that need it.
        "intel-highrisk.json": {"count": len(high_risk), "items": high_risk},
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
        "preemptive-brief.json": build_preemptive_brief(items),
        "review-queue.json": {
            "count": len(review_queue),
            "items": review_queue,
            "verdicts": list(VALID_VERDICTS),
            "static_mode": True,
            "note_zh": "靜態站僅供檢視；標記真／偽陽性需在本機 API 模式操作",
            "note_en": "Read-only on the static site; record verdicts in local API mode",
        },
        "rule-accuracy.json": rule_accuracy,
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
            "last_harvest": metrics,
        },
        "scan-status.json": {
            "manual_scan_allowed": False,
            "cooldown_remaining_sec": 0,
            "cooldown_sec": MANUAL_SCAN_COOLDOWN_SEC,
            "last_manual_scan": await get_meta("last_manual_scan"),
            "last_scheduled_scan": await get_meta("last_scheduled_scan"),
            "harvest_running": False,
            "static_mode": True,
            "last_harvest": {
                "failure_rate": metrics.get("failure_rate"),
                "steps_failed": metrics.get("steps_failed"),
                "nested_feed_failures": metrics.get("nested_feed_failures"),
                "items_collected": metrics.get("items_collected"),
                "duration_sec": metrics.get("duration_sec"),
                "finished_at": metrics.get("finished_at"),
                "failed": metrics.get("failed"),
            },
            "note_zh": "GitHub Pages 為靜態站，請用 GitHub Actions「Run workflow」觸發更新",
            "note_en": "Static GitHub Pages site — trigger update via Actions workflow_dispatch",
        },
        "meta.json": {
            "exported_at": now_iso(),
            "timezone": "Asia/Taipei",
            "mode": "static",
            "harvest_summary": summary.get("steps"),
            "harvest_metrics": metrics,
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

    total_bytes = 0
    for name, obj in payloads.items():
        path = OUT_DIR / name
        # separators + no indent: this is machine-read, not browsed by hand
        path.write_text(
            json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str),
            encoding="utf-8",
        )
        size = path.stat().st_size
        total_bytes += size
        print(f"[export] wrote {path} ({size / 1024:.0f} KB)")
    print(f"[export] payload total {total_bytes / 1024 / 1024:.2f} MB")

    print("[export] complete")


if __name__ == "__main__":
    asyncio.run(export())
