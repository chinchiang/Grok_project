"""SOC CTI Early-Warning Dashboard API."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import (
    FINANCE_WATCHLIST,
    LAYERS,
    MANUAL_SCAN_COOLDOWN_SEC,
    MICROSOFT_WATCHLIST,
    SCHEDULE_HOURS,
    TZ_TAIPEI,
    TW_ELECTRONICS_WATCHLIST,
)
from .collectors import run_full_harvest
from .database import (
    get_kpis,
    get_meta,
    get_source_health,
    init_db,
    now_iso,
    query_intel,
    set_meta,
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

scheduler = AsyncIOScheduler(timezone=TZ_TAIPEI)
_harvest_lock = asyncio.Lock()


async def scheduled_harvest() -> None:
    async with _harvest_lock:
        summary = await run_full_harvest()
        await set_meta("last_scheduled_scan", now_iso())
        await set_meta("last_scan_summary", str(summary.get("steps")))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Register 07:00 and 15:00 Asia/Taipei
    for hour in SCHEDULE_HOURS:
        scheduler.add_job(
            scheduled_harvest,
            CronTrigger(hour=hour, minute=0, timezone=TZ_TAIPEI),
            id=f"harvest_{hour:02d}",
            replace_existing=True,
            max_instances=1,
        )
    scheduler.start()
    # Bootstrap if empty
    items = await query_intel(limit=1)
    if not items:
        asyncio.create_task(_bootstrap())
    yield
    scheduler.shutdown(wait=False)


async def _bootstrap() -> None:
    async with _harvest_lock:
        try:
            await run_full_harvest()
            await set_meta("last_scheduled_scan", now_iso())
            await set_meta("bootstrap_done", "1")
        except Exception:
            pass


app = FastAPI(
    title="SOC CTI Early Warning Dashboard",
    version="1.0.0",
    description="CISA KEV + 7-layer OSINT CTI for Taiwan ODM/EMS manufacturing SOC",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "timezone": "Asia/Taipei",
        "server_time": now_iso(),
        "schedule_hours": list(SCHEDULE_HOURS),
    }


@app.get("/api/kpis")
async def api_kpis() -> dict[str, Any]:
    kpis = await get_kpis()
    kpis["last_scheduled_scan"] = await get_meta("last_scheduled_scan")
    kpis["last_manual_scan"] = await get_meta("last_manual_scan")
    return kpis


@app.get("/api/intel")
async def api_intel(
    priority: str | None = Query(None, pattern="^(P0|P1|P2|P3)$"),
    verification: str | None = Query(
        None, pattern="^(confirmed|credible|unverified)$"
    ),
    ransomware: bool = False,
    tw: bool = False,
    finance: bool = False,
    microsoft: bool = False,
    layer: str | None = None,
    q: str | None = None,
    limit: int = Query(150, ge=1, le=500),
) -> dict[str, Any]:
    items = await query_intel(
        priority=priority,
        verification=verification,
        ransomware_only=ransomware,
        tw_only=tw,
        finance_only=finance,
        microsoft_only=microsoft,
        layer_id=layer,
        q=q,
        limit=limit,
    )
    return {"count": len(items), "items": items}


def _entity_counts(items: list[dict[str, Any]], entities_key: str) -> dict[str, int]:
    by_entity: dict[str, int] = {}
    for item in items:
        for ent in item.get(entities_key) or []:
            k = ent.get("key") or "unknown"
            by_entity[k] = by_entity.get(k, 0) + 1
    return by_entity


def _split_ransom(items: list[dict[str, Any]]) -> tuple[list, list]:
    ransom = [i for i in items if i.get("is_ransomware")]
    other = [i for i in items if not i.get("is_ransomware")]
    return ransom, other


@app.get("/api/tw-dashboard")
async def api_tw_dashboard() -> dict[str, Any]:
    """Dedicated Taiwan electronics / semiconductor victim & ransomware view."""
    all_tw = await query_intel(tw_only=True, limit=200)
    ransom, non_ransom = _split_ransom(all_tw)
    # Also surface global ransomware that may affect supply chain (P0/P1)
    global_ransom = await query_intel(ransomware_only=True, limit=80)
    by_entity = _entity_counts(all_tw, "tw_entities")
    return {
        "watchlist": TW_ELECTRONICS_WATCHLIST,
        "tw_items": all_tw,
        "tw_ransomware": ransom,
        "tw_other": non_ransom,
        "global_ransomware_highlight": [
            g for g in global_ransom if g.get("priority") in ("P0", "P1")
        ][:40],
        "entity_counts": by_entity,
        "stats": {
            "tw_total": len(all_tw),
            "tw_ransomware": len(ransom),
            "tw_other": len(non_ransom),
        },
    }


@app.get("/api/finance-dashboard")
async def api_finance_dashboard() -> dict[str, Any]:
    """Dedicated financial-sector / banking / payments threat view."""
    items = await query_intel(finance_only=True, limit=200)
    ransom, other = _split_ransom(items)
    kev_fin = [i for i in items if i.get("source_name") and "KEV" in i["source_name"]]
    return {
        "watchlist": FINANCE_WATCHLIST,
        "items": items,
        "ransomware": ransom,
        "other": other,
        "kev_items": kev_fin[:40],
        "entity_counts": _entity_counts(items, "finance_entities"),
        "stats": {
            "total": len(items),
            "ransomware": len(ransom),
            "other": len(other),
            "kev": len(kev_fin),
        },
    }


@app.get("/api/microsoft-dashboard")
async def api_microsoft_dashboard() -> dict[str, Any]:
    """Dedicated Microsoft product / ecosystem vulnerability & threat view."""
    items = await query_intel(microsoft_only=True, limit=200)
    ransom, other = _split_ransom(items)
    kev_ms = [i for i in items if i.get("source_name") and "KEV" in i["source_name"]]
    # Prefer KEV / high priority in primary lists for SOC focus
    kev_ransom = [i for i in kev_ms if i.get("is_ransomware")]
    kev_other = [i for i in kev_ms if not i.get("is_ransomware")]
    return {
        "watchlist": MICROSOFT_WATCHLIST,
        "items": items,
        "ransomware": ransom,
        "other": other,
        "kev_items": kev_ms[:60],
        "kev_ransomware": kev_ransom[:40],
        "kev_other": kev_other[:40],
        "entity_counts": _entity_counts(items, "ms_entities"),
        "stats": {
            "total": len(items),
            "ransomware": len(ransom),
            "other": len(other),
            "kev": len(kev_ms),
        },
    }


@app.get("/api/layers")
async def api_layers() -> dict[str, Any]:
    health = await get_source_health()
    by_layer: dict[str, list] = {L["id"]: [] for L in LAYERS}
    for h in health:
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
    return {
        "layers": layers_out,
        "schedule": {
            "timezone": "Asia/Taipei",
            "hours": list(SCHEDULE_HOURS),
            "description_zh": "每日 07:00、15:00（臺灣時間）自動巡檢",
            "description_en": "Daily automatic harvest at 07:00 and 15:00 (Asia/Taipei)",
        },
        "last_scheduled_scan": await get_meta("last_scheduled_scan"),
        "last_manual_scan": await get_meta("last_manual_scan"),
    }


@app.get("/api/scan/status")
async def scan_status() -> dict[str, Any]:
    last = await get_meta("last_manual_scan")
    remaining = 0
    allowed = True
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=TZ_TAIPEI)
            elapsed = (datetime.now(TZ_TAIPEI) - last_dt).total_seconds()
            remaining = max(0, int(MANUAL_SCAN_COOLDOWN_SEC - elapsed))
            allowed = remaining <= 0
        except ValueError:
            allowed = True
    return {
        "manual_scan_allowed": allowed,
        "cooldown_remaining_sec": remaining,
        "cooldown_sec": MANUAL_SCAN_COOLDOWN_SEC,
        "last_manual_scan": last,
        "last_scheduled_scan": await get_meta("last_scheduled_scan"),
        "harvest_running": _harvest_lock.locked(),
    }


@app.post("/api/scan/manual")
async def manual_scan() -> dict[str, Any]:
    """Trigger immediate intel harvest — limited to once per 30 minutes."""
    status = await scan_status()
    if not status["manual_scan_allowed"]:
        raise HTTPException(
            status_code=429,
            detail={
                "message_zh": f"手動巡檢冷卻中，請 {status['cooldown_remaining_sec']} 秒後再試",
                "message_en": f"Manual scan cooling down — retry in {status['cooldown_remaining_sec']}s",
                "cooldown_remaining_sec": status["cooldown_remaining_sec"],
            },
        )
    if _harvest_lock.locked():
        raise HTTPException(
            status_code=409,
            detail={
                "message_zh": "巡檢作業進行中，請稍候",
                "message_en": "A harvest is already running",
            },
        )

    async with _harvest_lock:
        summary = await run_full_harvest()
        await set_meta("last_manual_scan", now_iso())
        await set_meta("last_scan_summary", str(summary.get("steps")))

    return {
        "ok": True,
        "finished_at": now_iso(),
        "summary": summary,
        "next_manual_available_in_sec": MANUAL_SCAN_COOLDOWN_SEC,
    }


# Static frontend (relative asset paths for GitHub Pages + local)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
async def index():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(404, "Frontend not found")
    return FileResponse(index_path)


@app.get("/{asset_path:path}")
async def frontend_assets(asset_path: str):
    """Serve frontend files (styles.css, app.js, data/*.json) for local dual-mode."""
    if asset_path.startswith("api/"):
        raise HTTPException(404)
    target = (FRONTEND_DIR / asset_path).resolve()
    try:
        target.relative_to(FRONTEND_DIR.resolve())
    except ValueError:
        raise HTTPException(404)
    if target.is_file():
        return FileResponse(target)
    raise HTTPException(404)
