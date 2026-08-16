"""SOC CTI Early-Warning Dashboard API."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import (
    ALLOW_UNAUTHENTICATED_WRITES,
    API_KEY,
    CORS_ORIGINS,
    FINANCE_WATCHLIST,
    LAYERS,
    MANUAL_SCAN_COOLDOWN_SEC,
    OBSOLETE_SOURCE_IDS,
    OT_IT_SOURCE_CATALOG,
    SCHEDULE_HOURS,
    TZ_TAIPEI,
    TW_ELECTRONICS_WATCHLIST,
)
from .ms_dashboard import build_microsoft_dashboard
from .preemptive import build_preemptive_brief
from .collectors import run_full_harvest
from .database import (
    VALID_VERDICTS,
    get_kpis,
    get_meta,
    get_rule_accuracy,
    get_source_health,
    init_db,
    mark_stale_items,
    now_iso,
    query_intel,
    set_analyst_verdict,
    set_meta,
)

log = logging.getLogger("soc_cti")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

scheduler = AsyncIOScheduler(timezone=TZ_TAIPEI)
_harvest_lock = asyncio.Lock()


def _load_last_harvest_metrics() -> dict[str, Any] | None:
    """Best-effort parse of the structured blob written by run_full_harvest."""
    raw = None
    # get_meta is async; callers must await a wrapper. This sync helper is only
    # used after the value has already been fetched.
    return None


async def _last_harvest() -> dict[str, Any] | None:
    raw = await get_meta("last_harvest_metrics")
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


async def scheduled_harvest() -> None:
    async with _harvest_lock:
        summary = await run_full_harvest()
        # mark_stale is already inside run_full_harvest; keep a meta timestamp
        await set_meta("last_scheduled_scan", now_iso())
        await set_meta("last_scan_summary", str(summary.get("steps")))
        metrics = summary.get("metrics") or {}
        log.info(
            "scheduled_harvest done failure_rate=%s steps_failed=%s items=%s",
            metrics.get("failure_rate"),
            metrics.get("steps_failed"),
            metrics.get("items_collected"),
        )


def _log_write_auth_posture() -> None:
    """Say out loud, at startup, whether writes are protected."""
    if API_KEY:
        log.info("write endpoints require an API key (X-API-Key / Bearer)")
    elif ALLOW_UNAUTHENTICATED_WRITES:
        log.warning(
            "SOC_CTI_ALLOW_UNAUTHENTICATED is set: POST /api/scan/manual and "
            "POST /api/intel/{id}/verdict accept unauthenticated requests. Any "
            "web page the browser visits can trigger them cross-origin. Set "
            "SOC_CTI_API_KEY instead."
        )
    else:
        log.warning(
            "SOC_CTI_API_KEY is not set: write endpoints are disabled (401). "
            "Set SOC_CTI_API_KEY to enable manual scans and analyst verdicts."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _log_write_auth_posture()
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
            summary = await run_full_harvest()
            await set_meta("last_scheduled_scan", now_iso())
            await set_meta("bootstrap_done", "1")
            metrics = summary.get("metrics") or {}
            log.info(
                "bootstrap harvest done failure_rate=%s items=%s",
                metrics.get("failure_rate"),
                metrics.get("items_collected"),
            )
        except Exception:
            # Was a bare pass: a first-run failure left the dashboard empty with
            # no explanation anywhere. Record it so /api/health-adjacent state
            # and the server log both say what happened.
            log.exception("bootstrap harvest failed")
            try:
                await set_meta("bootstrap_error", now_iso())
            except Exception:
                log.exception("could not record bootstrap failure")


app = FastAPI(
    title="SOC CTI Early Warning Dashboard",
    version="1.0.0",
    description="CISA KEV + 7-layer OSINT CTI for Taiwan ODM/EMS manufacturing SOC",
    lifespan=lifespan,
)

# CORS_ORIGINS always resolves to a non-empty allowlist (config.py supplies the
# local default), so there is no wildcard fallback: "*" plus allow_credentials
# is rejected by browsers anyway and would silently widen the surface.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def _key_bytes(value: str) -> bytes:
    """Recover the on-the-wire bytes of a credential.

    ASGI decodes header values as latin-1, so a UTF-8 key arrives mojibake'd;
    re-encoding with latin-1 restores the original bytes. Environment values are
    already real text, hence the UTF-8 fallback. For ASCII keys — the normal
    case — both paths are identical.
    """
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError:
        return value.encode("utf-8")


UNAUTHENTICATED_DETAIL = {
    "message_zh": (
        "伺服器未設定 API 金鑰，寫入端點已停用。請設定環境變數 SOC_CTI_API_KEY "
        "後重啟；僅在明確接受風險時才設定 SOC_CTI_ALLOW_UNAUTHENTICATED=1。"
    ),
    "message_en": (
        "Server has no API key configured; write endpoints are disabled. Set "
        "SOC_CTI_API_KEY and restart, or set SOC_CTI_ALLOW_UNAUTHENTICATED=1 to "
        "accept the risk explicitly."
    ),
}

INVALID_KEY_DETAIL = {
    "message_zh": "需要有效 API 金鑰（X-API-Key 或 Authorization: Bearer）",
    "message_en": "Valid API key required (X-API-Key or Authorization: Bearer)",
}


def writes_require_key() -> bool:
    return bool(API_KEY) or not ALLOW_UNAUTHENTICATED_WRITES


async def require_api_key(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None),
) -> None:
    """Gate mutating endpoints. Fails closed.

    Accepts X-API-Key or Authorization: Bearer <token>. With no key configured
    the endpoint is *disabled* rather than open: binding to loopback is not an
    authentication boundary — a cross-origin POST from any page the analyst has
    open still reaches the handler (CORS withholds the response, not the write),
    so an unauthenticated /api/scan/manual or /verdict is reachable by CSRF.
    SOC_CTI_ALLOW_UNAUTHENTICATED=1 restores the old permissive behaviour for
    throwaway local runs, and is announced in the startup log.
    """
    if not API_KEY:
        if ALLOW_UNAUTHENTICATED_WRITES:
            return
        raise HTTPException(status_code=401, detail=UNAUTHENTICATED_DETAIL)
    provided = (x_api_key or "").strip()
    if not provided and authorization:
        auth = authorization.strip()
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        else:
            provided = auth
    # Constant-time compare so response latency leaks no prefix information.
    # Compare as bytes: compare_digest() rejects non-ASCII str outright, so a
    # header carrying any byte >= 0x80 would otherwise raise 500 instead of 401.
    if not provided or not secrets.compare_digest(
        _key_bytes(provided), API_KEY.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail=INVALID_KEY_DETAIL)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    last = await _last_harvest()
    return {
        "status": "ok",
        "timezone": "Asia/Taipei",
        "server_time": now_iso(),
        "schedule_hours": list(SCHEDULE_HOURS),
        # writes_require_key() is the posture the client must satisfy;
        # write_endpoints_enabled is false when no key is configured at all.
        "api_key_required": writes_require_key(),
        "write_endpoints_enabled": bool(API_KEY) or ALLOW_UNAUTHENTICATED_WRITES,
        "last_harvest": (
            {
                "finished_at": last.get("finished_at"),
                "failure_rate": last.get("failure_rate"),
                "steps_failed": last.get("steps_failed"),
                "nested_feed_failures": last.get("nested_feed_failures"),
                "items_collected": last.get("items_collected"),
                "duration_sec": last.get("duration_sec"),
            }
            if last
            else None
        ),
    }


@app.get("/api/kpis")
async def api_kpis() -> dict[str, Any]:
    kpis = await get_kpis()
    kpis["last_scheduled_scan"] = await get_meta("last_scheduled_scan")
    kpis["last_manual_scan"] = await get_meta("last_manual_scan")
    last = await _last_harvest()
    if last:
        kpis["last_harvest"] = {
            "failure_rate": last.get("failure_rate"),
            "steps_failed": last.get("steps_failed"),
            "nested_feed_failures": last.get("nested_feed_failures"),
            "items_collected": last.get("items_collected"),
            "duration_sec": last.get("duration_sec"),
            "finished_at": last.get("finished_at"),
        }
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
    status: str | None = Query(None, pattern="^(open|stale)$"),
    verdict: str | None = Query(
        None, pattern="^(true_positive|false_positive|unknown)$"
    ),
    unreviewed: bool = False,
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
        status=status,
        verdict=verdict,
        unreviewed_only=unreviewed,
    )
    return {"count": len(items), "items": items}


class VerdictIn(BaseModel):
    """Analyst review outcome for one intel item (2.9)."""

    verdict: Literal["true_positive", "false_positive", "unknown"]
    note: str = Field("", max_length=1000)
    by: str = Field("analyst", max_length=80)


@app.post("/api/intel/{item_id}/verdict")
async def api_set_verdict(
    item_id: str, body: VerdictIn, _: None = Depends(require_api_key)
) -> dict[str, Any]:
    """Record whether a flagged item was real. This is what makes rule
    precision measurable instead of anecdotal — see /api/rule-accuracy."""
    ok = await set_analyst_verdict(item_id, body.verdict, body.note, body.by)
    if not ok:
        raise HTTPException(404, {"message_zh": "查無此情資", "message_en": "No such item"})
    return {"ok": True, "id": item_id, "verdict": body.verdict, "at": now_iso()}


@app.get("/api/review-queue")
async def api_review_queue(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    """Open, unverified, unreviewed P3 items — the human-review backlog the
    methodology promises but never surfaced anywhere."""
    items = await query_intel(
        priority="P3",
        verification="unverified",
        status="open",
        unreviewed_only=True,
        limit=limit,
    )
    return {"count": len(items), "items": items, "verdicts": list(VALID_VERDICTS)}


@app.get("/api/rule-accuracy")
async def api_rule_accuracy() -> dict[str, Any]:
    """Per-rule precision from analyst verdicts — the feedback loop for tuning
    thresholds and watchlists with data rather than intuition."""
    return await get_rule_accuracy()


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
    """
    Dedicated Microsoft tab:
    Windows OS, enterprise platforms (Defender/SharePoint/Exchange/Entra),
    Microsoft TI campaigns/IOCs, P1, CISA KEV exploited, official corroboration.
    """
    items = await query_intel(microsoft_only=True, limit=300)
    return build_microsoft_dashboard(items)


@app.get("/api/preemptive-brief")
async def api_preemptive_brief(limit: int = Query(300, ge=1, le=500)) -> dict[str, Any]:
    """先制式資安日報：KEV/EPSS/CVSS 三訊號排序＋組織脈絡＋八節正體中文日報。"""
    items = await query_intel(limit=limit)
    return build_preemptive_brief(items)


@app.get("/api/ot-catalog")
async def api_ot_catalog() -> dict[str, Any]:
    """OT/IT source catalog: 1 gov · 2 research · 3 media · 4 frameworks."""
    cats = {
        1: {
            "id": 1,
            "name_zh": "官方與政府級預警（優先訂閱）",
            "name_en": "Official / government early-warning (priority)",
            "note_zh": "CISA ICS Advisory 為全球最權威公開 OT／ICS 漏洞預警；建議每日必查，並與 KEV 交叉比對。",
            "note_en": "CISA ICS Advisories are the most authoritative public OT/ICS vuln feed; daily must-check; cross-check KEV.",
        },
        2: {
            "id": 2,
            "name_zh": "專業 OT／ICS 威脅研究機構",
            "name_en": "Specialist OT/ICS threat research",
            "note_zh": "公開部落格與年度報告適合作為威脅建模與 ATT&CK for ICS mapping 輸入。",
            "note_en": "Public blogs/annual reports feed threat modeling & ATT&CK for ICS mapping.",
        },
        3: {
            "id": 3,
            "name_zh": "產業新聞與專題媒體",
            "name_en": "Industry news & specialist media",
            "note_zh": "高頻 ICS／OT 新聞、會議與事件追蹤。",
            "note_en": "High-cadence ICS/OT news, events, and conferences.",
        },
        4: {
            "id": 4,
            "name_zh": "框架與知識庫（非即時，但極重要）",
            "name_en": "框架與知識庫（非即時，但極重要）",
            "note_zh": "MITRE ATT&CK for ICS 等為威脅建模／偵測對照基準，非 RSS 新聞流。",
            "note_en": "MITRE ATT&CK for ICS etc. are modeling/detection baselines, not RSS streams.",
        },
    }
    # Fix accidental zh copy in name_en for cat 4
    cats[4]["name_en"] = "Frameworks & knowledge bases (not live news)"
    by_cat: dict[int, list] = {1: [], 2: [], 3: [], 4: []}
    for s in OT_IT_SOURCE_CATALOG:
        by_cat.setdefault(int(s.get("cat") or 0), []).append(s)
    return {
        "categories": [cats[i] for i in (1, 2, 3, 4)],
        "sources": OT_IT_SOURCE_CATALOG,
        "by_category": {str(k): v for k, v in by_cat.items() if k},
    }


@app.get("/api/layers")
async def api_layers() -> dict[str, Any]:
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
    last = await _last_harvest()
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
        "last_harvest": last,
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
    harvest_metrics = await _last_harvest()
    return {
        "manual_scan_allowed": allowed,
        "cooldown_remaining_sec": remaining,
        "cooldown_sec": MANUAL_SCAN_COOLDOWN_SEC,
        "last_manual_scan": last,
        "last_scheduled_scan": await get_meta("last_scheduled_scan"),
        "harvest_running": _harvest_lock.locked(),
        # writes_require_key() is the posture the client must satisfy;
        # write_endpoints_enabled is false when no key is configured at all.
        "api_key_required": writes_require_key(),
        "write_endpoints_enabled": bool(API_KEY) or ALLOW_UNAUTHENTICATED_WRITES,
        "last_harvest": harvest_metrics,
    }


@app.post("/api/scan/manual")
async def manual_scan(_: None = Depends(require_api_key)) -> dict[str, Any]:
    """Trigger immediate intel harvest — limited to once per 30 minutes.

    Requires X-API-Key when SOC_CTI_API_KEY is set.
    """
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
        "summary": summary.get("steps"),
        "metrics": summary.get("metrics"),
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
