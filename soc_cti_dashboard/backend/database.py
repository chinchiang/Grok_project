"""SQLite persistence for intel items, source health, scan locks."""

from __future__ import annotations

import json
import aiosqlite
from datetime import datetime
from typing import Any

from .config import DB_PATH, DATA_DIR, TZ_TAIPEI


SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_items (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    title_en TEXT,
    summary TEXT,
    summary_en TEXT,
    priority TEXT NOT NULL CHECK (priority IN ('P0','P1','P2','P3')),
    verification TEXT NOT NULL CHECK (verification IN ('confirmed','credible','unverified')),
    layer_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    sources_json TEXT NOT NULL DEFAULT '[]',
    cve_id TEXT,
    product TEXT,
    vendor TEXT,
    is_ransomware INTEGER NOT NULL DEFAULT 0,
    is_tw_industry INTEGER NOT NULL DEFAULT 0,
    tw_entities_json TEXT DEFAULT '[]',
    is_finance INTEGER NOT NULL DEFAULT 0,
    finance_entities_json TEXT DEFAULT '[]',
    is_microsoft INTEGER NOT NULL DEFAULT 0,
    ms_entities_json TEXT DEFAULT '[]',
    known_ransomware_campaign INTEGER NOT NULL DEFAULT 0,
    epss REAL,
    cvss REAL,
    date_added TEXT,
    published_at TEXT,
    fetched_at TEXT NOT NULL,
    url TEXT,
    admiralty TEXT,
    raw_json TEXT,
    tags_json TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_intel_priority ON intel_items(priority);
CREATE INDEX IF NOT EXISTS idx_intel_ransomware ON intel_items(is_ransomware);
CREATE INDEX IF NOT EXISTS idx_intel_tw ON intel_items(is_tw_industry);
CREATE INDEX IF NOT EXISTS idx_intel_cve ON intel_items(cve_id);
CREATE INDEX IF NOT EXISTS idx_intel_fetched ON intel_items(fetched_at);

CREATE TABLE IF NOT EXISTS source_health (
    source_id TEXT PRIMARY KEY,
    layer_id TEXT NOT NULL,
    name TEXT NOT NULL,
    last_success TEXT,
    last_error TEXT,
    last_attempt TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    item_count INTEGER DEFAULT 0,
    latency_ms INTEGER DEFAULT 0,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS scan_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Columns added after initial schema (safe to re-run)
_MIGRATIONS = [
    "ALTER TABLE intel_items ADD COLUMN is_finance INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE intel_items ADD COLUMN finance_entities_json TEXT DEFAULT '[]'",
    "ALTER TABLE intel_items ADD COLUMN is_microsoft INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE intel_items ADD COLUMN ms_entities_json TEXT DEFAULT '[]'",
    "ALTER TABLE intel_items ADD COLUMN extras_json TEXT DEFAULT '{}'",
]


def now_iso() -> str:
    return datetime.now(TZ_TAIPEI).isoformat(timespec="seconds")


async def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        for sql in _MIGRATIONS:
            try:
                await db.execute(sql)
            except Exception:
                # column already exists
                pass
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_intel_finance ON intel_items(is_finance)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_intel_ms ON intel_items(is_microsoft)"
        )
        await db.commit()


def _pack_extras(item: dict[str, Any]) -> str:
    """Serialize ops/display extras into extras_json."""
    if item.get("extras_json"):
        return item["extras_json"] if isinstance(item["extras_json"], str) else json.dumps(
            item["extras_json"], ensure_ascii=False
        )
    extras = {
        "priority_rationale": item.get("priority_rationale"),
        "priority_rationale_en": item.get("priority_rationale_en"),
        "evidence_count": item.get("evidence_count"),
        "assets": item.get("assets")
        or (
            json.loads(item["assets_json"])
            if isinstance(item.get("assets_json"), str) and item.get("assets_json")
            else item.get("assets_json")
        ),
        "sop_id": item.get("sop_id"),
        "sop_zh": item.get("sop_zh"),
        "sop_en": item.get("sop_en"),
        "owner": item.get("owner"),
        "sla_hours": item.get("sla_hours"),
        "is_live": bool(item.get("is_live")),
    }
    return json.dumps(extras, ensure_ascii=False, default=str)


async def upsert_intel(item: dict[str, Any]) -> None:
    # Defaults for optional category fields (older callers)
    item.setdefault("is_finance", 0)
    item.setdefault("finance_entities_json", "[]")
    item.setdefault("is_microsoft", 0)
    item.setdefault("ms_entities_json", "[]")
    item["extras_json"] = _pack_extras(item)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO intel_items (
                id, title, title_en, summary, summary_en, priority, verification,
                layer_id, source_name, sources_json, cve_id, product, vendor,
                is_ransomware, is_tw_industry, tw_entities_json,
                is_finance, finance_entities_json, is_microsoft, ms_entities_json,
                known_ransomware_campaign, epss, cvss, date_added, published_at,
                fetched_at, url, admiralty, raw_json, tags_json, extras_json
            ) VALUES (
                :id, :title, :title_en, :summary, :summary_en, :priority, :verification,
                :layer_id, :source_name, :sources_json, :cve_id, :product, :vendor,
                :is_ransomware, :is_tw_industry, :tw_entities_json,
                :is_finance, :finance_entities_json, :is_microsoft, :ms_entities_json,
                :known_ransomware_campaign, :epss, :cvss, :date_added, :published_at,
                :fetched_at, :url, :admiralty, :raw_json, :tags_json, :extras_json
            )
            ON CONFLICT(id) DO UPDATE SET
                title=excluded.title,
                title_en=excluded.title_en,
                summary=excluded.summary,
                summary_en=excluded.summary_en,
                priority=excluded.priority,
                verification=excluded.verification,
                layer_id=excluded.layer_id,
                source_name=excluded.source_name,
                sources_json=excluded.sources_json,
                cve_id=excluded.cve_id,
                product=excluded.product,
                vendor=excluded.vendor,
                is_ransomware=excluded.is_ransomware,
                is_tw_industry=excluded.is_tw_industry,
                tw_entities_json=excluded.tw_entities_json,
                is_finance=excluded.is_finance,
                finance_entities_json=excluded.finance_entities_json,
                is_microsoft=excluded.is_microsoft,
                ms_entities_json=excluded.ms_entities_json,
                known_ransomware_campaign=excluded.known_ransomware_campaign,
                epss=excluded.epss,
                cvss=excluded.cvss,
                date_added=excluded.date_added,
                published_at=excluded.published_at,
                fetched_at=excluded.fetched_at,
                url=excluded.url,
                admiralty=excluded.admiralty,
                raw_json=excluded.raw_json,
                tags_json=excluded.tags_json,
                extras_json=excluded.extras_json
            """,
            item,
        )
        await db.commit()


async def delete_source_health(source_id: str) -> None:
    """Remove a source_health row (e.g. obsolete aggregate entries)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM source_health WHERE source_id=?", (source_id,))
        await db.commit()


async def upsert_source_health(row: dict[str, Any]) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO source_health (
                source_id, layer_id, name, last_success, last_error,
                last_attempt, status, item_count, latency_ms, detail
            ) VALUES (
                :source_id, :layer_id, :name, :last_success, :last_error,
                :last_attempt, :status, :item_count, :latency_ms, :detail
            )
            ON CONFLICT(source_id) DO UPDATE SET
                layer_id=excluded.layer_id,
                name=excluded.name,
                last_success=COALESCE(excluded.last_success, source_health.last_success),
                last_error=excluded.last_error,
                last_attempt=excluded.last_attempt,
                status=excluded.status,
                item_count=excluded.item_count,
                latency_ms=excluded.latency_ms,
                detail=excluded.detail
            """,
            row,
        )
        await db.commit()


async def set_meta(key: str, value: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scan_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        await db.commit()


async def get_meta(key: str) -> str | None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT value FROM scan_meta WHERE key=?", (key,)
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else None


def _row_to_item(r: aiosqlite.Row) -> dict[str, Any]:
    d = dict(r)
    d["sources"] = json.loads(d.get("sources_json") or "[]")
    d["tw_entities"] = json.loads(d.get("tw_entities_json") or "[]")
    d["finance_entities"] = json.loads(d.get("finance_entities_json") or "[]")
    d["ms_entities"] = json.loads(d.get("ms_entities_json") or "[]")
    d["tags"] = json.loads(d.get("tags_json") or "[]")
    d["is_ransomware"] = bool(d.get("is_ransomware"))
    d["is_tw_industry"] = bool(d.get("is_tw_industry"))
    d["is_finance"] = bool(d.get("is_finance"))
    d["is_microsoft"] = bool(d.get("is_microsoft"))
    d["known_ransomware_campaign"] = bool(d.get("known_ransomware_campaign"))
    try:
        extras = json.loads(d.get("extras_json") or "{}")
    except json.JSONDecodeError:
        extras = {}
    if isinstance(extras, dict):
        for k, v in extras.items():
            if v is not None and k not in d:
                d[k] = v
        d["assets"] = extras.get("assets") or []
        d["evidence_count"] = extras.get("evidence_count") or len(d.get("sources") or [])
        d["is_live"] = bool(extras.get("is_live"))
    return d


async def query_intel(
    *,
    priority: str | None = None,
    verification: str | None = None,
    ransomware_only: bool = False,
    tw_only: bool = False,
    finance_only: bool = False,
    microsoft_only: bool = False,
    layer_id: str | None = None,
    q: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if priority:
        clauses.append("priority = ?")
        params.append(priority)
    if verification:
        clauses.append("verification = ?")
        params.append(verification)
    if ransomware_only:
        clauses.append("is_ransomware = 1")
    if tw_only:
        clauses.append("is_tw_industry = 1")
    if finance_only:
        clauses.append("is_finance = 1")
    if microsoft_only:
        clauses.append("is_microsoft = 1")
    if layer_id:
        clauses.append("layer_id = ?")
        params.append(layer_id)
    if q:
        clauses.append(
            "(title LIKE ? OR summary LIKE ? OR cve_id LIKE ? OR vendor LIKE ? OR product LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like, like])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        f"SELECT * FROM intel_items{where} "
        "ORDER BY CASE priority "
        "WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END, "
        "fetched_at DESC LIMIT ?"
    )
    params.append(limit)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cur:
            rows = await cur.fetchall()
            return [_row_to_item(r) for r in rows]


async def _series_30d(db: aiosqlite.Connection, where_sql: str) -> list[dict[str, Any]]:
    """Build last-30-day daily counts for sparklines (date, count)."""
    series: list[dict[str, Any]] = []
    async with db.execute(
        f"""
        SELECT substr(COALESCE(date_added, published_at, fetched_at), 1, 10) AS d,
               COUNT(*) AS n
        FROM intel_items
        WHERE {where_sql}
          AND substr(COALESCE(date_added, published_at, fetched_at), 1, 10)
              >= date('now', '-29 days')
        GROUP BY d
        ORDER BY d
        """
    ) as cur:
        rows = await cur.fetchall()
    by_day = {r[0]: int(r[1]) for r in rows if r[0]}
    from datetime import timedelta

    today = datetime.now(TZ_TAIPEI).date()
    for i in range(29, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        series.append({"date": d, "count": by_day.get(d, 0)})
    return series


async def get_kpis() -> dict[str, Any]:
    async with aiosqlite.connect(DB_PATH) as db:
        async def one(sql: str, *p: Any) -> int:
            async with db.execute(sql, p) as cur:
                row = await cur.fetchone()
                return int(row[0] if row and row[0] is not None else 0)

        p0 = await one("SELECT COUNT(*) FROM intel_items WHERE priority='P0'")
        p1 = await one("SELECT COUNT(*) FROM intel_items WHERE priority='P1'")
        p2 = await one("SELECT COUNT(*) FROM intel_items WHERE priority='P2'")
        p3 = await one("SELECT COUNT(*) FROM intel_items WHERE priority='P3'")
        kev_total = await one(
            "SELECT COUNT(*) FROM intel_items WHERE source_name LIKE '%KEV%'"
        )
        recent_kev = await one(
            """
            SELECT COUNT(*) FROM intel_items
            WHERE source_name LIKE '%KEV%'
              AND date_added IS NOT NULL
              AND date_added >= date('now', '-7 days')
            """
        )
        kev_60d = await one(
            """
            SELECT COUNT(*) FROM intel_items
            WHERE source_name LIKE '%KEV%'
              AND date_added IS NOT NULL
              AND date_added >= date('now', '-60 days')
            """
        )
        tw_total = await one("SELECT COUNT(*) FROM intel_items WHERE is_tw_industry=1")
        tw_ransom = await one(
            "SELECT COUNT(*) FROM intel_items WHERE is_tw_industry=1 AND is_ransomware=1"
        )
        # Risk KPIs (event-oriented)
        breach = await one(
            """
            SELECT COUNT(*) FROM intel_items
            WHERE is_ransomware=1 OR source_name LIKE '%HIBP%'
               OR source_name LIKE '%DataBreach%' OR source_name LIKE '%ThreatFox%'
            """
        )
        big5 = await one(
            """
            SELECT COUNT(*) FROM intel_items
            WHERE is_tw_industry=1 AND (
              tw_entities_json LIKE '%"big5"%'
              OR tw_entities_json LIKE '%foxconn%'
              OR tw_entities_json LIKE '%pegatron%'
              OR tw_entities_json LIKE '%quanta%'
              OR tw_entities_json LIKE '%compal%'
              OR tw_entities_json LIKE '%wistron%'
            )
            """
        )
        semi = await one(
            """
            SELECT COUNT(*) FROM intel_items
            WHERE is_tw_industry=1 AND tw_entities_json LIKE '%"semi"%'
            """
        )
        ems = await one(
            """
            SELECT COUNT(*) FROM intel_items
            WHERE is_tw_industry=1 AND (
              tw_entities_json LIKE '%"electronics"%'
              OR tw_entities_json LIKE '%"odm"%'
              OR tw_entities_json LIKE '%"display"%'
              OR tw_entities_json LIKE '%"industrial"%'
            )
            """
        )
        unverified = await one(
            "SELECT COUNT(*) FROM intel_items WHERE verification='unverified'"
        )
        finance_total = await one("SELECT COUNT(*) FROM intel_items WHERE is_finance=1")
        ms_total = await one("SELECT COUNT(*) FROM intel_items WHERE is_microsoft=1")
        ransom_all = await one("SELECT COUNT(*) FROM intel_items WHERE is_ransomware=1")
        healthy = await one(
            "SELECT COUNT(*) FROM source_health WHERE status='healthy'"
        )
        total_src = await one("SELECT COUNT(*) FROM source_health")
        health_pct = round(100.0 * healthy / total_src, 1) if total_src else 0.0

        series = {
            "breach": await _series_30d(
                db,
                "is_ransomware=1 OR source_name LIKE '%HIBP%' OR source_name LIKE '%DataBreach%'",
            ),
            "big5": await _series_30d(
                db, "is_tw_industry=1 AND tw_entities_json LIKE '%\"big5\"%'"
            ),
            "semi": await _series_30d(
                db, "is_tw_industry=1 AND tw_entities_json LIKE '%\"semi\"%'"
            ),
            "ems": await _series_30d(
                db,
                "is_tw_industry=1 AND (tw_entities_json LIKE '%\"electronics\"%' OR tw_entities_json LIKE '%\"odm\"%')",
            ),
            "unverified": await _series_30d(db, "verification='unverified'"),
            "kev": await _series_30d(db, "source_name LIKE '%KEV%'"),
            "p0": await _series_30d(db, "priority='P0'"),
        }

        return {
            "p0_count": p0,
            "p1_count": p1,
            "p2_count": p2,
            "p3_count": p3,
            "kev_total": kev_total,
            "kev_recent_7d": recent_kev,
            "kev_recent_60d": kev_60d,
            "tw_industry_count": tw_total,
            "tw_ransomware_count": tw_ransom,
            "finance_count": finance_total,
            "microsoft_count": ms_total,
            "ransomware_count": ransom_all,
            "breach_count": breach,
            "big5_count": big5,
            "semi_count": semi,
            "ems_count": ems,
            "unverified_count": unverified,
            "source_health_pct": health_pct,
            "sources_healthy": healthy,
            "sources_total": total_src,
            "series_30d": series,
            "unit": "件",
            "as_of": now_iso(),
        }


async def get_source_health() -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM source_health ORDER BY layer_id, source_id"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]
