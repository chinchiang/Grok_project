"""SQLite persistence for intel items, source health, scan locks."""

from __future__ import annotations

import json
import re

import aiosqlite
from datetime import datetime
from typing import Any

from .config import DB_PATH, DATA_DIR, TZ_TAIPEI
from .dates import normalize_feed_date
from .textclean import ENTITY_RE, clean_text


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
    # 2.7 lifecycle — an item that stops being re-observed should age out of the
    # operational counts instead of inflating P0 forever.
    "ALTER TABLE intel_items ADD COLUMN first_seen TEXT",
    "ALTER TABLE intel_items ADD COLUMN last_seen TEXT",
    "ALTER TABLE intel_items ADD COLUMN status TEXT NOT NULL DEFAULT 'open'",
    # 2.9 analyst feedback — closes the loop so rule precision can be measured
    # instead of guessed. Never overwritten by a re-harvest.
    "ALTER TABLE intel_items ADD COLUMN analyst_verdict TEXT",
    "ALTER TABLE intel_items ADD COLUMN verdict_note TEXT",
    "ALTER TABLE intel_items ADD COLUMN verdict_at TEXT",
    "ALTER TABLE intel_items ADD COLUMN verdict_by TEXT",
]

# How long an unseen item stays "open" before it is counted as stale (2.7)
STALE_AFTER_DAYS = 14

VALID_VERDICTS = ("true_positive", "false_positive", "unknown")


def now_iso() -> str:
    return datetime.now(TZ_TAIPEI).isoformat(timespec="seconds")


def today_taipei() -> str:
    """Local (Asia/Taipei) date. SQLite's date('now') is UTC, which shifted every
    'last 7 days' window by a day for the first 8 hours of each Taipei day."""
    return datetime.now(TZ_TAIPEI).date().isoformat()


def days_ago_taipei(days: int) -> str:
    from datetime import timedelta

    return (datetime.now(TZ_TAIPEI).date() - timedelta(days=days)).isoformat()


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
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_intel_status ON intel_items(status)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_intel_last_seen ON intel_items(last_seen)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_intel_verdict ON intel_items(analyst_verdict)"
        )
        # Backfill lifecycle timestamps for rows written before the migration
        await db.execute(
            "UPDATE intel_items SET first_seen = COALESCE(first_seen, fetched_at), "
            "last_seen = COALESCE(last_seen, fetched_at) "
            "WHERE first_seen IS NULL OR last_seen IS NULL"
        )
        await _backfill_html_entities(db)
        await _backfill_fake_corroboration(db)
        await _backfill_feed_dates(db)
        await db.commit()


async def _backfill_html_entities(db: aiosqlite.Connection) -> int:
    """Decode entities left in rows harvested before the collector was fixed.

    The database survives between runs (it is restored from the Actions cache),
    and an item is only rewritten when its feed still carries it. Without this,
    text already stored as `&nbsp;` would keep rendering as `&nbsp;` on the
    dashboard indefinitely. Idempotent: cleaned rows no longer match.
    """
    cur = await db.execute(
        "SELECT id, summary, summary_en, title, title_en FROM intel_items "
        "WHERE summary LIKE '%&%;%' OR summary_en LIKE '%&%;%' "
        "OR title LIKE '%&%;%' OR title_en LIKE '%&%;%'"
    )
    rows = await cur.fetchall()
    await cur.close()

    fixed = 0
    for item_id, summary, summary_en, title, title_en in rows:
        values = (summary, summary_en, title, title_en)
        if not any(v and ENTITY_RE.search(v) for v in values):
            continue  # an innocent '&' plus a ';' elsewhere, not an entity
        cleaned = [clean_text(v, keep_newlines=True) if v else v for v in values]
        await db.execute(
            "UPDATE intel_items SET summary=?, summary_en=?, title=?, title_en=? "
            "WHERE id=?",
            (*cleaned, item_id),
        )
        fixed += 1
    return fixed


SYNTHETIC_SOURCE = "secondary-media-citation"


async def _backfill_fake_corroboration(db: aiosqlite.Connection) -> int:
    """Retract trust that was granted by a fabricated second source.

    collectors/rss.py used to append SYNTHETIC_SOURCE and claim two sources
    whenever a dark-web-indirect article merely name-dropped an org, which
    graded single-source trade press as credible / B2 / P2. The collector no
    longer does this, but the database survives between runs (restored from the
    Actions cache), so rows already written keep their inflated grade until they
    are rewritten -- and they are only rewritten while the feed still carries
    them. Dropping the synthetic source leaves one real source, and a
    single-source dark-web-indirect item is unverified / C3 / P3 by spec
    (priority.assign_priority with force_p3_review=True short-circuits, and
    assign_verification returns C3), so the new values are fully determined.

    Idempotent: repaired rows no longer contain SYNTHETIC_SOURCE.
    """
    cur = await db.execute(
        "SELECT id, sources_json, extras_json FROM intel_items WHERE sources_json LIKE ?",
        (f"%{SYNTHETIC_SOURCE}%",),
    )
    rows = await cur.fetchall()
    await cur.close()

    fixed = 0
    for item_id, sources_json, extras_json in rows:
        try:
            sources = json.loads(sources_json or "[]")
        except json.JSONDecodeError:
            continue
        if not isinstance(sources, list) or SYNTHETIC_SOURCE not in sources:
            continue
        real = [s for s in sources if s != SYNTHETIC_SOURCE]
        try:
            extras = json.loads(extras_json or "{}")
        except json.JSONDecodeError:
            extras = {}
        if isinstance(extras, dict):
            extras["evidence_count"] = len(real)
            extras_out = json.dumps(extras, ensure_ascii=False, default=str)
        else:
            extras_out = extras_json

        if len(real) >= 2:
            # Genuinely corroborated by other feeds (aggregate.py merged them);
            # only the phantom source and the inflated count need removing.
            await db.execute(
                "UPDATE intel_items SET sources_json=?, extras_json=? WHERE id=?",
                (json.dumps(real, ensure_ascii=False), extras_out, item_id),
            )
        else:
            await db.execute(
                "UPDATE intel_items SET sources_json=?, extras_json=?, "
                "verification='unverified', admiralty='C3', priority='P3' WHERE id=?",
                (json.dumps(real, ensure_ascii=False), extras_out, item_id),
            )
        fixed += 1
    return fixed


# The two shapes dates.normalize_feed_date can produce: a bare day, or a Taipei
# timestamp (Asia/Taipei has had no DST since 1979, so the offset is always +08).
# GLOB, not LIKE: it has character classes and is case-sensitive, and '+' / ':'
# are literals in it.
_CANONICAL_DAY_GLOB = "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
_CANONICAL_TS_GLOB = _CANONICAL_DAY_GLOB + "T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]+08:00"


def _noncanonical_date_sql(column: str) -> str:
    return (
        f"({column} IS NOT NULL AND {column} <> '' "
        f"AND {column} NOT GLOB '{_CANONICAL_DAY_GLOB}' "
        f"AND {column} NOT GLOB '{_CANONICAL_TS_GLOB}')"
    )


async def _backfill_feed_dates(db: aiosqlite.Connection) -> int:
    """Rewrite feed dates stored in a format the day bucket cannot read.

    RSS mandates RFC-822, so collectors stored ``'Mon, 20 Jul 2026 20:03:43
    +0530'`` verbatim; ``substr(…, 1, 10)`` turns that into ``'Mon, 20 Ju'`` and
    the row disappears from every sparkline (see dates.py for the full account).
    upsert_intel now normalises on write, but the database is restored from the
    Actions cache between runs and a row is only rewritten while its feed still
    carries it — without this, the existing 30-day history would stay broken
    permanently, which is the whole point of keeping the cache.

    Idempotent: every value normalize_feed_date returns is one of the two
    canonical shapes the SELECT excludes, so a second pass matches nothing.
    """
    cur = await db.execute(
        "SELECT id, date_added, published_at FROM intel_items "
        f"WHERE {_noncanonical_date_sql('date_added')} "
        f"OR {_noncanonical_date_sql('published_at')}"
    )
    rows = await cur.fetchall()
    await cur.close()

    fixed = 0
    for item_id, date_added, published_at in rows:
        new_added = normalize_feed_date(date_added)
        new_published = normalize_feed_date(published_at)
        if (new_added, new_published) == (date_added, published_at):
            continue
        await db.execute(
            "UPDATE intel_items SET date_added=?, published_at=? WHERE id=?",
            (new_added, new_published, item_id),
        )
        fixed += 1
    return fixed


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
    # Single choke point for date formats. Collectors hand over whatever their
    # feed emitted — RFC-822 from RSS, RFC-3339 from Atom, a bare day from KEV —
    # and every consumer below reads these two columns as ISO (see dates.py).
    item["published_at"] = normalize_feed_date(item.get("published_at"))
    item["date_added"] = normalize_feed_date(item.get("date_added"))
    item.setdefault("first_seen", item.get("fetched_at") or now_iso())
    item.setdefault("last_seen", item.get("fetched_at") or now_iso())

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO intel_items (
                id, title, title_en, summary, summary_en, priority, verification,
                layer_id, source_name, sources_json, cve_id, product, vendor,
                is_ransomware, is_tw_industry, tw_entities_json,
                is_finance, finance_entities_json, is_microsoft, ms_entities_json,
                known_ransomware_campaign, epss, cvss, date_added, published_at,
                fetched_at, url, admiralty, raw_json, tags_json, extras_json,
                first_seen, last_seen, status
            ) VALUES (
                :id, :title, :title_en, :summary, :summary_en, :priority, :verification,
                :layer_id, :source_name, :sources_json, :cve_id, :product, :vendor,
                :is_ransomware, :is_tw_industry, :tw_entities_json,
                :is_finance, :finance_entities_json, :is_microsoft, :ms_entities_json,
                :known_ransomware_campaign, :epss, :cvss, :date_added, :published_at,
                :fetched_at, :url, :admiralty, :raw_json, :tags_json, :extras_json,
                :first_seen, :last_seen, 'open'
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
                extras_json=excluded.extras_json,
                -- Lifecycle: first sighting is immutable, re-observation reopens
                first_seen=COALESCE(intel_items.first_seen, excluded.first_seen),
                last_seen=excluded.last_seen,
                status='open'
                -- analyst_verdict / verdict_* are deliberately absent: a harvest
                -- must never overwrite an analyst's review of an item.
            """,
            item,
        )
        await db.commit()


async def items_for_aggregation(days: int = 14, limit: int = 1200) -> list[dict[str, Any]]:
    """Recent items considered for cross-source corroboration (2.5).

    The cutoff compares strings, so it only bounds anything while the columns
    hold ISO (upsert_intel guarantees it): an RFC-822 published_at used to sort
    above every cutoff — 'M' > '2' — and let the window admit rows of any age.
    """
    cutoff = days_ago_taipei(days)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM intel_items "
            "WHERE COALESCE(date_added, published_at, fetched_at) >= ? "
            "ORDER BY fetched_at DESC LIMIT ?",
            (cutoff, limit),
        ) as cur:
            return [_row_to_item(r) for r in await cur.fetchall()]


# Collectors bake an "unverified" badge into the title at ingest time. Once
# corroboration raises the verification, that prefix contradicts the card's own
# badge, so it is stripped when the item is upgraded.
_UNVERIFIED_PREFIX = re.compile(r"^\[(?:未核實 Unverified|Unverified)\]\s*")


async def apply_aggregation(
    item_id: str,
    *,
    sources: list[str],
    priority: str,
    verification: str,
    admiralty: str,
    rationale_zh: str,
    rationale_en: str,
    corroborated_by: list[str],
) -> None:
    """Persist a corroboration result without disturbing analyst verdicts."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT extras_json, title, title_en FROM intel_items WHERE id=?",
            (item_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return
        if verification != "unverified":
            title = _UNVERIFIED_PREFIX.sub("", row["title"] or "")
            title_en = _UNVERIFIED_PREFIX.sub("", row["title_en"] or "")
            await db.execute(
                "UPDATE intel_items SET title=?, title_en=? WHERE id=?",
                (title, title_en, item_id),
            )
        try:
            extras = json.loads(row["extras_json"] or "{}")
        except json.JSONDecodeError:
            extras = {}
        if not isinstance(extras, dict):
            extras = {}
        extras.update(
            {
                "evidence_count": len(sources),
                "priority_rationale": rationale_zh,
                "priority_rationale_en": rationale_en,
                "corroborated_by": corroborated_by,
            }
        )
        await db.execute(
            "UPDATE intel_items SET sources_json=?, priority=?, verification=?, "
            "admiralty=?, extras_json=? WHERE id=?",
            (
                json.dumps(sources, ensure_ascii=False),
                priority,
                verification,
                admiralty,
                json.dumps(extras, ensure_ascii=False, default=str),
                item_id,
            ),
        )
        await db.commit()


async def mark_stale_items(days: int = STALE_AFTER_DAYS) -> int:
    """Age out items that stopped being re-observed (2.7).

    KPIs previously counted every P0 ever ingested, so the "immediate action"
    number only ever grew. Stale items stay queryable but drop out of the open
    counts. Items an analyst has already ruled on keep their verdict.
    """
    cutoff = days_ago_taipei(days)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE intel_items SET status='stale' "
            "WHERE status='open' AND COALESCE(last_seen, fetched_at) < ?",
            (cutoff,),
        )
        await db.commit()
        return cur.rowcount or 0


async def set_analyst_verdict(
    item_id: str, verdict: str, note: str = "", by: str = "analyst"
) -> bool:
    """Record a human review outcome (2.9). Returns False if the item is unknown."""
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"verdict must be one of {VALID_VERDICTS}")
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE intel_items SET analyst_verdict=?, verdict_note=?, "
            "verdict_at=?, verdict_by=? WHERE id=?",
            (verdict, note[:1000], now_iso(), by[:80], item_id),
        )
        await db.commit()
        return (cur.rowcount or 0) > 0


async def get_rule_accuracy() -> dict[str, Any]:
    """Precision per rule dimension, from analyst verdicts (2.9).

    Without this the only way to tune thresholds and watchlists was intuition:
    nothing recorded whether a P0 was real. Dimensions are the levers that
    actually decide priority, so each one gets its own precision figure.
    """
    dimensions = {
        "priority_P0": "priority='P0'",
        "priority_P1": "priority='P1'",
        "priority_P2": "priority='P2'",
        "priority_P3": "priority='P3'",
        "verification_confirmed": "verification='confirmed'",
        "verification_credible": "verification='credible'",
        "verification_unverified": "verification='unverified'",
        "tw_industry": "is_tw_industry=1",
        "tw_plus_ransomware": "is_tw_industry=1 AND is_ransomware=1",
        "finance": "is_finance=1",
        "microsoft": "is_microsoft=1",
        "ransomware": "is_ransomware=1",
        "kev": "source_name LIKE '%KEV%'",
    }
    out: dict[str, Any] = {}
    async with aiosqlite.connect(DB_PATH) as db:
        async def counts(where: str) -> tuple[int, int, int]:
            async with db.execute(
                f"SELECT "
                f"SUM(analyst_verdict='true_positive'), "
                f"SUM(analyst_verdict='false_positive'), "
                f"SUM(analyst_verdict IS NOT NULL AND analyst_verdict<>'') "
                f"FROM intel_items WHERE {where}"
            ) as cur:
                row = await cur.fetchone()
                return (
                    int(row[0] or 0),
                    int(row[1] or 0),
                    int(row[2] or 0),
                )

        for name, where in dimensions.items():
            tp, fp, reviewed = await counts(where)
            async with db.execute(
                f"SELECT COUNT(*) FROM intel_items WHERE {where}"
            ) as cur:
                total = int((await cur.fetchone())[0] or 0)
            judged = tp + fp
            out[name] = {
                "total": total,
                "reviewed": reviewed,
                "true_positive": tp,
                "false_positive": fp,
                # None (not 0) when nothing has been reviewed — an unreviewed
                # rule is unknown, not perfect.
                "precision": round(tp / judged, 3) if judged else None,
                "review_coverage": round(reviewed / total, 3) if total else None,
            }

        async with db.execute(
            "SELECT COUNT(*) FROM intel_items "
            "WHERE analyst_verdict IS NOT NULL AND analyst_verdict<>''"
        ) as cur:
            reviewed_total = int((await cur.fetchone())[0] or 0)
        async with db.execute("SELECT COUNT(*) FROM intel_items") as cur:
            grand_total = int((await cur.fetchone())[0] or 0)

    return {
        "dimensions": out,
        "reviewed_total": reviewed_total,
        "items_total": grand_total,
        "review_coverage": round(reviewed_total / grand_total, 3) if grand_total else None,
        "verdicts": list(VALID_VERDICTS),
        "as_of": now_iso(),
        "note_zh": "precision = 真陽性 /（真陽性＋偽陽性）；未複核者不計入，precision 為 null 代表尚無資料",
        "note_en": "precision = TP/(TP+FP) over reviewed items only; null means nothing reviewed yet",
    }


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
    d["status"] = d.get("status") or "open"
    d["is_stale"] = d["status"] == "stale"
    return d


def _escape_like(term: str) -> str:
    """Escape LIKE wildcards so a search for '100%' does not match everything."""
    return (
        term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )


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
    status: str | None = None,
    verdict: str | None = None,
    unreviewed_only: bool = False,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if priority:
        clauses.append("priority = ?")
        params.append(priority)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if verdict:
        clauses.append("analyst_verdict = ?")
        params.append(verdict)
    if unreviewed_only:
        clauses.append("(analyst_verdict IS NULL OR analyst_verdict = '')")
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
            "(title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\' "
            "OR cve_id LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\' "
            "OR product LIKE ? ESCAPE '\\')"
        )
        like = f"%{_escape_like(q)}%"
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


def _entity_clause(
    column: str, keys: tuple[str, ...] = (), tiers: tuple[str, ...] = ()
) -> tuple[str, list[Any]]:
    """Match watchlist entities via json_each instead of LIKE '%"key"%'.

    The LIKE form matched the token anywhere in the serialized blob — a key
    could be satisfied by an alias or a tier and vice versa — and could never
    use an index. This addresses key and tier separately, as intended.
    """
    parts: list[str] = []
    params: list[Any] = []
    if keys:
        ph = ",".join("?" for _ in keys)
        parts.append(f"json_extract(je.value, '$.key') IN ({ph})")
        params.extend(keys)
    if tiers:
        ph = ",".join("?" for _ in tiers)
        parts.append(f"json_extract(je.value, '$.tier') IN ({ph})")
        params.extend(tiers)
    if not parts:
        return "0", []
    sql = (
        f"EXISTS (SELECT 1 FROM json_each(intel_items.{column}) je "
        f"WHERE {' OR '.join(parts)})"
    )
    return sql, params


async def _series_30d(db: aiosqlite.Connection, where_sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
    """Build last-30-day daily counts for sparklines (date, count).

    The bare substr is only a day because upsert_intel normalises both date
    columns to ISO and _backfill_feed_dates repairs the cached rows; a raw RSS
    RFC-822 value slices to 'Mon, 20 Ju' and drops the row from the chart. See
    dates.py.
    """
    series: list[dict[str, Any]] = []
    async with db.execute(
        f"""
        SELECT substr(COALESCE(date_added, published_at, fetched_at), 1, 10) AS d,
               COUNT(*) AS n
        FROM intel_items
        WHERE {where_sql}
          AND substr(COALESCE(date_added, published_at, fetched_at), 1, 10) >= ?
        GROUP BY d
        ORDER BY d
        """,
        (*(params or []), days_ago_taipei(29)),
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
    """Operational KPIs.

    Two corrections over the original (2.7 / 2.8):

    * Counts are windowed. Previously every P0 ever ingested was counted, so the
      "immediate action" figure only grew and stopped meaning anything. The
      headline numbers are now *open* (not aged out), with explicit new-in-7d
      and new-in-30d alongside the all-time totals.
    * Date boundaries are Asia/Taipei. SQLite's date('now') is UTC, which put
      every "last 7 days" window a day out for the first 8 hours of each
      Taipei day — on a dashboard whose whole premise is the Taipei clock.
    """
    d7 = days_ago_taipei(7)
    d30 = days_ago_taipei(30)
    d60 = days_ago_taipei(60)
    open_ = "status='open'"

    big5_sql, big5_p = _entity_clause(
        "tw_entities_json",
        keys=("quanta", "compal", "inventec", "wistron", "pegatron"),
        tiers=("big5",),
    )
    semi_sql, semi_p = _entity_clause("tw_entities_json", tiers=("semi",))
    ems_sql, ems_p = _entity_clause(
        "tw_entities_json",
        keys=("foxconn",),
        tiers=("electronics", "ems", "display", "industrial"),
    )

    async with aiosqlite.connect(DB_PATH) as db:
        async def one(sql: str, *p: Any) -> int:
            async with db.execute(sql, p) as cur:
                row = await cur.fetchone()
                return int(row[0] if row and row[0] is not None else 0)

        async def count(where: str, *p: Any) -> int:
            return await one(f"SELECT COUNT(*) FROM intel_items WHERE {where}", *p)

        # --- priority: all-time, currently open, and newly seen -------------
        prio: dict[str, dict[str, int]] = {}
        for p in ("P0", "P1", "P2", "P3"):
            prio[p] = {
                "total": await count("priority=?", p),
                "open": await count(f"priority=? AND {open_}", p),
                "new_7d": await count(
                    "priority=? AND COALESCE(first_seen, fetched_at) >= ?", p, d7
                ),
                "new_30d": await count(
                    "priority=? AND COALESCE(first_seen, fetched_at) >= ?", p, d30
                ),
            }

        stale_total = await count("status='stale'")

        # --- KEV ------------------------------------------------------------
        kev_where = "source_name LIKE '%KEV%'"
        kev_tracked = await count(kev_where)
        recent_kev = await count(
            f"{kev_where} AND date_added IS NOT NULL AND date_added >= ?", d7
        )
        kev_60d = await count(
            f"{kev_where} AND date_added IS NOT NULL AND date_added >= ?", d60
        )

        # --- sector counts ---------------------------------------------------
        tw_total = await count("is_tw_industry=1")
        tw_open = await count(f"is_tw_industry=1 AND {open_}")
        tw_ransom = await count("is_tw_industry=1 AND is_ransomware=1")
        big5 = await count(f"is_tw_industry=1 AND {big5_sql}", *big5_p)
        semi = await count(f"is_tw_industry=1 AND {semi_sql}", *semi_p)
        ems = await count(f"is_tw_industry=1 AND {ems_sql}", *ems_p)
        finance_total = await count("is_finance=1")
        ms_total = await count("is_microsoft=1")
        ransom_all = await count("is_ransomware=1")

        # Breach = actual disclosure/extortion events. ThreatFox is an IOC feed,
        # not a breach record, and used to inflate this by hundreds of items.
        breach_where = (
            "is_ransomware=1 OR source_name LIKE '%HIBP%' "
            "OR source_name LIKE '%DataBreach%'"
        )
        breach = await count(breach_where)
        ioc_total = await count("source_name LIKE '%ThreatFox%' OR layer_id='L3'")

        # --- verification ----------------------------------------------------
        total_items = await count("1=1")
        unverified = await count("verification='unverified'")
        verified_pct = (
            round(100.0 * (total_items - unverified) / total_items, 1)
            if total_items
            else 0.0
        )
        # L1 is almost entirely CISA KEV, which is confirmed by definition and
        # drowns out how well the OSINT layers are actually corroborated.
        osint_total = await count("layer_id NOT IN ('L1','T1')")
        osint_unverified = await count(
            "layer_id NOT IN ('L1','T1') AND verification='unverified'"
        )
        osint_verified_pct = (
            round(100.0 * (osint_total - osint_unverified) / osint_total, 1)
            if osint_total
            else 0.0
        )

        # --- analyst review coverage (2.9) -----------------------------------
        reviewed = await count("analyst_verdict IS NOT NULL AND analyst_verdict<>''")
        review_queue = await count(
            f"priority='P3' AND verification='unverified' AND {open_} "
            "AND (analyst_verdict IS NULL OR analyst_verdict='')"
        )

        healthy = await one("SELECT COUNT(*) FROM source_health WHERE status='healthy'")
        total_src = await one("SELECT COUNT(*) FROM source_health")
        health_pct = round(100.0 * healthy / total_src, 1) if total_src else 0.0

        series = {
            "breach": await _series_30d(db, breach_where),
            "big5": await _series_30d(db, big5_sql, big5_p),
            "semi": await _series_30d(db, semi_sql, semi_p),
            "ems": await _series_30d(db, ems_sql, ems_p),
            "unverified": await _series_30d(db, "verification='unverified'"),
            "kev": await _series_30d(db, kev_where),
            "p0": await _series_30d(db, "priority='P0'"),
        }

        return {
            # Back-compatible headline keys now mean "currently open"
            "p0_count": prio["P0"]["open"],
            "p1_count": prio["P1"]["open"],
            "p2_count": prio["P2"]["open"],
            "p3_count": prio["P3"]["open"],
            "priority_windows": prio,
            "stale_count": stale_total,
            "stale_after_days": STALE_AFTER_DAYS,
            "kev_tracked": kev_tracked,
            # kev_total kept for older clients; it is the tracked window, not the
            # size of the CISA catalog.
            "kev_total": kev_tracked,
            "kev_recent_7d": recent_kev,
            "kev_recent_60d": kev_60d,
            "tw_industry_count": tw_total,
            "tw_industry_open": tw_open,
            "tw_ransomware_count": tw_ransom,
            "finance_count": finance_total,
            "microsoft_count": ms_total,
            "ransomware_count": ransom_all,
            "breach_count": breach,
            "ioc_count": ioc_total,
            "big5_count": big5,
            "semi_count": semi,
            "ems_count": ems,
            "items_total": total_items,
            "unverified_count": unverified,
            "verified_pct": verified_pct,
            "osint_verified_pct": osint_verified_pct,
            "osint_total": osint_total,
            "reviewed_count": reviewed,
            "review_queue_count": review_queue,
            "source_health_pct": health_pct,
            "sources_healthy": healthy,
            "sources_total": total_src,
            "series_30d": series,
            "unit": "件",
            "timezone": "Asia/Taipei",
            "as_of": now_iso(),
        }


async def get_source_health() -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM source_health ORDER BY layer_id, source_id"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]
