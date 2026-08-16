"""RSS dates must reach the 30-day trend charts.

RSS 2.0 mandates RFC-822 (``Mon, 20 Jul 2026 20:03:43 +0530``) and the
collectors stored that string verbatim, but every consumer takes the day from
``substr(COALESCE(date_added, published_at, fetched_at), 1, 10)``. That slice is
``'Mon, 20 Ju'`` — no calendar day — so RSS-sourced rows were counted in *none*
of the seven sparklines, while the same string compared ``>= '2026-08-02'`` as
true (``'M'`` > ``'2'``) and let the 14-day corroboration window admit rows of
any age.

Both halves are pinned here: the write path must canonicalise, and the startup
backfill must repair the rows already cached — the SQLite file is restored from
the Actions cache between runs and a row is only rewritten while its feed still
carries it, so fixing the collectors alone would leave the existing 30-day
history broken for good.
"""

import re
from datetime import datetime, timedelta
from email.utils import format_datetime

import aiosqlite
import pytest

import backend.database as db
from backend.config import TZ_TAIPEI
from backend.dates import day_bucket, normalize_feed_date

from test_lifecycle_and_review import row, store  # noqa: F401  (fixture)

# What the columns are allowed to hold: a bare day, or a Taipei timestamp.
CANONICAL = re.compile(r"\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}\+08:00)?")

# Verbatim from frontend/data and preemptive_daily_brief/output — the formats the
# live feeds actually emit, not invented ones.
REAL_WORLD = [
    ("Mon, 22 Jun 2026 07:00:00 GMT", "2026-06-22"),
    ("Thu, 23 Jul 2026 01:03:42 -0700", "2026-07-23"),
    ("Tue, 21 Jul 2026 20:27:51 +0530", "2026-07-21"),
    # 17:14 UTC is already the next day in Taipei: the bucket is the Taipei one,
    # because every other day boundary in this project is (see today_taipei).
    ("Wed, 22 Jul 2026 17:14:06 GMT", "2026-07-23"),
    ("2026-07-20T19:06:49.526256+00:00", "2026-07-21"),
    ("2026-06-13 09:43:12", "2026-06-13"),  # abuse.ch first_seen_utc
    ("2026-06-12", "2026-06-12"),  # CISA KEV dateAdded
]


def _rfc822(days_ago: int) -> tuple[str, str]:
    """An RFC-822 stamp at noon Taipei N days back, plus the day it belongs to."""
    when = datetime.now(TZ_TAIPEI).replace(
        hour=12, minute=0, second=0, microsecond=0
    ) - timedelta(days=days_ago)
    return format_datetime(when), when.date().isoformat()


# --- the normaliser -----------------------------------------------------------

@pytest.mark.parametrize("raw,expected_day", REAL_WORLD)
def test_real_feed_formats_all_yield_a_day(raw, expected_day):
    assert day_bucket(raw) == expected_day
    assert CANONICAL.fullmatch(normalize_feed_date(raw))


def test_a_bare_day_is_returned_untouched():
    """KEV publishes dates, not timestamps; there is no clock to convert."""
    assert normalize_feed_date("2026-06-12") == "2026-06-12"


@pytest.mark.parametrize(
    "raw", [None, "", "   ", "N/A", "2026", "Mon, 20 Ju", "2026-13-45"]
)
def test_non_dates_become_null_rather_than_poisoning_the_bucket(raw):
    """published_at wins the COALESCE ahead of fetched_at, so a non-date left in
    place removes the row from the charts entirely. NULL falls back to a
    timestamp that is always ISO."""
    assert normalize_feed_date(raw) is None
    assert day_bucket(raw) == ""


@pytest.mark.parametrize("raw,_day", REAL_WORLD)
def test_normalisation_is_idempotent(raw, _day):
    """The startup backfill re-reads what it wrote; a second pass must be a
    no-op, or every run would rewrite the same rows."""
    once = normalize_feed_date(raw)
    assert normalize_feed_date(once) == once


def test_day_bucket_is_the_sql_slice_of_the_stored_value():
    """day_bucket() is the Python mirror of substr(..., 1, 10); the guarantee is
    that it agrees with the SQL once the value is stored."""
    raw = "Wed, 22 Jul 2026 17:14:06 GMT"
    stored = normalize_feed_date(raw)
    assert day_bucket(raw) == stored[:10]
    assert raw[:10] != stored[:10]  # the bug: slicing the raw value


# --- the write path -----------------------------------------------------------

@pytest.mark.asyncio
async def test_rss_dates_reach_the_30_day_sparkline(store):
    """The headline regression: an RSS item must be counted on the day it was
    published, not dropped."""
    await store.init_db()
    raw, day = _rfc822(3)
    await store.upsert_intel(row("rss", published_at=raw))

    series = {p["date"]: p["count"] for p in (await store.get_kpis())["series_30d"]["unverified"]}
    assert series[day] == 1
    # Sanity: it landed on the published day, not on today via fetched_at.
    today = datetime.now(TZ_TAIPEI).date().isoformat()
    if today != day:
        assert series[today] == 0


@pytest.mark.asyncio
async def test_every_stored_feed_date_is_iso_or_null(store):
    """Structural invariant the SQL day bucket depends on. Any collector may add
    a new source tomorrow; upsert_intel is the one place that can hold this."""
    await store.init_db()
    for n, (raw, _day) in enumerate(REAL_WORLD):
        await store.upsert_intel(row(f"i{n}", published_at=raw, date_added=raw))
    await store.upsert_intel(row("junk", published_at="N/A", date_added="Mon, 20 Ju"))

    async with aiosqlite.connect(store.DB_PATH) as conn:
        async with conn.execute("SELECT date_added, published_at FROM intel_items") as cur:
            values = [v for pair in await cur.fetchall() for v in pair]
    assert values
    assert all(v is None or CANONICAL.fullmatch(v) for v in values)


@pytest.mark.asyncio
async def test_the_ransom_collector_keeps_the_post_date(store):
    """RansomLook's RSS fallback dates posts in RFC-822 and the collector sliced
    it into date_added — the first COALESCE key, so it decided the bucket."""
    from backend.collectors.ransom import _upsert_ransom_victim_item

    await store.init_db()
    raw, day = _rfc822(2)
    await _upsert_ransom_victim_item(
        source_id="ransomlook",
        source_name="RansomLook",
        victim="Example Corp",
        group="examplegang",
        discovered=raw,
    )
    stored = (await store.query_intel(limit=5))[0]
    assert stored["date_added"] == day


# --- the cached rows ----------------------------------------------------------

async def _poke(path, item_id: str, published_at: str) -> None:
    """Write a pre-fix value straight into the column, bypassing upsert_intel."""
    async with aiosqlite.connect(path) as conn:
        await conn.execute(
            "UPDATE intel_items SET published_at=? WHERE id=?", (published_at, item_id)
        )
        await conn.commit()


@pytest.mark.asyncio
async def test_startup_repairs_rows_written_before_the_fix(store):
    await store.init_db()
    await store.upsert_intel(row("old"))
    raw, day = _rfc822(5)
    await _poke(store.DB_PATH, "old", raw)

    await store.init_db()  # the harvest's own startup, on the restored cache

    assert (await store.query_intel(limit=5))[0]["published_at"] == normalize_feed_date(raw)
    series = {p["date"]: p["count"] for p in (await store.get_kpis())["series_30d"]["unverified"]}
    assert series[day] == 1


@pytest.mark.asyncio
async def test_the_backfill_does_not_rewrite_the_same_rows_twice(store):
    await store.init_db()
    await store.upsert_intel(row("a", published_at="2026-06-12"))
    await store.upsert_intel(row("b", published_at="Mon, 22 Jun 2026 07:00:00 GMT"))
    await _poke(store.DB_PATH, "b", "Mon, 22 Jun 2026 07:00:00 GMT")

    async with aiosqlite.connect(store.DB_PATH) as conn:
        assert await store._backfill_feed_dates(conn) == 1
        await conn.commit()
        assert await store._backfill_feed_dates(conn) == 0


@pytest.mark.asyncio
async def test_the_aggregation_window_no_longer_admits_ancient_rows(store):
    """'Mon, 22 Jun 2026 …' >= '2026-08-02' is true on a string compare, so the
    14-day corroboration window used to consider the whole table."""
    await store.init_db()
    old = datetime.now(TZ_TAIPEI) - timedelta(days=400)
    await store.upsert_intel(row("ancient", published_at=format_datetime(old)))
    await store.upsert_intel(row("fresh", published_at=format_datetime(datetime.now(TZ_TAIPEI))))

    considered = {i["id"] for i in await store.items_for_aggregation(days=14)}
    assert considered == {"fresh"}
