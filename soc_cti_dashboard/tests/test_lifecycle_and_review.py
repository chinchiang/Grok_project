"""Lifecycle, KPI windows and the analyst feedback loop (2.7 / 2.8 / 2.9).

Each test drives a real SQLite file through the actual data layer, because the
properties being asserted — that a verdict survives a re-harvest, that day
boundaries are Taipei's, that stale items leave the open counts — only exist at
the persistence layer.
"""

import json

import pytest

import backend.database as db


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Isolated database for one test."""
    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    return db


def row(iid="i1", **kw):
    base = {
        "id": iid,
        "title": "Example advisory",
        "title_en": "Example advisory",
        "summary": "body",
        "summary_en": "body",
        "priority": "P3",
        "verification": "unverified",
        "layer_id": "L6",
        "source_name": "The Hacker News",
        "sources_json": "[]",
        "cve_id": None,
        "product": "",
        "vendor": "",
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
        "date_added": None,
        "published_at": None,
        "fetched_at": db.now_iso(),
        "url": "https://example.com/a",
        "admiralty": "C3",
        "raw_json": "{}",
        "tags_json": "[]",
    }
    base.update(kw)
    return base


# --- 2.9 feedback loop --------------------------------------------------------

@pytest.mark.asyncio
async def test_verdict_survives_a_reharvest(store):
    """The whole loop depends on this: if a harvest wiped verdicts, precision
    could never accumulate and analyst work would be lost twice a day."""
    await store.init_db()
    await store.upsert_intel(row())
    assert await store.set_analyst_verdict("i1", "false_positive", "媒體單篇", "kai")

    await store.upsert_intel(row(title="Example advisory (updated)"))

    got = (await store.query_intel(limit=10))[0]
    assert got["analyst_verdict"] == "false_positive"
    assert got["verdict_note"] == "媒體單篇"
    assert got["verdict_by"] == "kai"
    assert got["title"].endswith("(updated)")  # content still refreshed


@pytest.mark.asyncio
async def test_unknown_item_and_bad_verdict_are_rejected(store):
    await store.init_db()
    assert await store.set_analyst_verdict("nope", "true_positive") is False
    await store.upsert_intel(row())
    with pytest.raises(ValueError):
        await store.set_analyst_verdict("i1", "probably")


@pytest.mark.asyncio
async def test_precision_is_none_until_something_is_reviewed(store):
    """An unreviewed rule is unknown, not perfect — 0 reviews must not read
    as 100% precision."""
    await store.init_db()
    await store.upsert_intel(row(priority="P0"))
    acc = await store.get_rule_accuracy()
    assert acc["dimensions"]["priority_P0"]["precision"] is None

    await store.set_analyst_verdict("i1", "false_positive")
    acc = await store.get_rule_accuracy()
    assert acc["dimensions"]["priority_P0"]["precision"] == 0.0
    assert acc["dimensions"]["priority_P0"]["false_positive"] == 1


@pytest.mark.asyncio
async def test_review_queue_excludes_already_reviewed(store):
    await store.init_db()
    await store.upsert_intel(row("a"))
    await store.upsert_intel(row("b"))
    await store.set_analyst_verdict("a", "true_positive")
    queue = await store.query_intel(
        priority="P3", verification="unverified", status="open", unreviewed_only=True
    )
    assert [i["id"] for i in queue] == ["b"]


# --- 2.7 lifecycle ------------------------------------------------------------

@pytest.mark.asyncio
async def test_stale_items_leave_open_counts_but_are_kept(store):
    await store.init_db()
    old = store.days_ago_taipei(40)
    await store.upsert_intel(row("old", priority="P0", fetched_at=old, last_seen=old))
    await store.upsert_intel(row("new", priority="P0"))

    assert await store.mark_stale_items(days=14) == 1
    kpis = await store.get_kpis()
    assert kpis["p0_count"] == 1                       # open only
    assert kpis["priority_windows"]["P0"]["total"] == 2  # nothing deleted
    assert kpis["stale_count"] == 1


@pytest.mark.asyncio
async def test_reobserving_an_item_reopens_it(store):
    await store.init_db()
    old = store.days_ago_taipei(40)
    await store.upsert_intel(row("x", fetched_at=old, last_seen=old))
    await store.mark_stale_items(days=14)
    await store.upsert_intel(row("x"))  # seen again in this harvest
    got = (await store.query_intel(limit=5))[0]
    assert got["status"] == "open"


@pytest.mark.asyncio
async def test_first_seen_is_immutable(store):
    await store.init_db()
    first = store.days_ago_taipei(5)
    await store.upsert_intel(row("x", fetched_at=first, first_seen=first))
    await store.upsert_intel(row("x"))
    got = (await store.query_intel(limit=5))[0]
    assert got["first_seen"] == first


# --- 2.8 KPI correctness ------------------------------------------------------

@pytest.mark.asyncio
async def test_breach_kpi_excludes_ioc_feeds(store):
    """ThreatFox is an IOC feed, not a breach record; it used to inflate the
    breach headline by hundreds of items."""
    await store.init_db()
    await store.upsert_intel(row("ransom", is_ransomware=1, source_name="RansomLook"))
    await store.upsert_intel(row("ioc", source_name="abuse.ch ThreatFox", layer_id="L3"))
    kpis = await store.get_kpis()
    assert kpis["breach_count"] == 1
    assert kpis["ioc_count"] == 1


@pytest.mark.asyncio
async def test_entity_counts_use_json_keys_not_substrings(store):
    """LIKE '%\"semi\"%' also matched an alias or tier containing the token."""
    await store.init_db()
    await store.upsert_intel(
        row(
            "real",
            is_tw_industry=1,
            tw_entities_json=json.dumps([{"key": "tsmc", "matched": "tsmc", "tier": "semi"}]),
        )
    )
    await store.upsert_intel(
        row(
            "decoy",
            is_tw_industry=1,
            tw_entities_json=json.dumps(
                [{"key": "other", "matched": "semi conductor plant", "tier": "electronics"}]
            ),
        )
    )
    kpis = await store.get_kpis()
    assert kpis["semi_count"] == 1


@pytest.mark.asyncio
async def test_osint_verification_rate_excludes_l1(store):
    """L1 is almost all CISA KEV, confirmed by definition; including it hid how
    well the OSINT layers were actually corroborated."""
    await store.init_db()
    await store.upsert_intel(row("kev", layer_id="L1", verification="confirmed"))
    await store.upsert_intel(row("osint", layer_id="L6", verification="unverified"))
    kpis = await store.get_kpis()
    assert kpis["verified_pct"] == 50.0
    assert kpis["osint_verified_pct"] == 0.0


@pytest.mark.asyncio
async def test_day_windows_use_taipei_not_utc(store):
    """SQLite date('now') is UTC, so for the first 8 hours of each Taipei day
    every 'last 7 days' window was a day out."""
    from datetime import datetime, timedelta
    from backend.config import TZ_TAIPEI

    expected = (datetime.now(TZ_TAIPEI).date() - timedelta(days=7)).isoformat()
    assert store.days_ago_taipei(7) == expected
    assert store.today_taipei() == datetime.now(TZ_TAIPEI).date().isoformat()


# --- 3.5 query hardening ------------------------------------------------------

@pytest.mark.asyncio
async def test_like_wildcards_in_search_are_escaped(store):
    """'%' and '_' must be literals, not wildcards — otherwise a search for
    '100%' silently matched every row in the table."""
    await store.init_db()
    await store.upsert_intel(row("a", title="EPSS 100% exploitation probability"))
    await store.upsert_intel(row("b", title="Unrelated advisory"))
    await store.upsert_intel(row("c", title="CVE_2026_1 placeholder"))

    assert [i["id"] for i in await store.query_intel(q="100%")] == ["a"]
    # A bare wildcard now finds the rows literally containing it, not all rows
    assert [i["id"] for i in await store.query_intel(q="%")] == ["a"]
    # '_' likewise is a literal, so it must not match the single-char gap in "CVE-2026"
    assert [i["id"] for i in await store.query_intel(q="CVE_2026")] == ["c"]


# --- 2.9 false-positive demotion (engine grade vs operational board) ----------

@pytest.mark.asyncio
async def test_false_positive_leaves_the_p0_board_but_keeps_engine_grade(store):
    """An analyst FP must leave P0 operational counts without rewriting
    precision: the scorer said P0, and that is what we measure."""
    await store.init_db()
    await store.upsert_intel(row(priority="P0", verification="confirmed"))
    assert await store.set_analyst_verdict("i1", "false_positive", "媒體單篇", "kai")

    got = (await store.query_intel(limit=5))[0]
    assert got["priority"] == "P3"
    assert got["engine_priority"] == "P0"
    assert got["analyst_verdict"] == "false_positive"
    assert got["demoted_by_verdict"] is True

    kpis = await store.get_kpis()
    assert kpis["p0_count"] == 0
    acc = await store.get_rule_accuracy()
    assert acc["dimensions"]["priority_P0"]["false_positive"] == 1
    assert acc["dimensions"]["priority_P0"]["precision"] == 0.0
    assert acc["dimensions"]["priority_P3"]["false_positive"] == 0


@pytest.mark.asyncio
async def test_reharvest_cannot_restore_a_false_positive_p0(store):
    await store.init_db()
    await store.upsert_intel(row(priority="P0"))
    await store.set_analyst_verdict("i1", "false_positive")
    await store.upsert_intel(row(priority="P0", title="Example advisory (updated)"))

    got = (await store.query_intel(limit=5))[0]
    assert got["priority"] == "P3"
    assert got["engine_priority"] == "P0"
    assert got["title"].endswith("(updated)")
    assert got["analyst_verdict"] == "false_positive"
    assert (await store.get_kpis())["p0_count"] == 0


@pytest.mark.asyncio
async def test_clearing_a_false_positive_restores_engine_priority(store):
    await store.init_db()
    await store.upsert_intel(row(priority="P0"))
    await store.set_analyst_verdict("i1", "false_positive")
    await store.set_analyst_verdict("i1", "true_positive")

    got = (await store.query_intel(limit=5))[0]
    assert got["priority"] == "P0"
    assert got.get("demoted_by_verdict") in (None, False)
    assert (await store.get_kpis())["p0_count"] == 1


@pytest.mark.asyncio
async def test_aggregation_does_not_upgrade_a_false_positive(store):
    await store.init_db()
    await store.upsert_intel(row(priority="P3", verification="unverified"))
    await store.set_analyst_verdict("i1", "false_positive")
    await store.apply_aggregation(
        "i1",
        sources=["The Hacker News", "BleepingComputer"],
        priority="P2",
        verification="credible",
        admiralty="B2",
        rationale_zh="雙源",
        rationale_en="dual",
        corroborated_by=["BleepingComputer"],
    )
    got = (await store.query_intel(limit=5))[0]
    assert got["priority"] == "P3"
    assert got["verification"] == "unverified"


@pytest.mark.asyncio
async def test_cached_false_positive_p0_is_demoted_on_init(store):
    """Rows FPed before demotion existed still sit at P0 in the Actions cache."""
    import aiosqlite

    await store.init_db()
    await store.upsert_intel(row(priority="P0"))
    async with aiosqlite.connect(store.DB_PATH) as conn:
        await conn.execute(
            "UPDATE intel_items SET analyst_verdict='false_positive', "
            "priority='P0' WHERE id='i1'"
        )
        await conn.commit()
        n = await store._backfill_false_positive_demotion(conn)
        await conn.commit()
        assert n == 1
        assert await store._backfill_false_positive_demotion(conn) == 0

    got = (await store.query_intel(limit=5))[0]
    assert got["priority"] == "P3"
    assert got["engine_priority"] == "P0"
    assert (await store.get_kpis())["p0_count"] == 0
