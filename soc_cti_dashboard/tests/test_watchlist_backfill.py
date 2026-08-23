"""Cached rows must be re-flagged when the watchlist matcher changes.

The Actions SQLite file is restored between harvests. A feed only rewrites a
row while it still carries that item, so 'MSI samples' posts scored under the
old alias stay on the Taiwan dashboard until this backfill runs.
"""

import json

import pytest

from test_lifecycle_and_review import row, store  # noqa: F401


@pytest.mark.asyncio
async def test_msi_installer_posts_leave_the_taiwan_board(store):
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="msi-fp",
            title="[未核實 Unverified] [X @cyb3rops] We identified multiple MSI samples associated with the loader",
            summary="Windows Installer MSI package used as a loader",
            is_tw_industry=1,
            tw_entities_json=json.dumps(
                [{"key": "msi", "matched": "msi", "tier": "electronics"}]
            ),
            tags_json=json.dumps(["x-twitter", "unverified", "tw-industry"]),
        )
    )

    n = await _run(store)
    assert n == 1

    item = (await store.query_intel(q="MSI samples"))[0]
    assert item["is_tw_industry"] is False
    assert item["tw_entities"] == []
    assert "tw-industry" not in (item.get("tags") or [])


@pytest.mark.asyncio
async def test_gigabytes_boilerplate_is_cleared(store):
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="gb-fp",
            title="claimed victim listing",
            summary="we have hundreds of gigabytes of your files",
            is_tw_industry=1,
            tw_entities_json=json.dumps(
                [{"key": "gigabyte", "matched": "gigabyte", "tier": "electronics"}]
            ),
            tags_json=json.dumps(["tw-industry", "ransomware"]),
            is_ransomware=1,
        )
    )

    await store.init_db()

    item = (await store.query_intel(q="claimed victim"))[0]
    assert item["is_tw_industry"] is False
    assert all(e.get("key") != "gigabyte" for e in item["tw_entities"])


@pytest.mark.asyncio
async def test_real_gigabyte_advisory_stays(store):
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="gb-tp",
            title="🇹🇼 TWCERT TVN｜技嘉科技｜Gigabyte Control Center - Improper Access Control",
            summary="技嘉科技 Gigabyte Control Center 存在不當存取控制",
            is_tw_industry=0,
            tw_entities_json="[]",
            source_name="TWCERT TVN",
            layer_id="L2",
            verification="credible",
        )
    )

    await store.init_db()

    item = (await store.query_intel(q="Control Center"))[0]
    assert item["is_tw_industry"] is True
    assert any(e.get("key") == "gigabyte" for e in item["tw_entities"])


@pytest.mark.asyncio
async def test_false_tw_plus_kev_p0_falls_back_to_p1(store):
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="kev-fp",
            title="[KEV] CVE-2026-1 — path traversal",
            summary="we have hundreds of gigabytes of your files",
            source_name="CISA KEV",
            layer_id="L1",
            verification="confirmed",
            priority="P0",
            is_tw_industry=1,
            tw_entities_json=json.dumps(
                [{"key": "gigabyte", "matched": "gigabyte", "tier": "electronics"}]
            ),
            known_ransomware_campaign=0,
        )
    )

    await store.init_db()

    item = (await store.query_intel(q="CVE-2026-1"))[0]
    assert item["is_tw_industry"] is False
    assert item["priority"] == "P1"
    assert item["verification"] == "confirmed"


@pytest.mark.asyncio
async def test_backfill_is_idempotent_and_keeps_verdicts(store):
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="msi-fp2",
            title="Windows Installer MSI package failed",
            is_tw_industry=1,
            tw_entities_json=json.dumps(
                [{"key": "msi", "matched": "msi", "tier": "electronics"}]
            ),
        )
    )
    assert await store.set_analyst_verdict("msi-fp2", "false_positive", "安裝檔", "kai")

    first = await _run(store)
    assert first >= 1
    second = await _run(store)
    assert second == 0

    item = (await store.query_intel(q="Installer"))[0]
    assert item["analyst_verdict"] == "false_positive"
    assert item["verdict_note"] == "安裝檔"
    assert item["priority"] == "P3"


async def _run(store) -> int:
    import aiosqlite

    async with aiosqlite.connect(store.DB_PATH) as conn:
        n = await store._backfill_watchlist_flags(conn)
        await conn.commit()
        return n
