"""Corroboration must be cross-source, not a name-drop in the article body.

collectors/rss.py used to append a synthetic "secondary-media-citation" source
and set source_count = 2 whenever an entry's text mentioned any watchlist org.
source_count >= 2 is exactly the gate that makes a single dark-web-indirect feed
credible / B2, so vendor thought-leadership ("Why Modern SOCs Need Multi-Layered
Detections") and Exchange end-of-support news were published as two-source
dark-web intel. Six rows in the deployed export carried it.

Two halves are pinned here: the collector must not invent a source, and the
startup backfill must retract the trust already granted — the database is
restored from the Actions cache between runs, so fixing the collector alone would
leave those rows credible forever.
"""

import json
import pathlib

import pytest

import backend.database as db
from backend.priority import assign_verification

from test_lifecycle_and_review import row, store  # noqa: F401  (fixture)

SYNTHETIC = "secondary-media-citation"


# --- the producing side -------------------------------------------------------

def test_no_collector_fabricates_a_second_source():
    """Structural guard: the string must not reappear in any collector."""
    import backend.collectors as collectors

    pkg_dir = pathlib.Path(collectors.__file__).parent
    offenders = [
        f"{path.name}:{lineno}"
        for path in sorted(pkg_dir.glob("*.py"))
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if SYNTHETIC in line and not line.lstrip().startswith("#")
    ]
    assert offenders == [], (
        "a synthesised source counts as corroboration downstream: " + "; ".join(offenders)
    )


def test_single_darkweb_indirect_source_is_not_credible():
    """The gate the fabricated source was defeating."""
    v1, a1 = assign_verification(
        in_kev=False,
        layer_id="L6",
        source_count=1,
        is_darkweb_indirect=True,
        source_class="media",
    )
    assert (v1, a1) == ("unverified", "C3")
    v2, a2 = assign_verification(
        in_kev=False,
        layer_id="L6",
        source_count=2,
        is_darkweb_indirect=True,
        source_class="media",
    )
    assert v2 != "unverified", "two genuine sources must still be able to elevate"


# --- the stored side ----------------------------------------------------------

@pytest.mark.asyncio
async def test_backfill_demotes_rows_that_had_only_a_fabricated_second_source(store):
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="fake2",
            title="Why Modern SOCs Need Multi-Layered Detections",
            priority="P2",
            verification="credible",
            admiralty="B2",
            sources_json=json.dumps(["The Hacker News (indirect DW)", SYNTHETIC]),
        )
    )

    await store.init_db()  # a later run re-opens the carried-over database

    items = await store.query_intel(q="Multi-Layered")
    assert items, "row disappeared"
    item = items[0]
    assert item["sources"] == ["The Hacker News (indirect DW)"]
    assert item["evidence_count"] == 1
    assert item["verification"] == "unverified"
    assert item["admiralty"] == "C3"
    assert item["priority"] == "P3"


@pytest.mark.asyncio
async def test_backfill_keeps_genuinely_dual_sourced_rows_credible(store):
    """67 of the deployed dark-web rows carry two real scrapers. Retracting the
    fabrication must not sweep those up."""
    await store.init_db()
    real = ["Ransomware.live", "RansomLook"]
    await store.upsert_intel(
        row(
            iid="dual",
            title="Leak site victim listing",
            priority="P2",
            verification="credible",
            admiralty="B2",
            sources_json=json.dumps(real),
        )
    )

    await store.init_db()

    item = (await store.query_intel(q="Leak site"))[0]
    assert item["sources"] == real
    assert item["verification"] == "credible"
    assert item["priority"] == "P2"


@pytest.mark.asyncio
async def test_backfill_keeps_the_real_sources_when_three_were_listed(store):
    """Only the synthetic entry is removed; two survivors keep their grade."""
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="three",
            title="Triple sourced advisory",
            priority="P1",
            verification="credible",
            admiralty="B2",
            sources_json=json.dumps(["Ransomware.live", "RansomLook", SYNTHETIC]),
        )
    )

    await store.init_db()

    item = (await store.query_intel(q="Triple sourced"))[0]
    assert item["sources"] == ["Ransomware.live", "RansomLook"]
    assert item["evidence_count"] == 2
    assert item["verification"] == "credible", "two real sources still corroborate"
    assert item["priority"] == "P1"


@pytest.mark.asyncio
async def test_backfill_is_idempotent_and_leaves_verdicts_alone(store):
    """It runs on every startup and writes to intel_items, so the 2.9 guarantee
    (analyst verdicts survive a re-harvest) has to hold here too."""
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="fake3",
            title="Retract me",
            verification="credible",
            admiralty="B2",
            sources_json=json.dumps(["BleepingComputer (indirect DW)", SYNTHETIC]),
        )
    )
    assert await store.set_analyst_verdict("fake3", "false_positive", "媒體單篇", "kai")

    await store.init_db()
    first = (await store.query_intel(q="Retract me"))[0]
    await store.init_db()
    second = (await store.query_intel(q="Retract me"))[0]

    assert first["sources"] == second["sources"] == ["BleepingComputer (indirect DW)"]
    assert second["verification"] == "unverified"
    assert second["analyst_verdict"] == "false_positive"
    assert second["verdict_note"] == "媒體單篇"
