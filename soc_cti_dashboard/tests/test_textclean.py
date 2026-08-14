"""Feed text must reach the analyst as characters, not as HTML entities.

The frontend escapes every string it renders, which is correct — but it means
an entity left in the stored text is displayed verbatim. Before this was fixed
the deployed dashboard showed 114 literal `&nbsp;` across the Microsoft and
review-queue tabs, so these tests pin both halves: the collector that produces
the text, and the backfill that repairs text already in the database.
"""

import pathlib

import pytest

import backend.database as db
from backend.collectors._base import _parse_rss_entries, _strip_html
from backend.textclean import clean_text

from test_lifecycle_and_review import row, store  # noqa: F401  (fixture)


# --- the producing side -------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("<p>News&nbsp;&nbsp;here</p>", "News here"),
        ("Fortinet &amp; Palo Alto", "Fortinet & Palo Alto"),
        ("Tom&#39;s Hardware", "Tom's Hardware"),
        ("patch &mdash; now", "patch — now"),
        ("&hellip;read more", "…read more"),
        # Already clean text is left alone, including a bare ampersand.
        ("AT&T outage", "AT&T outage"),
        ("", ""),
    ],
)
def test_entities_become_characters(raw, expected):
    assert _strip_html(raw) == expected


def test_entity_encoded_markup_does_not_survive_as_a_tag():
    """Unescaping can reveal markup the source had encoded, so tags are
    stripped again afterwards — otherwise this fix would hand a live tag to any
    future consumer that does not escape."""
    assert _strip_html("&lt;script&gt;alert(1)&lt;/script&gt; payload") == "alert(1) payload"


def test_cleaning_is_idempotent():
    once = _strip_html("<b>A&nbsp;&amp;&nbsp;B</b>")
    assert once == "A & B"
    assert _strip_html(once) == once


def test_rss_summaries_are_cleaned_not_just_tag_stripped():
    """The regression lived here: _parse_rss_entries used its own inline tag
    strip instead of _strip_html, so entities bypassed the cleaner entirely."""
    feed = """<?xml version="1.0"?>
    <rss version="2.0"><channel><title>t</title>
      <item>
        <title>SharePoint exploit</title>
        <description>&lt;p&gt;steals keys&amp;nbsp;&amp;nbsp;SC Media&lt;/p&gt;</description>
        <link>https://example.com/1</link>
      </item>
    </channel></rss>"""
    entries = _parse_rss_entries(feed, profile="https://example.com", limit=5)
    assert entries, "feed did not parse"
    assert "&nbsp;" not in entries[0]["summary"]
    assert entries[0]["summary"] == "steals keys SC Media"


def test_summary_truncation_still_applies_after_cleaning():
    long_body = "<p>" + ("verylongword " * 400) + "</p>"
    feed = f"""<?xml version="1.0"?>
    <rss version="2.0"><channel><title>t</title>
      <item><title>x</title><description>{long_body}</description>
      <link>https://example.com/2</link></item>
    </channel></rss>"""
    entries = _parse_rss_entries(feed, profile="p", limit=5)
    assert len(entries[0]["summary"]) <= 1200


def test_repair_pass_keeps_line_structure():
    """Summaries we compose ourselves are line-structured (KEV, ICS). A repair
    pass is allowed to decode entities, not to reflow the text."""
    text = "Nx Console flaw&nbsp;here\n廠商/產品：Nx / Nx Console\n必要處置：patch"
    out = clean_text(text, keep_newlines=True)
    assert out.count("\n") == 2
    assert "&nbsp;" not in out
    assert out.startswith("Nx Console flaw here")


def test_no_collector_strips_tags_by_hand():
    """The bug was four copies of the same two-line tag strip, in _base, rss,
    osint and ransom. Fixing one left the other three leaking, so the guard is
    structural: cleaning feed text belongs to clean_text, nowhere else."""
    import backend.collectors as collectors

    pkg_dir = pathlib.Path(collectors.__file__).parent
    offenders = []
    for path in sorted(pkg_dir.glob("*.py")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if "<[^>]+>" in line:
                offenders.append(f"{path.name}:{lineno} {line.strip()}")
    assert offenders == [], (
        "hand-rolled tag stripping bypasses entity decoding: " + "; ".join(offenders)
    )


# --- the stored side ----------------------------------------------------------

@pytest.mark.asyncio
async def test_backfill_repairs_rows_written_before_the_fix(store):
    """The database is restored from the Actions cache between runs and an item
    is only rewritten while its feed still carries it. Fixing the collector
    alone would leave old rows showing `&nbsp;` on the dashboard forever."""
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="dirty",
            summary="steals keys&nbsp;&nbsp;SC Media",
            summary_en="steals keys&nbsp;&nbsp;SC Media",
            title="SharePoint &amp; Exchange",
            title_en="SharePoint &amp; Exchange",
        )
    )

    await store.init_db()  # a later run re-opens the carried-over database

    items = await store.query_intel(q="SC Media")
    assert items, "row disappeared"
    item = items[0]
    assert item["summary"] == "steals keys SC Media"
    assert item["summary_en"] == "steals keys SC Media"
    assert item["title"] == "SharePoint & Exchange"


@pytest.mark.asyncio
async def test_backfill_leaves_clean_rows_untouched(store):
    """It runs on every startup, so it has to be a no-op once the data is
    clean — including for text with a bare '&' and a ';' somewhere after it,
    which matches the SQL pre-filter but is not an entity."""
    await store.init_db()
    original = "AT&T outage; see advisory"
    await store.upsert_intel(row(iid="clean", summary=original, summary_en=original))

    await store.init_db()

    items = await store.query_intel(q="AT&T")
    assert items[0]["summary"] == original


@pytest.mark.asyncio
async def test_backfill_does_not_reflow_structured_summaries(store):
    """KEV and ICS summaries are composed line by line. Repairing an entity in
    one of them must not flatten the rest into a single paragraph."""
    await store.init_db()
    await store.upsert_intel(
        row(
            iid="kev1",
            summary="Nx Console flaw&nbsp;here\n廠商/產品：Nx\n必要處置：patch",
        )
    )

    await store.init_db()

    items = await store.query_intel(q="Nx Console")
    assert "&nbsp;" not in items[0]["summary"]
    assert items[0]["summary"].count("\n") == 2, items[0]["summary"]


@pytest.mark.asyncio
async def test_backfill_does_not_touch_analyst_verdicts(store):
    """It writes to intel_items, so the 2.9 guarantee has to hold here too."""
    await store.init_db()
    await store.upsert_intel(row(iid="v1", summary="body&nbsp;text"))
    assert await store.set_analyst_verdict("v1", "true_positive", "確認", "kai")

    await store.init_db()

    items = await store.query_intel(q="body")
    assert items[0]["summary"] == "body text"
    assert items[0]["analyst_verdict"] == "true_positive"
