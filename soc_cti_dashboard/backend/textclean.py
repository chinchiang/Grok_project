"""Canonical plain-text cleaning for anything that reaches the UI.

Kept in its own module so the collectors (which produce the text) and the
database (which backfills rows written before the fix) share one definition
instead of drifting apart. It depends on nothing else in the package, so
neither importer creates a cycle.
"""

from __future__ import annotations

import html
import re

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
# Same collapsing, but blind to newlines so structured summaries keep their lines.
_INLINE_WS_RE = re.compile(r"[^\S\n]+")
_BLANK_LINES_RE = re.compile(r"\n{3,}")

# Cheap pre-filter for the backfill: only rows that could hold an entity.
ENTITY_RE = re.compile(r"&(?:[a-zA-Z][a-zA-Z0-9]{1,31}|#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6});")


def clean_text(s: str | None, *, keep_newlines: bool = False) -> str:
    """Strip markup and decode entities into the characters they stand for.

    Both halves matter. The frontend escapes every string it renders, so an
    entity that survives here is shown to the analyst verbatim -- `&nbsp;`
    instead of a space. Tags are stripped a second time because unescaping can
    reveal markup that the source had entity-encoded (`&lt;script&gt;`).

    `keep_newlines` is for repairing text that is already stored: summaries we
    compose ourselves are line-structured, and a repair pass has no business
    reflowing them into one line.
    """
    s = _TAG_RE.sub(" ", s or "")
    s = html.unescape(s)
    s = _TAG_RE.sub(" ", s)
    # The whitespace pass also absorbs the U+00A0 that &nbsp; just became.
    if keep_newlines:
        s = _INLINE_WS_RE.sub(" ", s)
        s = _BLANK_LINES_RE.sub("\n\n", s)
        return "\n".join(line.strip() for line in s.split("\n")).strip()
    return _WS_RE.sub(" ", s).strip()
