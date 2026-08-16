"""Feed timestamp normalisation — one canonical date format in the database.

Every feed dates its items in whatever its format mandates: RSS 2.0 requires
RFC-822 (``Mon, 20 Jul 2026 20:03:43 +0530``), Atom uses RFC-3339, JSON trackers
emit ISO-8601 with or without the ``T``, and CISA KEV publishes a bare
``YYYY-MM-DD``. Everything downstream, however, reads the stored value as ISO
and takes the day from the first ten characters:

* ``database.py::_series_30d`` groups the 30-day sparklines by that slice, and
* ``database.py::items_for_aggregation`` compares it against a ``YYYY-MM-DD``
  cutoff.

Slicing RFC-822 yields ``'Mon, 20 Ju'``, which matches no calendar day, so every
RSS-sourced row was silently absent from all seven trend charts. The same string
compared ``>= '2026-08-02'`` as *true* (``'M'`` > ``'2'``), so the 14-day
corroboration window admitted rows of any age instead.

Hence normalisation on the way in (``database.py::upsert_intel``) rather than
parsing on the way out: with one canonical form in the column the SQL day bucket
stays a plain slice, and rows written before this existed are repaired by
``database.py::_backfill_feed_dates``.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime

from .config import TZ_TAIPEI

# A bare date is already a day bucket and carries no clock to convert.
_DATE_ONLY = re.compile(r"\d{4}-\d{2}-\d{2}")


def _parse(raw: str) -> datetime | None:
    """Best-effort datetime from any feed's date string."""
    try:
        # Covers ISO-8601 / RFC-3339, with 'T' or a space, offset or none.
        # `Z` predates fromisoformat's tolerance for it in older interpreters.
        return datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError:
        pass
    try:
        # RSS 2.0 mandates RFC-822 dates; this is the same parser
        # preemptive_daily_brief/scripts/fetch_rss.py::_norm_date uses.
        return parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None


def normalize_feed_date(value: object) -> str | None:
    """Canonicalise one feed timestamp for storage, or drop it.

    A bare ``YYYY-MM-DD`` is returned unchanged; anything else parseable comes
    back as Asia/Taipei ISO-8601, the timezone every day boundary in this
    project is measured in (see ``database.py::today_taipei`` — a UTC day bucket
    is a day out for the last eight hours of each Taipei day).

    Anything unparseable becomes ``None`` rather than being stored verbatim.
    That is deliberate: these columns are only ever read as dates, and a
    non-date value in ``published_at`` wins the ``COALESCE`` ahead of
    ``fetched_at``, taking the row out of the day buckets altogether. ``NULL``
    lets it fall back to a timestamp that is always ISO.

    Idempotent: every value this returns normalises to itself.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if _DATE_ONLY.fullmatch(raw):
        try:
            return date.fromisoformat(raw).isoformat()  # identity, but validates
        except ValueError:
            return None  # date-shaped yet impossible, e.g. 2026-13-45
    dt = _parse(raw)
    if dt is None:
        return None
    if dt.tzinfo is None:
        # RFC-5322 '-0000' and a naked local time both mean "offset unknown";
        # UTC is what feeds are written against (abuse.ch even names the field
        # first_seen_utc). Guessing Taipei would shift genuine UTC stamps.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ_TAIPEI).isoformat(timespec="seconds")


def day_bucket(value: object) -> str:
    """The Taipei day a timestamp belongs to, or ``''``.

    The Python mirror of the ``substr(COALESCE(...), 1, 10)`` the KPI queries
    use, for the places that bucket in Python instead of SQL.
    """
    return (normalize_feed_date(value) or "")[:10]
