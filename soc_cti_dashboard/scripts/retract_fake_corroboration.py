"""Retract trust granted by the fabricated "secondary-media-citation" source.

collectors/rss.py used to append a synthetic second source whenever an article
body name-dropped one of ~11 watchlist orgs, then set source_count = 2. That is
the credibility gate for a single dark-web-indirect feed, so vendor
thought-leadership and end-of-support news were published as credible / B2
two-source intel.

The collector no longer does this and database.py::_backfill_fake_corroboration
repairs the cached SQLite rows on startup. This script applies the same
retraction to the static JSON payloads already committed under frontend/data,
which is what GitHub Pages serves until the next successful harvest.

Idempotent: rows without the synthetic source are left untouched.

    python -m scripts.retract_fake_corroboration [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

SYNTHETIC_SOURCE = "secondary-media-citation"
DATA_DIR = Path(__file__).resolve().parent.parent / "frontend" / "data"


def _retract(item: dict) -> bool:
    """Strip the synthetic source from one item. True if it changed."""
    sources = item.get("sources")
    if not isinstance(sources, list) or SYNTHETIC_SOURCE not in sources:
        return False
    real = [s for s in sources if s != SYNTHETIC_SOURCE]
    item["sources"] = real
    item["evidence_count"] = len(real)
    if "sources_json" in item:
        item["sources_json"] = json.dumps(real)
    if len(real) < 2:
        # Same demotion as assign_verification() gives a single
        # dark-web-indirect source: unverified / C3, and no watchlist auto-P0.
        item["verification"] = "unverified"
        item["admiralty"] = "C3"
        item["priority"] = "P3"
    return True


def _iter_items(payload):
    """Every dict in the payload, at any depth.

    The exports repeat items across derived buckets — intel.json carries each row
    in both ``items`` and ``by_priority[P*]`` — so a key-name allowlist would
    leave a retracted row still showing its old grade one level down.
    """
    if isinstance(payload, dict):
        yield payload
        for value in payload.values():
            yield from _iter_items(value)
    elif isinstance(payload, list):
        for value in payload:
            yield from _iter_items(value)


def _rebuild_by_priority(payload) -> None:
    """Re-derive intel.json's by_priority buckets after a demotion to P3."""
    if not isinstance(payload, dict):
        return
    items = payload.get("items")
    buckets = payload.get("by_priority")
    if not isinstance(items, list) or not isinstance(buckets, dict):
        return
    for prio in list(buckets):
        buckets[prio] = [
            i for i in items if isinstance(i, dict) and i.get("priority") == prio
        ]


def _sync_kpis(data_dir: Path) -> str:
    """Re-derive the KPI counters the demotion changes, from intel.json.

    kpis.json is a whole-database snapshot while intel.json is a 400-row export,
    so this is only sound when they cover the same rows — asserted below via
    items_total. Formulas mirror database.py::get_kpis / _series_30d exactly
    (windows on COALESCE(first_seen, fetched_at), the sparkline day bucket on
    COALESCE(date_added, published_at, fetched_at)), with the export timestamp as
    the reference clock instead of "now". Anything not listed here is left alone
    and self-corrects on the next harvest, where init_db() runs the same
    retraction against the cached database.
    """
    intel_path = data_dir / "intel.json"
    kpi_path = data_dir / "kpis.json"
    if not (intel_path.exists() and kpi_path.exists()):
        return "kpis.json or intel.json missing — skipped"
    intel = json.loads(intel_path.read_text(encoding="utf-8"))
    kpis = json.loads(kpi_path.read_text(encoding="utf-8"))
    items = [i for i in intel.get("items") or [] if isinstance(i, dict)]
    if not items or kpis.get("items_total") != len(items):
        return (
            f"kpis.json covers {kpis.get('items_total')} rows but intel.json has "
            f"{len(items)} — counters left untouched (regenerate via export_static)"
        )

    ref = str(kpis.get("exported_at") or "")[:10]
    if len(ref) != 10:
        return "kpis.json has no usable exported_at — counters left untouched"
    ref_date = date.fromisoformat(ref)
    d7 = (ref_date - timedelta(days=7)).isoformat()
    d30 = (ref_date - timedelta(days=30)).isoformat()

    def seen(i: dict) -> str:
        return str(i.get("first_seen") or i.get("fetched_at") or "")

    def day(i: dict) -> str:
        return str(i.get("date_added") or i.get("published_at") or i.get("fetched_at") or "")[:10]

    windows = {}
    for prio in ("P0", "P1", "P2", "P3"):
        rows = [i for i in items if i.get("priority") == prio]
        windows[prio] = {
            "total": len(rows),
            "open": sum(1 for i in rows if i.get("status") == "open"),
            "new_7d": sum(1 for i in rows if seen(i) >= d7),
            "new_30d": sum(1 for i in rows if seen(i) >= d30),
        }

    total = len(items)
    unverified = sum(1 for i in items if i.get("verification") == "unverified")
    osint = [i for i in items if i.get("layer_id") not in ("L1", "T1")]
    osint_unverified = sum(1 for i in osint if i.get("verification") == "unverified")

    kpis["priority_windows"] = windows
    for prio in ("P0", "P1", "P2", "P3"):
        kpis[f"{prio.lower()}_count"] = windows[prio]["open"]
    kpis["unverified_count"] = unverified
    kpis["verified_pct"] = round(100.0 * (total - unverified) / total, 1) if total else 0.0
    kpis["osint_total"] = len(osint)
    kpis["osint_verified_pct"] = (
        round(100.0 * (len(osint) - osint_unverified) / len(osint), 1) if osint else 0.0
    )

    series = (kpis.get("series_30d") or {}).get("unverified")
    if isinstance(series, list):
        by_day: dict[str, int] = {}
        for i in items:
            if i.get("verification") == "unverified":
                by_day[day(i)] = by_day.get(day(i), 0) + 1
        for point in series:
            if isinstance(point, dict) and point.get("date"):
                point["count"] = by_day.get(point["date"], 0)

    kpi_path.write_text(
        json.dumps(kpis, ensure_ascii=False, separators=(",", ":"), default=str),
        encoding="utf-8",
    )
    return (
        f"kpis.json: P2 open={windows['P2']['open']} P3 open={windows['P3']['open']} "
        f"unverified={unverified} verified_pct={kpis['verified_pct']}"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--check",
        action="store_true",
        help="report affected rows without writing (exit 1 if any remain)",
    )
    args = ap.parse_args()

    total = 0
    for path in sorted(DATA_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"skip {path.name}: {exc}", file=sys.stderr)
            continue
        fixed = sum(1 for item in _iter_items(payload) if _retract(item))
        if not fixed:
            continue
        total += fixed
        print(f"{path.name}: {fixed} row(s) retracted")
        if not args.check:
            _rebuild_by_priority(payload)
            # separators match export_static.py so the diff is confined to the
            # rows that actually changed.
            path.write_text(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str),
                encoding="utf-8",
            )

    if not total:
        print("no fabricated corroboration found")
    if args.check:
        return 1 if total else 0
    # Re-derived from the item rows either way: it is a pure recomputation, so
    # running it on an already-clean export is a no-op.
    print(_sync_kpis(DATA_DIR))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
