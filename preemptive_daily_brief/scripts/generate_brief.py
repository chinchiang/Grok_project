"""Orchestrate fetch → dedupe → classify → compose → write daily_YYYY-MM-DD.md/.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python -m preemptive_daily_brief.scripts.generate_brief` from repo root
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from preemptive_daily_brief.lib.compose import compose_brief  # noqa: E402
from preemptive_daily_brief.lib.paths import OUTPUT_DIR  # noqa: E402
from preemptive_daily_brief.lib.state import ReportedState  # noqa: E402


def _merge(buckets: list[dict]) -> tuple[list[dict], list[dict]]:
    items: list[dict] = []
    failed: list[dict] = []
    seen: set[str] = set()
    for bucket in buckets:
        if not bucket.get("ok", True) and bucket.get("error"):
            failed.append(
                {
                    "id": bucket.get("source") or "",
                    "name": bucket.get("source") or "",
                    "url": bucket.get("used_url") or "",
                    "error": bucket.get("error") or "來源今日無法存取",
                }
            )
        for f in bucket.get("failed") or []:
            failed.append(f)
        for it in bucket.get("items") or []:
            key = str(it.get("cve_id") or it.get("url") or it.get("id") or it.get("title"))
            if key in seen:
                # Prefer the row that already knows it is KEV / has EPSS
                continue
            seen.add(key)
            items.append(it)
    return items, failed


def _enrich(items: list[dict]) -> list[dict]:
    """Attach EPSS onto CVE rows that do not yet have a score. Failures are silent."""
    need = [i["cve_id"] for i in items if i.get("cve_id") and i.get("epss") is None]
    if not need:
        return items
    try:
        from preemptive_daily_brief.scripts.fetch_epss import enrich_epss

        scores = enrich_epss(need[:40])
    except Exception:
        return items
    for i in items:
        cve = i.get("cve_id")
        if cve and cve in scores:
            i["epss"] = scores[cve]["epss"]
            i["epss_percentile"] = scores[cve].get("percentile")
    return items


def run_live() -> tuple[list[dict], list[dict]]:
    from preemptive_daily_brief.scripts.fetch_epss import fetch_epss_high
    from preemptive_daily_brief.scripts.fetch_kev import fetch_kev
    from preemptive_daily_brief.scripts.fetch_nvd import fetch_nvd
    from preemptive_daily_brief.scripts.fetch_rss import fetch_rss_tier

    state = ReportedState()
    buckets = [
        fetch_kev(state),
        fetch_epss_high(),
        fetch_nvd(),
        fetch_rss_tier(),
    ]
    items, failed = _merge(buckets)
    return _enrich(items), failed


def run_from_intel() -> tuple[list[dict], list[dict]]:
    """Use the SOC dashboard snapshot if present (no extra network)."""
    candidates = [
        ROOT / "soc_cti_dashboard" / "frontend" / "data" / "intel.json",
        ROOT / "soc_cti_dashboard" / "frontend" / "data" / "intel-highrisk.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("items") or []
        if items:
            return items, []
    return [], [{"id": "intel", "name": "intel.json", "url": "", "error": "找不到既有情資快照"}]


def write_outputs(brief: dict) -> tuple[Path, Path]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    md_path = OUTPUT_DIR / f"daily_{brief['date']}.md"
    json_path = OUTPUT_DIR / f"daily_{brief['date']}.json"
    md_path.write_text(brief["markdown"], encoding="utf-8")
    slim = {k: v for k, v in brief.items() if k != "markdown"}
    # keep markdown in the JSON too — the dashboard download button needs it
    slim["markdown"] = brief["markdown"]
    slim["exec_markdown"] = brief.get("exec_markdown") or ""
    json_path.write_text(json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")
    return md_path, json_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="產出今日先制式資安日報")
    parser.add_argument(
        "--from-intel",
        action="store_true",
        help="從 soc_cti_dashboard 既有情資組裝，不打外網",
    )
    parser.add_argument(
        "--no-state-update",
        action="store_true",
        help="寫出日報但不更新 state/reported.json",
    )
    args = parser.parse_args(argv)

    if args.from_intel:
        items, failed = run_from_intel()
    else:
        items, failed = run_live()

    state = ReportedState()
    brief = compose_brief(items, failed_sources=failed, reported=state)
    md_path, json_path = write_outputs(brief)
    if not args.no_state_update:
        # remember classified-level fields via the slim rows + originals
        for it in items:
            state.remember(it)
        state.save()

    stats = brief["stats"]
    print(
        f"日報已產出 {brief['date']}（{brief['weekday_zh']}）\n"
        f"  P0={stats['p0']}  P1={stats['p1']}  本組織相關={stats['org_hits']}  總計={stats['total']}\n"
        f"  失敗來源={len(stats['failed_sources'])}: "
        + (", ".join(f.get('name') or f.get('id') or '?' for f in stats['failed_sources']) or "無")
        + f"\n  {md_path}\n  {json_path}"
    )
    print("是否要同步產生一頁式主管版？已一併寫入 JSON 的 exec_markdown 欄位。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
