"""One-shot: demote unverified single-source OSINT from P0/P1 → P3.

Matches the new rule: X OSINT / dark-web indirect / single-source L6
cannot auto-elevate on watchlist + ransomware keywords alone.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))

from soc_cti_dashboard.backend.ops import explain_priority, pick_sop  # noqa: E402

DB_PATH = ROOT / "data" / "cti.db"
INTEL_PATH = ROOT / "frontend" / "data" / "intel.json"
KPI_PATH = ROOT / "frontend" / "data" / "kpis.json"


def _parse_json_list(val) -> list:
    if isinstance(val, list):
        return val
    if not val:
        return []
    try:
        out = json.loads(val)
        return out if isinstance(out, list) else []
    except Exception:
        return []


def should_demote(row: dict) -> bool:
    ver = row.get("verification") or ""
    pri = row.get("priority") or ""
    if ver != "unverified" or pri not in ("P0", "P1"):
        return False

    title = f"{row.get('title') or ''} {row.get('title_en') or ''}"
    tags = _parse_json_list(row.get("tags") if "tags" in row else row.get("tags_json"))
    sources = _parse_json_list(
        row.get("sources") if "sources" in row else row.get("sources_json")
    )
    layer = row.get("layer_id") or ""
    src_name = row.get("source_name") or ""

    # X OSINT single-source
    if (
        "[X @" in title
        or "x-twitter" in tags
        or src_name.startswith("X @")
        or src_name.startswith("@")
        or any(str(s).startswith("@") for s in sources)
    ):
        return True

    # Leak-site / dual-track dark-web indirect, single source
    if "darkweb-indirect" in tags and len(sources) <= 1:
        return True

    # Generic L6 unverified single-source cards
    if (
        layer == "L6"
        and len(sources) <= 1
        and ("未核實" in title or "[Unverified]" in title or "unverified" in tags)
    ):
        return True

    return False


def main() -> None:
    rz, re_ = explain_priority(
        priority="P3", source_count=1, forced_p3_review=True
    )
    sop = pick_sop(
        priority="P3",
        verification="unverified",
        is_darkweb=True,
        is_ransomware=True,
    )

    demoted_ids: list[str] = []

    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        rows = cur.execute(
            """
            SELECT id, title, title_en, priority, verification, layer_id,
                   source_name, sources_json, tags_json, extras_json
            FROM intel_items
            WHERE priority IN ('P0','P1') AND verification='unverified'
            """
        ).fetchall()
        print(f"DB candidates: {len(rows)}")
        for r in rows:
            d = dict(r)
            if not should_demote(d):
                print(f"  skip  {d['priority']} {d['title'][:90]}")
                continue
            try:
                extras = json.loads(d.get("extras_json") or "{}")
            except Exception:
                extras = {}
            extras.update(
                {
                    "priority_rationale": rz,
                    "priority_rationale_en": re_,
                    "sop_id": sop["sop_id"],
                    "sop_zh": sop["sop_zh"],
                    "sop_en": sop["sop_en"],
                    "owner": sop["owner"],
                    "sla_hours": sop["sla_hours"],
                }
            )
            tags = _parse_json_list(d.get("tags_json"))
            if "p3-review" not in tags:
                tags.append("p3-review")
            cur.execute(
                "UPDATE intel_items SET priority=?, tags_json=?, extras_json=? WHERE id=?",
                (
                    "P3",
                    json.dumps(tags, ensure_ascii=False),
                    json.dumps(extras, ensure_ascii=False),
                    d["id"],
                ),
            )
            demoted_ids.append(d["id"])
            print(f"  demote {d['priority']} -> P3  {d['title'][:90]}")
        conn.commit()
        conn.close()
    else:
        print(f"DB not found: {DB_PATH}")

    if INTEL_PATH.exists():
        data = json.loads(INTEL_PATH.read_text(encoding="utf-8"))
        items = (
            data
            if isinstance(data, list)
            else data.get("items") or data.get("intel") or []
        )
        n = 0
        for it in items:
            if not should_demote(it):
                continue
            it["priority"] = "P3"
            it["priority_rationale"] = rz
            it["priority_rationale_en"] = re_
            it["sop_id"] = sop["sop_id"]
            it["sop_zh"] = sop["sop_zh"]
            it["sop_en"] = sop["sop_en"]
            it["owner"] = sop["owner"]
            it["sla_hours"] = sop["sla_hours"]
            tags = it.get("tags") or []
            if isinstance(tags, list) and "p3-review" not in tags:
                tags.append("p3-review")
                it["tags"] = tags
            n += 1
            print(f"  JSON demote -> P3  {(it.get('title') or '')[:90]}")
        INTEL_PATH.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"JSON demoted: {n}")

        # Refresh KPI counts if present
        if KPI_PATH.exists() and isinstance(data, list):
            try:
                kpis = json.loads(KPI_PATH.read_text(encoding="utf-8"))
                counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
                for it in data:
                    p = it.get("priority")
                    if p in counts:
                        counts[p] += 1
                if isinstance(kpis, dict):
                    for key, val in (
                        ("p0", counts["P0"]),
                        ("p1", counts["P1"]),
                        ("p2", counts["P2"]),
                        ("p3", counts["P3"]),
                    ):
                        if key in kpis:
                            kpis[key] = val
                        elif "counts" in kpis and isinstance(kpis["counts"], dict):
                            kpis["counts"][key] = val
                    # also common shapes
                    if "priority" in kpis and isinstance(kpis["priority"], dict):
                        kpis["priority"].update(
                            {
                                "P0": counts["P0"],
                                "P1": counts["P1"],
                                "P2": counts["P2"],
                                "P3": counts["P3"],
                            }
                        )
                    KPI_PATH.write_text(
                        json.dumps(kpis, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    print(f"KPI refreshed: {counts}")
            except Exception as e:
                print(f"KPI refresh skipped: {e}")
    else:
        print(f"intel.json not found: {INTEL_PATH}")

    print(f"Done. DB demoted: {len(demoted_ids)}")


if __name__ == "__main__":
    main()
