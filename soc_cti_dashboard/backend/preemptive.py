"""Dashboard adapter: harvested intel → preemptive daily-brief payload."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Repo root so `preemptive_daily_brief` imports when PYTHONPATH is soc_cti_dashboard/
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from preemptive_daily_brief.lib.compose import compose_from_intel
from preemptive_daily_brief.lib.state import ReportedState


def build_preemptive_brief(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure function used by the API and by export_static.py."""
    state_path = _REPO_ROOT / "preemptive_daily_brief" / "state" / "reported.json"
    reported = ReportedState(state_path) if state_path.exists() else None
    return compose_from_intel(items, reported=reported)
