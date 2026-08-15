"""Resolved paths for the preemptive_daily_brief package."""

from __future__ import annotations

from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = PKG_DIR / "config"
STATE_DIR = PKG_DIR / "state"
OUTPUT_DIR = PKG_DIR / "output"
CACHE_DIR = PKG_DIR / "cache"
REPORTED_PATH = STATE_DIR / "reported.json"
