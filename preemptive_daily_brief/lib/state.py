"""Dedup fingerprints: CVE id, URL hash, title fingerprint, EPSS snapshot."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import REPORTED_PATH


def _title_fp(title: str) -> str:
    norm = " ".join((title or "").lower().split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def _url_hash(url: str) -> str:
    return hashlib.sha256((url or "").strip().encode("utf-8")).hexdigest()[:16]


class ReportedState:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or REPORTED_PATH
        self.data: dict[str, Any] = {"items": {}, "updated_at": None}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self.data = {"items": {}, "updated_at": None}
        self.data.setdefault("items", {})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.path.write_text(
            json.dumps(self.data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _keys_for(self, item: dict[str, Any]) -> list[str]:
        keys: list[str] = []
        if item.get("cve_id"):
            keys.append(f"cve:{item['cve_id']}")
        if item.get("url"):
            keys.append(f"url:{_url_hash(str(item['url']))}")
        if item.get("title"):
            keys.append(f"title:{_title_fp(str(item['title']))}")
        if item.get("id"):
            keys.append(f"id:{item['id']}")
        return keys

    def lookup(self, item: dict[str, Any]) -> dict[str, Any] | None:
        store = self.data.get("items") or {}
        for k in self._keys_for(item):
            if k in store:
                return store[k]
        return None

    def is_duplicate(self, item: dict[str, Any]) -> bool:
        return self.lookup(item) is not None

    def remember(self, item: dict[str, Any]) -> None:
        rec = {
            "cve_id": item.get("cve_id"),
            "url": item.get("url"),
            "title": item.get("title"),
            "in_kev": bool(item.get("in_kev")),
            "epss": item.get("epss"),
            "poc": bool(item.get("poc")),
            "mass_exploitation": bool(item.get("mass_exploitation")),
            "brief_priority": item.get("brief_priority"),
            "seen_at": datetime.now(timezone.utc).isoformat(),
        }
        store = self.data.setdefault("items", {})
        for k in self._keys_for(item):
            store[k] = rec

    def remember_all(self, items: list[dict[str, Any]]) -> None:
        for it in items:
            self.remember(it)
