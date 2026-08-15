"""Shared HTTP helper — stdlib only; one source failing never aborts the run."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from preemptive_daily_brief.lib.paths import CACHE_DIR

UA = "GrokProject-PreemptiveBrief/1.0 (defensive-research)"


def fetch_bytes(url: str, *, timeout: int = 25, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "application/json, application/xml, text/xml, */*", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_json(url: str, **kw: Any) -> Any:
    raw = fetch_bytes(url, **kw)
    return json.loads(raw.decode("utf-8", errors="replace"))


def fetch_text(url: str, **kw: Any) -> str:
    return fetch_bytes(url, **kw).decode("utf-8", errors="replace")


def try_urls(urls: list[str], *, as_json: bool = True, cache_name: str | None = None) -> tuple[Any | None, str | None, str | None]:
    """Return (payload, used_url, error). First success wins."""
    last_err = None
    for url in urls:
        try:
            payload = fetch_json(url) if as_json else fetch_text(url)
            if cache_name:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                suffix = ".json" if as_json else ".txt"
                path = CACHE_DIR / f"{cache_name}{suffix}"
                if as_json:
                    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                else:
                    path.write_text(str(payload), encoding="utf-8")
            return payload, url, None
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            time.sleep(0.4)
    return None, None, last_err
