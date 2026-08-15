"""Tiny YAML subset loader so the module has no PyYAML dependency.

Supports the config files in this package: mappings, lists of mappings,
scalars (str / int / float / bool / null), and nested lists of scalars.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_yaml(path: Path | str) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return parse_simple_yaml(text)


def parse_simple_yaml(text: str) -> Any:
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if (not raw.strip()) or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))
    value, _ = _parse_block(lines, 0, 0)
    return value


def _parse_block(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[Any, int]:
    if i >= len(lines):
        return {}, i
    _, content = lines[i]
    if content.startswith("- "):
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_map(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[dict[str, Any], int]:
    out: dict[str, Any] = {}
    while i < len(lines):
        ind, content = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise ValueError(f"unexpected indent at {content!r}")
        if content.startswith("- "):
            break
        if ":" not in content:
            raise ValueError(f"expected key: value, got {content!r}")
        key, rest = content.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        i += 1
        if rest:
            out[key] = _parse_scalar(rest)
            continue
        if i < len(lines) and lines[i][0] > indent:
            child, i = _parse_block(lines, i, lines[i][0])
            out[key] = child
        else:
            out[key] = None
    return out, i


def _parse_list(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[list[Any], int]:
    out: list[Any] = []
    while i < len(lines):
        ind, content = lines[i]
        if ind < indent:
            break
        if not content.startswith("- "):
            break
        rest = content[2:].strip()
        i += 1
        if rest and ":" in rest and not rest.startswith("[") and not rest.startswith("{") and not (
            rest.startswith('"') or rest.startswith("'")
        ):
            key, val = rest.split(":", 1)
            item: dict[str, Any] = {key.strip(): _parse_scalar(val.strip()) if val.strip() else None}
            if i < len(lines) and lines[i][0] > indent:
                extra, i = _parse_map(lines, i, lines[i][0])
                if item[key.strip()] is None and key.strip() in extra:
                    pass
                item.update(extra)
            out.append(item)
        elif rest:
            out.append(_parse_scalar(rest))
        else:
            if i < len(lines) and lines[i][0] > indent:
                child, i = _parse_block(lines, i, lines[i][0])
                out.append(child)
            else:
                out.append(None)
    return out, i


def _parse_scalar(raw: str) -> Any:
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(p.strip()) for p in _split_flow(inner)]
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    low = raw.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", "none"):
        return None
    try:
        if "." in raw:
            return float(raw)
        return int(raw)
    except ValueError:
        return raw


def _split_flow(inner: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_q = False
    q = ""
    for ch in inner:
        if in_q:
            buf.append(ch)
            if ch == q:
                in_q = False
            continue
        if ch in ('"', "'"):
            in_q = True
            q = ch
            buf.append(ch)
            continue
        if ch == ",":
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts
