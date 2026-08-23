"""Hashed lockfiles must stay the thing CI installs (R4-20).

A ranged requirements.txt plus `pip install pytest` meant each harvest
resolved to whatever PyPI served that morning, including a compromised
wheel still inside the declared range. These checks fail if the lock
loses its hashes or the workflow goes back to an unpinned extra.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
REQ = ROOT / "requirements.txt"
DEV = ROOT / "requirements-dev.txt"
WF = REPO / ".github/workflows/deploy-cti-dashboard.yml"


def _requirement_names(text: str) -> list[str]:
    names = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        if line.startswith("-r ") or line.startswith("-c "):
            continue
        name = line.split("\\")[0].split(";")[0].strip()
        if name:
            names.append(name)
    return names


def test_runtime_lockfile_pins_and_hashes_every_package():
    text = REQ.read_text(encoding="utf-8")
    names = _requirement_names(text)
    assert names, "requirements.txt is empty"
    assert all("==" in n for n in names), names
    assert text.count("--hash=sha256:") >= len(names)
    assert "fastapi==" in text
    assert "httpx==" in text


def test_dev_lockfile_pins_pytest_with_hashes():
    text = DEV.read_text(encoding="utf-8")
    names = _requirement_names(text)
    assert any(n.startswith("pytest==") for n in names)
    assert any(n.startswith("pytest-asyncio==") for n in names)
    assert text.count("--hash=sha256:") >= len(names)


def test_ci_installs_with_require_hashes_and_no_unpinned_pytest():
    text = WF.read_text(encoding="utf-8")
    assert "--require-hashes" in text
    assert "requirements-dev.txt" in text
    assert "pip install -q pytest" not in text
    assert "pip install pytest" not in text
