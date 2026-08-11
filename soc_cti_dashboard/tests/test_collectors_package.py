"""Guards for the collectors package split (4.3).

collectors.py was a single 3.8k-line module. It is now one file per source
family, which only stays safe if the public surface and the import wiring keep
working — the two things a split silently breaks.
"""

import ast
import importlib
import pathlib

import pytest

import backend.collectors as collectors

PKG_DIR = pathlib.Path(collectors.__file__).parent

# Everything the single module used to expose, including the private helpers
# imported directly by other tests.
PUBLIC_SURFACE = [
    "_id", "_client", "_mark", "_strip_html", "_parse_rss_entries",
    "collect_rss_layer", "collect_registered_intel_feeds",
    "collect_cisa_kev", "_fetch_epss_batch", "collect_epss_top_scores",
    "collect_cisa_ics", "_collect_cisa_ics_from_github_csv",
    "_resolve_easm_targets", "_upsert_easm_finding",
    "collect_shodan_easm", "collect_censys_easm",
    "collect_hibp_breaches",
    "collect_threatfox", "collect_otx_pulses",
    "_victim_domain", "_victim_name_key", "_group_key", "_victim_day",
    "_ransom_match", "_upsert_ransom_victim_item",
    "collect_ransomware_live", "collect_ransomlook",
    "dual_source_ransom_trackers",
    "collect_x_osint_accounts", "collect_x_darkweb_accounts",
    "dual_source_darkweb_verify",
    "run_full_harvest",
]


@pytest.mark.parametrize("name", PUBLIC_SURFACE)
def test_every_name_the_old_module_exposed_still_resolves(name):
    assert callable(getattr(collectors, name)), f"{name} missing from the package"


def test_no_name_is_defined_in_two_modules():
    """A duplicated definition means one copy silently wins on import."""
    seen: dict[str, str] = {}
    dupes = []
    for path in sorted(PKG_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in seen:
                    dupes.append(f"{node.name} in {seen[node.name]} and {path.name}")
                seen[node.name] = path.name
    assert dupes == []


def test_every_submodule_imports_cleanly():
    """Catches a relative import left at the wrong depth after the move."""
    for path in sorted(PKG_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        importlib.import_module(f"backend.collectors.{path.stem}")


def test_function_local_relative_imports_target_the_parent_package():
    """run_full_harvest imports aggregate/database inside the function body, so
    the AST is unchanged by the move while the meaning is not: at package depth
    `from .database` resolves to backend.collectors.database and fails only at
    runtime, inside a try/except that would have logged it and moved on."""
    offenders = []
    for path in sorted(PKG_DIR.glob("*.py")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if not line.startswith((" ", "\t")):
                continue  # module level is checked by the import test above
            if stripped.startswith("from .") and not stripped.startswith("from .."):
                target = stripped.split()[1].lstrip(".")
                # a sibling module is fine; a parent-package module is not
                if not (PKG_DIR / f"{target}.py").exists():
                    offenders.append(f"{path.name}:{lineno} {stripped}")
    assert offenders == [], f"relative imports at the wrong depth: {offenders}"


def test_harvest_reaches_the_parent_package():
    """The concrete case the guard above exists for."""
    from backend.collectors import harvest

    src = pathlib.Path(harvest.__file__).read_text()
    assert "from ..aggregate import" in src
    assert "from ..database import" in src


# Tripwire for the split being undone, not a style rule: the original module was
# 3.8k lines across 32 functions. A module legitimately grows when its source
# family gains logic, so the bar is set where a file stops being one family's
# worth of code and starts being a monolith again.
MONOLITH_LINES = 1200


def test_package_is_not_one_big_module_again():
    sizes = {p.name: len(p.read_text().splitlines()) for p in PKG_DIR.glob("*.py")}
    oversized = {n: s for n, s in sizes.items() if s > MONOLITH_LINES}
    assert oversized == {}, f"modules growing back toward a monolith: {oversized}"


def test_no_module_holds_most_of_the_package():
    """Size alone can be misleading, so also check the shape: if one file holds
    over half the package, the split has effectively been reversed."""
    sizes = {p.name: len(p.read_text().splitlines()) for p in PKG_DIR.glob("*.py")}
    total = sum(sizes.values())
    dominant = {n: s for n, s in sizes.items() if total and s / total > 0.5}
    assert dominant == {}, f"one module dominates the package: {dominant} of {total}"
