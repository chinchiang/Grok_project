"""Dual-source ransomware victim matching (2.6).

Matching used to normalise both titles to bare alphanumerics and compare for
equality. Short or generic victim names therefore collided across unrelated
posts, and a collision promoted the item to Credible — which, once the TW
watchlist and ransomware flags were also set, was a path to P0.

A match now needs a shared domain, or the same name *and* the same ransomware
group *and* postings close together in time.
"""

import pytest

from backend.collectors import (
    _group_key,
    _ransom_match,
    _victim_day,
    _victim_domain,
    _victim_name_key,
)


def live(**kw):
    base = {
        "post_title": "Acme Manufacturing",
        "group_name": "lockbit3",
        "discovered": "2026-07-01 10:00:00",
        "website": "",
    }
    base.update(kw)
    return base


def look(**kw):
    base = {
        "post_title": "Acme Manufacturing",
        "group_name": "LockBit 3.0",
        "discovered": "2026-07-03 08:00:00",
        "website": "",
    }
    base.update(kw)
    return base


# --- accepted -----------------------------------------------------------------

def test_same_domain_is_enough():
    why = _ransom_match(
        live(post_title="Totally Different Ltd", website="https://www.acme.com.tw/en"),
        look(post_title="Acme", website="acme.com.tw"),
    )
    assert why and why.startswith("domain=")


def test_name_plus_group_plus_close_dates():
    why = _ransom_match(live(), look())
    assert why and "name+group" in why


def test_legal_suffixes_do_not_block_a_name_match():
    assert _ransom_match(live(post_title="Acme Manufacturing Ltd."), look()) is not None


def test_group_version_differences_still_match():
    assert _group_key("LockBit 3.0") == _group_key("lockbit3") == "lockbit"


# --- rejected -----------------------------------------------------------------

def test_same_name_different_group_is_not_corroboration():
    """Two gangs naming a similarly-named victim is not a second source."""
    assert _ransom_match(live(), look(group_name="alphv")) is None


def test_same_name_same_group_but_months_apart():
    assert _ransom_match(live(), look(discovered="2026-10-20")) is None


def test_missing_dates_do_not_pass():
    assert _ransom_match(live(discovered=""), look(discovered="")) is None


def test_short_generic_name_is_rejected():
    """'ABC' style stubs collided constantly under the old exact-key match."""
    assert _ransom_match(live(post_title="ABC"), look(post_title="ABC")) is None


def test_unrelated_victims_do_not_match():
    assert _ransom_match(live(), look(post_title="Globex Industries")) is None


# --- helpers ------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://www.acme.com.tw/path?x=1", "acme.com.tw"),
        ("ACME.COM", "acme.com"),
        ("www2.example.org", "example.org"),
        ("not a domain", ""),
        ("", ""),
    ],
)
def test_domain_extraction(raw, expected):
    assert _victim_domain(raw) == expected


def test_name_key_strips_legal_suffixes_and_punctuation():
    assert _victim_name_key("Acme Manufacturing, Ltd.") == _victim_name_key(
        "ACME  Manufacturing"
    )


@pytest.mark.parametrize(
    "raw",
    ["2026-07-01", "2026-07-01 10:00:00", "2026-07-01T10:00:00+08:00", "07/01/2026"],
)
def test_day_parsing_handles_tracker_formats(raw):
    assert _victim_day(raw) is not None


def test_day_parsing_returns_none_for_junk():
    assert _victim_day("", "not a date") is None
