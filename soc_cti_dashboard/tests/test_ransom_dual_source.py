"""Dual-source ransomware victim matching (T5/T6 agent spec).

Dual-confirmed when:
  A. shared domain, or
  B. name similarity ≥ 0.85 AND group similarity ≥ 0.90 (or alias)
     AND discovery-date gap ≤ 7 days (hard cap 14).

Single-source / X / media-indirect must stay unverified + P3.
"""

import pytest

from backend.collectors import (
    _group_key,
    _ransom_match,
    _victim_day,
    _victim_domain,
    _victim_name_key,
)
from backend.collectors.ransom import (
    DEFAULT_DAY_GAP,
    GROUP_SIM_THRESHOLD,
    NAME_SIM_THRESHOLD,
    _similarity,
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
    assert why and "name=" in why and "group=" in why


def test_legal_suffixes_do_not_block_a_name_match():
    assert _ransom_match(live(post_title="Acme Manufacturing Ltd."), look()) is not None


def test_tw_legal_suffix_stripped():
    assert _victim_name_key("鴻海精密工業股份有限公司") == _victim_name_key("鴻海精密工業")


def test_group_version_differences_still_match():
    assert _group_key("LockBit 3.0") == _group_key("lockbit3") == "lockbit"


def test_group_alias_clop():
    assert _group_key("Cl0p") == _group_key("clop") == "clop"


def test_name_similarity_threshold_allows_minor_typo():
    """≥85% similarity still dual-confirms (spec §一)."""
    # "Acme Manufacturing" vs "Acme Manufacturings" is high similarity
    why = _ransom_match(
        live(post_title="Acme Manufacturing"),
        look(post_title="Acme Manufacturings"),
    )
    assert why is not None
    assert _similarity(
        _victim_name_key("Acme Manufacturing"),
        _victim_name_key("Acme Manufacturings"),
    ) >= NAME_SIM_THRESHOLD


def test_default_window_is_seven_days():
    assert DEFAULT_DAY_GAP == 7
    # 6 days apart → pass
    assert (
        _ransom_match(
            live(discovered="2026-07-01"),
            look(discovered="2026-07-07"),
        )
        is not None
    )
    # 8 days apart → fail under default window
    assert (
        _ransom_match(
            live(discovered="2026-07-01"),
            look(discovered="2026-07-09"),
        )
        is None
    )


# --- rejected -----------------------------------------------------------------

def test_same_name_different_group_is_not_corroboration():
    """Two gangs naming a similarly-named victim is not a second source."""
    assert _ransom_match(live(), look(group_name="alphv")) is None


def test_same_name_same_group_but_months_apart():
    assert _ransom_match(live(), look(discovered="2026-10-20")) is None


def test_missing_dates_do_not_pass():
    assert _ransom_match(live(discovered=""), look(discovered="")) is None


def test_short_generic_name_is_rejected():
    """'ABC' style stubs must not dual-confirm on name path."""
    assert _ransom_match(live(post_title="ABC"), look(post_title="ABC")) is None


def test_unrelated_victims_do_not_match():
    assert _ransom_match(live(), look(post_title="Globex Industries")) is None


def test_low_name_similarity_rejected():
    """Far-apart names must not pass the 85% gate."""
    why = _ransom_match(
        live(post_title="Acme Manufacturing"),
        look(post_title="Globex Trading Partners"),
    )
    assert why is None


def test_group_sim_threshold_constant():
    assert GROUP_SIM_THRESHOLD == 0.90
    assert NAME_SIM_THRESHOLD == 0.85


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


# --- CJK legal forms ----------------------------------------------------------

@pytest.mark.parametrize(
    "full,bare",
    [
        ("鴻海精密工業股份有限公司", "鴻海精密工業"),
        ("台積電股份有限公司", "台積電"),
        ("緯創資通有限公司", "緯創資通"),
        ("某某控股集團", "某某"),
    ],
)
def test_cjk_legal_forms_are_stripped(full, bare):
    """CJK names have no whitespace, so the token filter never sees a glued-on
    legal form — they are suffix-stripped instead."""
    assert _victim_name_key(full) == _victim_name_key(bare)


@pytest.mark.parametrize("name", ["台灣大哥大", "中國信託商業銀行", "公司田溪"])
def test_cjk_stripping_does_not_eat_the_name(name):
    """Only true legal forms go. A geographic or descriptive word is part of the
    name, and removing it would merge unrelated victims."""
    assert _victim_name_key(name) == name


def test_cjk_victims_dual_confirm_across_trackers():
    """The end-to-end case: one tracker lists the full legal name, the other the
    short form — previously they never matched."""
    assert (
        _ransom_match(
            live(post_title="鴻海精密工業股份有限公司"),
            look(post_title="鴻海精密工業"),
        )
        is not None
    )
