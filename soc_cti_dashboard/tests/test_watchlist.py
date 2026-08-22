"""Watchlist alias matching (2.2).

Aliases used to be plain substrings, which produced systematic false
positives on real intel — most damagingly "gigabyte" inside the
"we have hundreds of gigabytes of your files" boilerplate that every
leak-site post carries, tagging ransomware items as Taiwan electronics and
feeding the TW+ransomware P0 path.
"""

import pytest

from backend.priority import (
    match_finance_entities,
    match_microsoft_entities,
    match_tw_entities,
)


def keys(hits):
    return {h["key"] for h in hits}


# --- false positives that used to fire ---------------------------------------

@pytest.mark.parametrize(
    "text,label",
    [
        ("we have hundreds of gigabytes of your files", "leak-site boilerplate"),
        ("the archive spans 235 gigabytes of documents", "unit word"),
        ("packet tracer output attached", "acer inside tracer"),
        ("stack tracer crash in the kernel", "acer inside tracer"),
        ("database corruption in the storage layer", "ase inside database"),
        ("cve-2023-32315 exploited in the wild", "wistron ticker in CVE id"),
        ("cve-2022-23303 and cve-2022-23304", "tsmc ticker in CVE id"),
        ("record ids 37963, 391144938, 45090", "pegatron ticker in a number"),
        ("2026-07-20t19:02:03.782357+00:00", "asus ticker in a timestamp"),
        ("影響筆數：2303416", "umc/novatek ticker in a record count"),
        ("Windows Installer MSI package failed", "msi installer homonym"),
        ("ASX listed miners rally on metals", "australian securities exchange"),
    ],
)
def test_no_false_positive(text, label):
    assert keys(match_tw_entities(text.lower())) == set(), label


def test_kyowa_is_not_outlook_web_access():
    """'owa ' used to match the company name 'Kyowa Singapore'."""
    assert "exchange" not in keys(
        match_microsoft_entities("kyowa singapore pte ltd claimed by morpheus")
    )


# --- true positives that must survive ----------------------------------------

@pytest.mark.parametrize(
    "text,expected",
    [
        ("Acer confirms breach of after-sales systems", "acer"),
        ("Quanta Computer hit by ransomware", "quanta"),
        ("台積電傳出供應鏈事件", "tsmc"),
        ("廣達遭勒索軟體攻擊", "quanta"),
        ("Micro-Star released a BIOS fix", "msi"),
        ("微星發布 BIOS 更新", "msi"),
        ("MSI, Gigabyte and Asus issued advisories", "gigabyte"),
        ("Lite-On disclosed an incident", "liteon"),
    ],
)
def test_true_positive_survives(text, expected):
    assert expected in keys(match_tw_entities(text.lower()))


@pytest.mark.parametrize(
    "text",
    [
        "TSMC (2330) reported a supplier incident",
        "2330.TW dropped three percent",
        "TWSE 2330 halted trading",
        "股票代號 2330 公告重大訊息",
    ],
)
def test_ticker_matches_only_with_market_context(text):
    assert "tsmc" in keys(match_tw_entities(text.lower()))


# --- alias modes -------------------------------------------------------------

def test_hyphen_alias_is_a_prefix():
    """Microsoft actor names are enumerated: storm-1175, storm-0558…"""
    assert "threat_intel" in keys(
        match_microsoft_entities("campaign storm-1175 targets vpn appliances")
    )


def test_star_alias_tolerates_inflection():
    assert "threat_intel" in keys(
        match_microsoft_entities("threat actors rely on malware-free intrusions")
    )
    assert "threat_intel" in keys(
        match_microsoft_entities("a threat actor was observed")
    )


def test_inflection_is_opt_in_not_global():
    """'gigabytes' must stay unmatched even though 'threat actors' matches."""
    assert keys(match_tw_entities("hundreds of gigabytes")) == set()


def test_finance_matching_unchanged_on_real_phrases():
    assert keys(match_finance_entities("bank of taiwan outage")) == {"bot", "banking"}
    assert keys(match_finance_entities("swift network compromise")) == {"payments"}
    # leak-dump wording is not a finance-sector signal
    assert keys(match_finance_entities("financial documents were leaked")) == set()
