"""Cross-source corroboration (2.5).

Collectors each see only their own feed, so everything was written with
source_count=1 and the "≥2 independent sources" rules effectively never fired
for news: five outlets covering one breach stayed five single-source P3s.
"""

import pytest

from backend.aggregate import (
    _independent,
    _jaccard,
    event_cves,
    find_corroborations,
    link_domain,
    title_tokens,
)


def item(iid, source, title, url="https://example.com/a", **kw):
    base = {
        "id": iid,
        "source_name": source,
        "title": title,
        "title_en": title,
        "summary": "",
        "url": url,
        "cve_id": None,
        "tags": [],
    }
    base.update(kw)
    return base


# --- clustering ---------------------------------------------------------------

def test_same_cve_across_outlets_is_corroboration():
    items = [
        item("a", "CISA KEV", "[KEV] CVE-2026-50522 SharePoint RCE",
             url="https://cisa.gov/x", cve_id="CVE-2026-50522"),
        item("b", "The Hacker News", "SharePoint RCE under active exploitation",
             url="https://thehackernews.com/y", cve_id="CVE-2026-50522"),
    ]
    linked = find_corroborations(items)
    assert linked["a"] == {"b"} and linked["b"] == {"a"}


def test_similar_headlines_without_a_cve_still_cluster():
    items = [
        item("a", "BleepingComputer",
             "Critical SharePoint RCE flaw exploited to steal machine keys",
             url="https://bleepingcomputer.com/1"),
        item("b", "The Record",
             "Attackers exploit critical SharePoint RCE flaw to steal machine keys",
             url="https://therecord.media/2"),
    ]
    assert find_corroborations(items).get("a") == {"b"}


def test_unrelated_stories_do_not_cluster():
    items = [
        item("a", "BleepingComputer", "Fortinet VPN appliances targeted by new botnet",
             url="https://bleepingcomputer.com/1"),
        item("b", "The Record", "Ransomware gang leaks hospital records in Brazil",
             url="https://therecord.media/2"),
    ]
    assert find_corroborations(items) == {}


def test_generic_security_words_alone_do_not_cluster():
    """Headlines made only of stopword vocabulary must not collapse together."""
    items = [
        item("a", "Feed A", "New security update released for the vulnerability",
             url="https://a.com/1"),
        item("b", "Feed B", "Security advisory reports a new data issue",
             url="https://b.com/2"),
    ]
    assert find_corroborations(items) == {}


# --- independence guards ------------------------------------------------------

def test_same_source_is_not_its_own_corroboration():
    a = item("a", "The Hacker News", "SharePoint RCE exploited", url="https://thn.com/1")
    b = item("b", "The Hacker News", "SharePoint RCE exploited", url="https://thn.com/2")
    assert _independent(a, b) is False


def test_same_domain_is_not_corroboration():
    """A site feed and its own Google News mirror are one report, not two."""
    a = item("a", "The Hacker News", "SharePoint RCE exploited",
             url="https://thehackernews.com/post")
    b = item("b", "THN ICS", "SharePoint RCE exploited",
             url="https://www.thehackernews.com/post")
    assert _independent(a, b) is False


def test_mirrored_article_does_not_inflate_evidence():
    items = [
        item("a", "The Hacker News", "SharePoint RCE actively exploited now",
             url="https://thehackernews.com/p", cve_id="CVE-2026-1"),
        item("b", "THN ICS", "SharePoint RCE actively exploited now",
             url="https://thehackernews.com/p", cve_id="CVE-2026-1"),
    ]
    assert find_corroborations(items) == {}


# --- helpers ------------------------------------------------------------------

def test_ui_prefixes_are_stripped_before_comparing():
    a = title_tokens("🪟 微軟相關｜Critical SharePoint RCE under exploitation")
    b = title_tokens("Critical SharePoint RCE under exploitation")
    assert _jaccard(a, b) == 1.0


def test_cve_is_found_in_body_as_well_as_field():
    got = event_cves({"title": "flaw", "summary": "tracked as cve-2026-50522"})
    assert got == {"CVE-2026-50522"}


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://www.example.com/a/b", "example.com"),
        ("http://example.com", "example.com"),
        ("", ""),
    ],
)
def test_link_domain(url, expected):
    assert link_domain(url) == expected


def test_cjk_headlines_cluster_via_bigrams():
    items = [
        item("a", "TWCERT", "台灣製造業遭勒索軟體攻擊導致產線停擺", url="https://twcert.org.tw/1"),
        item("b", "iThome", "勒索軟體攻擊台灣製造業產線停擺", url="https://ithome.com.tw/2"),
    ]
    assert find_corroborations(items).get("a") == {"b"}
