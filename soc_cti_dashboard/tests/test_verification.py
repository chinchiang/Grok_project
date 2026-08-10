"""Source-reliability grading tests (R3-1).

L2/L7 mix authorities (CISA, PSIRT, Dragos) with trade press (Dark Reading,
THN, SecurityWeek). Before R3-1 the layer alone granted single-source
"credible", so one ICS news article that merely mentioned a watchlist company
plus "ransomware" passed the TW+ransomware P0 gate. These tests lock in that
only authoritative classes are credible on a single source.
"""

import pytest

from backend.config import (
    INTEL_FEEDS,
    SOURCE_CLASS_COMMUNITY,
    SOURCE_CLASS_MEDIA,
    SOURCE_CLASS_OFFICIAL_GOV,
    SOURCE_CLASS_OSINT,
    SOURCE_CLASS_RESEARCH,
    SOURCE_CLASS_VENDOR_PSIRT,
    derive_source_class,
)
from backend.priority import assign_priority, assign_verification


# --- single-source credibility by class -------------------------------------

@pytest.mark.parametrize(
    "source_class,expected",
    [
        (SOURCE_CLASS_OFFICIAL_GOV, "credible"),
        (SOURCE_CLASS_VENDOR_PSIRT, "credible"),
        (SOURCE_CLASS_RESEARCH, "credible"),
        (SOURCE_CLASS_MEDIA, "unverified"),
        (SOURCE_CLASS_COMMUNITY, "unverified"),
        (SOURCE_CLASS_OSINT, "unverified"),
    ],
)
def test_single_source_credibility_depends_on_class(source_class, expected):
    verification, _ = assign_verification(
        in_kev=False,
        layer_id="L7",
        source_count=1,
        is_darkweb_indirect=False,
        source_class=source_class,
    )
    assert verification == expected


def test_two_media_sources_are_credible():
    """Corroboration is the escape hatch: 2 independent outlets → credible."""
    verification, admiralty = assign_verification(
        in_kev=False,
        layer_id="L7",
        source_count=2,
        is_darkweb_indirect=False,
        source_class=SOURCE_CLASS_MEDIA,
    )
    assert (verification, admiralty) == ("credible", "B2")


def test_default_class_is_conservative():
    """An unclassified source must not be credible on one report."""
    verification, _ = assign_verification(
        in_kev=False, layer_id="L2", source_count=1, is_darkweb_indirect=False
    )
    assert verification == "unverified"


def test_kev_and_l1_unaffected_by_class():
    assert assign_verification(
        in_kev=True, layer_id="L1", source_count=1, is_darkweb_indirect=False,
        source_class=SOURCE_CLASS_MEDIA,
    ) == ("confirmed", "A1")
    assert assign_verification(
        in_kev=False, layer_id="L1", source_count=1, is_darkweb_indirect=False,
        source_class=SOURCE_CLASS_MEDIA,
    ) == ("confirmed", "A2")


# --- the end-to-end regression this change exists for -----------------------

def test_single_media_article_cannot_reach_p0():
    """R3-1 regression: one Dark Reading ICS story naming a TW watchlist
    company + ransomware must stay in the P3 review queue, not become P0."""
    verification, _ = assign_verification(
        in_kev=False,
        layer_id="L7",
        source_count=1,
        is_darkweb_indirect=False,
        source_class=derive_source_class("darkreading_ics_gnews"),
    )
    assert verification == "unverified"
    assert (
        assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=True,
            is_tw_industry=True,
            epss=None,
            source_count=1,
            layer_id="L7",
            verification=verification,
        )
        == "P3"
    )


def test_official_gov_advisory_still_reaches_p0():
    """The gate must not over-correct: a CISA/TWCERT advisory naming a TW
    watchlist company + ransomware is exactly what P0 is for."""
    verification, _ = assign_verification(
        in_kev=False,
        layer_id="L2",
        source_count=1,
        is_darkweb_indirect=False,
        source_class=derive_source_class("twcert_news_rss"),
    )
    assert verification == "credible"
    assert (
        assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=True,
            is_tw_industry=True,
            epss=None,
            source_count=1,
            layer_id="L2",
            verification=verification,
        )
        == "P0"
    )


# --- registry / derivation --------------------------------------------------

def test_derive_prefers_registry_then_tags_then_default():
    assert derive_source_class("fortinet_psirt") == SOURCE_CLASS_VENDOR_PSIRT
    # registry wins over tags
    assert (
        derive_source_class("darkreading_ics_gnews", ["official-gov"])
        == SOURCE_CLASS_MEDIA
    )
    # unregistered source falls back to tags
    assert derive_source_class("some_new_feed", ["ot-gov"]) == SOURCE_CLASS_OFFICIAL_GOV
    assert derive_source_class("some_new_feed", ["ot-media"]) == SOURCE_CLASS_MEDIA
    # nothing to go on → conservative
    assert derive_source_class("some_new_feed") == SOURCE_CLASS_MEDIA


def test_every_l2_l7_feed_is_explicitly_classified():
    """L2/L7 are the only layers where class changes the outcome, so every feed
    there must be in the registry rather than silently defaulting to media."""
    from backend.config import SOURCE_CLASS_REGISTRY

    unclassified = [
        f["source_id"]
        for f in INTEL_FEEDS
        if f.get("layer_id") in ("L2", "L7")
        and not f.get("source_class")
        and f["source_id"] not in SOURCE_CLASS_REGISTRY
    ]
    assert unclassified == [], f"unclassified L2/L7 feeds: {unclassified}"
