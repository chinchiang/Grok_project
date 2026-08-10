"""Unit tests for exclusive P0–P3 priority rules (R2-2 verification gate)."""

from backend.priority import assign_priority


def test_dual_verified_tw_ransom_is_p0():
    assert (
        assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=True,
            is_tw_industry=True,
            epss=None,
            source_count=2,
            layer_id="L6",
            verification="credible",
        )
        == "P0"
    )


def test_single_source_tw_ransom_stays_p3():
    assert (
        assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=True,
            is_tw_industry=True,
            epss=None,
            source_count=1,
            layer_id="L6",
            force_p3_review=True,
            verification="unverified",
        )
        == "P3"
    )


def test_kev_without_elevation_is_p1():
    assert (
        assign_priority(
            in_kev=True,
            known_ransomware_campaign=False,
            is_ransomware=False,
            is_tw_industry=False,
            epss=None,
            source_count=1,
            layer_id="L1",
            verification="confirmed",
        )
        == "P1"
    )


def test_unverified_tw_ransom_without_force_still_not_p0():
    # Gate is verification, not only force_p3
    assert (
        assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=True,
            is_tw_industry=True,
            epss=None,
            source_count=1,
            layer_id="L6",
            verification="unverified",
        )
        == "P3"
    )


def test_dual_source_tw_ransom_mimics_collector_order():
    """Regression: collectors must resolve verification BEFORE assign_priority.

    If verification is omitted (default unverified), dual-source TW ransomware
    incorrectly lands on P2 (multi-source ransomware) instead of P0.
    """
    dual_verified = True
    is_tw = True
    is_ransom = True
    source_count = 2
    force_p3 = not dual_verified
    verification = "credible" if dual_verified else "unverified"

    # Correct collector order → P0
    assert (
        assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=is_ransom,
            is_tw_industry=is_tw,
            epss=None,
            source_count=source_count,
            layer_id="L6",
            force_p3_review=force_p3,
            verification=verification,
        )
        == "P0"
    )

    # Bug order (forgot verification=) → P2, not P0
    assert (
        assign_priority(
            in_kev=False,
            known_ransomware_campaign=False,
            is_ransomware=is_ransom,
            is_tw_industry=is_tw,
            epss=None,
            source_count=source_count,
            layer_id="L6",
            force_p3_review=force_p3,
        )
        == "P2"
    )
