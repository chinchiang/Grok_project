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
