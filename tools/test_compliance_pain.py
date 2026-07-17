# tools/test_compliance_pain.py
import pytest
from compliance_pain import (
    CIS_GCP_20_EXCEPTIONS, asset_band, customer_effect, deadline,
    finding_grade, is_exposure_class, pain_level, remediation_column,
)


@pytest.mark.parametrize("cr,ir,ar,expected", [
    ("H", "H", "H", "High"), ("H", "H", "M", "High"),
    ("H", "H", "L", "Medium"),          # a single Low demotes two Highs
    ("L", "M", "H", "Medium"), ("L", "L", "H", "Medium"),
    ("L", "L", "M", "Low"), ("L", "L", "L", "Low"),
    (None, None, None, "High"),         # fail-safe HHH
])
def test_asset_band(cr, ir, ar, expected):
    assert asset_band(cr, ir, ar) == expected


@pytest.mark.parametrize("severity,governed,expected", [
    ("high", True, "Major"), ("critical", True, "Major"),
    ("medium", True, "Moderate"), ("low", True, "Minor"),
    (None, True, "Moderate"),           # unscored Fail -> Moderate prior
    ("high", False, "Moderate"),        # non-governed severity is unscored
    ("low", False, "Moderate"),         # cannot self-reduce either
])
def test_finding_grade(severity, governed, expected):
    assert finding_grade(severity, governed) == expected


# T01-T12: PAIN fixtures (grade, band, multi_agency -> N-level)
@pytest.mark.parametrize("grade,band,multi,expected", [
    ("Major", "High", True, 5),      # T01
    ("Major", "High", False, 4),     # T02
    ("Major", "Medium", True, 4),    # T03
    ("Major", "Medium", False, 3),   # T04
    ("Major", "Low", True, 2),       # T05 Narrow: no multi promotion
    ("Moderate", "High", True, 2),   # T06 raw CIS Fail on crown jewel
    ("Moderate", "Medium", False, 2),# T07
    ("Moderate", "Low", True, 1),    # T08
    ("Minor", "High", True, 1),      # T09 CAT III floor
    ("Major", "High", None, 5),      # T11 unknown scope -> multi
])
def test_pain(grade, band, multi, expected):
    assert pain_level(customer_effect(grade, band), multi) == expected


def test_moderate_to_minor_moves_at_most_one_band():
    order = ["Minimal", "Narrow", "Disruptive", "Debilitating"]
    for band in ("High", "Medium", "Low"):
        step = (order.index(customer_effect("Moderate", band))
                - order.index(customer_effect("Minor", band)))
        assert step in (0, 1)
        if customer_effect("Moderate", band) != "Minimal":
            assert step == 1


# C01-C09: column fixtures
def _cloud(category, **kw):
    return {"family": "cloud", "category": category, **kw}


@pytest.mark.parametrize("finding,expected", [
    (_cloud("PUBLIC_BUCKET_ACL"), "LEV+IRV"),                       # C01
    (_cloud("USER_MANAGED_SERVICE_ACCOUNT_KEY"), "NLEV"),           # C02
    (_cloud("SSL_NOT_ENFORCED", attached_resource_public=True),
     "LEV+IRV"),                                                    # C03
    (_cloud("SSL_NOT_ENFORCED", attached_resource_public=False),
     "NLEV"),                                                       # C04
    ({"family": "host-os", "admin_plane_open": True}, "LEV+IRV"),   # C05
    ({"family": "host-os", "admin_plane_open": False}, "NLEV"),     # C06
    (_cloud("USER_MANAGED_SERVICE_ACCOUNT_KEY", override="LEV+NIRV"),
     "LEV+NIRV"),                                                   # C07
    (_cloud("OPENSSH_CONFIG"), "NLEV"),                             # C08 token guard
    ({"family": "host-os"}, "LEV+IRV"),                             # C09 unknown -> open
])
def test_column(finding, expected):
    assert remediation_column(finding, CIS_GCP_20_EXCEPTIONS) == expected


def test_keyword_rule_matches_all_gcp_exposure_categories():
    for cat in ("KMS_PUBLIC_KEY", "OPEN_SSH_PORT", "OPEN_RDP_PORT",
                "PUBLIC_IP_ADDRESS", "PUBLIC_BUCKET_ACL",
                "PUBLIC_SQL_INSTANCE", "SQL_PUBLIC_IP", "PUBLIC_DATASET"):
        assert is_exposure_class(cat, CIS_GCP_20_EXCEPTIONS)


@pytest.mark.parametrize("cls,pain,col,expected", [
    ("D", 2, "LEV+IRV", 24),   # the anchor case: CAT II/Medium/public
    ("D", 5, "LEV+IRV", 0.5),
    ("D", 2, "NLEV", 192),
    ("C", 3, "NLEV", 128),
    ("AB", 2, "LEV+IRV", 96),
    ("D", 1, "LEV+IRV", None), # N1: no deadline
])
def test_deadline(cls, pain, col, expected):
    assert deadline(cls, pain, col) == expected


def test_exercisability_never_changes_pain():
    p = pain_level(customer_effect("Moderate", "Medium"), True)
    for col in ("LEV+IRV", "LEV+NIRV", "NLEV"):
        assert p == 2 and deadline("D", p, col) is not None
