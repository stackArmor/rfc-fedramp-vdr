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


@pytest.mark.parametrize("severity,governed,unscored,expected", [
    ("high", True, False, "Major"), ("critical", True, False, "Major"),
    ("medium", True, False, "Moderate"), ("low", True, False, "Minor"),
    (None, True, True, "Moderate"),    # CIS: structurally unscored -> prior
    (None, True, False, "Major"),      # stripped severity fails loud (F-1)
    ("", True, False, "Major"),        # blank from scored source fails loud
    ("severity_unspecified", True, False, "Major"),  # unknown label fails loud (G-8)
    ("high", False, False, "Moderate"),  # non-governed severity is unscored
    ("low", False, False, "Moderate"),   # cannot self-reduce either
])
def test_finding_grade(severity, governed, unscored, expected):
    assert finding_grade(severity, governed, structurally_unscored=unscored) == expected


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
    (_cloud("OPENSSH_CONFIG"), "LEV+IRV"),  # C08 not in vocabulary -> unreviewed fails loud (F-2)
    ({"family": "host-os"}, "LEV+IRV"),                             # C09 unknown -> open
])
def test_column(finding, expected):
    assert remediation_column(finding, CIS_GCP_20_EXCEPTIONS) == expected


def test_token_guard_rejects_substring_matches():
    exc = {"add": set(), "remove": set(), "surface": set()}
    assert not is_exposure_class("OPENSSH_CONFIG", exc)


def test_keyword_rule_matches_pure_exposure_categories():
    for cat in ("KMS_PUBLIC_KEY", "OPEN_SSH_PORT", "OPEN_RDP_PORT",
                "PUBLIC_BUCKET_ACL", "PUBLIC_SQL_INSTANCE", "PUBLIC_DATASET"):
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


def test_api_key_findings_default_exercisable_surface():
    # C-1: client-embedded API keys are public by design; unknown
    # distribution fails safe to the fast clock, evidence overrides down.
    f = _cloud("API_KEY_APPS_UNRESTRICTED")
    assert remediation_column(f, CIS_GCP_20_EXCEPTIONS) == "LEV+IRV"
    f = _cloud("API_KEY_APPS_UNRESTRICTED", attached_resource_public=False)
    assert remediation_column(f, CIS_GCP_20_EXCEPTIONS) == "NLEV"


def test_normalization_handles_non_gcp_category_grammars():
    # O-1: AWS Config hyphen-lowercase IDs must tokenize
    assert is_exposure_class("s3-bucket-public-read-prohibited",
                             {"add": set(), "remove": set(), "surface": set()})
    assert not is_exposure_class("restricted-ssh",
                                 {"add": set(), "remove": set(), "surface": set()})


def test_novel_category_outside_vocabulary_fails_loud():
    # F-2/O-6: unreviewed categories ride the fast clock until adjudicated
    f = _cloud("ALLOYDB_PUBLICLY_ACCESSIBLE")
    assert remediation_column(f, CIS_GCP_20_EXCEPTIONS) == "LEV+IRV"


def test_dnssec_is_ops_plane_not_surface():
    # O-11: integrity hardening fails the unauthenticated-exercise test
    f = _cloud("DNSSEC_DISABLED")
    assert remediation_column(f, CIS_GCP_20_EXCEPTIONS) == "NLEV"


def test_dropped_tokens_no_longer_classify():
    # O-2/C-7: EXTERNAL and UNRESTRICTED are collision-prone; carried by
    # add-entries instead of auto-match
    exc = {"add": set(), "remove": set(), "surface": set()}
    assert not is_exposure_class("SQL_EXTERNAL_SCRIPTS_ENABLED", exc)


def test_unrecognized_family_and_missing_category_fail_loud():
    # F-7
    assert remediation_column({"family": "network-device"}) == "LEV+IRV"
    assert remediation_column({"family": "cloud"}, CIS_GCP_20_EXCEPTIONS) == "LEV+IRV"


def test_unknown_cert_class_raises():
    with pytest.raises(ValueError):
        deadline("E", 3, "NLEV")


def test_backtest_distribution_class_d_high_band():
    from backtest_cis_gcp import backtest
    dist = backtest("../data/samples/cis-gcp-foundation-2.0-sample.csv",
                    band="High", cert_class="D")
    hot = sum(n for (pain, col), n in dist.items() if pain >= 4)
    total = sum(dist.values())
    assert total > 1000          # the sample has 1,378 findings
    assert hot < 10              # no N4/N5 flood even on High-band assumption
    fast = sum(n for (pain, col), n in dist.items() if col == "LEV+IRV")
    assert fast < 20  # gate widened by adjudication C-1/C-2 (API keys +
    # PUBLIC_IP default exercisable); expected fast = 14 of 1378 (1.0%)
