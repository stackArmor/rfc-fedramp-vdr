# tools/compliance_pain.py
"""Reference implementation of the compliance-finding PAIN method.

Normative source: docs/superpowers/plans/2026-07-16-compliance-finding-pain-strategy.md
Deadline matrix pinned from vdr-pain-cvss.tex Appendix app:matrix.
"""

MULT = {"L": 0.5, "M": 1.0, "H": 1.5}

EFFECT_MATRIX = {
    ("Major", "High"): "Debilitating",
    ("Major", "Medium"): "Disruptive",
    ("Major", "Low"): "Narrow",
    ("Moderate", "High"): "Narrow",
    ("Moderate", "Medium"): "Narrow",
    ("Moderate", "Low"): "Minimal",
    ("Minor", "High"): "Minimal",
    ("Minor", "Medium"): "Minimal",
    ("Minor", "Low"): "Minimal",
}

PAIN_TABLE = {  # effect -> (single-agency, multi-agency)
    "Debilitating": (4, 5),
    "Disruptive": (3, 4),
    "Narrow": (2, 2),
    "Minimal": (1, 1),
}

EXPOSURE_TOKENS = {"PUBLIC", "OPEN", "ANONYMOUS", "UNRESTRICTED",
                   "INTERNET", "EXTERNAL", "WORLD"}

# Per-benchmark-version exception table (governed artifact).
# remove: adjudicated keyword false positives — UNRESTRICTED in the API-key
# categories scopes the key, not an internet surface; exercising requires
# possessing the key (same precondition reasoning as A9 example 1).
CIS_GCP_20_EXCEPTIONS = {
    "add": set(),        # keyword rule covers all eight exposure categories
    "remove": {"API_KEY_APPS_UNRESTRICTED", "API_KEY_APIS_UNRESTRICTED"},
    "surface": {"WEAK_SSL_POLICY", "SSL_NOT_ENFORCED",
                "SQL_NO_ROOT_PASSWORD", "DNSSEC_DISABLED",
                "RSASHA1_FOR_SIGNING"},
}

_AB = {5: {"LEV+IRV": 4, "LEV+NIRV": 8, "NLEV": 32},
       4: {"LEV+IRV": 8, "LEV+NIRV": 32, "NLEV": 64},
       3: {"LEV+IRV": 32, "LEV+NIRV": 64, "NLEV": 192},
       2: {"LEV+IRV": 96, "LEV+NIRV": 160, "NLEV": 192}}
_C = {5: {"LEV+IRV": 2, "LEV+NIRV": 4, "NLEV": 16},
      4: {"LEV+IRV": 4, "LEV+NIRV": 8, "NLEV": 64},
      3: {"LEV+IRV": 16, "LEV+NIRV": 32, "NLEV": 128},
      2: {"LEV+IRV": 48, "LEV+NIRV": 128, "NLEV": 192}}
_D = {5: {"LEV+IRV": 0.5, "LEV+NIRV": 1, "NLEV": 8},
      4: {"LEV+IRV": 2, "LEV+NIRV": 8, "NLEV": 32},
      3: {"LEV+IRV": 8, "LEV+NIRV": 16, "NLEV": 64},
      2: {"LEV+IRV": 24, "LEV+NIRV": 96, "NLEV": 192}}
DEADLINES = {"A": _AB, "B": _AB, "AB": _AB, "C": _C, "D": _D}


def asset_band(cr, ir, ar):
    if cr is None or ir is None or ar is None:
        return "High"  # fail-safe: unclassified scores loud (HHH)
    mean = (MULT[cr] + MULT[ir] + MULT[ar]) / 3
    if mean < 0.75:
        return "Low"
    if mean < 1.25:
        return "Medium"
    return "High"


def finding_grade(severity, governed):
    if not governed or severity is None:
        return "Moderate"  # structural-absence prior, not a fail-safe
    s = severity.lower()
    if s in ("critical", "high"):
        return "Major"
    if s == "low":
        return "Minor"
    return "Moderate"


def customer_effect(grade, band):
    return EFFECT_MATRIX[(grade, band)]


def pain_level(effect, multi_agency):
    if multi_agency is None:
        multi_agency = True  # fail-safe: unknown scope scores loud
    single, multi = PAIN_TABLE[effect]
    return multi if multi_agency else single


def is_exposure_class(category, exceptions):
    if category in exceptions["remove"] or category in exceptions["surface"]:
        return False
    if category in exceptions["add"]:
        return True
    return bool(set(category.split("_")) & EXPOSURE_TOKENS)


def remediation_column(finding, exceptions=None):
    override = finding.get("override")
    if override in ("LEV+IRV", "LEV+NIRV"):
        return override  # evidence-backed, recorded in the audit record
    family = finding["family"]
    if family == "host-os":
        exercisable = finding.get("admin_plane_open", True)
    elif family == "host-app":
        exercisable = finding.get("service_open", True)
    else:  # cloud
        exc = exceptions or {"add": set(), "remove": set(), "surface": set()}
        category = finding["category"]
        if category in exc["surface"]:
            exercisable = finding.get("attached_resource_public", True)
        else:
            exercisable = is_exposure_class(category, exc)
    return "LEV+IRV" if exercisable else "NLEV"


def deadline(cert_class, pain, column):
    if pain <= 1:
        return None  # N1 carries no FedRAMP remediation deadline
    return DEADLINES[cert_class][pain][column]
