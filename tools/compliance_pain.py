# tools/compliance_pain.py
"""Reference implementation of the compliance-finding PAIN method.

Normative source: docs/superpowers/plans/2026-07-16-compliance-finding-pain-strategy.md
Deadline matrix pinned from vdr-pain-cvss.tex Appendix app:matrix.
"""

import re

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

EXPOSURE_TOKENS = {"PUBLIC", "OPEN", "ANONYMOUS", "INTERNET", "WORLD"}

# Admin-plane port set for the host-OS exposure join (governed parameter;
# derived from firewall inventory, not from the STIG scan itself).
ADMIN_PORTS = {22, 3389, 5985, 5986, 5900, 10250}

# Per-(benchmark, version, scanner) exception artifact (canonical, hashed in
# production; see decision log G-2/F-5). vocabulary = every category this
# benchmark version emits; a scanned category ABSENT from it is unreviewed
# and fails loud to LEV+IRV.
# surface = exercisable iff the attached resource is public (join from
# inventory or same-scan exposure state; unknown attachment -> public).
# API_KEY_*: client-embedded API keys are public by design; unknown
# distribution defaults exercisable (decision log C-1, reversing Task 3).
CIS_GCP_20_EXCEPTIONS = {
    "add": set(),
    "remove": set(),
    "surface": {"WEAK_SSL_POLICY", "SSL_NOT_ENFORCED", "SQL_NO_ROOT_PASSWORD",
                "PUBLIC_IP_ADDRESS", "SQL_PUBLIC_IP",
                "API_KEY_APPS_UNRESTRICTED", "API_KEY_APIS_UNRESTRICTED"},
    "vocabulary": frozenset({
        "ACCESS_TRANSPARENCY_DISABLED", "ADMIN_SERVICE_ACCOUNT",
        "API_KEY_APIS_UNRESTRICTED", "API_KEY_APPS_UNRESTRICTED",
        "API_KEY_EXISTS", "API_KEY_NOT_ROTATED", "AUDIT_CONFIG_NOT_MONITORED",
        "AUDIT_LOGGING_DISABLED", "AUTO_BACKUP_DISABLED",
        "BIGQUERY_TABLE_CMEK_DISABLED", "BUCKET_IAM_NOT_MONITORED",
        "BUCKET_POLICY_ONLY_DISABLED", "CLOUD_ASSET_API_DISABLED",
        "COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED", "COMPUTE_SERIAL_PORTS_ENABLED",
        "CONFIDENTIAL_COMPUTING_DISABLED", "CUSTOM_ROLE_NOT_MONITORED",
        "DATAPROC_CMEK_DISABLED", "DATASET_CMEK_DISABLED", "DEFAULT_NETWORK",
        "DEFAULT_SERVICE_ACCOUNT_USED", "DISK_CSEK_DISABLED",
        "DNS_LOGGING_DISABLED", "DNSSEC_DISABLED",
        "ESSENTIAL_CONTACTS_NOT_CONFIGURED", "FIREWALL_NOT_MONITORED",
        "FULL_API_ACCESS", "INSTANCE_OS_LOGIN_DISABLED", "IP_FORWARDING_ENABLED",
        "KMS_KEY_NOT_ROTATED", "KMS_PROJECT_HAS_OWNER", "KMS_PUBLIC_KEY",
        "KMS_ROLE_SEPARATION", "LEGACY_NETWORK",
        "LOAD_BALANCER_LOGGING_DISABLED", "LOCKED_RETENTION_POLICY_NOT_SET",
        "LOG_NOT_EXPORTED", "MFA_NOT_ENFORCED", "NETWORK_NOT_MONITORED",
        "NON_ORG_IAM_MEMBER", "OPEN_RDP_PORT", "OPEN_SSH_PORT",
        "OS_LOGIN_DISABLED", "OVER_PRIVILEGED_SERVICE_ACCOUNT_USER",
        "OWNER_NOT_MONITORED", "PUBLIC_BUCKET_ACL", "PUBLIC_DATASET",
        "PUBLIC_IP_ADDRESS", "PUBLIC_SQL_INSTANCE", "ROUTE_NOT_MONITORED",
        "RSASHA1_FOR_SIGNING", "SECRETS_IN_ENVIRONMENT_VARIABLES",
        "SERVICE_ACCOUNT_KEY_NOT_ROTATED", "SERVICE_ACCOUNT_ROLE_SEPARATION",
        "SHIELDED_VM_DISABLED", "SQL_CONTAINED_DATABASE_AUTHENTICATION",
        "SQL_CROSS_DB_OWNERSHIP_CHAINING", "SQL_EXTERNAL_SCRIPTS_ENABLED",
        "SQL_INSTANCE_NOT_MONITORED", "SQL_LOCAL_INFILE",
        "SQL_LOG_CONNECTIONS_DISABLED", "SQL_LOG_DISCONNECTIONS_DISABLED",
        "SQL_LOG_ERROR_VERBOSITY", "SQL_LOG_MIN_DURATION_STATEMENT_ENABLED",
        "SQL_LOG_MIN_ERROR_STATEMENT_SEVERITY", "SQL_LOG_MIN_MESSAGES",
        "SQL_LOG_STATEMENT", "SQL_NO_ROOT_PASSWORD", "SQL_PUBLIC_IP",
        "SQL_REMOTE_ACCESS_ENABLED", "SQL_SKIP_SHOW_DATABASE_DISABLED",
        "SQL_TRACE_FLAG_3625", "SQL_USER_CONNECTIONS_CONFIGURED",
        "SQL_USER_OPTIONS_CONFIGURED", "SSL_NOT_ENFORCED",
        "USER_MANAGED_SERVICE_ACCOUNT_KEY",
        "VPC_FLOW_LOGS_SETTINGS_NOT_RECOMMENDED", "WEAK_SSL_POLICY",
    }),
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


def finding_grade(severity, governed, structurally_unscored=False):
    if not governed:
        return "Moderate"  # unpinned provenance takes the calibrated prior
    if severity is None or severity == "":
        # blank from a scored source is a data gap, not structural absence
        return "Moderate" if structurally_unscored else "Major"
    s = severity.lower()
    if s in ("critical", "high"):
        return "Major"
    if s in ("medium", "moderate"):
        return "Moderate"
    if s == "low":
        return "Minor"
    return "Major"  # unrecognized label under a governed mapping fails loud


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
    tokens = set(re.split(r"[^A-Z0-9]+", category.upper())) - {""}
    return bool(tokens & EXPOSURE_TOKENS)


def remediation_column(finding, exceptions=None):
    override = finding.get("override")
    if override in ("LEV+IRV", "LEV+NIRV"):
        return override  # evidence-backed, recorded in the audit record
    family = finding.get("family")
    if family == "host-os":
        exercisable = finding.get("admin_plane_open", True)
    elif family == "host-app":
        exercisable = finding.get("service_open", True)
    elif family == "cloud":
        exc = exceptions or {"add": set(), "remove": set(), "surface": set()}
        category = finding.get("category")
        vocabulary = exc.get("vocabulary")
        if category is None:
            exercisable = True  # missing provider metadata fails loud
        elif category in exc["surface"]:
            exercisable = finding.get("attached_resource_public", True)
        elif vocabulary and category not in vocabulary:
            exercisable = True  # unreviewed novel category fails loud
        else:
            exercisable = is_exposure_class(category, exc)
    else:
        exercisable = True  # unrecognized family fails loud, flag for rule authoring
    return "LEV+IRV" if exercisable else "NLEV"


def deadline(cert_class, pain, column):
    if cert_class not in DEADLINES:
        raise ValueError(f"unknown certification class: {cert_class!r}")
    if pain <= 1:
        return None  # N1 carries no FedRAMP remediation deadline
    return DEADLINES[cert_class][pain][column]
