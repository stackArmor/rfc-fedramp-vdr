# Compliance-Finding PAIN and Remediation Strategy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a defensible, deterministic method for assigning PAIN levels and remediation deadlines to security-benchmark/compliance findings (STIG, CIS, cloud-configuration), plus a reference implementation, back-test, and TeX addendum.

**Architecture:** A severity×asset effect matrix (mirroring the CVE method's impact×CR/IR/AR combination) produces the customer-effect band; FedRAMP's effect/scope table produces PAIN; a finding-level *internet-exercisability* test (per benchmark family) selects the remediation column; the existing `VDR-TFR-PVR` matrix selects the deadline. The full normative method is specified in Part A of this document; the tasks in Part B implement, validate, and publish it.

**Tech Stack:** Python 3 + pytest (reference implementation and fixtures), LaTeX/tectonic (addendum), markdown (this strategy).

**Supersedes:** `docs/superpowers/plans/2026-07-16-compliance-finding-pain-adversarial-review.md`. Key changes from that plan:

1. The asset-band→effect default (High→Debilitating) and Low-only severity adjustment are **replaced** by a severity×asset effect matrix. Unscored `Fail` carries a **Moderate** prior instead of a worst-case prior.
2. The asset-level internet-accessibility flag is **replaced** by a finding-level internet-exercisability test with per-benchmark-family operational rules.
3. A governed per-benchmark determination table (built at table-build time by a keyword/token generator, guidance-level) replaces any per-rule classification for cloud benchmarks; host benchmarks need zero per-rule mapping.
4. Unknown agency scope now has an explicit fail-safe default (multi-agency) — a gap in the prior plan.
5. The audit record adds affected-resource substitution rationale, exercisability rule version, and severity provenance.

## Global Constraints

- Commit messages are authored by Matthew Venne; never reference Claude, no Co-Authored-By lines (per user CLAUDE.md).
- The repository is public: sample scan data MUST be sanitized (no org IDs, no assessed-resource domains) before committing.
- FedRAMP effect/scope semantics are fixed: Narrow=N2 and Minimal=N1 regardless of agency count; N5 only for Debilitating multi-agency.
- Internet exercisability changes the remediation column only, never PAIN (no double-counting one fact).
- Missing **provider-controlled** metadata fails safe loud (asset→HHH/High, scope→multi-agency, admin-plane exposure→open, a category absent from the benchmark version's reviewed vocabulary→LEV+IRV (unreviewed fails loud); a reviewed-but-untagged category→NLEV as a disclosed calibration choice). Missing **structurally absent** metadata (benchmark severity) takes the calibrated Moderate prior — this distinction must be stated wherever the prior is used.
- Deadline day counts come only from the pinned `VDR-TFR-PVR` matrix in `vdr-pain-cvss.tex` (Appendix `app:matrix`); never invent benchmark-specific day counts. N1 has no deadline.
- The TeX addendum follows the established whitepaper register: plain language, `IN PLAIN TERMS` boxes, math behind the prose, pinned normative sources.
- Terminology: "internet-accessible" (entry points) and "internet-reachable" (FedRAMP's broader status) are never interchangeable; this method introduces and defines "internet-exercisable" for benchmark findings and must not present it as a redefinition of FedRAMP's IRV.

---

# Part A — Normative method specification

This is the content the reference implementation, fixtures, and addendum are built from. It is complete; tasks reference it by section.

## A1. Evaluation and disposition gate

Only a confirmed failed condition enters PAIN calculation.

1. `Pass` is not a finding.
2. A scanner result that does not match the effective state is a **false positive**.
3. A recommendation that does not apply to the asset's actual role is **not applicable**. N/A dispositions are auditable out-of-scope decisions with a mandatory reportable rationale.
4. A failed configuration neutralized by an effective control is **fully mitigated**; evidence and retained PAIN are recorded.
5. A weakness intentionally justified rather than eliminated is an **accepted finding**. Acceptance does not lower computed PAIN.
6. A weakness reduced but not eliminated by a compensating control is **partially mitigated**: grade/effect are re-evaluated against the residual condition on cited evidence, and the pre- and post-mitigation N-ratings are recorded.

The scoring algorithm is never weakened to compensate globally for scanner noise; noise is resolved here, per finding, with evidence.

## A2. Asset-value band

Encode the affected asset's CR/IR/AR as CVSS multipliers L=0.5, M=1.0, H=1.5:

```text
asset_mean = (CR + IR + AR) / 3
Low     when asset_mean < 0.75      # exactly {LLL, LLM}
Medium  when 0.75 <= mean < 1.25    # everything else
High    when asset_mean >= 1.25     # exactly {HHH, HHM}
```

Attainable means are sixths (0.5 … 1.5), so the thresholds are never hit exactly. The plain-language equivalent (stated in the addendum): **High = at least two High requirements and no Low; Low = at least two Low requirements and no High; otherwise Medium.**

- Missing/unresolved asset metadata → HHH → High (provider-controlled metadata fails safe loud).
- **Affected-resource substitution:** a finding that reasonably affects a higher-value dependent resource, administrative plane, shared credential store, or control plane is evaluated against that higher-value resource, not the point of detection. Every substitution records the substituted resource and rationale in the audit record (A8).

## A3. Finding grade (severity, governed)

| Grade | Sources |
|---|---|
| **Major** | STIG CAT I; governed scanner Critical/High |
| **Moderate** | STIG CAT II; governed scanner Medium; **unscored `Fail`** (the calibrated prior) |
| **Minor** | STIG CAT III; governed scanner Low |

Provenance rules:

- DISA CATs are authoritative. Scanner severities count only under a documented, stable, governed mapping (e.g., Google SCC finding-category severities qualify; a provider's ad-hoc relabel does not).
- Non-governed severities are treated as unscored → Moderate. Providers can neither self-escalate nor self-reduce.
- CIS Level 1/2 profiles are not severities.
- Rationale for the Moderate prior (must appear in the addendum): missing benchmark severity is **structural** (CIS publishes none), not a provider omission, so a worst-case default is miscalibration, not fail-safety; CAT II is the empirical mode of benchmark content; and labeling hundreds of hardening deviations "potentially debilitating multi-agency events" destroys the incident signal for findings that deserve it.

Severity provenance is resolved through a pinned, versioned source registry: structurally-unscored sources (CIS) take the Moderate prior; scanners on the published governed list are governed by default and cannot be un-elected; a blank or unrecognized severity from a scored/governed source fails loud to Major. Starter governed list: DISA STIG CATs, Google SCC category severities, AWS FSBP control severities.

## A4. Customer-effect matrix (grade × asset band)

| Grade | Asset High | Asset Medium | Asset Low |
|---|---|---|---|
| Major | Debilitating | Disruptive | Narrow |
| Moderate | Narrow | Narrow | Minimal |
| Minor | Minimal | Minimal | Minimal |

- The asset band is a ceiling: severity never raises effect above what the asset supports (Major/Low is still Narrow).
- Calibration knob (documented, deliberate): Moderate/High = Narrow, not Disruptive. The alternative puts every CAT II and raw CIS Fail on high-value multi-agency assets at N4 — incident-class in Class D — which is the flood this design exists to prevent. The multi-agency PAIN column has no N3; the line between "incident" (N4+) and "maintenance" (N2−) sits exactly at the Disruptive boundary.
- Grade transition invariant: Moderate→Minor moves the effect down at most one band (exactly one unless already Minimal).
- Evidence-gated escalation override: documented evidence that a specific finding yields direct High C/I/A impact on the (substituted) resource promotes the grade one step (Moderate→Major), audited and expected rare. The N5↔N2 boundary on High assets (e.g., an account-lockout CAT II on an internet-exercisable crown-jewel admin plane capped at N2) is the calibration's named residual risk.

## A5. Effect × agency scope → PAIN

| Customer effect | Single agency | Multi-agency |
|---|---:|---:|
| Debilitating | N4 | N5 |
| Disruptive | N3 | N4 |
| Narrow | N2 | N2 |
| Minimal | N1 | N1 |

Unknown agency scope → multi-agency (fail-safe; provider-controlled metadata).

## A6. Remediation column — internet exercisability

Normative test: **a benchmark finding is internet-exercisable iff an unauthenticated internet actor can exercise the failed condition as it currently stands, with no precondition the finding does not itself supply.** (Same spirit as the `FRD-LEV` unauthenticated-automation floor, `vdr-pain-cvss.tex:457`.) This is an operational test for benchmark findings; it is not a redefinition of FedRAMP's IRV, and the addendum must say so.

Per-family operational rules:

- **Host benchmarks, OS-level (RHEL/Windows STIG & CIS):** exercisable iff the admin/login plane (governed port set, default {22, 3389, 5985, 5986, 5900, 10250}) is world-open. Unknown → open (fail-safe). No per-rule mapping. `admin_plane_open` is the output of a required join against governed firewall/LB inventory; a WAF/ALB-fronted service surface counts as open (mitigation, not closure).
- **Host benchmarks, application-level (web/db STIGs):** exercisable iff that application's service surface is internet-open.
- **Cloud-configuration benchmarks:** exercisable iff the finding category is **exposure-class** under the governed **determination table** for that (benchmark, version, scanner):
  - Normative object: a governed, content-hashed determination table per (benchmark, version, scanner) that assigns every category in the version's vocabulary an effective classification — exposure-class (always exercisable), `surface` (exercisable iff the attached resource is public, joined from the same scan's exposure findings; unknown attachment → public, fail-safe), or identity/operations-plane (not exercisable). Classification reads scanner-emitted category identifiers only, never rule prose and never per-resource IAM analysis; the determination at scoring time is a lookup, reproducible from table hash + category. Scanned categories absent from the vocabulary fail loud to LEV+IRV pending review. Canonical tables published + content-hashed; provider deltas enumerated per-entry with rationale; reclassifying a category out of exposure-class is a hard assessor-review trigger.
  - Table encoding (canonical serialization, review decisions relative to the recommended generator): `add` / `remove` / `surface` / `vocabulary`. The encoding concentrates review effort on deviations; the effective per-category classification is what binds.
  - Recommended generator (implementation guidance, non-normative): the category identifier contains any of {PUBLIC, OPEN, ANONYMOUS, INTERNET, WORLD} as a **normalized token** (uppercase, split on non-alphanumeric runs — `OPEN_SSH_PORT` matches, `OPENSSH_CONFIG` does not), **or** contains the literal any-address CIDR `0.0.0.0` or `::/0` (matched as a literal substring before tokenization, since normalization would reduce `0.0.0.0` to a bare `0`; `sg-allow-ingress-from-0.0.0.0-0` matches, `TLS_1_0_ENABLED` does not). EXTERNAL/UNRESTRICTED excluded from the auto-match set as collision-prone; carried by `add` entries instead. The generator runs at table-build time, not scoring time — its output is frozen into the reviewed, hashed table. Collision-screening a benchmark's full category list at table-build time, and any automated/agentic pre-classification of exposure relevance, are sound and useful but not required — token/pattern matching against a reviewed table meets the bar.
  - Vocabulary categories with no exposure or surface classification are identity/operations-plane → not exercisable. Justification: the finding fails the unauthenticated test at its precondition (e.g., a user-managed SA key requires possessing the secret; the public control plane alone gives an internet actor nothing).
- **Overrides (evidence-backed, audited, expected to be uncommon):** LEV+NIRV when evidence shows a likely tenant/internal/adjacent/local actor can exercise the condition (worked example: MFA-not-enforced-class findings); LEV+IRV when evidence shows public usability (e.g., known-leaked key — at which point incident response applies); LEV+IRV also available on transitive-reachability evidence (indirect internet payload paths, mirroring the CVE companion) — the baseline test is sound but incomplete with respect to IRV: exercisable implies IRV, never the converse. A data-plane grant to allUsers or allAuthenticatedUsers is exposure-class regardless of category name (allAuthenticatedUsers satisfies the unauthenticated test).

Column selection:

```text
column = LEV+IRV  if internet-exercisable (or override)
column = LEV+NIRV if evidence-backed internal-exploitability override
column = NLEV     otherwise
```

Exercisability never changes PAIN.

## A7. Deadline

`deadline = M[Certification Class][PAIN][column]` using the pinned `VDR-TFR-PVR` matrix (`vdr-pain-cvss.tex`, Appendix `app:matrix`; days, 0.5 = 12 hours; Classes A and B share a schedule; N1 has no deadline):

| PAIN | A/B: L+I / L+N / NLEV | C: L+I / L+N / NLEV | D: L+I / L+N / NLEV |
|---|---|---|---|
| N5 | 4 / 8 / 32 | 2 / 4 / 16 | 0.5 / 1 / 8 |
| N4 | 8 / 32 / 64 | 4 / 8 / 64 | 2 / 8 / 32 |
| N3 | 32 / 64 / 192 | 16 / 32 / 128 | 8 / 16 / 64 |
| N2 | 96 / 160 / 192 | 48 / 128 / 192 | 24 / 96 / 192 |

Reference outcome (the anchor case from design review): CAT II on a medium-value internet-exercisable host = Moderate × Medium → Narrow → N2 → LEV+IRV → **24 days in Class D** (96 NLEV→192; A/B 96; C 48).

## A8. Minimum audit record

benchmark + version; rule/category identifier and scanner result; disposition + evidence (if not an unqualified Fail); affected asset + resolved archetype; **affected-resource substitution + rationale (if applied)**; CR/IR/AR + derived band; agency scope (+ "defaulted" marker if unknown); tenancy basis (agencies served + evidence) for any single-agency assertion on a shared-service archetype; severity + provenance (grade + why governed/unscored); customer effect + PAIN; exercisability determination + **rule-set/exception-table content hash + provider delta list**; enforced-state evidence pointer for any affirmative not-exercisable determination; substitution decision and basis, recorded when applied AND when declined; column + override evidence reference; Certification Class, evaluation completion time, deadline.

## A9. Worked examples (constrain review and addendum)

1. **User-managed SA key (GCP, `USER_MANAGED_SERVICE_ACCOUNT_KEY`):** ops-plane (no keyword match) → NLEV. The public GCP API plane is not the finding's exposure; the actor lacks the secret. NIRV override on evidence of broad internal availability + harmful permissions; IRV only on known public disclosure. Contrast: API keys (`API_KEY_APPS_UNRESTRICTED`) do NOT take this reasoning — client-embedded API keys are public by design, so the unknown-distribution default is exercisable, with a down-override only on evidence the key is server-side-only (decision log C-1).
2. **Public bucket (`PUBLIC_BUCKET_ACL`):** exposure-class by keyword → LEV+IRV. Governed SCC High → Major; on a High-value multi-agency data archetype → N5 → 12 hours in Class D. Correct: that is an incident.
3. **`SSL_NOT_ENFORCED` on Cloud SQL where `SQL_PUBLIC_IP` is Compliant:** surface-class, attached resource not public → NLEV.
4. **CAT II on public web VM (admin ports closed):** OS-level finding → not exercisable via 443 → NLEV. Medium asset → N2 → 192 days Class D.
5. **MFA not enforced:** strict test says not exercisable (needs a credential); named in the addendum as the canonical case where a provider should consider the NIRV (or deliberate IRV) override.

## A10. Acceptance criteria

1. Every output reproducible from the A8 audit record.
2. No baseline input requires metadata ordinary scanners/inventory don't provide; the only governed artifacts are the severity mappings and per-benchmark exception tables (~dozen rows each).
3. PAIN always matches FedRAMP effect/scope semantics; N5 only Debilitating multi-agency.
4. Exercisability changes columns only, never PAIN; Certification Class changes deadlines only, never PAIN.
5. Provider-controlled unknowns fail safe loud; the Moderate prior is disclosed as a calibrated structural default, with the provider-controlled/structural distinction stated (the Moderate prior is gated on the source registry's structurally-unscored marker; vocabulary-absent categories fail loud).
6. Back-test on real scans shows no systematic N4/N5 flood in Class D; exposure-class findings land on fast clocks; per-finding surprise overrides stay well under 1%, with standing category-level overrides (MFA-class, tenant-isolation families) counted separately as family rules.
7. Two independent reviewers given the same findings, pinned rule set, and evidence produce identical results (determinism), including on affected-resource substitution cases.

---

# Part B — Tasks

> **Note:** Task 2/3 code blocks show the pre-review implementation; the adjudicated changes of 2026-07-17 (decision log `2026-07-16-compliance-pain-review-findings.md`) supersede them where they differ — `tools/` is authoritative.

### Task 1: Mark the prior plan superseded

**Files:**
- Modify: `docs/superpowers/plans/2026-07-16-compliance-finding-pain-adversarial-review.md` (status lines at top)

**Interfaces:**
- Produces: a clear pointer so no future session executes the superseded design.

- [ ] **Step 1: Edit the status header**

Replace the existing `**Status:**` line (line 4) with:

```markdown
**Status:** SUPERSEDED — see `2026-07-16-compliance-finding-pain-strategy.md`.
The severity×asset effect matrix replaces §3.3–3.4; finding-level internet
exercisability replaces §3.6; the §7 test matrix is obsolete.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/
git commit -m "Supersede compliance-PAIN review plan with converged strategy"
```

### Task 2: Reference implementation with machine-checkable fixtures (TDD)

**Files:**
- Create: `tools/compliance_pain.py`
- Test: `tools/test_compliance_pain.py`

**Interfaces:**
- Produces: `asset_band(cr, ir, ar) -> str` ("Low"|"Medium"|"High"; args "L"/"M"/"H"/None), `finding_grade(severity, governed) -> str` ("Major"|"Moderate"|"Minor"; severity str|None), `customer_effect(grade, band) -> str`, `pain_level(effect, multi_agency) -> int` (multi_agency bool|None), `is_exposure_class(category, exceptions) -> bool`, `remediation_column(finding, exceptions) -> str`, `deadline(cert_class, pain, column) -> float|None`, constant `CIS_GCP_20_EXCEPTIONS`. Task 3 imports all of these.

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tools && python -m pytest test_compliance_pain.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'compliance_pain'`

- [ ] **Step 3: Write the implementation**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tools && python -m pytest test_compliance_pain.py -q`
Expected: all tests PASS (0 failures)

- [ ] **Step 5: Commit**

```bash
git add tools/compliance_pain.py tools/test_compliance_pain.py
git commit -m "Add compliance-PAIN reference implementation and fixtures"
```

### Task 3: Sanitized sample scan and back-test

**Files:**
- Create: `data/samples/cis-gcp-foundation-2.0-sample.csv` (sanitized copy of `/Users/matthewvenne/Downloads/cis-google-cloud-platform-foundation-2-0_compliance_2026-07-16.csv`)
- Create: `tools/backtest_cis_gcp.py`
- Test: extend `tools/test_compliance_pain.py`

**Interfaces:**
- Consumes: everything Task 2 produces.
- Produces: `backtest(csv_path, band, cert_class) -> dict` mapping `(pain, column)` to weighted finding counts; CLI prints a distribution table.

- [ ] **Step 1: Sanitize and copy the sample (repo is public — required)**

```bash
mkdir -p data/samples
sed -e 's/^Assessed resource,.*/Assessed resource,REDACTED/' \
    -e 's/^Assessed organization ID,.*/Assessed organization ID,REDACTED/' \
    "/Users/matthewvenne/Downloads/cis-google-cloud-platform-foundation-2-0_compliance_2026-07-16.csv" \
    > data/samples/cis-gcp-foundation-2.0-sample.csv
grep -c "REDACTED" data/samples/cis-gcp-foundation-2.0-sample.csv
```

Expected: `2`. Then visually confirm no other identifying values remain: `head -12 data/samples/cis-gcp-foundation-2.0-sample.csv`.

- [ ] **Step 2: Write the failing back-test test**

Append to `tools/test_compliance_pain.py`:

```python
def test_backtest_distribution_class_d_high_band():
    from backtest_cis_gcp import backtest
    dist = backtest("../data/samples/cis-gcp-foundation-2.0-sample.csv",
                    band="High", cert_class="D")
    hot = sum(n for (pain, col), n in dist.items() if pain >= 4)
    total = sum(dist.values())
    assert total > 1000          # the sample has 1,378 findings
    assert hot < 10              # no N4/N5 flood even on High-band assumption
    fast = sum(n for (pain, col), n in dist.items() if col == "LEV+IRV")
    assert fast < 10             # only exposure-class findings ride LEV+IRV
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd tools && python -m pytest test_compliance_pain.py -q -k backtest`
Expected: FAIL — `ModuleNotFoundError: No module named 'backtest_cis_gcp'`

- [ ] **Step 4: Write the back-test script**

```python
#!/usr/bin/env python3
# tools/backtest_cis_gcp.py
"""Back-test the compliance-PAIN method against an SCC CIS GCP report.

Usage: python backtest_cis_gcp.py ../data/samples/cis-gcp-foundation-2.0-sample.csv
Assumes: multi-agency scope, one uniform asset-band assumption per run
(the SCC report is category-level; per-resource archetypes come later).
"""
import csv
import sys
from collections import Counter

from compliance_pain import (CIS_GCP_20_EXCEPTIONS, customer_effect, deadline,
                             finding_grade, pain_level, remediation_column)

# Attached-resource exposure for surface-class categories, joined from the
# same scan's exposure findings (SQL_PUBLIC_IP is Compliant in this sample).
ATTACHED_PUBLIC = {"SSL_NOT_ENFORCED": False, "WEAK_SSL_POLICY": True,
                   "SQL_NO_ROOT_PASSWORD": False, "DNSSEC_DISABLED": True,
                   "RSASHA1_FOR_SIGNING": True}


def rows(path):
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = None
        for row in reader:
            if header is None:
                if row and row[0] == "Control":
                    header = row
                continue
            if len(row) == len(header):
                yield dict(zip(header, row))


def backtest(path, band, cert_class):
    dist = Counter()
    for r in rows(path):
        if r["Status"] != "Non-compliant":
            continue
        n = int(r["Findings"])
        grade = finding_grade(r["Severity"], governed=True)  # SCC is governed
        pain = pain_level(customer_effect(grade, band), True)
        finding = {"family": "cloud", "category": r["Finding category"]}
        if r["Finding category"] in ATTACHED_PUBLIC:
            finding["attached_resource_public"] = ATTACHED_PUBLIC[r["Finding category"]]
        col = remediation_column(finding, CIS_GCP_20_EXCEPTIONS)
        dist[(pain, col)] += n
    return dist


def main():
    path = sys.argv[1]
    for band in ("High", "Medium"):
        dist = backtest(path, band, "D")
        print(f"\n== Asset band assumption: {band} (Class D, multi-agency) ==")
        for (pain, col), n in sorted(dist.items(), reverse=True):
            d = deadline("D", pain, col)
            due = "no deadline" if d is None else f"{d} days"
            print(f"  N{pain}  {col:9s}  {n:5d} findings  -> {due}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests and the script**

Run: `cd tools && python -m pytest test_compliance_pain.py -q && python backtest_cis_gcp.py ../data/samples/cis-gcp-foundation-2.0-sample.csv`
Expected: all tests PASS; printed distribution shows single-digit N4/N5 and LEV+IRV counts, bulk at N2/N1 NLEV. If the flood assertions fail, that is a **method finding** — stop and adjudicate against A10 criterion 6 before proceeding.

- [ ] **Step 6: Commit**

```bash
git add data/samples/ tools/backtest_cis_gcp.py tools/test_compliance_pain.py
git commit -m "Back-test compliance-PAIN method against sanitized CIS GCP scan"
```

### Task 4: Adversarial review of the calibrated method

**Files:**
- Create: `docs/superpowers/plans/2026-07-16-compliance-pain-review-findings.md` (decision log)

**Interfaces:**
- Consumes: Part A, Task 2 fixtures, Task 3 distribution.
- Produces: adjudicated go/no-go per A10; any accepted change re-runs Tasks 2–3.

- [ ] **Step 1: Dispatch independent red-team reviews** (subagents or human reviewers: FedRAMP/VDR, 3PAO, vuln-management practitioner, cloud/platform security). Each must attack with concrete counterexamples, in the format `issue / counterexample / severity / affected rule / recommended change / new complexity introduced`. Required attack surface:
  - Matrix calibration: is Moderate/High=Narrow defensible ("a CAT II on the crown jewel is Narrow?"), and is the two-band Major↔Moderate gap on High assets acceptable?
  - The Moderate prior: does the structural-absence vs provider-omission argument survive a 3PAO challenge? Can a provider suppress governed severities to ride the prior? (No: unscored → Moderate is *higher* than governed Low — verify no gaming path exists in either direction.)
  - Keyword rule: validate token vocabulary against AWS and Azure CIS/Security Hub category names; hunt false negatives (exposure rules with none of the tokens) and false positives; confirm categories come from the scanner, not the provider (naming is not provider-gameable).
  - Exercisability edge cases: MFA-class findings, serial-console, DNSSEC, IP-forwarding; document each strict-test outcome and whether the override guidance suffices.
  - Determinism: two reviewers, ten findings, identical pinned rule set — including at least two affected-resource substitution cases.
  - VER reporting compatibility of dispositions and of the "defaulted" audit markers.
- [ ] **Step 2: Adjudicate** — decision log entry per finding; reject changes requiring unavailable metadata; reject changes that merge PAIN/exercisability/accessibility; re-run `python -m pytest tools -q` after every accepted algorithm change and update Part A in place.
- [ ] **Step 3: Gate** — proceed to Task 5 only when all A10 criteria hold. Commit the decision log:

```bash
git add docs/superpowers/plans/2026-07-16-compliance-pain-review-findings.md
git commit -m "Record adversarial review adjudication for compliance-PAIN method"
```

### Task 5: TeX addendum

**Files:**
- Create: `vdr-pain-compliance.tex` (standalone companion — the prior plan's Phase 5 preference — so the CVE memo's math stays uncluttered)

**Interfaces:**
- Consumes: Part A verbatim as the normative content; Task 3 distribution as the empirical section; `vdr-pain-cvss.tex` preamble/macros as the style template.

- [ ] **Step 1: Draft the addendum** with this section map (content = the referenced Part A section, adapted to whitepaper register — plain language, flowing prose, no draft-history framing):
  1. Scope and the vulnerability definition (benchmark findings are FedRAMP vulnerabilities) — pin the four normative FedRAMP URLs from the superseded plan §2 plus the CIS profiles FAQ, at a reviewed commit/date.
  2. Disposition gate (A1).
  3. Asset band (A2) — state the plain-language band rule, formula as derivation; affected-resource substitution with its audit obligation.
  4. Finding grade and provenance (A3) — including the structural-absence rationale, stated in full.
  5. Effect matrix (A4) and PAIN (A5) — with the "multi-agency has no N3" observation and the calibration-knob disclosure.
  6. Internet exercisability (A6) — labeled an operational test, explicitly NOT a redefinition of FedRAMP IRV; governed determination table (keyword generator as guidance) + the CIS GCP 2.0 table as the worked appendix; MFA as the override worked example.
  7. Deadlines (A7) — reference, not restate, the `app:matrix` tables.
  8. Audit record (A8), worked examples (A9), back-test results (Task 3 output).
  9. `IN PLAIN TERMS` box: the method uses only what scanners actually emit; unknowns the provider controls score loud; the one calibrated default (unscored = Moderate) is disclosed, not hidden.
  10. Known limitations: over-prioritizes some non-exercisable findings on exposed surfaces, under-prioritizes internally exploitable findings absent an override; never described as equivalent to a full LEV evaluation.
- [ ] **Step 2: Build**

Run: `tectonic vdr-pain-compliance.tex`
Expected: PDF builds with zero errors.

- [ ] **Step 3: Render and visually inspect every page** (tables, matrix, plain boxes), fix, rebuild.
- [ ] **Step 4: Commit**

```bash
git add vdr-pain-compliance.tex
git commit -m "Add compliance-finding PAIN and remediation addendum"
```

### Task 6: Repository integration and verification

**Files:**
- Modify: `README.md` (document index — add the addendum alongside the existing memos)

**Interfaces:**
- Consumes: built `vdr-pain-compliance.pdf`.

- [ ] **Step 1: Update `README.md`** document index with the new companion (match the existing entries' format for `vdr-pain-cvss` / `internet-reachability`).
- [ ] **Step 2: Rebuild all affected PDFs**: `tectonic vdr-pain-compliance.tex` (and any doc whose index/cross-references changed). Expected: clean builds.
- [ ] **Step 3: Verify hygiene**

Run: `git diff --check && git status --short`
Expected: no whitespace errors; only intended files listed (no `.claude/worktrees/` or `output/` changes).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "Index the compliance-finding PAIN addendum"
```
