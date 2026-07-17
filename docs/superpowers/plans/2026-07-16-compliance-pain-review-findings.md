# Compliance-PAIN Adversarial Review — Adjudication Decision Log

**Date:** 2026-07-17
**Inputs:** four independent red-team reviews (FedRAMP/VDR policy `F-*`, 3PAO gaming/determinism `G-*`, vuln-mgmt operations `O-*`, cloud/platform exercisability `C-*`), full texts in `.superpowers/sdd/task-4-redteam-*.md`. Totals: 6 Critical, 23 Important, 8 Minor, 21 survived attacks.
**Adjudication rules applied (plan Task 4):** reject changes requiring metadata ordinary scanners/inventory don't provide; reject changes that merge PAIN, exploitability, and accessibility; every accepted algorithm change re-runs the full fixture suite; Part A updated in place.

**Headline:** every reviewer independently confirmed the arithmetic core (A2 band math, A4/A5 tables, A7 lookup, token matching on scanner-emitted categories) is deterministic and not provider-gameable; N5 remains reachable only for Debilitating multi-agency; exercisability provably never touches PAIN. Every live attack lands on an **ungoverned input** or a **vocabulary/normalization gap**. The accepted changes are therefore governance and classifier-input fixes, not scoring-model changes. One prior adjudication (Task 3, API keys) is REVERSED.

---

## Accepted — Critical

**F-1 / G-1 / G-8 / O-9 (consolidated): severity provenance gets a pinned source registry.**
The Moderate prior was implementable only as a boolean the provider controlled, opening a downward path (strip a governed High → Moderate → N5→N2, 384× clock stretch) and making "structural absence" indistinguishable from a data gap. Accepted:
- A pinned, versioned **source registry** records, per benchmark source: structurally-unscored (CIS — eligible for the Moderate prior), or governed mapping (with the scanner's full label vocabulary at a pinned version). A scanner on the published governed list is governed by default; un-election is not available. Starter list: DISA STIG CATs, Google SCC category severities, AWS FSBP control severities.
- `finding_grade` now takes `structurally_unscored`: blank/missing severity from a **scored** source fails loud to Major; the Moderate prior applies only to registry-marked structurally-unscored sources; an unrecognized label under a governed mapping fails loud to Major (G-8).
- O-9's "stable" test replaced with a concrete one: severity published per category in vendor documentation at a pinned version. O-9's exposure-raises-grade-floor recommendation is **rejected** (it would route the column signal into PAIN — the axis-separation constraint governs).

**G-2 / F-5: exception tables become canonical, hashed, delta-audited artifacts.**
A version *string* enforces nothing; the `remove` set was a silent clock-slowing lever (the repo's own API-key commit was the proof of concept). Accepted: canonical exception tables are published per (benchmark, version, scanner) and content-hashed; A8 carries the hash; any provider delta from canonical is enumerated per-entry with rationale and flagged for assessor review; a `remove` of a token-matching category is a hard review trigger.

**C-1: API-key adjudication REVERSED (corrects this method's own Task 3 decision).**
The Task 3 rationale ("exercising requires possessing the key," borrowed from the SA-key example) is factually wrong for API keys: client-embedded GCP API keys (Maps/Firebase web, mobile) are public by design, and `API_KEY_APPS_UNRESTRICTED` is precisely the finding that the compensating restriction on an already-public key is missing. Accepted: both API_KEY categories move from `remove` to `surface`, attachment = "key is client-distributed," unknown → exercisable (fail-safe toward the fast clock); down-override to NLEV only with evidence the key is server-side-only and network-scoped. A9 example 1 gains an explicit contrast: the SA-key reasoning does **not** transfer to API keys. The back-test gate moves from `fast < 10` to `fast < 20` — a documented consequence of this reversal plus C-2, not threshold tuning (expected fast: 14 of 1,378 = 1.0%).

**O-1: keyword classifier normalized for non-GCP category grammars.**
`category.split("_")` + uppercase tokens return all-false for AWS Config (`s3-bucket-public-read-prohibited`), Security Hub, and Azure naming. Accepted: normalize (uppercase, split on non-alphanumeric runs) before token matching; A6 states the keyword rule is defined only for scanners emitting stable machine category IDs — prose-only scanners require vocabulary + `add` tables.

**O-3: host admin-plane input is a named, mandatory inventory join — not scanner-emitted metadata.**
Accepted as a clarification: `admin_plane_open` is defined as the output of a required join against governed firewall/LB inventory (the same source the CSP benchmark's own 3.6/3.7 controls read); A10 #2 amended to name inventory joins as baseline inputs. The unknown→open fail-safe is **retained** (O-3's unknown→NLEV flip is rejected): firewall state is a discoverable unknown, and the doctrine is to score discoverable unknowns loud to force the join — the flood O-3 computes is the documented cost of operating without a firewall feed, and the addendum says so plainly.

## Accepted — Important

**F-2 / O-6: per-version category vocabulary closes the unmapped-vs-untagged conflation.**
The plan claimed "unmapped → LEV+IRV" while the code sent every non-matching category to NLEV. Accepted: the exception artifact gains the benchmark version's full **category vocabulary**; a category in the vocabulary but untagged → NLEV as a *disclosed calibration choice* (known ops-plane); a category **absent** from the vocabulary (e.g., SCC's monthly additions, `ALLOYDB_PUBLICLY_ACCESSIBLE`) → LEV+IRV and flagged unreviewed. Global Constraints and A10 #5 reworded to say exactly this.

**F-3: exercisability disclosed as sound-but-incomplete w.r.t. IRV, plus a transitive override.**
`exercisable ⟹ IRV`, never the converse; the baseline can only under-select the fast clock. A transitive-evidence override to LEV+IRV (mirroring the CVE companion's transitive branch) gives the VER-EVA-EIR indirect-payload case an IRV-direction home. Normative text + audit field; the override mechanism already exists.

**F-4: partially-mitigated disposition added.** Re-evaluates grade/effect against the residual condition on cited evidence, records pre/post N — matching VER's expectation that the clock is satisfied by partial mitigation to a lower N.

**F-6: evidence-gated grade-escalation override (Moderate→Major, one step, audited, rare).** The encryption-at-rest CAT II on a shared multi-agency datastore is a real under-claim at Narrow; the override gives the evidenced minority a home without reopening the flood. Fenced by the same registry/assessor-review governance as F-1/G-2.

**F-7: input guards.** Family whitelist {host-os, host-app, cloud}; unrecognized family or missing cloud category fails safe to LEV+IRV; unknown Certification Class raises an explicit error instead of `KeyError`.

**G-3: tenancy-basis audit field.** Shared-service/control-plane archetypes default multi-agency; a single-agency assertion on them requires recorded tenancy evidence. A8 field added.

**G-4: substitution decisions recorded both ways; trigger list named.** A2 gains a governed trigger list (control plane, shared credential store, admin/bastion plane, backup and logging infrastructure with reach into higher-value assets); A8 records the substitution decision **including when declined**, with basis. A full asset-adjacency graph is noted as the optional refinement that would make substitution table-driven — not baseline (metadata-availability rule). Residual judgment is disclosed.

**G-5: enforced-state evidence for affirmative "closed" assertions.** Any `False` on `admin_plane_open` / `service_open` / `attached_resource_public` requires an enforced-state evidence pointer (security-group/firewall rule ID, listener binding); observation-absence is not enforced state. Joins from scan/inventory are mandatory where the feed exists.

**G-6: two definitional pins.** (a) WAF/ALB-fronted service surfaces are **open** for `service_open` purposes — a WAF is mitigation, not closure. (b) Zone/global resources with no single attached resource: resolved by removing DNSSEC/RSASHA1 from surface (O-11) — integrity-hardening conditions fail the unauthenticated-exercise test (off-path/race preconditions) → NLEV with override available.

**C-2 / O-10: IP-assignment categories move to surface; surface redefined.** `PUBLIC_IP_ADDRESS` and `SQL_PUBLIC_IP` are reachability, not an exercisable surface (IAP-only bastion counterexample); they join against firewall/authorized-network state, unknown → exercisable. A6's surface definition broadened from "SSL/TLS family" to "categories exercisable only when the attached resource is public."

**C-4 / C-8: surface join requires a resource-level feed; CSV-only path made deterministic.** Absent a resource-level inventory/exposure feed, surface categories default to exercisable with an "attachment defaulted" audit marker. One documented category-level inference is permitted: when the attaching exposure control is fully Compliant in the same scan (e.g., `SQL_PUBLIC_IP` = 0 findings), all resources of that type are non-public and the surface finding may join False — evidence, not assumption.

**C-5: data-plane public-grant sub-rule.** A grant to `allUsers` or `allAuthenticatedUsers` on any data-plane surface (Cloud Run invoker, Functions, Pub/Sub, registries) is exposure-class regardless of category name; `allAuthenticatedUsers` satisfies the unauthenticated test (a Google account is self-suppliable). Per-benchmark `add` entries as such categories appear.

**C-6 / O-12: override budget made population-aware.** A10 #6 reframed: <1% of findings may need per-finding surprise overrides, but *standing category-level* overrides (MFA-class, tenant-isolation families in multi-tenant SaaS) are family rules, measured separately; a multi-tenant provider may adopt a benchmark-family NIRV default for tenant-reachable findings with the rationale recorded once.

**O-2 / C-7: EXTERNAL and UNRESTRICTED dropped from the auto-match token set.** Their true positives are carried by PUBLIC/OPEN/INTERNET plus `add` entries; their false-positive rate (API-key pair, `SQL_EXTERNAL_SCRIPTS_ENABLED`, Azure identity recommendations) grows the `remove` table without bound. Token set: {PUBLIC, OPEN, ANONYMOUS, INTERNET, WORLD}. A collision-screen step (grep every category list for token hits, adjudicate each) becomes a normative table-build step.

**O-7: table identity and cadence.** Tables keyed (benchmark, version, scanner); a monthly new-category diff is an operating requirement, not a version-boundary event; A10 #2's "~dozen rows" corrected to an honest per-estate count.

**O-8: grouping rule for reporting.** Weaknesses reported grouped by (benchmark, category, PAIN, column) with affected-resource count; fastest clock governs the group; per-finding records retained in the audit layer. Reporting-layer only.

## Accepted — Minor

**F-8:** N/A disposition documented as auditable out-of-scope with mandatory reportable rationale. **F-9:** addendum stops presenting the scope default as broadly protective (it bites only Major findings). **O-11:** DNSSEC/RSASHA1 out of surface → NLEV default (see G-6b).

## Rejected

**G-7 (matrix change: Moderate×High×exercisable → Disruptive):** REJECTED on the axis-separation constraint — it would let exercisability set PAIN, the exact double-count the method forbids. The accepted mitigations are F-6's evidence-gated escalation (the account-lockout CAT II can be escalated on evidence) and a named residual-risk disclosure in the addendum using G-7's brute-force example. The N5↔N2 boundary on High assets is real and is now documented as the calibration's known cliff, owned by the certifying provider.
**O-9 (exposure raises the grade floor):** rejected, same constraint (see F-1 consolidation).
**O-3 (unknown admin-plane → NLEV):** rejected; loud fail-safe retained for discoverable unknowns (see Accepted-Critical entry).
**O-4 (admin-plane bit gates only a login-plane rule subset):** rejected as baseline — it reintroduces the per-rule mapping A6 exists to avoid. The over-generation on admin-open hosts (a bastion's full CAT II set riding LEV+IRV) is retained as the **named, disclosed error shape** of the host proxy; the login-plane rule-group refinement is documented as an optional governed extension for providers who want it. O-8's grouping rule carries the reporting load.
**O-5 (softer unclassified-host default):** rejected; unclassified → High is the discoverable-unknown doctrine working as designed, and weakening it recreates the silent-under-classification hole. Disclosed as a known flood vector with inventory classification named an operating precondition.
**G-4 (mandatory adjacency graph):** the graph is optional refinement; mandatory form rejected on metadata availability.

## Gate assessment (A10)

Criteria 1, 3, 4 (audit reproducibility, FedRAMP semantics, axis separation): **pass**, reconfirmed by all four reviewers' survived-attack lists. Criterion 2: **pass as amended** (inventory joins and the registry/vocabulary artifacts are now named baseline inputs). Criterion 5: **pass as amended** (vocabulary mechanism makes the unmapped→loud claim true; Moderate prior gated on the registry). Criterion 6: **pass as reframed** (population-aware budget). Criterion 7: **conditionally pass** — the six input-supply divergences in G-6's ten-finding table are closed by the accepted governance fields; the two by-design judgment points (MFA-class override, substitution in the absence of adjacency data) are disclosed as such. **Proceed to Task 5 (addendum) once the accepted code/plan changes land and the full fixture suite passes.**
