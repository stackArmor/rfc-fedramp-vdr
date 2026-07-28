# PAIN Security-Requirements Ceiling — Publication and Implementation Plan

**Goal:** Make intended federal information use the explicit first step of PAIN
derivation, while preserving reusable asset archetypes, the existing
high-centered PAIN calculation, and the full dimensionality of Confidentiality,
Integrity, and Availability.

**Recommendation:** Publish one new foundational white paper first, then revise
the existing PAIN method and calibration papers to consume it. The new paper
owns the NIST SP 800-60/FIPS 199 derivation and its agency-risk semantics. The
method paper owns the end-to-end PAIN algorithm. The calibration paper owns the
mathematical consequence at the Debilitating boundary. This avoids forcing a
large information-categorization argument into papers whose existing purposes
are already well defined.

**Working title:** *Before the PAIN Equation: Deriving Security-Requirements
Ceilings from Intended Federal Information Types*

**Proposed source:** `vdr-pain-security-requirements.tex`

## 1. Normative model to establish before writing

### 1.1 Keep the FIPS 199 vector and high-water mark distinct

For each applicable information type, retain its applied objective vector:

```text
SCinformation-type = {(C, level), (I, level), (A, level)}
```

For a system, take the maximum independently on each objective:

```text
SCsystem(C) = max applied C across applicable intended information types
SCsystem(I) = max applied I across applicable intended information types
SCsystem(A) = max applied A across applicable intended information types
```

The FIPS 199 high-water mark then names the system's overall impact level:

```text
system impact = max(SCsystem(C), SCsystem(I), SCsystem(A))
```

Consequences:

- A system with any applied High objective is a High-impact system overall.
- A genuinely Moderate system has no High objective.
- The overall label `High` MUST NOT be expanded into `H/H/H`; PAIN retains the
  actual vector, such as `H/M/L`.
- FedRAMP Class is not substituted for the vector. A Class/value divergence is
  either corroboration to resolve or an authorization/categorization mismatch.

This is the precise meaning intended by “do not use the high-water mark” in the
PAIN calculation: do not scalarize the three-dimensional vector. It does not
discard the FIPS 199 rule that any High objective makes the system High overall.

### 1.2 Make intended use, not generic technical capability, the boundary

Define:

- `T_CSO`: information types the Cloud Service Offering is designed and
  authorized to process, including service-generated records needed to operate
  the offering.
- `T_agency`: information types the agency intends and is authorized to process
  through that offering.
- `T_agency,CSO = T_CSO ∩ T_agency`: applicable intended information types for
  that agency's use of that offering.

Uploads, free text, files, and integrations do not add every hypothetically
possible information type. They matter only when the intended use permits the
content or when a governed contamination/spillage scenario is being assessed.
Prohibited or accidental content is handled through data-use restrictions,
spillage procedures, and fail-safe review—not silently added to normal PAIN
categorization.

For each applicable type, begin with the NIST SP 800-60 provisional vector,
apply its objective-specific special factors to the agency's actual use, and
preserve the rationale for every adjustment.

### 1.3 Derive the ceiling at the agency and affected-asset scope

For agency `a` and objective `o`:

```text
agencyCeiling_a(o) =
    max appliedImpact_a,t(o) for t in T_CSO ∩ T_agency,a
```

For asset `x`, let `A_x` be the definite agencies whose data or mission can be
affected through that asset:

```text
assetCeiling_x(o) = max agencyCeiling_a(o) for a in A_x
```

For a single-agency asset, this is that agency's vector. For a genuinely shared
asset, the per-objective maximum across the affected agencies raises only the
dimensions justified by their intended information types.

The existing vector approximation remains useful when type-level membership is
not available:

```text
assetCeiling_x(o) ≈ min(SSO(o), max ASO_a(o) for a in A_x)
```

The paper must label this as an approximation. A type-aware intersection is the
preferred derivation because vector-only `min` can combine unrelated High
objectives from different information types without proving that the agency's
intended use and the offering's intended use actually overlap.

### 1.4 Preserve archetypes as a separate, system-relative input

An asset archetype expresses the affected component's role and consequence
within the CSO architecture. It is not a claim about every possible agency data
type and it is not an intrinsic property of the software product.

Examples:

- a primary system-of-record database may have uncapped
  `CR:H/IR:H/AR:M`;
- an ephemeral cache may have `CR:L/IR:L/AR:L`;
- the same database engine may map differently when used as a session store,
  job broker, or disposable cache.

The mapping is reusable across agency deployments of the same CSO because the
agency-specific intended information types enter through the ceiling, not
through a rewritten archetype catalog.

Use distinct terms throughout:

- **archetype requirements**: the uncapped, system-relative vector;
- **security-requirements ceiling**: the intended-use vector;
- **effective security requirements**: the vector PAIN actually consumes.

For asset `x` and objective `o`:

```text
effectiveRequirement_x(o) =
    min(archetypeRequirement_x(o), assetCeiling_x(o))
```

The ceiling can only lower an archetype requirement; it never raises one.

### 1.5 State whose risk PAIN measures

NIST SP 800-60 and FIPS 199 impact levels describe adverse effect on federal
operations, federal assets, individuals, and the federal mission. PAIN therefore
measures potential impact to the agency/government in the assessed use.

Risk is subjective to the stakeholder:

- information can be Low for federal confidentiality because disclosure would
  have only limited adverse effect on the government's mission;
- the same disclosure may matter more to the CSP's brand, competitive position,
  or corporate reputation;
- that CSP consequence does not raise the agency PAIN calculation unless it
  creates a documented adverse effect on the federal mission, federal assets,
  or affected individuals.

The paper should call this a scope boundary, not a claim that CSP risk is
unimportant.

### 1.6 Bound the hyperscaler and downstream-CSP case

An upstream CSP may support many downstream CSOs without knowing the ultimate
agency customers or intended information types behind each dependency. Requiring
the downstream CSPs to disclose their agency customer lists is unrealistic and
may itself be contractually or operationally prohibited.

Treat this as a compositional evidence problem, not as permission to invent
agency identities:

1. When a downstream CSO can provide a non-identifying, per-objective ceiling
   attestation, the upstream CSP can aggregate those vectors without receiving
   agency names or detailed information-type inventories.
2. When no such attestations exist, a sufficiently broad and heterogeneous set
   of confirmed downstream CSO dependencies should conservatively saturate
   toward the upstream system's authorization envelope:
   - Moderate system: `M/M/M`;
   - High system: `H/H/H`.
3. The saturation vector is an uncertainty approximation, not evidence that
   every downstream use has that vector and not a replacement for a known,
   narrower intended-use profile.
4. The number or diversity threshold that triggers saturation must be governed
   and disclosed. It must not be presented as a result derived by NIST or
   FedRAMP.
5. A High objective still cannot be introduced into a genuinely Moderate
   system. `M/M/M` is the conservative upper envelope for that system; if a
   downstream use actually requires High, that is an authorization-boundary
   mismatch.

This paper should state the approximation and its rationale, then leave a full
cross-CSP composition method to future work. A later profile could standardize a
privacy-preserving assertion containing only the downstream CSO identifier,
authorization impact level, dimensional ceiling, scope, evidence status, and
expiry—without exposing agency customers.

## 2. Downstream PAIN consequence — outside the foundational paper

The ceiling paper stops after deriving the effective Security Requirements
vector. It MUST NOT claim that NIST SP 800-60, FIPS 199, or FedRAMP
categorization independently makes Debilitating impossible for a Low- or
Moderate-impact system.

The following result belongs in the existing PAIN method and calibration papers
because it is a consequence of this project's adopted PAIN calculation:

1. The calibrated Debilitating boundary requires at least one effective High
   requirement aligned with High technical impact, plus a second High technical
   impact aligned with a Moderate-or-High requirement.
2. If the ceiling contains only Low and Moderate objectives, every effective
   asset requirement is at most Moderate.
3. With `CR/IR/AR ≤ M/M/M`, even `C/I/A = H/H/H` produces
   `S_H = 0.918578...`, below the `0.933` Debilitating threshold.
4. Therefore, **under the adopted high-centered PAIN formula and `0.933`
   threshold**, a correctly categorized Low- or Moderate-impact system cannot
   produce a Debilitating customer-effect classification.
5. Because any High objective makes the system High under the FIPS 199
   high-water mark, Debilitating is reachable only in a High-impact system
   (and, under the adopted FedRAMP mapping, a High/Class D offering).

The method and calibration papers must qualify the result carefully:

- This is a PAIN methodology corollary, not a NIST or FedRAMP rule.
- A different PAIN aggregation or threshold could produce a different result.
- High/Class D makes Debilitating *possible*, not automatic.
- A vulnerability still needs the qualifying compound technical-impact pattern
  on an asset whose effective requirements retain the relevant High dimension.
- Multi-agency scope does not create Debilitating. It raises Disruptive from N3
  to N4 and Debilitating from N4 to N5; it can separately raise a shared asset's
  ceiling when the additional definite agency introduces a higher applicable
  objective.

## 3. Publication architecture

### 3.1 New foundational paper

Create `vdr-pain-security-requirements.tex` with these sections:

1. Status, scope, and relationship to the PAIN method
2. The missing first step in the PAIN derivation
3. Risk is stakeholder-relative: agency impact versus CSP impact
4. NIST SP 800-60 information types and provisional vectors
5. Applied special factors and agency responsibility
6. Full C/I/A vectors versus the FIPS 199 overall high-water mark
7. CSO intended-use set, agency intended-use set, and their intersection
8. Single-agency and multi-agency ceiling derivation
9. Archetype requirements versus effective requirements
10. Handoff contract: the effective vector supplied to downstream PAIN methods
11. Worked examples:
    - Moderate vector capped at `M/M/M`;
    - High confidentiality only, preserving `H/M/L`;
    - two agencies where a shared asset rises on one objective;
    - generic free-text capability that does not authorize hypothetical High
      content;
    - government Low impact versus CSP reputational concern.
12. Governance, attestations, evidence, and change control
13. Cross-CSP dependencies and the non-normative hyperscaler approximation
14. Limitations and prohibited overclaims
15. Reproducibility appendix for catalog counts and equations

The foundational paper should end at the handoff vector. It may state that
different downstream PAIN methods can produce different consequences from that
vector, but it should not derive, defend, or advertise the current method's
Debilitating reachability result.

The NIST catalog summary can support:

- 170 records total;
- 168 scored types and two non-scoring delivery mechanisms;
- 11 provisionally containing at least one High objective;
- four provisionally `H/H/H`;
- 94 additional records whose special-factor text contains an explicit
  conditional High path;
- 63 with no explicit provisional or special-factor High path.

Before publication, manually audit the 94 conditional records. Do not present
“105 can potentially be High” as “most uses are High”: a conditional path is not
an applied High objective. Conversely, do not claim that only a small fraction
of types have *any possible* High path, because 105 of 168 have a provisional or
conditional path. The defensible statement is that provisional High is rare and
conditional High requires narrow, affirmative facts. Any claim that only a small
subset of agencies actually meets those facts needs separate evidence or should
be omitted.

### 3.2 Primary PAIN method

Update `vdr-pain-cvss.tex` after the new paper stabilizes:

- add the ceiling, archetype requirements, and effective requirements to
  terminology;
- insert the intended-use ceiling before the current PAIN equation;
- change the math inputs from raw archetype `CR/IR/AR` to effective
  `CR/IR/AR`;
- add the two-stage equation:

  ```text
  effective = min(archetype, ceiling)
  PAIN severity = f(CVSS impact, effective)
  ```

- rewrite the archetype section so data-type categorization belongs to the
  ceiling and architectural role belongs to the archetype;
- revise fail-safe language: an absent ceiling runs conservatively uncapped,
  but is not a fully evidenced agency-specific derivation;
- update worked examples to name the raw archetype vector, resolved ceiling,
  and effective vector;
- add the methodology-specific Debilitating corollary after the effective
  requirements enter the PAIN formula, and cross-reference the foundational
  paper only for the ceiling derivation;
- version the change as a methodology revision rather than an editorial patch.

### 3.3 Calibration paper

Update `vdr-pain-calibration.tex` without re-litigating NIST categorization:

- declare that the 729-state lattice is the unconstrained mathematical domain;
- add a ceiling-constrained reachability section;
- prove that an `L/M`-only ceiling removes all 70 Debilitating states;
- show that the all-Moderate maximum remains Disruptive;
- distinguish “the threshold remains reachable in the complete lattice” from
  “the threshold is reachable in this categorized deployment”;
- update limitations, worked scenarios, implementation guidance, and version
  history.

### 3.4 Plain-language and publication surfaces

After the technical papers:

- update `vdr-pain-companion-blog.tex` with the four-stage story:
  intended use → ceiling → archetype cap → PAIN;
- update `docs/pain-playground.html` so it can show raw archetype,
  ceiling, effective vector, and the High-only Debilitating invariant;
- update `README.md`, `docs/index.html`, build instructions, and published PDFs;
- retire or clearly mark `docs/pain-compound-impact-proposal.md` as historical,
  because its earlier threshold design is now superseded and would confuse this
  derivation.

## 4. Supporting repository alignment

### 4.1 `trivy-plugin-vdr-skills`

Align the security-objectives assessment only after the paper fixes the terms:

- change “optional ceiling” language to distinguish:
  - a complete agency-specific PAIN derivation, which includes a ceiling; and
  - conservative uncapped legacy operation, which remains safe but less precise;
- preserve exact NIST information-type membership for the CSO and each agency,
  not only aggregate SSO/ASO vectors;
- derive each agency ceiling from confirmed overlapping intended types;
- represent the set of agencies applicable to each deployment/tenancy scope;
- support an explicit `downstream-cso-approximation` aggregation basis with the
  confirmed dependency count/diversity evidence, authorization envelope,
  saturation rationale, confidence, expiry, and manual-review requirement;
- retain per-objective maxima and the overall FIPS 199 impact label separately;
- state explicitly that any High objective produces an overall High system;
- reserve `CSO` for Cloud Service Offering and avoid reusing it for “component
  security objectives”;
- update the JSON schema, example, derivation script, validator, and tests in one
  versioned change;
- keep archetype generation separate and reusable.

### 4.2 `trivy-plugin-vdr`

The current plugin already performs:

```text
effective = min(archetype, deployment-wide ceiling)
```

Keep that behavior as the compatibility baseline, then design scoped ceiling
resolution before changing code:

- cluster/default ceiling for homogeneous deployments;
- namespace or workload ceiling for agency-specific tenancy;
- shared-asset ceiling derived from the definite agencies that asset can affect;
- precedence aligned with existing archetype and multi-agency resolution;
- runtime flag retained as an explicit global override;
- reports preserve archetype requirements, resolved ceiling and source,
  effective requirements, recalculation status, and agency scope;
- absent ceiling remains conservative uncapped behavior, but reports can mark
  the derivation as legacy/undeclared rather than implying an agency-specific
  ceiling was assessed.

Do not infer agency information types from a workload name, agency identity, or
the CSO's generic ability to accept arbitrary content.

## 5. Validation gates

### 5.1 Source and terminology audit

- Verify every FIPS 199, NIST SP 800-60, and FedRAMP definition against the
  pinned primary source.
- Distinguish verbatim definitions, paraphrases, and the paper's own policy.
- Verify the mapping from FedRAMP High to Class D used by the method.
- Prohibit `High = H/H/H` language.
- Prohibit “Moderate system with one High objective” language.
- Use “intended and authorized information types,” not hypothetical capability.

### 5.2 Mathematical property tests

Add exhaustive tests for:

- no High ceiling dimension ⇒ no Debilitating result;
- Debilitating result ⇒ at least one High effective requirement;
- any High ceiling dimension ⇒ overall FIPS 199 impact is High;
- adding an agency to a shared asset cannot lower its ceiling;
- adding an agency does not change a single-agency asset's ceiling;
- a ceiling never raises an archetype requirement;
- a High overall label never overwrites the other two vector dimensions;
- vector approximation and type-aware intersection differences are surfaced,
  not hidden.
- a downstream-CSP saturation approximation never exceeds the upstream
  authorization envelope;
- adding a confirmed downstream vector cannot lower an aggregate ceiling;
- absence of downstream customer identities is never represented as evidence
  that no higher-impact use exists.

### 5.3 Artifact and publication checks

- run all security-objectives catalog/schema tests;
- run all plugin scoring/report tests;
- compile every changed TeX document with `tectonic`;
- render and visually inspect every page;
- verify internal references, citations, document index links, and PDF links;
- run `git diff --check` in each repository;
- confirm no unrelated or existing user changes are included.

## 6. Execution sequence

- [ ] **Phase 0 — adjudicate terminology and equations.** Approve Section 1 of
  this plan, especially type-level intersection versus vector approximation and
  asset-scoped multi-agency ceilings. Treat Section 2 only as a downstream
  integration constraint.
- [ ] **Phase 1 — source audit and reproducibility notebook.** Validate the
  official definitions, catalog counts, and conditional-High records before
  drafting the foundational paper.
- [ ] **Phase 2 — write the foundational paper.** Draft, compile, visually
  review, and obtain an adversarial methodology review.
- [ ] **Phase 3 — integrate the primary and calibration papers.** Make the
  ceiling a first-class input, update examples and version histories, and rerun
  all lattice proofs, including the methodology-specific Debilitating
  consequence.
- [ ] **Phase 4 — align the security-objectives workflow.** Version the
  type-aware, agency-scoped artifact and validators.
- [ ] **Phase 5 — design and implement scoped runtime ceilings.** Preserve the
  existing global ceiling as compatibility behavior; add narrower resolution
  only after its schema and precedence are reviewed.
- [ ] **Phase 6 — update the companion blog, playground, README, site, and
  published PDFs.**
- [ ] **Phase 7 — cross-repository release validation.** Run exhaustive tests,
  compare docs to runtime behavior, and publish coordinated version notes.

## 7. Decisions to approve before implementation

1. Adopt the type-aware intersection as normative and retain `min(SSO, ASO)` as
   a documented approximation, or keep the vector approximation normative.
   **Recommendation: type-aware normative.**
2. Scope ceilings per affected asset/tenancy rather than only per deployment.
   **Recommendation: yes; retain a deployment-wide shortcut for homogeneous
   systems.**
3. Treat a declared ceiling as required for a fully agency-specific PAIN
   derivation while keeping omission as conservative legacy behavior.
   **Recommendation: yes.**
4. Publish the derivation as a standalone foundational paper before folding its
   result into the method and calibration papers.
   **Recommendation: yes.**
5. Use the restrained statistical claim: provisional High is rare; conditional
   High is fact-dependent. Do not claim that few information types have any
   possible High path or that few agencies qualify without separate evidence.
   **Recommendation: yes.**
6. Keep the hyperscaler/downstream-CSP saturation model non-normative in this
   paper, using `M/M/M` for Moderate and `H/H/H` for High only as a governed
   uncertainty approximation when downstream dimensional evidence is
   unavailable.
   **Recommendation: yes; defer a privacy-preserving cross-CSP attestation
   profile to future work.**
