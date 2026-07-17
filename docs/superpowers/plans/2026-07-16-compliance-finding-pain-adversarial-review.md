# Compliance-Finding PAIN and Remediation Method: Adversarial Review Plan

**Date:** 2026-07-16  
**Status:** SUPERSEDED — see `2026-07-16-compliance-finding-pain-strategy.md`.
The severity×asset effect matrix replaces §3.3–3.4; finding-level internet
exercisability replaces §3.6; the §7 test matrix is obsolete.
**Prospective deliverable:** A standalone addendum to `vdr-pain-cvss.tex` covering
security benchmark and compliance findings  
**Primary standards in scope:** FedRAMP 2026 VDR, VER, and Definitions; CVSS v3.1
Security Requirements; CIS Benchmarks; DISA STIG/SCAP content

## 1. Problem statement

FedRAMP treats weaknesses beyond traditional CVEs as vulnerabilities. This includes
security benchmark failures, misconfigurations, exposures, control gaps, and similar
findings. The existing PAIN method derives the potential agency impact of a CVE by
combining the vulnerability's C/I/A impact vector with the affected asset's
CR/IR/AR Security Requirements and multi-agency scope. Security benchmark findings
create a related but different problem:

1. They do not consistently provide a vulnerability impact vector.
2. CIS Benchmarks generally report a recommendation as Pass/Fail and do not assign
   a traditional High/Medium/Low severity. Some commercial scanners add their own
   severity, but those assignments are not uniform across tools.
3. STIG rules generally provide a severity category, and scanners may translate it
   into High/Medium/Low.
4. Available scan metadata normally does not identify a likely threat actor, prove
   that a service is listening, describe an internal abuse path, or state whether a
   failed setting independently creates an exploitable capability.
5. Creating an EPSS-like likelihood grade, exploitability profile, or hand-curated
   rule classification for every benchmark check would be expensive, difficult to
   maintain, and inconsistent with the objective of a simple operational method.
6. Benchmark results have a meaningful rate of false positives, not-applicable
   checks, alternative implementations, compensating controls, and justified or
   accepted deviations. The method must not create noise merely to appear precise.

The requested method should reuse the asset metadata already required by the PAIN
method: `asset-archetype` or direct CR/IR/AR, `multi-agency`, Certification Class,
and internet accessibility. It must work when the scanner reports only Fail, while
also respecting an authoritative Low severity when one is available. It should
reserve N5 for the same class of finding as the CVE method: a potentially
debilitating finding affecting more than one agency on a high-value asset.

The initial proposal was a top-down ladder. Every confirmed finding starts at N5
and receives one or more downgrades for lack of internet accessibility,
single-agency scope, Medium or Low asset value, and Low scanner severity, with N1 as
the floor. For remediation, the initial proposal considered treating likely
exploitability as equal to internet accessibility so that no LEV+NIRV lane would
need to be calculated.

The adversarial review must decide whether that proposal is defensible as written,
whether the final approach below is more faithful to FedRAMP's definitions without
becoming operationally impractical, and where the remaining approximation risk must
be disclosed.

## 2. Governing constraints

Reviewers must test the method against the following constraints rather than against
an imagined richer dataset:

- FedRAMP's definition of vulnerability expressly includes control gaps,
  misconfigurations, exposures, and other weaknesses, not only CVEs.
- PAIN describes the potential customer effect of exploitation. Internet
  reachability and likely exploitability are separate evaluation axes used to select
  a remediation-timeframe column.
- The PAIN words have fixed semantics: Minimal, Narrow, Disruptive, and
  Debilitating. Multi-agency scope changes the mapping only for Disruptive and
  Debilitating effects; Narrow and Minimal may affect one or more agencies without
  moving above N2 or N1.
- FedRAMP requires contextual evaluation but does not prescribe EPSS or another
  specific exploitability framework.
- A production method must be computable from ordinary benchmark scan output and
  existing asset inventory. A method that depends on metadata not normally present
  is not an acceptable baseline.
- Missing asset classification or missing internet-accessibility evidence must not
  silently reduce priority.
- False-positive, not-applicable, fully mitigated, and accepted findings are
  dispositions. They are not substitute severity or exploitability values.

Normative sources to pin when the addendum is drafted:

- [FedRAMP Definitions: Vulnerability](https://github.com/FedRAMP/2026-markdown/blob/main/definitions.md#vulnerability)
- [FedRAMP Definitions: LEV](https://github.com/FedRAMP/2026-markdown/blob/main/definitions.md#likely-exploitable-vulnerability-lev)
- [VER: Estimate Potential Agency Impact](https://github.com/FedRAMP/2026-markdown/blob/main/providers/rev5/rules/vulnerability-evaluation-and-reporting.md#estimate-potential-agency-impact)
- [VER: Evaluation Factors](https://github.com/FedRAMP/2026-markdown/blob/main/providers/rev5/rules/vulnerability-evaluation-and-reporting.md#evaluation-factors)
- [VDR: Mitigation and Remediation Expectations](https://github.com/FedRAMP/2026-markdown/blob/main/providers/rev5/rules/vulnerability-detection-and-response.md#mitigation-and-remediation-expectations)
- [CIS Benchmarks FAQ: Level 1 and Level 2 profiles](https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq)

## 3. Final approach proposed for review

### 3.1 Evaluation and disposition gate

Only a confirmed failed condition enters PAIN calculation.

1. `Pass` is not a finding.
2. A scanner result that does not match the effective state is a false positive.
3. A recommendation that does not apply to the asset's actual role is not
   applicable.
4. A failed configuration that remains present but is neutralized by an effective
   control is fully mitigated; the evidence and retained PAIN are recorded as
   required by the broader method.
5. A weakness that remains and is intentionally justified rather than eliminated is
   an accepted finding. Acceptance does not lower its computed PAIN.

This gate contains benchmark noise. The scoring algorithm must not be weakened to
compensate globally for false positives or justified exceptions.

### 3.2 Derive the asset-value band

Use the affected asset's governed CR/IR/AR Security Requirements. Encode Low,
Medium, and High as the existing CVSS multipliers `0.5`, `1.0`, and `1.5` and compute:

```text
asset_mean = (CR + IR + AR) / 3

Low     when asset_mean < 0.75
Medium  when 0.75 <= asset_mean < 1.25
High    when asset_mean >= 1.25
```

This produces the requested examples:

- `HHM -> High`
- `LMH -> Medium`
- `LLM -> Low`

Missing or unresolved asset metadata defaults to `HHH -> High`. A finding that
reasonably affects a higher-value dependent resource, administrative plane, shared
credential store, or control plane is evaluated against that higher-value affected
resource rather than against a misleadingly low-value point of detection.

The review must challenge both the arithmetic mean and its thresholds. In
particular, reviewers should test whether a single High requirement can be obscured
when the failed check clearly targets that C/I/A dimension. A dimension-specific
refinement may be recommended, but it must remain optional unless ordinary scanner
metadata can support it.

### 3.3 Convert asset value to a customer-effect band

The asset band supplies the default potential customer effect when the benchmark
does not provide a reliable vulnerability impact vector:

| Asset-value band | Default customer effect |
|---|---|
| High | Debilitating |
| Medium | Disruptive |
| Low | Narrow |

This is an impact ceiling and default, not a claim that every benchmark failure
fully compromises the asset. It is a deliberate fail-safe response to missing
finding-impact metadata.

### 3.4 Apply the optional severity adjustment

Severity is an optional downward modifier, never a required input:

- An authoritative or governed `Low` severity lowers the customer-effect band by
  one step: Debilitating to Disruptive, Disruptive to Narrow, or Narrow to Minimal.
- `Moderate`, `Medium`, `High`, `Critical`, unscored, or simple `Fail` supplies no
  reduction.
- The floor is Minimal.
- CIS Level 1 and Level 2 profiles are not finding severities and must not be used
  as this input.
- A scanner-created Low may be credited only when its mapping is documented,
  stable, and governed. Otherwise the finding is treated as unscored.

The proposed method intentionally does not let scanner severity raise the effect
above the value of the assets reasonably affected. A nominally low-value host that
provides a path to a high-value target is handled by the affected-resource rule in
Section 3.2, not by allowing an opaque scanner label to override asset context.

### 3.5 Map customer effect and agency scope to PAIN

Apply FedRAMP's customer-effect semantics directly:

| Customer effect | Single agency | Multi-agency |
|---|---:|---:|
| Debilitating | N4 | N5 |
| Disruptive | N3 | N4 |
| Narrow | N2 | N2 |
| Minimal | N1 | N1 |

This table replaces literal N5-minus-downgrades arithmetic. It gives the same result
as the original proposal for the most common High and Medium cases, while preventing
multi-agency scope from incorrectly promoting a Narrow or Minimal effect.

### 3.6 Select the remediation column with an explicit metadata-limited proxy

Ordinary benchmark results cannot support a full LEV calculation. The method must
state that limitation rather than manufacture unavailable precision. Use this
operational profile:

```text
if internet_accessible is true or unknown:
    column = LEV + IRV
else if provider has affirmative evidence of likely non-internet exploitation:
    column = LEV + NIRV
else:
    column = NLEV
```

Interpretation:

- A confirmed benchmark finding on an internet-accessible resource is presumed LEV
  and IRV for timeframe selection.
- A finding on a resource shown not to be internet-accessible is presumed NLEV.
- LEV+NIRV remains available as an affirmative override when the provider already
  has evidence that a likely tenant, internal, adjacent, or local actor can exercise
  the failed condition. The baseline does not require scanners to generate that
  evidence for every benchmark rule.
- Missing accessibility evidence fails safe to the LEV+IRV column.
- Scanner severity does not determine LEV. Severity approximates impact; the proxy
  above approximates likelihood and exposure.

This is not a claim that LEV logically equals internet accessibility. It is a
documented operational proxy forced by limited benchmark metadata. The review must
determine whether the proxy is conservative enough, whether it creates unacceptable
false negatives for internal attack paths, and whether the sparse LEV+NIRV override
is governable without becoming a hidden per-rule classification project.

Internet accessibility does **not** also lower PAIN. Using the same accessibility
flag to reduce both PAIN and the remediation column would double-discount a single
piece of metadata and could expand deadlines by orders of magnitude.

### 3.7 Select the deadline

Certification Class does not change PAIN. It selects the existing FedRAMP
`VDR-TFR-PVR` table after PAIN and the remediation column have been determined:

```text
deadline = M[Certification Class][PAIN][column]
```

N1 retains no FedRAMP remediation deadline. The addendum must reproduce or reference
the same Class A/B, C, and D tables already pinned in `vdr-pain-cvss.tex`; it must not
invent benchmark-specific day counts.

### 3.8 Minimum audit record

The computed result must be reproducible from these fields:

- benchmark and version;
- rule/check identifier and scanner result;
- disposition and evidence reference, if not an unqualified confirmed Fail;
- affected asset identifier and resolved archetype;
- CR/IR/AR and derived asset-value band;
- single- or multi-agency scope;
- scanner severity and severity provenance, if credited;
- customer-effect band and PAIN;
- internet-accessibility value and source;
- remediation column, including the evidence reference for any LEV+NIRV override;
- Certification Class, evaluation completion time, and calculated deadline.

No per-rule EPSS analogue, attack-path graph, listener inventory, likely-actor label,
or hand-maintained exploitability grade is required by the baseline.

## 4. Decision rationale for reviewers

This section records the public, reviewable reasoning behind the proposal. It is the
decision log reviewers should challenge; it is not private chain-of-thought.

### Decision 1: Do not start at N1 and count upward

Starting at N1 makes missing metadata look safe and requires positive evidence to
raise priority. FedRAMP's customer-effect definitions and the existing PAIN method
use fail-safe defaults. The proposal therefore retains the top-down philosophy:
unknown asset value becomes High, and unscored Fail receives no severity reduction.

### Decision 2: Keep the top-down philosophy, but use the PAIN mapping table

A literal decrement ladder encodes agency scope as a universal one-level modifier.
FedRAMP's definitions do not work that way: multi-agency scope distinguishes N4 from
N3 and N5 from N4 only for Disruptive and Debilitating effects. Narrow remains N2
and Minimal remains N1 for one or more agencies. The effect/scope table preserves
the original N5 reservation without mislabeling low-effect findings.

### Decision 3: Make asset value the default impact signal

The affected asset's CR/IR/AR is the only impact metadata available consistently
across CVE, STIG, CIS, cloud-configuration, and other benchmark findings. For an
unscored benchmark failure, it is more reproducible than analyst intuition or a
scanner-specific label. It represents the consequence ceiling if the failed control
is exercised against that resource.

### Decision 4: Credit reliable Low severity, but do not require severity

Ignoring STIG or governed scanner severity would discard useful information. Making
severity mandatory would make CIS and other Pass/Fail benchmarks impossible to
score consistently. A one-band reduction for Low respects available information
without allowing scanner-specific scales to dominate PAIN.

### Decision 5: Keep internet accessibility out of PAIN

Accessibility changes the probability and urgency of exploitation, not the customer
effect after successful exploitation. FedRAMP already uses reachability and
exploitability to select the remediation column. Lowering PAIN for lack of
accessibility and then selecting a slower column would count the same fact twice.

### Decision 6: Use a disclosed proxy instead of pretending LEV metadata exists

A correct LEV determination would need current actor, path, service, credential,
mitigation, and adverse-capability data. Ordinary STIG/CIS/cloud benchmark results do
not provide it. The proposed accessibility proxy is intentionally simple and
testable. It favors rapid treatment of public exposures while permitting, but not
requiring, an evidence-backed internal-exploitability override.

### Decision 7: Preserve LEV+NIRV as an override lane

Defining LEV as exactly equal to internet accessibility would make all private
tenant, insider, local-privilege, and lateral-movement findings NLEV by construction.
The override retains that valuable distinction without requiring a catalog-wide
classification exercise.

### Decision 8: Handle benchmark noise through disposition

Reducing every benchmark finding because some scanners produce false positives
would understate confirmed weaknesses. False positives, not-applicable checks,
effective alternative controls, and accepted findings have different meanings and
must remain distinguishable in reporting and audit evidence.

## 5. Worked classification expectations

These examples constrain the review. They are not substitutes for the full test
matrix.

### RHEL STIG finding

- Resolve PAIN from the RHEL host's archetype, agency scope, and STIG/scanner
  severity when governed.
- A public RHEL host defaults to LEV+IRV.
- A private RHEL host defaults to NLEV.
- A private host may be overridden to LEV+NIRV when the provider already has
  affirmative evidence of likely tenant, local-user, or adjacent exploitation.
- The method does not require every STIG rule to be pre-tagged as remote, local,
  logging, resilience, or documentation-only.

### Public S3 bucket

- A confirmed publicly accessible bucket defaults to LEV+IRV.
- Account-level or organization-level controls that actually block public access are
  evaluated during disposition as false-positive or fully-mitigating evidence.
- PAIN comes from the reasonably affected data/resource archetype and multi-agency
  scope, not from the word `public` alone.

### Security group open to `0.0.0.0/0`

- If the affected resource is actually internet-accessible, the finding defaults to
  LEV+IRV.
- If inventory establishes that the resource is not internet-accessible, the
  finding defaults to NLEV unless affirmative internal exploitability evidence
  supports LEV+NIRV.
- The baseline does not require listener, route, authentication, or service-abuse
  metadata beyond the governed internet-accessibility result.

### Exported GCP service-account private key

- Merely creating/exporting a key does not itself prove that a likely actor can
  obtain it. A non-public finding therefore defaults to NLEV.
- Known broad internal availability plus harmful permissions supports a LEV+NIRV
  override.
- Known public disclosure or public usability supports LEV+IRV.
- Disabled or deleted keys are handled as mitigation or remediation, not as a lower
  arbitrary likelihood score.

## 6. Required adversarial attacks

The reviewers' job is to break the method, not to polish its prose. Each review must
answer the questions below with a concrete counterexample or state why the proposed
rule survives.

### 6.1 Standards and semantic attacks

- Does using internet accessibility as a proxy conflict materially with FedRAMP's
  definition of IRV, which is broader and finding-specific?
- Is the proxy still acceptable when explicitly scoped to benchmark findings whose
  formats lack trigger metadata?
- Does mapping High asset value to Debilitating effect overstate the meaning of an
  ordinary configuration failure?
- Does the proposed PAIN table ever assign an N-level whose customer-effect or
  agency-count semantics are impossible for the finding?
- Does the method treat accepted, false-positive, and fully mitigated findings in a
  way compatible with VER reporting?

### 6.2 Mathematical and boundary attacks

- Test every one of the 27 CR/IR/AR combinations against the mean thresholds.
- Identify mixed vectors where the mean hides a High requirement relevant to the
  failed check.
- Test all combinations of asset band, Low/non-Low severity, and agency scope.
- Confirm that Low severity never drops below N1 and that N5 is reachable only for
  Debilitating multi-agency findings.
- Compare the result with literal N5-minus-downgrades and document every divergence.
- Quantify deadline changes caused by moving between LEV+IRV, LEV+NIRV, and NLEV for
  every Class and PAIN level.

### 6.3 Metadata-availability attacks

- Can every baseline input be populated from actual scanner output, inventory, and
  governed provider configuration?
- Is internet accessibility available for non-network resources such as service
  accounts, object-storage policies, SaaS settings, and organizational controls?
- If not, does defaulting unknown to LEV+IRV create nonsensical results for resources
  with no network surface?
- Can an accessibility source prove effective public access rather than merely a
  permissive-looking policy fragment?
- Does severity provenance impose more operational work than the value of the Low
  downgrade justifies?

### 6.4 False-positive and gaming attacks

- Can a provider relabel a scanner severity as Low to gain a downgrade?
- Can a provider mark assets single-agency even when a shared control plane affects
  several agencies?
- Can a provider classify a pivot or administrative asset as Low because it stores
  no customer data?
- Can `not internet-accessible` be asserted from lack of observation rather than
  enforced topology?
- Can an accepted exception be used to erase PAIN or the historical evaluation?
- Does the NLEV default for private findings incentivize moving labels rather than
  reducing risk?

### 6.5 Operational and noise attacks

- Calculate the expected distribution of N1--N5 and deadlines on at least one real
  RHEL STIG scan, one CIS scan, and one cloud-configuration scan.
- Determine whether public-host STIG findings flood LEV+IRV even when the failed
  checks are banners, logging details, or other non-exercisable conditions.
- Determine whether private-host NLEV hides high-risk weak authentication, local
  privilege, or credential findings.
- Test whether grouping related findings reduces noise without concealing the
  individual failed controls.
- Measure analyst overrides required per 1,000 findings. If routine operation
  requires widespread LEV+NIRV overrides, the proxy has failed its simplicity goal.

### 6.6 Inter-reviewer consistency attacks

- Give the same ten findings to at least two independent reviewers using only the
  proposed rules and available evidence.
- Compare disposition, asset band, scope, severity credit, PAIN, and remediation
  column.
- Any disagreement must identify an ambiguous rule, missing governed field, or
  irreducible judgment point.
- The method fails determinism review if different reviewers routinely produce
  different results without different evidence.

## 7. Minimum test matrix

The implementation must include machine-checkable fixtures for at least these cases:

| ID | Asset | Scope | Severity | Accessible | Override | Expected PAIN | Expected column |
|---|---|---|---|---:|---:|---:|---|
| T01 | High | Multi | Fail | yes | no | N5 | LEV+IRV |
| T02 | High | Single | Fail | yes | no | N4 | LEV+IRV |
| T03 | Medium | Multi | Fail | yes | no | N4 | LEV+IRV |
| T04 | Medium | Single | Fail | yes | no | N3 | LEV+IRV |
| T05 | Low | Multi | Fail | yes | no | N2 | LEV+IRV |
| T06 | High | Multi | Low | yes | no | N4 | LEV+IRV |
| T07 | Medium | Multi | Low | yes | no | N2 | LEV+IRV |
| T08 | Low | Multi | Low | yes | no | N1 | LEV+IRV, no deadline |
| T09 | High | Multi | Fail | no | no | N5 | NLEV |
| T10 | High | Multi | Fail | no | yes | N5 | LEV+NIRV |
| T11 | Medium | Single | Fail | unknown | no | N3 | LEV+IRV |
| T12 | Low | Single | Low | no | no | N1 | NLEV, no deadline |

Additional paired fixtures must prove that changing only internet accessibility does
not change PAIN, changing only Certification Class does not change PAIN, and changing
only authoritative severity from Fail to Low changes the customer-effect band by
exactly one step.

## 8. Review procedure

### Phase 1: Independent red-team reviews

- [ ] Assign at least one FedRAMP/VDR reviewer, one 3PAO or assessment reviewer, one
  vulnerability-management practitioner, and one cloud/platform security reviewer.
- [ ] Provide this plan, the pinned source text, the existing PAIN memo, and the same
  test fixtures to every reviewer.
- [ ] Require findings in a common format: `issue`, `counterexample`, `severity`,
  `affected rule`, `recommended change`, and `new complexity introduced`.
- [ ] Prohibit prose-only objections that provide no concrete scenario or policy
  conflict.

### Phase 2: Empirical back-test

- [ ] Run the method against representative RHEL STIG, CIS, AWS, and GCP benchmark
  result sets.
- [ ] Record input completeness, PAIN distribution, remediation-column distribution,
  number of dispositions, and manual overrides.
- [ ] Compare deadlines against the original N5-minus-downgrades proposal.
- [ ] Flag any case where the methods differ by more than one PAIN level or more than
  one remediation column.
- [ ] Manually inspect the highest twenty and lowest twenty results for obvious
  misprioritization.

### Phase 3: Adjudication

- [ ] Maintain a decision log for every accepted or rejected review finding.
- [ ] Reject changes that require unavailable baseline metadata unless the review
  proves the field can be generated reliably at scale.
- [ ] Reject changes that silently merge PAIN, exploitability, and accessibility.
- [ ] Require an explicit disclosure for every known approximation retained for
  operational simplicity.
- [ ] Re-run the full test matrix after every algorithm change.

### Phase 4: Addendum drafting

- [ ] Draft the addendum only after the scoring algorithm and proxy survive review.
- [ ] Separate normative method statements from rationale and from illustrative
  examples.
- [ ] Label the internet-accessibility rule as an operational proxy, not as a new
  FedRAMP definition of LEV or IRV.
- [ ] Include the disposition gate, equations, effect/scope table, remediation-column
  rule, audit fields, and worked examples.
- [ ] Add an `IN PLAIN TERMS` box explaining that the method uses the data scanners
  actually provide and fails safe when key metadata is missing.
- [ ] Pin official sources to a reviewed commit/date before publication.

### Phase 5: Repository integration and verification

- [ ] Decide whether the addendum is a new standalone TeX document or an appendix to
  `vdr-pain-cvss.tex`; prefer a standalone companion if it would otherwise obscure
  the CVE-specific mathematical method.
- [ ] Update `README.md` and the document index.
- [ ] Add executable test fixtures for the PAIN and column-selection rules.
- [ ] Build all affected PDFs with `tectonic`.
- [ ] Render and visually inspect every changed PDF page, including tables and
  equations.
- [ ] Run `git diff --check` and verify that unrelated worktree files remain
  untouched.

## 9. Acceptance criteria

The approach is ready for addendum drafting only when all of the following are true:

1. Every output is reproducible from the minimum audit record.
2. No required baseline field depends on per-rule exploitability metadata that
   ordinary benchmark scanners do not provide.
3. The PAIN output always matches FedRAMP's customer-effect and agency-scope
   semantics.
4. Internet accessibility changes the remediation column but never PAIN.
5. N5 is limited to Debilitating multi-agency findings.
6. Low severity is optional, provenance-controlled, and produces exactly one
   customer-effect reduction.
7. Unknown asset value and unknown internet accessibility fail safe.
8. The LEV+NIRV override is evidence-backed and uncommon enough to remain
   operationally manageable.
9. False positives and exceptions are resolved through disposition rather than
   hidden scoring discounts.
10. Back-testing does not reveal systematic flooding of public benchmark findings or
    systematic suppression of important private findings. If it does, the proxy must
    be revised or the limitation must be judged unacceptable.

## 10. Explicitly rejected baseline designs

The following remain available for comparison but are not the proposed baseline:

- **Literal N5-minus-downgrades:** rejected because it promotes Narrow
  multi-agency effects to N3 and double-counts accessibility when combined with the
  timeframe matrix.
- **Start at N1 and add points:** rejected because missing metadata lowers priority
  and because additive points do not naturally reproduce FedRAMP's effect/scope
  semantics.
- **LEV exactly equals IRV with no exception:** rejected because it makes likely
  internal, tenant, adjacent, and local exploitation impossible to represent.
- **Every confirmed compliance finding is LEV:** retained as a conservative
  comparator, but rejected as the default because it puts non-exercisable logging,
  documentation, and resilience findings on aggressive LEV clocks.
- **Per-rule EPSS analogue or exploitability taxonomy:** rejected because benchmark
  formats do not supply the required inputs and maintaining the taxonomy would
  defeat the simplicity objective.
- **Scanner severity determines LEV:** rejected because severity represents impact,
  not exploitation likelihood, and is absent or inconsistent across benchmark
  ecosystems.

## 11. Known limitation to carry into review

The proposed remediation proxy deliberately trades finding-level precision for
implementability. It will over-prioritize some non-exercisable findings on public
resources and under-prioritize some internally exploitable findings on private
resources unless an override is supplied. Adversarial review must determine whether
that error shape is acceptable. The final addendum must not hide it, describe it as
equivalent to a complete LEV evaluation, or imply that FedRAMP itself defines
internet accessibility and likely exploitability as the same concept.
