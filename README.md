# FedRAMP VDR/VER — PAIN scoring method, VLEV & VEX proposals

A deterministic, standards-grounded method for prioritizing vulnerabilities under
FedRAMP **VDR** (Vulnerability Detection and Response) and **VER** (Vulnerability
Evaluation Requirements), plus companion proposals to refine the exploitability axis
and to carry per-finding disposition as VEX.

📄 **[Read the PDFs](https://stackarmor.github.io/rfc-fedramp-vdr/)** — rendered on GitHub Pages.
🧪 **[Development preview](https://stackarmor.github.io/rfc-fedramp-vdr/dev/)** —
the `dev` branch is published here without replacing the production root; see
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the review and promotion flow.
💬 **[Join the discussion](https://github.com/stackArmor/rfc-fedramp-vdr/discussions)** —
feedback, questions, and critique welcome.

The core idea: FedRAMP defines *Potential Agency Impact* (PAIN, N1–N5) and a
remediation-timeframe matrix but leaves the classifier — the function from a CVE on a
specific asset to a PAIN level — unspecified. That classifier already exists, in
standardized form, as the **Environmental metric group of CVSS** (the CR/IR/AR
Security Requirements and the Modified Impact Sub-Score). This work makes the mapping
explicit, deterministic, and auditable. Before the vulnerability math begins, a
separate intended-use derivation maps confirmed NIST SP 800-60 information types to
a dimensional ceiling over each asset's reusable architectural requirements.

## Documents

| Source | PDF | What it is |
|---|---|---|
| [`vdr-pain-cvss.tex`](vdr-pain-cvss.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-cvss.pdf) | **The method.** *A Deterministic, CVSS-Environmental Method for FedRAMP VDR/VER Vulnerability Prioritization* — closed-form PAIN derivation, the VDR-TFR-PVR remediation matrix, worked examples, a reference architecture, and an example asset-archetype catalog. |
| [`vdr-pain-security-requirements.tex`](vdr-pain-security-requirements.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-security-requirements.pdf) | **The upstream derivation.** *Before the PAIN Equation: Deriving Security-Requirements Ceilings from Intended Federal Information Types* — maps confirmed CSO and agency intended use through NIST SP 800-60 and FIPS 199, preserves the full C/I/A vector, separates reusable architectural archetypes from agency consequence, handles affected multi-agency scope, and bounds the hyperscaler approximation. It also separates Certification Class as the provider's operational assurance commitment, defines the agency/CSP contract decision for High-objective use below Class D, and adds an Availability-specific assurance case connecting AR:H to uptime, RTO/RPO, disaster recovery, testing, and contract evidence without prescribing one architecture. |
| [`vdr-pain-calibration.tex`](vdr-pain-calibration.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-calibration.pdf) | **Calibration companion.** *Calibrating PAIN Without Abandoning CVSS: High-Centered Normalization and Standards-Anchored Thresholds* — corrects the Medium-centered normalization defect, derives all three PAIN word boundaries from stated consequence scenarios, treats compound dimensional impact as a transparent vulnerability-breadth proxy without adding CWE as a severity input, documents governed provider variation, exhaustively tests the 729-state lattice, and reports anonymized operational backtests. |
| [`vdr-pain-compliance.tex`](vdr-pain-compliance.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-compliance.pdf) | **Addendum to the method.** *A Deterministic PAIN and Remediation Method for FedRAMP Compliance and Security-Benchmark Findings* — extends the PAIN method to security-benchmark and compliance findings (STIG, CIS, cloud configuration): a severity×asset effect matrix, an internet-exercisability test for remediation timeframes, and governed classifier artifacts — validated by adversarial review and a back-test against a real CIS GCP scan. |
| [`vlev-proposal.tex`](vlev-proposal.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/vlev-proposal.pdf) | **Companion proposal.** *A Finer Exploitability Gradation (VLEV) for FedRAMP VDR/VER* — splits exploitability into three bands (NLEV / LEV / VLEV) aligned to CISA Vulnrichment's `none` / `poc` / `active` states, with the full six-column remediation grid per Certification Class. |
| [`vex-cyclonedx.tex`](vex-cyclonedx.tex) | [release](https://github.com/stackArmor/rfc-fedramp-vdr/releases/latest) | **Companion proposal.** *A CycloneDX VEX Profile for FedRAMP VDR/VER Disposition and Response* — recommends CycloneDX VEX as the machine-readable carrier for the post-detection disposition step (false positive, not-reachable, mitigated, or accepted-with-attested-response), with a VER field mapping, an OCI distribution pattern, and an optional CISA-label crosswalk. |
| [`internet-reachability.tex`](internet-reachability.tex) | [Technical PDF](https://stackarmor.github.io/rfc-fedramp-vdr/internet-reachability.pdf) · [Plain-language companion](https://stackarmor.github.io/rfc-fedramp-vdr/internet-reachability-companion-blog.pdf) | **Companion proposal.** *Internet Reachability at Scale under the FedRAMP VDR/VER Rules* — recommends a present operational profile using direct exposure, reusable CVE-level indirect-trigger promotion, governed entry-point-to-local chain promotion, and standing prevention assertions backed by existing assessment, DAST, and remediation evidence. This produces a conditional convergence toward direct accessibility plus known uncovered indirect triggers and boundary-scoped chained-access cases while preserving each downstream CVSS vector and upstream provenance. A separate non-normative full-information equation documents optional richer interoperability; it is not proposed as a current FedRAMP requirement. |

Rendered PDFs are published on **[GitHub Pages](https://stackarmor.github.io/rfc-fedramp-vdr/)** — or build them from the `.tex` sources as below.

## Building

Lightest local option (single binary, auto-fetches packages):

```sh
brew install tectonic        # one-time
tectonic vdr-pain-cvss.tex         # -> vdr-pain-cvss.pdf
tectonic vdr-pain-security-requirements.tex # -> upstream derivation PDF
tectonic vdr-pain-calibration.tex  # -> vdr-pain-calibration.pdf
tectonic vdr-pain-compliance.tex   # -> vdr-pain-compliance.pdf
tectonic vlev-proposal.tex         # -> vlev-proposal.pdf
tectonic vex-cyclonedx.tex         # -> vex-cyclonedx.pdf
tectonic internet-reachability.tex # -> internet-reachability.pdf
tectonic internet-reachability-companion-blog.tex # -> plain-language PDF
```

Or with a full TeX install: `latexmk -pdf vdr-pain-cvss.tex`. Or paste the `.tex`
into [Overleaf](https://overleaf.com) (no install).

## Scope & status

These are informational documents. The method memo specifies how to satisfy FedRAMP's
existing VDR/VER requirements; the example archetype catalog and the remediation-day
values are illustrative. Each Cloud Service Provider should own its architectural
archetype mapping, while the agency-specific Security Requirements ceiling is derived
separately from confirmed intended federal information use. The VLEV document is a forward-looking proposal for FedRAMP's
consideration, intentionally separate from the method memo. The VEX/CycloneDX document
is an implementation profile: one defensible way to satisfy the existing VER disposition
and reporting requirements, with the choice of format left to the provider.

## Feedback & discussion

Comments, questions, and critique are welcome in
**[GitHub Discussions](https://github.com/stackArmor/rfc-fedramp-vdr/discussions)**.
Start with the pinned welcome thread, or open a new topic — input from CSPs, 3PAOs,
agency reviewers, and the FedRAMP PMO is all valued.

## Author

Matthew Venne, Chief Technology Officer, [stackArmor](https://stackarmor.com).
