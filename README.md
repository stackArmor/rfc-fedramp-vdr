# FedRAMP VDR/VER — PAIN scoring method, VLEV & VEX proposals

A deterministic, standards-grounded method for prioritizing vulnerabilities under
FedRAMP Rev5 **VDR** (Vulnerability Disclosure Report) and **VER** (Vulnerability
Evaluation Requirements), plus companion proposals to refine the exploitability axis
and to carry per-finding disposition as VEX.

📄 **[Read the PDFs](https://stackarmor.github.io/rfc-fedramp-vdr/)** — rendered on GitHub Pages.
💬 **[Join the discussion](https://github.com/stackArmor/rfc-fedramp-vdr/discussions)** —
feedback, questions, and critique welcome.

The core idea: FedRAMP defines *Potential Agency Impact* (PAIN, N1–N5) and a
remediation-timeframe matrix but leaves the classifier — the function from a CVE on a
specific asset to a PAIN level — unspecified. That classifier already exists, in
standardized form, as the **Environmental metric group of CVSS** (the CR/IR/AR
Security Requirements and the Modified Impact Sub-Score). This work makes the mapping
explicit, deterministic, and auditable.

## Documents

| Source | PDF | What it is |
|---|---|---|
| [`vdr-pain-cvss.tex`](vdr-pain-cvss.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-cvss.pdf) | **The method.** *A Deterministic, CVSS-Environmental Method for FedRAMP Rev5 VDR/VER Vulnerability Prioritization* — closed-form PAIN derivation, the VDR-TFR-PVR remediation matrix, worked examples, a reference architecture, and an example asset-archetype catalog. |
| [`vlev-proposal.tex`](vlev-proposal.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/vlev-proposal.pdf) | **Companion proposal.** *A Finer Exploitability Gradation (VLEV) for FedRAMP Rev5 VDR/VER* — splits exploitability into three bands (NLEV / LEV / VLEV) aligned to CISA Vulnrichment's `none` / `poc` / `active` states, with the full six-column remediation grid per Certification Class. |
| [`vex-cyclonedx.tex`](vex-cyclonedx.tex) | [release](https://github.com/stackArmor/rfc-fedramp-vdr/releases/latest) | **Companion proposal.** *A CycloneDX VEX Profile for FedRAMP Rev5 VDR/VER Disposition and Response* — recommends CycloneDX VEX as the machine-readable carrier for the post-detection disposition step (false positive, not-reachable, mitigated, or accepted-with-attested-response), with a VER field mapping, an OCI distribution pattern, and an optional CISA-label crosswalk. |

Rendered PDFs are published on **[GitHub Pages](https://stackarmor.github.io/rfc-fedramp-vdr/)** — or build them from the `.tex` sources as below.

## Building

Lightest local option (single binary, auto-fetches packages):

```sh
brew install tectonic        # one-time
tectonic vdr-pain-cvss.tex   # -> vdr-pain-cvss.pdf
tectonic vlev-proposal.tex   # -> vlev-proposal.pdf
tectonic vex-cyclonedx.tex   # -> vex-cyclonedx.pdf
```

Or with a full TeX install: `latexmk -pdf vdr-pain-cvss.tex`. Or paste the `.tex`
into [Overleaf](https://overleaf.com) (no install).

## Scope & status

These are informational documents. The method memo specifies how to satisfy FedRAMP's
existing VDR/VER requirements; the example archetype catalog and the remediation-day
values are illustrative — each Cloud Service Provider should derive its own from its
system categorization. The VLEV document is a forward-looking proposal for FedRAMP's
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
