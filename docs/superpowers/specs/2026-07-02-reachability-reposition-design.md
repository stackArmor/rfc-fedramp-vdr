# Repositioning the Internet-Reachability White Paper

**Date:** 2026-07-02
**Files affected:** `internet-reachability.tex` (major rewrite), `vdr-pain-cvss.tex` (definition box + cross-reference), `docs/*.pdf` (rebuilds)
**Source material:** `tmp/reachability-model.tex` (the original math-forward draft, untracked), current `internet-reachability.tex` (operational gate detail to preserve)

## 1. The position change

The current paper embraces the maximalist reading of FedRAMP's wording: every
vulnerability on every asset is presumed internet-reachable, and Phase B taint
sweeps nearly the whole estate into IRV scope unless topology evidence rules a
path out. The repositioned paper argues that reading is not practical:

- If everything is internet-reachable, the IRV determination provides almost no
  prioritization — the column that `VDR-TFR-PVR` exists to differentiate stops
  differentiating.
- Blanket IRV tagging buries a CSP in documentation and remediation timelines
  that the rules never intended. `VER-EVA-ELX` itself says most detected
  vulnerabilities are not likely exploitable; the rules are built for
  discrimination, not blanket classification.
- FedRAMP's own interception note (`VER-EVA-EIR`) lists **"sanitize"**
  verbatim among the preventions that remove IRV status: "intercept, inspect,
  filter, sanitize, reject, or otherwise deflect triggering payloads before
  they are processed by the vulnerable resource; once this prevention is in
  place the vulnerability should no longer be considered an internet-reachable
  vulnerability." Upstream input sanitization is therefore not a loophole — it
  is a prevention FedRAMP names.

The replacement position: reachability is computed per finding by an explicit
per-factor equation (restored from the original draft), and **verified input
sanitization terminates payload propagation to downstream components**.
Most real applications already sanitize internet-sourced input. The paper
asserts that **collecting the evidence of that sanitization is the auditor's
job**: the 3PAO's assessment verifies reasonable sanitization of
internet-sourced inputs to downstream components through SAST, DAST, unit and
integration tests, and code review — the CSP's ordinary SDLC artifacts, not a
new standing documentation burden. The authorizing agency or FedRAMP may
request the same evidence. **Additional scrutiny concentrates on components
that process data from unauthenticated users** — entry points and the
pre-authentication surfaces they feed — rather than uniform suspicion across
the estate. The fail-safe survives: where sanitization (or any other factor)
is not evidenced, the finding stays IRV. Evidence gaps still widen the IRV
set, never shrink it. What changes is that ordinary engineering practice,
verified in assessment, now counts as evidence, instead of only network
topology.

## 2. Paper structure (math spine + gates as computation)

Rebuild `internet-reachability.tex` around the mathematical spine of
`tmp/reachability-model.tex`, keeping the operational material from the
current paper as the "how you compute each predicate" layer. The tmp draft
already states the relationship: "the five gates are not a separate method —
they are how you compute E(a)."

Proposed section flow:

1. **Introduction** — VDR/VER context (condensed from current paper).
2. **The problem with "everything is reachable"** — new positioning section
   (the argument in §1 above). Keeps the reachable-vs-accessible vocabulary
   discipline; acknowledges `FRD-IRV`'s transitive language and answers it
   with the sanitization prevention FedRAMP itself names.
3. **The finding-level model** — from tmp §1: the factored form
   `IRV(v,a) = R(a) · 1[AV:N] · 1[protocol/version exposed]` and the set form
   `E(a) ∩ X(v) ≠ ∅`, each with symbol-by-symbol explanations and IN PLAIN
   TERMS boxes.
4. **Computing the asset tag R(a)** — from tmp §2: OR across paths, each path
   an AND of `route ∧ open ∧ ¬auth ∧ live`. The current paper's Gates 1–5
   become the evaluation procedure for these predicates: Gate 1 → route,
   Gate 2 (attribution-not-size) → open, Gate 3 (edge-auth criteria (a)–(d),
   remote-access vs customer-auth role) → ¬auth, Gate 4 (K8s routing) → the
   LB/ingress path family, Gate 5 → live. All recent Gate 2/Gate 3 substance
   is preserved, restated under the math.
5. **The descriptor space and surface propagation** — tmp §3–4: the
   ⟨κ, τ, π, ν, δ⟩ tuple, wildcard semantics, and E(a) as transfer functions
   composed along the path. **Add "Sanitize" as a fourth hop operation**
   alongside Filter / Translate / Authenticate.
6. **Sanitization as surface termination (new section)** — a component that
   validates or sanitizes internet-sourced input before handing data
   downstream applies a transfer function that strips the content-triggered
   descriptors from the surface it propagates (parameterized queries remove
   SQL-injection delivery; schema validation removes deserialization
   payloads). Downstream components behind a demonstrated sanitization
   boundary are NIRV for the neutralized vulnerability classes. Evidence
   classes: code review records, SAST findings/coverage, DAST results, unit
   and integration tests exercising the sanitization — producible on request.
   Unknown or undemonstrated sanitization → the surface propagates intact →
   IRV (fail-safe). This absorbs the current Phase B: topology absence prunes
   *all* descriptors on a missing edge; sanitization prunes *content*
   descriptors on a live edge.
7. **Worked examples** — tmp §5's three cases (AV:L, SSH-not-exposed, ALPN
   downgrade) plus a fourth: SQL injection flagged on a private database
   behind an application tier that demonstrates parameterized queries — NIRV
   with the evidence, IRV without it.
8. **Plug into PAIN** — tmp §6 unchanged in substance.
9. **Determinism and fail-safe** — tmp §7: progressive refinement table plus
   a row for sanitization evidence maturity.
10. **Perimeter mitigation (WAF)** — current §8 kept: FedRAMP permits the
    downgrade, we recommend keeping IRV + signed VEX attestation; KEV
    carve-out unchanged. Sanitization *at the perimeter* (WAF) stays under
    this attestation posture; sanitization *in the application code* is the
    new §6 factor — the paper will draw that line explicitly.
11. **Glossary** — current glossary, extended (SAST, DAST added).

Title changes to match the framing, e.g. "A Finding-Level Model for
Internet Reachability under the FedRAMP VDR/VER Rules."

## 3. Writing register

Grade 11–12 target, per direction. Math stays forward and prominent, but
every equation is immediately followed by prose naming each symbol, and every
major section carries an IN PLAIN TERMS box (both source documents already
use them; the style carries over). Flowing prose, no draft-history framing,
consistent with the established whitepaper style.

## 4. PAIN paper changes (`vdr-pain-cvss.tex`)

- Replace the `definitionbox` equation (currently the three-phase
  `[direct ∨ transitive] ∧ filters` form) with the factored finding-level
  form, condensed, and state plainly that the full definition, derivation,
  and evidence model live in the companion paper — the PAIN memo carries only
  the summary.
- Update the companion-paper title reference to the new title.
- Leave LEV logic, the `IRV_direct` proxy, and worked examples intact except
  where they name the old phase/filter vocabulary; those references get
  aligned to the new factor vocabulary (e.g. "taint-excluded" →
  "surface-excluded" / "sanitization-demonstrated").

## 5. Decisions made in the user's absence (flag for review)

1. **Structure:** math spine + gates as computation (not a wholesale replace
   that would drop the Gate 2/Gate 3 work, and not math bolted onto the
   current prose structure).
2. **Who owns sanitization evidence:** per Matthew's direction (2026-07-02),
   the paper asserts collecting it is the auditor's job — the 3PAO verifies
   sanitization during assessment via SAST/DAST/unit tests/code review drawn
   from the CSP's normal SDLC artifacts; the agency or FedRAMP may request the
   same evidence. Key support: FedRAMP continuous monitoring already requires
   regular DAST/web-application scanning, so the primary evidence stream
   exists today — no new machinery. Scrutiny concentrates on components
   processing unauthenticated-user data.
3. **How sanitization enters the math:** as a transfer-function hop operation
   (surface termination), not a bare extra boolean factor — it composes with
   the existing E(a) propagation and keeps the per-CWE-class granularity
   (sanitization for injection does not excuse a parser overflow in the same
   downstream component).
4. **WAF posture retained:** perimeter controls keep the attest-don't-downgrade
   recommendation; in-code sanitization is treated as stronger (it is part of
   the component's behavior, not a bolt-on device) and earns the NIRV call
   directly when demonstrated. This distinction is the paper's to defend.

## 6. Out of scope / follow-ups

- `internet-reachability-companion-blog.tex` will be stale after the rewrite
  and needs its own pass (separate task).
- `docs/index.html` blurb text may need a sentence updated.
- PDF rebuilds happen at implementation time, matching repo convention.
- `tmp/reachability-model.tex` gets retired (its content absorbed); whether to
  delete or keep in `tmp/` is a cleanup call at implementation.
