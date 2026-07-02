# Reachability Paper Repositioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild `internet-reachability.tex` around the finding-level mathematical model from `tmp/reachability-model.tex`, add the sanitization-as-surface-termination position, and align `vdr-pain-cvss.tex`, the README, and the published PDFs.

**Architecture:** Prose/LaTeX rewrite, no code. The paper is rewritten in place, section group by section group; every task leaves `internet-reachability.tex` compiling under tectonic. Source material is spliced from two places: `tmp/reachability-model.tex` (the math spine — equations, symbol lists, IN PLAIN TERMS boxes) and the current `internet-reachability.tex` (operational gate detail, WAF section, glossary).

**Tech Stack:** LaTeX (tectonic at `/opt/homebrew/bin/tectonic`), git.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-07-02-reachability-reposition-design.md` — every content decision traces to it.
- **Register:** grade 11–12. Math stays prominent; every displayed equation is immediately followed by prose naming each symbol; every major section carries an `IN PLAIN TERMS` box (the `plain` tcolorbox environment already defined in both source files).
- **Vocabulary discipline (never violate):** *internet-accessible* = an entry point that accepts traffic directly from the public internet; *internet-reachable* = FedRAMP's broader per-vulnerability status. Never interchangeable.
- **Style:** flowing prose, no bold-bullet scaffolding, no draft-history framing ("previously this paper said…" is banned; argue positions directly).
- **Commits:** plain `docs:` messages, authored as Matthew Venne. NEVER any Claude/AI attribution or Co-Authored-By line.
- **Compile check after every task:** `cd /Users/matthewvenne/github/rfc-fedramp-vdr && tectonic internet-reachability.tex` must exit 0.
- **New paper title (used in Tasks 1, 6, 7):** *A Finding-Level Model for Internet Reachability under the FedRAMP VDR/VER Rules*.
- Do not touch `internet-reachability-companion-blog.tex` (stale; separate follow-up task per spec §6).

---

### Task 1: Front matter, Introduction, and the new positioning section

**Files:**
- Modify: `internet-reachability.tex` (title block lines 31–33; abstract lines 38–41; §1 Introduction lines 43–50; §2 lines 52–72; §3 Scope Realism lines 74–103)

**Interfaces:**
- Produces: section labels later tasks cross-reference: `\label{sec:position}` (the new positioning section), `\label{sec:scope}` (kept), `\label{sec:model}` (stub added in Task 2). The `plain` box environment and `\code`/`\rfckw` macros are kept unchanged.

- [ ] **Step 1: Replace the title**

```latex
\title{\bfseries A Finding-Level Model for Internet Reachability\\ under the FedRAMP VDR/VER Rules}
```
Keep author and date lines as they are.

- [ ] **Step 2: Rewrite the abstract**

Content requirements (one paragraph, ~250 words, grade 11–12):
1. Open with the stakes: the IRV determination (`FRD-IRV`, `VER-EVA-EIR`) picks the `VDR-TFR-PVR` column; launched 2026-06-24, applies to 20x and Rev5.
2. State the problem: read maximally, FedRAMP's wording — any resource that ever processes internet-derived data hosts internet-reachable vulnerabilities — makes nearly every finding IRV. A determination that returns "yes" for everything prioritizes nothing and buries the provider in documentation and remediation clocks the rules never intended.
3. State the proposal: a finding-level model in which reachability is computed, factor by factor, from an explicit equation — the asset's exposed surface intersected with the delivery shapes the vulnerability actually requires — with every factor evidence-backed and defaulting to reachable when evidence is missing.
4. Name the sanitization position: FedRAMP's own interception note lists *sanitize* among the preventions that remove IRV status; most production applications already sanitize internet-sourced input, and a provider able to demonstrate that sanitization (code review, SAST, DAST, unit tests) on request earns the exclusion for downstream components.
5. Close with the retained WAF posture: perimeter interception is permitted as a downgrade; we still recommend attestation via signed VEX, with the `VDR-TFR-KEV` carve-out.

- [ ] **Step 3: Rewrite §1 Introduction (keep ~3 paragraphs)**

Keep from current: the rules context paragraph (launch date, three evaluations, `VER-RPT-VDT`), and the cost-of-getting-it-wrong paragraph including the `VER-EVA-ELX` "recklessly or deliberately" warning. Replace the third paragraph: instead of announcing the exclusion-gated method, preview the paper's argument — the maximalist reading is unworkable (forward-reference `\ref{sec:position}`), the determination must be a per-finding computation (forward-reference `\ref{sec:model}`), and demonstrable input sanitization is a FedRAMP-named prevention, not a loophole.

- [ ] **Step 4: Write the new positioning section**

```latex
\section{The Problem with ``Everything Is Reachable''}
\label{sec:position}
```

Content requirements (~5 paragraphs + one `plain` box):
1. Quote `FRD-IRV` and its transitive note (reuse the quotations already in current §2, lines 54–61 — keep the block quotes verbatim). Acknowledge plainly: read maximally, this wording sweeps in every component that ever touches internet-derived data.
2. Argue impracticality on prioritization: if the answer is "yes" for essentially every finding, the IRV/NIRV column of `VDR-TFR-PVR` stops discriminating — reuse the Class C matrix table (current lines 78–92, keep `\label{tab:pain}`) to show IRV vs NIRV is a 2×–4× clock difference that the maximalist reading erases.
3. Argue impracticality on burden: every IRV call must be evaluated and reported per vulnerability under `VER-RPT-VDT`; blanket IRV converts that reporting into a treadmill and pulls remediation clocks tight across the whole estate. Cite `VER-EVA-ELX`'s own proportionality statement ("most traditional vulnerabilities discovered by scanners or during assessment are not likely to be exploitable") as evidence the rules are built for discrimination.
4. The pivot — quote the `VER-EVA-EIR` interception note verbatim (currently quoted at line 196): ``intercept, inspect, filter, \textbf{sanitize}, reject, or otherwise deflect triggering payloads before they are processed by the vulnerable resource; once this prevention is in place the vulnerability should no longer be considered an internet-reachable vulnerability.'' Point out that *sanitize* is FedRAMP's word: upstream input sanitization is a named prevention. Most applications already do it; the honest question for a provider is not "does internet data ever flow here?" but "can you demonstrate the sanitization you already perform?"
5. Keep the vocabulary paragraph (current lines 68) verbatim: internet-accessible = entry point; internet-reachable = FedRAMP's broader status.
6. `plain` box, ~5 sentences: FedRAMP's words, taken to the letter, would label nearly everything internet-reachable; a label everything carries means nothing and helps no one. This paper computes reachability per finding from evidence, and treats the input checking your developers already do — when you can prove it — as exactly the prevention FedRAMP says removes reachability.

- [ ] **Step 5: Trim §3 Scope Realism**

Keep the section (`\label{sec:scope}`) but cut the table (moved into `sec:position` in Step 4) and keep the three observations list (LEV gates the tight columns; timeframes are should-level and satisfied by mitigation; the goal is determinism). Update the third bullet's last sentence: the goal is to make each call deterministic, evidence-backed, and auditable — *and proportionate*. Keep its `plain` box.

- [ ] **Step 6: Delete current §2 and stub the model section**

Delete current §2 (Reachability Attaches to Vulnerabilities, Not Resources — its quotes moved into `sec:position`). Add a stub so the file compiles:

```latex
\section{The Finding-Level Model}
\label{sec:model}
% populated in Task 2
```
Leave current §4–§9 (Method Overview through Summary) in place for now; Tasks 2–5 replace them.

- [ ] **Step 7: Compile**

Run: `tectonic internet-reachability.tex`
Expected: exit 0. Broken `\ref` warnings to sections not yet rewritten are acceptable; errors are not.

- [ ] **Step 8: Commit**

```bash
git add internet-reachability.tex
git commit -m "docs: reposition reachability paper against the maximalist reading"
```

---

### Task 2: The finding-level model and computing R(a) via the gates

**Files:**
- Modify: `internet-reachability.tex` — populate `sec:model`; replace current §4 Method Overview (lines ~105–162) and §5 Phase A (lines ~164–236) with the new §\ref{sec:model} and a "Computing the Asset Tag" section.
- Reference: `tmp/reachability-model.tex` §1 (lines 31–91) and §2 (lines 93–174); current Gates 1–5 text (lines 168–236).

**Interfaces:**
- Consumes: `\label{sec:model}` stub from Task 1.
- Produces: labels `\label{sec:model}`, `\label{sec:asset-tag}`, `\label{sec:gate3}` (kept, later tasks and the WAF section reference it); notation `R(a)`, `E(a)`, `X(v)`, `\mathrm{IRV}(v,a)` used by all later tasks.

- [ ] **Step 1: Populate the model section from tmp §1**

Splice `tmp/reachability-model.tex` lines 31–91 into `sec:model`, adapting: the repo paper uses the `plain` environment (same name in both files) and has no `keybox` — add the `keybox` definition to the preamble, copied from tmp lines 13–16:

```latex
\definecolor{boxblue}{HTML}{2C3E50}
\newtcolorbox{keybox}{enhanced,breakable,colback=boxblue!5,colframe=boxblue!55,
  boxrule=0.5pt,arc=2pt,left=8pt,right=8pt,top=5pt,bottom=5pt}
```

The two core equations, verbatim from tmp (factored form, lines 39–46; set form, lines 74–76):

```latex
\[
\boxed{\;
\begin{aligned}
\mathrm{IRV}(v,a)\;=\;&R(a)\ \cdot\ \mathbb{1}\!\left[\mathrm{AV}(v)=N\right]\\
&\cdot\ \mathbb{1}\!\left[\text{protocol/version of }v\text{ on the exposed surface}\right]
\end{aligned}
\;}
\]
```

```latex
\[
\mathrm{IRV}(v,a)\;=\;\mathbb{1}\!\left[\,E(a)\cap X(v)\neq\varnothing\,\right]
\]
```

Keep tmp's symbol bullets and both IN PLAIN TERMS boxes (tmp lines 48–55 and 77–86) — they are already at the target register. Keep the closing paragraph (tmp 87–91) tying the two forms together.

- [ ] **Step 2: Write the asset-tag section from tmp §2, folding in Gates 1–5**

```latex
\section{Computing the Asset Tag $R(a)$: The Five Gates}
\label{sec:asset-tag}
```

Open with tmp §2's framing and equations verbatim (tmp lines 100–107):

```latex
\begin{keybox}
\[
R(a)\;=\;\mathbb{1}\!\Big[\ \exists\,P\in\mathrm{paths}(a):\ \mathrm{reachable}(P)\ \Big]
\]
\[
\mathrm{reachable}(P)\;=\;\mathrm{route}(P)\ \wedge\ \mathrm{open}(P)\ \wedge\ \neg\,\mathrm{auth}(P)\ \wedge\ \mathrm{live}(P)
\]
\end{keybox}
```

Keep tmp's four-condition bullet list, the two-archetype keybox (tmp 125–134), the symbol legend (tmp 136–159), and the "(A) directly on the internet / (B) public load balancer" plain box (tmp 161–174).

Then five subsections mapping each predicate to its gate, carrying over the current paper's operational text:
- `\subsection{Gate 1: Routing — evaluating $\mathrm{route}(P)$}` — current Gate 1 text (lines 168–174) essentially unchanged.
- `\subsection{Gate 2: Source Attribution — evaluating $\mathrm{open}(P)$}` — current Gate 2 text (lines 176–187) including the attribution-not-size exclusion criterion and its plain box; add one bridging sentence: the `/20` threshold in the equation legend is the red-flag trigger, attribution is the decision.
- `\subsection{Gate 3: Edge Authentication — evaluating $\neg\,\mathrm{auth}(P)$}` — current Gate 3 text (lines 189–216) in full, keeping `\label{sec:gate3}`, the (a)–(d) exclusion criterion, the remote-access vs customer-authentication role test, both plain boxes, and the perimeter-is-accessible closing paragraphs. Add one bridging sentence at top: this is the $\mathrm{edgeAuth}(\cdot)$ predicate, evaluated on the host for the direct path and on the load balancer for the LB path.
- `\subsection{Gate 4: Kubernetes and Container Routing — the ingress path family}` — current Gate 4 text (lines 218–231) unchanged, framed as enumerating $\mathrm{pubLB}(a)$/$\mathrm{forwards}(L,a)$ for container estates.
- `\subsection{Gate 5: Process-to-Port Refinement — evaluating $\mathrm{live}(P)$}` — current Gate 5 text (lines 233–236), keeping its hard-limit paragraph but re-pointing its cross-reference from Phase B to the sanitization section (`\ref{sec:sanitization}`, defined in Task 4): a socketless queue worker parsing internet-uploaded files is reachable through the *content* channel unless sanitization evidence says otherwise.

- [ ] **Step 3: Delete the superseded sections**

Remove current §4 Method Overview (the three-phase figure, decision-rule equation at lines 153–158, and its plain box) and current §5 Phase A intro paragraph. The gates now live inside `sec:asset-tag`.

- [ ] **Step 4: Compile**

Run: `tectonic internet-reachability.tex`
Expected: exit 0.

- [ ] **Step 5: Commit**

```bash
git add internet-reachability.tex
git commit -m "docs: restore the factored finding-level equations and refit the five gates as the computation of R(a)"
```

---

### Task 3: Descriptor space and surface propagation, with Sanitize as a fourth hop operation

**Files:**
- Modify: `internet-reachability.tex` — replace current Phase B section (lines ~238–258) and Phase C section (lines ~260–292) with two new sections.
- Reference: `tmp/reachability-model.tex` §3 (lines 197–255) and §4 (lines 257–291); current Phase B/Filter text for salvage noted below.

**Interfaces:**
- Consumes: `E(a)`, `X(v)` notation from Task 2.
- Produces: `\label{sec:descriptors}`, `\label{sec:propagation}`; the four hop operations (Filter, Translate, Authenticate, Sanitize) that Task 4 builds on; the descriptor tuple `⟨κ, τ, π, ν, δ⟩`.

- [ ] **Step 1: Write the descriptor-space section from tmp §3**

`\section{The Descriptor Space}\label{sec:descriptors}` — tmp lines 197–255 essentially verbatim: the tuple, the field table, the wildcard-⋆ semantics, and the three-jobs-at-once bullets (AV gating free, protocol gating, ALPN gating). Salvage from current Filter 2 (lines 277–284): the EternalBlue worked passage — keep it as the running illustration of the π-field: SMB never on the exposed surface of a server that only receives PostgreSQL traffic. Salvage from current Filter 1 (lines 268–275): fold execution evidence in as a short paragraph — a descriptor intersection can only fire in code that runs; `code_not_present`/`code_not_reachable` evidence zeroes the finding regardless of surface, keeping the VEX justification names.

- [ ] **Step 2: Write the propagation section from tmp §4, adding Sanitize**

`\section{Where $E(a)$ Comes From: Surface Propagation}\label{sec:propagation}` — tmp lines 257–291: the transfer-function composition verbatim:

```latex
\begin{keybox}
\[
E(a)\;=\;\big(T_k\circ T_{k-1}\circ\cdots\circ T_1\big)(D_\top)
\]
\end{keybox}
```

Keep tmp's water-pressure plain box. Extend the hop-operations list from three to four:

```latex
\item \textbf{Sanitize} --- a component that validates or sanitizes
  internet-sourced input before handing data onward strips the
  \emph{content-triggered} descriptors it neutralizes from the surface it
  propagates downstream: parameterized queries remove SQL-injection delivery
  (CWE-89), schema validation removes deserialization payloads (CWE-502),
  output encoding removes stored-XSS delivery. Unlike the first three
  operations, which act on network hops, this one acts at a component
  boundary on the \emph{internal} legs of the path --- and it is earned only
  by evidence (Section~\ref{sec:sanitization}).
\end{enumerate}
```

Close with tmp's line: the gates are not a separate method — they are how you compute $E(a)$; and the internal legs (tier-to-tier plumbing) are where Sanitize applies. Salvage from current Phase B (lines 240–254): the declared-vs-observed evidence discipline (NetworkPolicies/SG rules as the declared graph, flow telemetry as the observed graph; observed flows only ever *add* edges; only enforcement rules paths out; quiet telemetry proves the past, not the future) — restated as how you enumerate the internal hops and their transfer functions, keeping the "no permitted path → all descriptors pruned → every finding on the asset NIRV" wholesale case with its enforcement-or-attestation evidence bar. Keep its plain box, adapted.

- [ ] **Step 3: Fold in the content-triggered vs peer-bound split**

From current Filter 3 (lines 286–292): keep the full passage — CWE lists, Heartbleed/regreSSHion vs SQL-i/Log4Shell, the two cautions (stored XSS is content-triggered; ReDoS is not peer-bound) — recast in descriptor terms as a subsection of `sec:descriptors`: peer-bound flaws require the attacker to *hold the connection*, so their required descriptor is never satisfied on internal legs (a new tier-to-tier connection is the intermediary's, not the attacker's); content-triggered flaws ride the data and survive every hop — which is exactly why Sanitize is the operation that stops them.

- [ ] **Step 4: Compile**

Run: `tectonic internet-reachability.tex`
Expected: exit 0.

- [ ] **Step 5: Commit**

```bash
git add internet-reachability.tex
git commit -m "docs: descriptor space and surface propagation with sanitization as a fourth hop operation"
```

---

### Task 4: The sanitization section and worked examples

**Files:**
- Modify: `internet-reachability.tex` — two new sections after `sec:propagation`.
- Reference: `tmp/reachability-model.tex` §5 (lines 293–334).

**Interfaces:**
- Consumes: Sanitize hop operation (Task 3), descriptor notation.
- Produces: `\label{sec:sanitization}` (referenced from Gate 5 in Task 2 and the WAF section in Task 5); `\label{sec:examples}`.

- [ ] **Step 1: Write the sanitization section**

`\section{Sanitization as Surface Termination}\label{sec:sanitization}` — the paper's new center of gravity, ~6 paragraphs + criterion quote + plain box:

1. The reality: production applications do not pass raw internet input to their datastores and workers; they parameterize queries, validate schemas, encode output, check types and bounds. The maximalist reading treats that engineering as if it did not exist. This section makes it count — as evidence, not as assumption.
2. The mechanics (ties to Task 3): a demonstrated sanitization boundary applies a Sanitize transfer function on the internal leg, removing the neutralized content-triggered descriptors from every downstream component's $E$. Per-class granularity: parameterized queries strip CWE-89 delivery but say nothing about CWE-502 deserialization on the same edge; each class's exclusion is earned separately.
3. The exclusion criterion, as a block quote:

```latex
\begin{quote}
\textbf{Exclusion criterion.} A content-triggered vulnerability $v$ (class
$c$) on downstream asset $a$ may be excluded from transitive reachability if
and only if every internal edge that carries internet-derived data toward $a$
passes through a component whose handling of that data neutralizes class $c$,
and the provider can produce evidence of that neutralization on request:
code-review records covering the input-handling paths, SAST results showing
the class is guarded on those paths, DAST or unit/integration tests
exercising the sanitization against class-$c$ payloads. The demonstration is
made to the 3PAO during assessment and to the authorizing agency or FedRAMP
on request.
\end{quote}
```

4. The regulatory grounding: this is not an invented discount — quote the `VER-EVA-EIR` interception verb list again briefly; *sanitize* is on it, and the note's own conclusion ("should no longer be considered an internet-reachable vulnerability") is FedRAMP granting exactly this exclusion. The paper's contribution is the evidence bar that makes the claim auditable rather than asserted.
5. The fail-safe: no evidence, no exclusion. Unknown sanitization → the descriptors propagate intact → IRV. Evidence gaps widen the IRV set, never shrink it. Also the revocation discipline: sanitization claims attach to the code paths reviewed; a major refactor of the input-handling tier re-opens the question, the same way a perimeter change re-opens a WAF claim.
6. Distinguish from the WAF (forward-ref `\ref{sec:waf}`): a WAF sanitizes at the perimeter — a bolt-on device with its own failure modes, which is why Section \ref{sec:waf} recommends attesting rather than downgrading. In-code sanitization is the component's own behavior, shipped and tested with the application; when demonstrated, it earns the NIRV call directly.
7. `plain` box: Your app almost certainly cleans what the internet sends before passing it along — that is what parameterized queries and input validation are. FedRAMP's own rules say a payload stopped before the vulnerable code sees it makes the flaw not internet-reachable. So the question an auditor should ask is not "does internet data ever flow to this database?" but "show me the code review, the scanner results, or the tests that prove the cleaning happens." Show them, and the downstream flaw is off the urgent clock; can't show them, and it stays on.

- [ ] **Step 2: Write the worked examples section**

`\section{The Model, Worked}\label{sec:examples}` — tmp §5's three cases verbatim (AV:L on an internet-facing host; sshd locked to the corporate /24; HTTP/2 rapid-reset behind an ALPN-downgrading LB, including its sole-path precondition note), plus a fourth:

4. **SQL injection on a private-subnet database behind the application tier.** The FedRAMP canonical case. $R(\text{db})=0$ for direct paths, but internet data flows to it through the app tier, so under the maximalist reading its CWE-89 findings are IRV. The app tier demonstrates parameterized queries on every code path that touches request data — code review of the data-access layer, SAST clean for CWE-89 on those paths, integration tests firing injection payloads. The Sanitize hop strips the CWE-89 descriptors: $X(v)\cap E(\text{db})=\varnothing$ → **NIRV**, with the evidence bundle as the audit artifact. The same database's CWE-502 finding in a replication listener is untouched by that evidence and stays IRV unless separately excluded. Without the evidence: IRV, full stop — the fail-safe, not a penalty.

- [ ] **Step 3: Compile**

Run: `tectonic internet-reachability.tex`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add internet-reachability.tex
git commit -m "docs: sanitization as surface termination with demonstration evidence, plus worked examples"
```

---

### Task 5: PAIN plug-in, fail-safe, WAF section, summary, glossary

**Files:**
- Modify: `internet-reachability.tex` — new PAIN and fail-safe sections; retitle/adjust current §8 WAF (lines ~294–322); rewrite §9 Summary (lines ~324–327); extend glossary (lines ~329–378).
- Reference: `tmp/reachability-model.tex` §6 (lines 336–354) and §7 (lines 356–390).

**Interfaces:**
- Consumes: `sec:sanitization`, `sec:gate3`, all notation.
- Produces: `\label{sec:waf}` (kept); complete paper.

- [ ] **Step 1: PAIN plug-in section from tmp §6**

`\section{Plugging into PAIN}` — tmp lines 336–354 verbatim (the three-case column selector and its plain box), with the sentence pointing to the companion memo *A Deterministic, CVSS-Environmental Method…* by title.

- [ ] **Step 2: Fail-safe section from tmp §7**

`\section{Determinism and the Fail-Safe}` — tmp lines 356–390: the coarse-to-fine table gains a fourth row:

```latex
sanitization of internal edges & \textbf{Earned} --- code review, SAST, DAST, unit tests, produced on request \\
```

Keep the fail-safe keybox and plain box verbatim; keep the closing maturity paragraph, extending the ladder: AV:L → NIRV today (free); SSH-not-exposed → NIRV today (SG + sockets); ALPN/sanitization exclusions → NIRV when evidenced, IRV until then.

- [ ] **Step 3: Adjust the WAF section**

Keep current §8 (lines 294–322) with `\label{sec:waf}` and all four paragraphs/bullet blocks, editing only:
- Fix stale cross-references (`Section~\ref{sec:phaseb}`, `Section~\ref{sec:gate3}` → `sec:propagation`/`sec:gate3`; "Phase~B exclusion" → "topology exclusion (Section~\ref{sec:propagation})"; "Filter~1" → "execution evidence (Section~\ref{sec:descriptors})").
- In the "FedRAMP permits the downgrade" paragraph, where the verb-list genericity is discussed ("upstream input sanitization" is already in its example list), add the one-line pointer: in-application sanitization is strong enough to carry its own section (`\ref{sec:sanitization}`) and, when demonstrated, earns the exclusion directly rather than through this section's attestation posture — the perimeter/in-code line drawn per spec §5.4.

- [ ] **Step 4: Rewrite the Summary**

~2 paragraphs: (1) the rules ask a per-vulnerability question, and the answer must discriminate — a determination that tags everything reachable is as useless as one that tags nothing; the factored equation computes each factor from evidence: $R(a)$ from the five gates, the surface from transfer functions, the vulnerability's requirements from its class. (2) Sanitization your developers already perform, once demonstrable, is FedRAMP-named prevention; the fail-safe keeps every unevidenced factor at reachable; the WAF recommendation stands (attest, don't downgrade; KEV clocks bend for nothing).

- [ ] **Step 5: Extend the glossary**

Add in alphabetical position:

```latex
\item[ALPN] Application-Layer Protocol Negotiation (TLS extension)
\item[DAST] Dynamic Application Security Testing
\item[SAST] Static Application Security Testing
```

- [ ] **Step 6: Full-paper consistency pass**

Run: `grep -n "Phase A\|Phase B\|Phase C\|Filter 1\|Filter 2\|Filter 3\|Exclusion-Gated\|exclusion-gated" internet-reachability.tex`
Expected: no hits (all phase/filter vocabulary replaced by model vocabulary). Also `grep -n "ref{sec:" internet-reachability.tex` — every target must exist.

- [ ] **Step 7: Compile (clean)**

Run: `tectonic internet-reachability.tex`
Expected: exit 0, and no undefined-reference warnings in output.

- [ ] **Step 8: Commit**

```bash
git add internet-reachability.tex
git commit -m "docs: PAIN plug-in, fail-safe ladder, WAF attestation posture, and glossary under the finding-level model"
```

---

### Task 6: PAIN paper alignment

**Files:**
- Modify: `vdr-pain-cvss.tex:359-388` (the `definitionbox`), plus the vocabulary hits found in Step 2.

**Interfaces:**
- Consumes: new paper title and factored equation.

- [ ] **Step 1: Rewrite the definition box**

Replace the equation and closing sentence inside the `definitionbox` (lines 368–388). Keep the `FRD-IRV` quotation and per-finding framing (lines 359–367); replace from "The determination is therefore made per finding:" through the end of the box with:

```latex
The determination is therefore made per finding:
\[
\mathrm{IRV}(v,a)\;=\;\mathbb{1}\!\left[\,E(a)\cap X(v)\neq\varnothing\,\right],
\]
where $E(a)$ is the \emph{exposed surface} --- the delivery shapes (protocol,
version, attack-vector class) an internet actor can actually get to component
$a$, computed by pushing the internet's traffic through every routing,
filtering, authentication, and \emph{sanitization} hop on the path --- and
$X(v)$ is the \emph{required surface} the vulnerability needs in order to
fire. Every factor defaults to reachable absent evidence; demonstrated input
sanitization on internal edges (code review, SAST, DAST, unit tests,
produced on request) removes the neutralized vulnerability classes from
downstream surfaces. Two corrections to common intuitions: (a) \code{FRD-IRV}
imposes no unauthenticated requirement --- ``unauthenticated automated
exploitation'' belongs to the \code{FRD-LEV} exploitability floor, not to
reachability; (b) edge authentication (an identity-aware proxy and a client
VPN alike) excludes a backend only in its \emph{remote-access} role, never as
customer authentication for the service itself. The full model, evidence
requirements, and worked cases are specified in the companion paper
\emph{A Finding-Level Model for Internet Reachability under the FedRAMP
VDR/VER Rules}.
\]
```
(Note: the two-corrections text condenses the existing (a)/(b) — keep their substance, drop the criterion-level detail now carried by the companion paper.)

- [ ] **Step 2: Sweep stale vocabulary and title references**

Run: `grep -n "Exclusion-Gated\|taint-excluded\|companion method\|Phase B\|per-vulnerability filters" vdr-pain-cvss.tex`
Fix each hit: the old companion title → new title (there is one at lines 385–387, handled in Step 1 — find any others); "taint-excluded under the companion method" (line ~437) → "surface-excluded under the companion model (no sanitized or unsanitized internal edge delivers its trigger class)"; "per-vulnerability filters" phrasing → "the vulnerability-side factors of the companion model". Keep `IRV_direct` LEV proxy logic untouched.

- [ ] **Step 3: Compile**

Run: `tectonic vdr-pain-cvss.tex`
Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add vdr-pain-cvss.tex
git commit -m "docs: point the PAIN memo at the finding-level reachability model for the full IRV definition"
```

---

### Task 7: README, site index, PDF rebuilds, cleanup

**Files:**
- Modify: `README.md:26` (the internet-reachability table row), `docs/index.html` (blurb if it names the old title/method)
- Create (rebuild): `docs/internet-reachability.pdf`, `docs/vdr-pain-cvss.pdf`
- Delete: `tmp/reachability-model.tex`, `tmp/reachability-model.pdf` (content absorbed; tmp/ is untracked so this is a filesystem removal only)

- [ ] **Step 1: Update the README table row**

Replace line 26's cell text with:

```markdown
| [`internet-reachability.tex`](internet-reachability.tex) | [PDF](https://stackarmor.github.io/rfc-fedramp-vdr/internet-reachability.pdf) | **Companion proposal.** *A Finding-Level Model for Internet Reachability under the FedRAMP VDR/VER Rules* — argues that reading FedRAMP's wording as "everything is internet-reachable" gives no meaningful prioritization, and computes IRV per finding instead: an explicit equation over the asset's exposed surface and the vulnerability's required trigger surface, with five evaluation gates, protocol-aware surface propagation, and demonstrable input sanitization (code review, SAST, DAST, unit tests) as FedRAMP-named prevention that terminates downstream reachability. Retains the WAF-attestation recommendation. |
```

- [ ] **Step 2: Update docs/index.html**

Run: `grep -n "Exclusion-Gated\|exclusion\|reachability" docs/index.html`
Update any card/blurb naming the old title or 5-gate framing to the new title and one-sentence description (same substance as the README row, shorter).

- [ ] **Step 3: Rebuild and publish the PDFs**

```bash
tectonic internet-reachability.tex && tectonic vdr-pain-cvss.tex
cp internet-reachability.pdf docs/internet-reachability.pdf
cp vdr-pain-cvss.pdf docs/vdr-pain-cvss.pdf
```
Expected: both compile exit 0; `git status` shows the two docs/ PDFs modified.

- [ ] **Step 4: Visual spot-check**

Open `internet-reachability.pdf` and check: title page shows the new title; the factored-form boxed equation renders; the keybox styling renders; the sanitization section's exclusion criterion block renders; glossary shows SAST/DAST.

- [ ] **Step 5: Remove the absorbed draft**

```bash
rm tmp/reachability-model.tex tmp/reachability-model.pdf
```

- [ ] **Step 6: Commit**

```bash
git add README.md docs/index.html docs/internet-reachability.pdf docs/vdr-pain-cvss.pdf internet-reachability.pdf vdr-pain-cvss.pdf
git commit -m "docs: rebuild PDFs and update README/site for the finding-level reachability model"
```
(Adjust the `git add` list to what `git status` actually shows — root-level PDFs are only added if the repo already tracks them; check with `git ls-files '*.pdf'`.)

---

## Self-Review Notes

- Spec coverage: §1 positioning → Task 1; §2 structure items 1–11 → Tasks 1–5 (intro/positioning: T1; model + R(a)/gates: T2; descriptors/propagation/sanitize op: T3; sanitization section + examples: T4; PAIN plug-in, fail-safe, WAF, glossary: T5); §3 register → global constraint; §4 PAIN paper → Task 6; §5 decisions carried as written; §6 follow-ups → companion blog explicitly out of scope, index.html and PDFs in Task 7, tmp retirement in Task 7.
- Cross-reference consistency: labels produced/consumed are listed per task; Task 5 Step 6 is the global check.
- No TDD test cycle exists for prose; the compile + grep checks are the per-task verification gates.
