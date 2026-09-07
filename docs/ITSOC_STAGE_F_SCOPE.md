# ITSOC Stage F — scope: "a platform that looks like one"

**Opened:** 2026-09-08 by owner request. **Base:** `main` @ `98c2ffc`.
**Predecessor:** Stage E ("legible intelligence") closed 2026-09-03; see `docs/STAGE_E_CLOSEOUT.md`.
**Reactivates the fleet.** Stage E's closeout required a new scope doc to do so. This is it.

---

## 0. The honest framing, first

Stage E built a defensible engine and proved it by attack. What it did not build is a product that
*looks* like the argument it makes. The console is dense, functional, and visibly assembled in
layers — thirteen flat nav items, a 1,838-line Incidents page, ten real design tokens, KPI cards that
read `0` twice out of four.

**Two things must be said plainly before any of this is dispatched.**

**This is new owner scope, not unblocked work.** Every remaining Stage E build item (E2, E3, E5, F1,
F2) is interview-gated, and the gate is Track A — owner-owned. Nothing below moves **A3 · book 3–4
demand interviews**, which the action-cards file calls *"the binding constraint. Everything in Track
B is subordinate to it."* Dispatching Stage F does not change that, and the coordinator should keep
saying so.

**But the case for doing it anyway is real, and it is not vanity.** Track A itself depends on this:
A1's pre-send check is *"README reads well as a first impression"*, A3 says *"demo only if they
ask"* — and a demo is the moment a sovereignty-constrained security lead decides whether this is a
serious product or a research artifact. A UI that reads as assembled undercuts an engine that was
built to be trusted. That is the argument for Stage F, and it is the standard it should be held to:
**does this make the product more credible in a 30-minute call with a security lead who did not ask
for a pitch?** Anything that does not serve that is out.

---

## 1. What is actually wrong — observed, not asserted

From the real running app (CB-1 evidence screenshots, both themes) and the source:

**Structure**
- **13 flat nav items**, no grouping. Findings, Incidents, Cases, Approvals, Intel, Network, Assets,
  Sources, Integrations, History, Reports, Settings — a list, not an information architecture.
- A dead **`EXPERIMENTAL / Command Center · off`** box occupies permanent nav real estate.
- **`Incidents.tsx` is 1,838 lines**; `CopilotRail.tsx` is 1,464. Both are past the point where a
  change can be reasoned about locally — and CopilotRail just took another 173 lines in CB-1.

**Density and redundancy**
- The KPI row is four large cards; on the demo run **two of them read `0`**. Big cards for empty
  numbers is the most expensive whitespace on the page.
- Every incident row carries **both a severity badge and a priority badge** (`HIGH`+`P2`,
  `CRITICAL`+`P1`). One is derived from the other; showing both teaches the reader nothing and costs
  a column.
- Every row carries a **`1 case` chip**. A value that is identical on every row is not information.
- A **`RECENT INCIDENTS` sidebar duplicates the incidents table** that is on screen beside it.
- Two adjacent `CRITICAL` rows on the same entity (`203.0.113.44`) read as duplication whether or not
  they are distinct clusters. If they are legitimate, the UI must say why.

**Craft**
- **~10 real design tokens** (`--bg --ink --bd --acc --crit --ok --radius --sans --mono --shadow`) in
  a 997-line stylesheet. No type scale, no spacing scale, no elevation system — so every new surface
  re-invents its own spacing, and it shows.
- The entity column mixes hostnames and IPs with no typographic distinction.
- The Copilot rail **overlays** the content it is discussing rather than docking beside it.

---

## 2. Non-negotiables — Stage F changes nothing about the engine

Every guardrail in `CLAUDE.md` and `GUARDRAILS.md` applies unchanged. Three matter especially here,
because a UI overhaul is exactly where they get quietly broken:

1. **`web/` is a pure API consumer. It never computes a verdict.** No card below may derive, infer,
   re-rank or "tidy" a severity, priority, agreement or eligibility client-side. If a value is not in
   the API response, the answer is a backend card, not a `useMemo`.
2. **Honest surfaces.** Real data or an honest empty state — never a placeholder, never a skeleton
   that implies data is coming when it is not, never a chart with invented axes. `unparsed / 0 lines
   parsed` stays as ugly and as honest as it is.
3. **No approve affordance outside the approvals surface.** `web/src/test/approvals.test.tsx`
   `SELECTOR-NULL` is a standing check and must pass on every card. A redesign that adds a friendly
   "Approve" button to a card view fails the stage, however good it looks.

And the standing gate: **`scripts/gate.sh --web` GREEN 23/23** on every card, with the suite count
reported. It is currently 44 files / 313 tests; a card that reduces it must say why, in the report.

---

## 3. Track G — the UI overhaul

Ordered. Each card is dispatchable on its own and assumes its predecessors merged.

### G0 · Design system foundation *(no visual change to any page)*
Replace ~10 ad-hoc custom properties with a real token set: a type scale, a spacing scale, elevation,
radii, and a **semantic** colour layer (`--surface-raised`, `--text-muted`, `--sev-critical`) rather
than raw values reused by coincidence. Light and dark defined as one system, not two hand-tuned
themes.

**Acceptance:** every page renders **pixel-unchanged** or with a documented, deliberate diff.
Screenshots both themes, before and after, side by side. This card's value is that it is invisible.
`gate.sh --web` green. *This is the foundation — nothing else in Track G dispatches before it lands.*

### G1 · Information architecture *(the nav, the shell)*
Group thirteen items into a structure with a stated rationale — the likely shape is **Triage**
(Findings, Incidents, Cases, Approvals) · **Context** (Intel, Assets, Network, Sources) ·
**Operate** (Integrations, History, Reports, Settings), but the card owner argues for their own and
justifies it. Remove the dead `EXPERIMENTAL / Command Center` box. Header and run-selector density
pass.

**Acceptance:** every existing route still reachable; no route orphaned. A written rationale for the
grouping. Keyboard navigation through the whole nav. Screenshots both themes.

### G2 · Incidents — the flagship page *(the 1,838-line file)*
The page a security lead will actually look at in a demo. Split the file into components with single
purposes; kill the badge redundancy (one severity representation, not two); remove the universal
`1 case` chip or make it carry information; give IPs and hostnames distinct typography; dock the
Copilot rail beside the content instead of over it; resolve the duplicate-looking `203.0.113.44`
rows — either group them or show why they are distinct.

**Constraint:** severity, priority and clustering come from the API exactly as sent. This card
changes *presentation of* verdicts, never verdicts.

**Acceptance:** no file over ~400 lines when done. Screenshots both themes, plus one with the rail
open. `SELECTOR-NULL` green. Suite count reported.

### G3 · Copilot rail *(the 1,464-line file)*
Split it, dock it, and make the advisory framing visually unmistakable — the ADVISORY label, the
citation-guard line and the "rules own the verdict" footer are the product's whole argument and
should look deliberate rather than appended. CB-1's `LearnedPanel` and its honest-absence states are
part of this.

**Constraint:** CB-1 and CB-1-FIX invariants hold. Values are read from the stored advisory block and
never re-derived at display time — *"two computations of one stored fact drift."*

**Acceptance:** every CB-1 rail test still green with no assertion weakened; the four model-kill
states screenshotted; `SELECTOR-NULL` green.

### G4 · Empty, loading and error states — an audit, not a feature
Every page, every state. This is where "honest surfaces" meets craft: an empty state should say what
is absent and what would fill it, never imply pending data. A failed connector shows its real error.
`0 lines parsed` stays honest and stops looking like a crash.

**Acceptance:** an inventory table of every page × {empty, loading, error, populated}, each either
screenshotted or named as unreachable with the reason. This is the card most likely to find real
bugs — treat a fake-green state as a finding, not a styling task.

### G5 · Accessibility and responsive
Contrast in both themes, focus states, keyboard paths, semantic landmarks, `aria` on icon-only
controls. Behaviour from ~1280px to ultrawide; the kanban board stays bounded and scrolls inside its
own region.

**Acceptance:** an automated pass (axe or equivalent) with results pasted and every remaining
violation named and justified; keyboard-only walkthrough of the Triage group.

### G6 · The first impression *(depends on G0–G5)*
A clean screenshot set of the real running app in both themes, the README rewritten around them, and
a short "what this is" page. **This is the card that actually serves A1 and A3.**

**Acceptance:** real app only — never a mockup, never a staged state (`GUARDRAILS.md`, the F0-EV
lesson). Committed screenshots plus the README diff.

---

## 4. Track H — engineering debt, decided but deferred

### H1 · Build toolchain — `vite` 5 → 8
Closes the accepted HIGH (GHSA-fx2h-pf6j-xcff) and drags `esbuild`. Deliberately deferred at DEP-1
because closing it means the whole build toolchain. **Do it before G2**, not after: a toolchain move
under a redesign makes it impossible to tell which change moved a pixel.
**Acceptance:** suite count unmoved (44/313), `web/dist` A/B compared against the pre-change build as
DEP-1 did, gate green.

### H2 · `react-router` 6 → 7 *(production dependency)*
Moderate advisory, but a production major with real routing-behaviour changes. Its own card, its own
UI verification. **Sequence it with G1**, since both touch navigation — but as separate commits with
separate evidence.

### H3 · Setup-field retirement *(blocked, not forgotten)*
`hookSettings.scripts.setup` is `pnpm install`; sixteen consecutive dispatches have reported setup
failure, absorbed by the standing preamble. When the owner's UI correction lands: verify one clean
setup, then remove the self-install step from `docs/ITSOC_ORCHESTRATOR_PROMPT.md` and log it.
*"A workaround that outlives its cause becomes cargo cult."*

---

## 5. Track I — still gated, listed so nobody re-proposes it

**E2** day-zero history import · **E3** org memory as reviewable rules · **E5** rule-change proposal
queue · **F1** connector matrix · **F2** multi-step runbooks. All **interview-gated**. **OPEN-15**
(the backwards criticality gradient) stays parked and becomes a materially better card once real
dispositions exist via E0/E2.

Do not dispatch any of these on the strength of Stage F reactivating the fleet. Stage F is a UI and
debt stage; it does not un-gate engine work.

---

## 6. Ordering

```
G0  design tokens        ── foundation, blocks everything in Track G
H1  vite 5 → 8           ── before G2, so a toolchain move never hides inside a redesign
G1  information arch     ── with H2 (react-router 7) sequenced alongside, separate commits
G2  incidents            ── the flagship
G3  copilot rail
G4  honest states audit  ── expect real findings here
G5  a11y + responsive
G6  first impression     ── the card that serves A1/A3
```

**One card at a time.** Stage E's standing discipline holds: dispatch, grade by re-running the
evidence yourself, merge, log, push, stand down. See `docs/ORCHESTRATOR_HANDOVER.md` §3 and §4.

---

## 7. How Stage F gets graded

Same shape as Stage E, with two additions specific to UI work:

- **Screenshots are evidence and follow the F0-EV rule.** Real running app, both themes, never a
  mockup, never staged. If a state cannot be reached with real data, say so honestly rather than
  fake it.
- **Every guard must still bite.** A redesign that leaves `SELECTOR-NULL` passing because the
  selector no longer exists has broken the check, not satisfied it. Confirm the check still fails
  when the affordance is reintroduced.

And the standing line, unchanged: **a demonstration that fails is the most valuable outcome
available.**

---

## 8. What this stage is NOT

Not a rewrite. Not a component-library adoption. Not a design-system-as-product exercise. Not new
engine capability, and not a route to un-gating interview-gated work. The detector stays frozen at
`364577c5…4876`; `web/` stays a pure API consumer; rules keep owning severity.

**And it does not book three interviews.** That remains the binding constraint, and it remains
Track A.
