# G1 · Information architecture (nav / shell) — worker report

**Card:** Stage F Track G, G1. **Base:** `010a50cf610764c3ae09e05a8cf93995ca429614`
(verified `git merge-base --is-ancestor` — HEAD *was* the base at dispatch, ancestry OK).
**Branch:** `Ankit512/g1-information-architecture` (card said `feat/g1-information-architecture`
— name mismatch only, a WARNING per `GUARDRAILS.md` §9, not a stop).
**Code commit:** `cf1fc5eb043a52bbe577c6ecf42c9ee21f2d7403`.
**Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`, unchanged
before and after. **`web/package.json` / `web/package-lock.json`:** byte-identical throughout
(md5 `6417982e…` / `45886ddb…` at start, after `npm install`, after the harness's `npm ci`,
and at the end).

---

## 0. Setup, as measured — not as assumed

Orca's setup step is still `pnpm install` at the repo root of an npm project whose JS lives in
`web/`; it failed, as the standing preamble expects. `npm --prefix web install` was run instead.
Resolved versions: **vite 5.4.21**, **vitest 3.2.7**, **react-router-dom 6.30.6** — i.e. this card
did **not** move H1 (vite 8) or H2 (react-router 7), which stay separate commits, later.

The card's MEASURED STARTING POINT was grepped rather than trusted, and it was accurate:
`CORE_NAV` 13 items, `EXPERIMENTAL_NAV` 1, `nav-aliases.test.tsx` asserting 13/14,
`tour.test.tsx` mapping `TOUR_STEPS` onto `CORE_NAV` order, and the `is-exp-empty`
"Command Center · off" box asserted by `shell.test.tsx`.

One thing the card did **not** say, and which turned out to matter: **`/command-center` is not a
route.** `grep -n '<Route' web/src/App.tsx` lists twenty paths and none of them is a command
centre. So the dead box was not merely occupying nav real estate — it was advertising a
destination that could never have been navigated to, in any state of the experimental flag.

---

## 1. The grouping, and the argument for it

```
        Overview                        home — the wordmark points here, the tour starts here

TRIAGE  Findings · Incidents · Cases · Approvals
CONTEXT Intel · Network · Assets · Sources
OPERATE Integrations · History · Reports · Settings

        Experimental  1  [OFF]         one disclosure row (OEM Engine)
```

### Why three groups, and why these three

The test is Stage F §0's: **does this make the product more credible in a 30-minute call with a
security lead who did not ask for a pitch?** A security lead in that call is not browsing an app;
they are asking three questions in sequence, and the nav should answer them in that order.

- **Triage — "what happened, and what do I do about it?"** This is the work. It is also the
  demo's spine: a finding becomes an incident, an incident earns a case, a case proposes an
  action that needs approval. Putting those four adjacent means the demo walks *down one group*
  instead of hopping a flat list, and the product's central claim — that a rule-owned verdict
  ends at a gated, human-approved action — is legible from the nav alone.
- **Context — "what else do I know about the things involved?"** These are lookups you make
  *about* something in Triage, never the reason you opened the app. Demoting them from peers of
  Incidents to a named second tier is the honest description of how they are used.
- **Operate — "how is this workspace wired, and what leaves it?"** Configuration and egress.
  For a sovereignty-constrained buyer this group is not filler: Integrations, History, Reports
  and Settings are collectively the answer to "what does this thing send anywhere", and they are
  more persuasive named as one thing than scattered.

Overview is **not** in a group. It is the home surface — what the wordmark points at, what
`TOUR_STEPS[0]` is, and the only item that is a summary of the other twelve rather than a peer
of them. Making it a member of Triage would have been tidier and less true.

### Why the order inside each group is not alphabetical

- **Triage** follows the analyst's escalation path, which is also the demo path.
- **Context** runs **outside-in**: external intel → the network we observed → the assets we own
  → the collectors that fed this run. That is decreasing distance from our own estate, and it
  ends on provenance, which is where a sceptical buyer wants to end.
- **Operate** runs inbound wiring → the stored past → what goes out → what governs both.

### Where I deviated from the card's suggested shape, and why

The card's likely shape put Context as *Intel, Assets, Network, Sources*; I use *Intel, Network,
Assets, Sources*. Two reasons, and the second is the load-bearing one:

1. Outside-in reads better than Intel → Assets → Network → Sources, which crosses from external
   to internal to external to internal.
2. **It keeps the flattened `CORE_NAV` order byte-for-byte identical to the pre-G1 flat nav.**
   `web/src/lib/tour.ts` is **outside this card's allowlist**, and `tour.test.tsx` asserts
   `TOUR_STEPS.map(route) === CORE_NAV.map(to)`. Swapping Network and Assets would have forced
   either an out-of-allowlist edit to `lib/tour.ts` or a weakened tour assertion. Neither is
   worth a nav ordering that is, at best, a coin toss. `SpotlightTour.tsx` and `tour.test.tsx`
   are therefore **untouched**, and the tour still walks the nav in visual order.

### `CORE_NAV` is now derived, not maintained

`NAV_GROUPS` is the source of truth; `CORE_NAV = [HOME_NAV, ...NAV_GROUPS.flatMap(g => g.items)]`.
Both `TOUR_STEPS` and the nav tests compare against `CORE_NAV`, so a hand-kept second copy is
precisely how the rendered nav and its tests drift apart without either side going red. A new
test asserts the derivation itself.

Each group also carries a `rationale` string, rendered as the section's `title`, so the grouping
explains itself in the product and not only in this report. A test asserts every group has one.

**No verdict is derived.** Grouping a link says nothing about the data behind it: no severity,
priority, eligibility or agreement is computed, re-ranked or tidied anywhere in this diff
(Stage F §2.1).

---

## 2. The dead box, and how OEM Engine stays reachable

Removed: the dashed `is-exp-empty` panel reading `Command Center · off`, plus its CSS rule and
the now-unused `.is-nav-group` rules.

Replaced by **one disclosure row**: `Experimental  1  [OFF]`, a real `<button>` carrying
`aria-pressed`, `aria-expanded` and `aria-controls`, whose tooltip names exactly what is hidden
and where to find it. The `1` is the live `EXPERIMENTAL_NAV.length`, so the row cannot lie about
how much it is hiding.

**OEM Engine was never gated by that box, and is not gated now.** `CommandPalette.tsx` lists
`nav-oem` unconditionally and `App.tsx` registers `<Route path="oem">` unconditionally; the
toggle only decides whether the *sidebar advertises* it. `CommandPalette.tsx` therefore needed
**no change at all** — it is in the allowlist and is untouched, and all six aliases (Threat
Intel, Enrichment, Discovery, Vulnerabilities, Collectors, Cases) land where they always did.
Both facts are now asserted rather than assumed (§4).

---

## 3. Header / run-selector density — subtractive, not compressive

- `RunSwitcher` and `RunHistory` were two separately bordered buttons doing one job: saying which
  run is loaded and letting you change it. They are now segments of **one** bordered provenance
  cluster (`role="group"`, `aria-label="Loaded run"`).
- `Refresh` becomes icon-only — still named for assistive tech (`aria-label`), still explained on
  hover.

**Nothing provenance-bearing is hidden.** The loaded run's filename, its `· unparsed` marker, the
full history popover, and RunHistory's own honest `— unreadable` row (which the selector does not
have, and which is why the two controls were *not* merged into one) all remain.

### Two density changes I made and then deliberately reverted

**(a) Shrinking the bar itself.** I first also took `.is-top` from `min-height:58px / padding:10px`
to `52px / 8px`. Measured consequence: **every page body on every route reflowed**, and the
before/after delta went from 1.85M changed pixels to **5.23M**. Stage F §4 makes exactly this
argument about H1 — *"a toolchain move under a redesign makes it impossible to tell which change
moved a pixel"* — and it applies to a header height under an IA card just as well. Reverted. G1's
density comes from removing header *objects*, not from compressing the bar, so G2 can still
attribute its own pixels to itself.

**(b) A cluster that cost a pixel.** With the bar's height restored, five routes *still* shifted
their entire body down by exactly 1px. Measured, not guessed: a 2D shift search found `dx:0,
dy:+1` with a **zero-pixel residual over 655,200 sampled pixels**. Cause: the cluster's border +
padding made its natural height 38px, and on the five routes whose header title has **no
subtitle** (`/`, `/alerts`, `/findings`, `/incidents`, and the not-found placeholder) the bar's
height is governed by the actions row rather than by a two-line title. Fixed by making the
cluster height-neutral (`height:32px; padding:1px`, inner buttons `28px`). Content-region shift
after the fix: **zero on every route**.

Both are in the commit's final state; both are recorded here because the *measurement* is the
point, not the tidy end state.

---

## 4. Every route still reachable — asserted, not claimed

`web/src/App.tsx` declares twenty in-shell paths. The new test
`(a3) G1 · no orphaned route — every route in App.tsx is reachable` carries the full census and
checks each claim against the **real rendered UI**, not against the constant:

| Route | Reached by | Checked how |
|---|---|---|
| `/` `/alerts` `/incidents` `/cases` `/approvals` `/intel` `/network` `/assets` `/sources` `/integrations` `/history` `/reports` `/settings` | grouped sidebar nav | the rendered `<aside>` has a link with that label and that `href` |
| `/oem` | ⌘K palette, with Experimental **off** | absent from the sidebar **and** present as a palette option |
| `/logout` | shell footer | rendered link `href="/logout"` |
| `/findings` | alias → `/alerts` | alias block (b)/(c), unchanged |
| `/threat-intel` `/enrichment` | alias → `/intel` | alias block (b)/(c), unchanged |
| `/discovery` `/vulnerabilities` | alias → `/network` | alias block (b)/(c), unchanged |
| `/collectors` | alias → `/sources` | alias block (b)/(c), unchanged |

The census is also asserted **exhaustive over the nav**: no `NAV` entry may point at a route the
census does not list, so adding a nav item without classifying it fails the test.

Independently, all twenty routes plus `/login`, `/signup` and a wildcard were **photographed
rendering** in both themes on the post-change build (§6). A route that renders in the production
SPA is not orphaned by the nav change.

---

## 5. Keyboard

No new keyboard mode was invented. Group headings are plain `<div>`s inside `role="group"` with
`aria-labelledby`, so they label the section for assistive tech **without consuming a Tab stop**;
the anchors are ordinary `<a>` elements in DOM order. The Tab path is therefore exactly what it
was, only grouped.

Asserted by a new test, `keeps a plain Tab path through the whole grouped nav, in CORE_NAV order`:
starting from the ⌘K pill, the next `CORE_NAV.length` Tab stops are the thirteen nav links, in
order, each verified by `href` **and** label; the following stop is the Experimental disclosure
button. This test also proved load-bearing — it was one of the two guards that caught mutation M2
(§7).

The experimental disclosure is a real button (Enter/Space), replacing a `div[role=button]` with a
hand-rolled `onKeyDown` that handled Enter but not Space.

---

## 6. Pixel evidence — real production SPA, both themes

**Method.** Every capture: real `log_analyzer.py --rules-only` run over
`tests/eval/cases/pos_bruteforce_compromise.log` (7/7 lines parsed, 2 findings, 0 from the model)
→ `npm run build` → `web/dist` served by **`console/serve.py`** → headless Chrome 152 over CDP,
1500×1000, `en-GB`, UTC, sRGB, fonts loaded, network idle, and **two byte-identical consecutive
screenshots** per state. No region masked, no state staged, no mockup anywhere.

The harness is the **already-graded G0 one**, copied to `G1-evidence/capture-visuals.mjs` with
only the evidence-tree path and the required-artefact list changed (G1 photographs the nav, so it
requires `AppShell.tsx` and `CommandPalette.tsx` to exist at HEAD before capturing — the
photograph-the-tree rule). The comparator is `G0-evidence/diff-visuals.mjs` run **unmodified**,
parameterised by its own documented env vars; reusing a comparator that was already attacked and
repaired beats forking a fresh one.

Both sides share **one frozen report payload** (`G1-evidence/frozen-run/report.json`), so the
comparator's `captureSettings` guard passes and a pixel verdict is attributable to the code
rather than to a fresh run's `generated_at`.

**Coverage.** 24 routes × 2 themes = **48 states per side**, which is more than the card asked
for (Overview + Incidents + one per group): Overview, all four Triage screens, all four Context
screens, all four Operate screens, OEM Engine, every alias route, login, signup, logout and the
wildcard. Side-by-side sheets: `G1-evidence/diff/<theme>-<slug>.png`.

### The verdict, and what it is attributable to

`visual-diff-inventory.json`: **48 states compared, 44 changed, 4 byte-identical.** The four
identical states are `/login` and `/signup` in both themes — the only two routes that render
**outside** the AppShell. That containment is the first evidence that the change did what it says.

"VISUAL DELTA PRESENT" is the *expected* verdict for an IA card, but expected is a claim, and a
claim about a tree gets measured (`GUARDRAILS.md` §6). `G1-evidence/attribution-shift.mjs` splits
every changed state into **sidebar** (`x < 224`), **header** (`x ≥ 224, y < 58`) and **content**
(the page itself), and two controls say which side of the change each region belongs to:

| Control | What it holds constant | Result |
|---|---|---|
| `after` vs `after-repeat` | same post-change tree, adjacent sessions | **47/48 byte-identical**, 4 changed pixels total — the harness is deterministic |
| `before` vs `before-repeat` | **the same base tree `010a50c`, no code change at all**, two sessions | 42/48 changed, 2,284,637 pixels — every bound at `minX ≥ 248` |

| Region | Under G1 | Under the no-change control | Verdict |
|---|---|---|---|
| Sidebar | 44/44 states changed | **0/44** | **Attributable to G1** |
| Header | 44/44 states changed | **0/44** | **Attributable to G1** |
| Content | 2,088,117 px | 2,284,637 px | **Not attributable to G1** |

For **40 of 44** states the content-region delta under G1 is **identical pixel-for-pixel** to the
delta the base tree produces against itself (`/integrations` 132,101 both ways; `/intel` 105,321;
`/cases` 74,134; `/collectors` 47,381; `/settings` 44). The four that differ are `/alerts` and
`/findings` in both themes, where **G1's delta is smaller than the control's** (123,791 vs
172,929 light; 125,804 vs 174,926 dark) — the same non-deterministic surface landing in a
different state, not an extra G1 effect. Full per-state table:
`G1-evidence/visual-attribution-summary.json`.

### Deliberate visual deltas — the complete list

1. **Sidebar: three group headings appear.** `Triage` / `Context` / `Operate`, 9.5px uppercase in
   `--mut2`. Their vertical cost is paid for by taking nav-row padding 7px → 5px and the sidebar
   gap 12px → 10px, and the net is measured rather than asserted: on `/settings` (light) the last
   non-background sidebar row above the footer moves from **y=655 to y=651**, so the grouped nav
   ends 4px *higher* than the flat one did despite carrying three new headings.
2. **Sidebar: the dashed `Command Center · off` box disappears**, replaced by a single
   `Experimental 1 [OFF]` row.
3. **Sidebar: `overflow-y:auto`.** A grouped nav is taller than a flat one; without this a short
   viewport would clip the footer instead of scrolling to it.
4. **Header: the two run controls gain a shared border and lose their individual ones.**
5. **Header: `Refresh` loses its text label**, keeping `aria-label` and `title`.
6. **Header: actions gap 8px → 6px, bar gap 16px → 12px.** Header region only; the bar's own
   height and padding are unchanged, which is why no page body reflows.

Deltas 1–3 are why every route's sidebar region changed; 4–6 are why every route's header region
changed. No token in the G0 registry was redefined — every new rule consumes existing tokens.

### A finding this card did not cause and does not fix

The `before` vs `before-repeat` control is itself a Stage F finding, and it is the more important
half of §6: **42 of 48 route-states differ between two capture sessions of an identical tree
served an identical frozen report**, every difference confined to the content region
(`minX ≥ 248`, never the sidebar). `/integrations` is the clearest case — the connector grid's
first column is stable while columns two and three carry different connectors in different
positions (`diff-base-control/light-integrations.png`). G0 saw a small version of this and
annotated 11 antialiased pixels on `dark:integrations`; measured across a full route matrix it is
much larger than 11 pixels and is ordering, not antialiasing.

This is not a G1 regression — it reproduces with **no code change whatsoever**. But it will make
G2's and G3's pixel evidence materially harder to attribute, and it is exactly the class of thing
G4 owns. Flagged for the orchestrator; **not** annotated away. `G1-evidence/diff-annotations.json`
is deliberately empty, and says why: the G0 comparator's contract is that an entry may be
annotated only with evidence a delta is *not* attributable to the change under test, and
inheriting G0's default annotations file would have applied G0's `dark:integrations` finding to a
run it was never measured on.

---

## 7. SELECTOR-NULL still has bite — and a gap it did not cover

Full proof, with the failing output, in `G1-evidence/selector-null/mutation-proof.md`.

- **M1** planted `data-testid="approval-approve"` on the advisory Copilot rail. **Three** guards
  fired, including `approvals.test.tsx` SELECTOR-NULL. Reverted; `git status` clean.
- **M2** planted the same control in **G1's own surface**, the app shell. It was caught — but by
  the accent-button budget and by G1's new keyboard test, **not** by any `approval-approve`
  assertion. Every member of that family renders an advisory component in isolation; **none
  renders the `AppShell`.** Persistent chrome on every route was outside the guard's reach.

That gap is closed inside this card's allowlist by a new `shell.test.tsx` assertion,
`SELECTOR-NULL (shell) — the app shell carries NO approve control off /approvals`, which fails
with M2 planted and passes with it removed. The check was extended, never satisfied by deletion.

---

## 8. Gate

**`scripts/gate.sh --web` — GATE GREEN, 23/23 PASS, 0 FAIL, 0 SKIP.**
Evidence: `gate-logs/20260910-083402/`, run on the committed tree `cf1fc5e`.

```
PASS run_eval · validate_real_selftest · threat_intel · test_auth_security ·
     test_copilot_workspace · test_overview · test_fsafe · test_mcp · test_intake ·
     test_audit_drift · test_ti_oem_egress · test_stage_e_wall · test_e7a_feature_contract ·
     test_battlecard_efficacy · test_approvals · test_attack_generator · test_train_triage ·
     test_efficacy_harness · test_console · test_recommend · web_vitest · web_build ·
     detector_freeze
```

**Vitest: 45 files / 328 tests, all passing. No reduction — +5 tests, no file added, no
assertion weakened.**

The base count was measured, not inferred: the three test files this card touches held **25**
tests at `010a50c` (`Tests 1 failed | 24 passed (25)` on the first run after the code change,
the one failure being the intended `Command Center` assertion), and hold **30** now. No other
test file was modified, so the base total was 45 files / 323 tests. Stage F §2's "44 files /
313 tests" predates G0 and is stale at this base.

The five added tests:

1. `nav-aliases` — `(a2) CORE_NAV is derived from the groups the sidebar actually renders`
2. `nav-aliases` — `(a3) no orphaned route — every route in App.tsx is reachable`
3. `shell` — `renders the G1 nav groups, with Overview above them as home`
4. `shell` — `keeps a plain Tab path through the whole grouped nav, in CORE_NAV order`
5. `shell` — `SELECTOR-NULL (shell) — the app shell carries NO approve control off /approvals`

The one **replaced** test is `houses Experimental group and toggles its visibility`, which
asserted the dead box's text. Its replacement,
`houses Experimental as one honest disclosure row — no dead 'Command Center' box`, keeps the
original toggle assertions and **adds**: the dead box is gone, `aria-pressed` tracks the flag,
the badge's count matches `EXPERIMENTAL_NAV.length`, the experimental screens are absent from the
sidebar while off **but present in the palette**, and toggling back off re-hides them and leaves
no box behind. Strictly stronger.

---

## 9. Allowlist and hygiene

| File | State |
|---|---|
| `web/src/components/layout/AppShell.tsx` | changed |
| `web/src/styles/itsoc.css` | changed (nav grouping + density only; G0 token registry untouched) |
| `web/src/test/nav-aliases.test.tsx` | changed |
| `web/src/test/shell.test.tsx` | changed |
| `web/src/components/CommandPalette.tsx` | **unchanged** — `/oem` and every alias were already unconditional |
| `web/src/components/SpotlightTour.tsx` | **unchanged** — `CORE_NAV` order preserved |
| `web/src/test/tour.test.tsx` | **unchanged** — passes as written |
| `docs/STAGE_F_REPORTS/G1-worker.md`, `docs/STAGE_F_REPORTS/G1-evidence/**` | added |

`git diff --check` clean. Nothing outside the allowlist. `web/dist` not committed (gitignored).
No npm dependency added; the evidence helpers are dependency-free Node scripts, and
`attribution-shift.mjs` reuses the PNG decoder already committed in the G0 harness verbatim rather
than reimplementing one. `graphify update .` run after the code edits (4758 nodes, 7893 edges).
Staged with explicit paths — no `git add -A`, no merge, no push.

**Not started, per the card:** H1 (vite 8) and H2 (react-router 7).

Evidence volume: 49MB, 301 PNGs (G0's precedent: 80MB, 455). The one thing dropped is the
`after` vs `after-repeat` side-by-side sheets — that comparison is 47/48 byte-identical, so the
sheets carry no information; its inventory (`visual-noise-control.json`, with a sha256 per image)
is kept.

---

## 10. For the orchestrator

1. **Ratify or reject the Context ordering deviation** (Intel · Network · Assets · Sources rather
   than the card's Intel · Assets · Network · Sources). The argument is §1; the practical benefit
   is that `lib/tour.ts` — outside the allowlist — needed no edit and no tour assertion was
   weakened.
2. **The cross-session content non-determinism (§6) wants a card.** It is not G1's and G1 does not
   fix it, but it degrades every subsequent Track G card's pixel evidence. G4 is the natural home.
3. **The SELECTOR-NULL family did not cover the app shell** (§7). G1 closed it for the shell;
   whether other persistent chrome is likewise uncovered is worth one grep before G2 lands.
