# CARD G0 — design system foundation

**Branch:** `Ankit512/g0-integration` (card named `feat/g0-design-system`; name mismatch only, WARNING).
**Base:** `bdbd496c5b082b92eec09af8554600561e132b84`, verified an ancestor of HEAD before any edit.
**Detector:** `anomaly_detector.py` sha256 `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`
— verified before work, after work, and by `scripts/gate.sh`'s own `detector_freeze` gate.

**Outcome: complete, gate green, zero visual delta attributable to the change.**

---

## 0. The corrected premise this card was dispatched with

The dispatch corrected an earlier mis-measurement, and the correction holds:

- `web/src/styles/itsoc.css` was **997 lines** at base (`998` counting the trailing newline as a line).
- The two CSS layers declared **49 distinct custom-property names**, *not* "about 10".
- There was **no** `--space-*`, `--text-*` or `--elevation-*` scale, and **no**
  `--surface-raised` / `--text-muted` semantic vocabulary.

So the problem was never "too few tokens". It was that 49 names carried raw values in
two parallel, hand-synchronised places (`itsoc.css` and `index.css`), with no scale
behind any of them. That is what this card fixes.

---

## 1. What shipped

### 1.1 Prior state of this branch, and what this dispatch actually had to do

Four commits from an earlier dispatch were already on the branch (`ac6ca48`, `1269377`,
`9ee2f22`, `9ddbde6`): the research note, a first cut of the registry, the token-contract
tests, and the production visual baseline.

**The branch arrived GATE RED.** `scripts/gate.sh --web` failed `web_vitest` with
**5 failing assertions across 3 files** — the committed token contract did not match the
committed CSS. Evidence: `gate-logs/20260908-205111/`. The five failures were:

| Failing test | Cause |
|---|---|
| `design-tokens` → shared scales once on bare `:root` | 12 `--type-<role>-<size\|line-height\|weight>` tokens did not exist |
| `design-tokens` → legacy alias is one-way | 47 errors: every alias declared **twice** (once per theme block) |
| `design-tokens` → Tailwind HSL adapter | 14 errors: every adapter declared twice; `--sev-*`/`--shadow*` owned by `index.css` |
| `shadow-tokens` → one authoritative owner | `--shadow` had 4 occurrences, contract wants 1 |
| `c4-themes` → warning status vs high severity | `--warn` resolved to 2 declarations, not 1 |

Fixing this was the substance of the dispatch. **Every one of the five was fixed in the
CSS, not in the tests. No assertion was weakened to obtain green.**

### 1.2 The token registry (`web/src/styles/itsoc.css`)

One authoritative registry in three tiers, documented in the file itself:

- **1.1 Shared scales** — theme-invariant, stated once on bare `:root`: type families,
  21 exact type sizes, 10 line heights, 6 weights, 15 tracking steps, a **new semantic
  type layer** (`--type-{caption,label,body,title}-{size,line-height,weight}`, each an
  alias onto a primitive so the ramp keeps one source), a 20-step spacing scale whose
  suffix *is* the pixel value, and a shape ladder plus exact-purpose radii.
- **1.2 Semantic roles** — per theme, same taxonomy in the same order in both blocks:
  surface, border, text, action/selection, severity, status, elevation, focus, overlay,
  and the Tailwind hsl channel forms. Only *values* differ between themes.
- **1.3 Compatibility aliases** — every historical spelling (`--bg`, `--ink`, `--crit`,
  `--radius`, `--shadow`, `--sev-*`, `--mono` …) **declared exactly once**, carrying no
  value of its own.

Counts: **49 → 198** distinct names; `itsoc.css` 997 → 1214 lines; `index.css` 104 → 66.

### 1.3 The cardinality fix (the core correction)

Aliases were repeated verbatim in the dark block *and* the light block. That is what a
value-owning theme system looks like — but **an alias owns nothing**. It carries a role
name, and `var()` resolves it against whichever theme is live *on the same element*
(`store/ui.ts` sets `data-theme` on `<html>`, which **is** `:root`). The per-theme copy
could only restate the same sentence twice while presenting itself as a second source of
truth. All 35 aliases now sit in one bare `:root` block; `index.css` collapses its two
byte-identical adapter blocks to one.

`--sev-*` and `--shadow*` moved from `index.css` into that block. They are read from TSX
inline styles (`lib/severity.ts`, `IngestNotifier.tsx`, `UnrecognizedBanner.tsx`) and from
`tailwind.config.ts` — exactly the sanctioned compatibility case — but they had an owner
in the file whose entire contract is that it owns nothing.

### 1.4 What was deliberately *not* done

- **Call sites were not migrated.** The `is-*` shell still writes `13px`, `var(--bg)`,
  `var(--radius)`. Migrating ~900 lines of literals is a pixel risk with no foundation
  benefit; G1–G6 consume the scale. Only the 5 call sites the earlier dispatch had already
  tokenised (rail, FAB, focus ring, two overlays) read the new names today.
- **Two measured drifts are preserved**, under deliberately-named `--compat-*` tokens so
  nobody tidies them away: `--primary`/`--ring` renders `114,91,241` while `--acc` renders
  `109,92,240`; dark `--muted-foreground` is one channel off `--mut`. Unifying either
  would move pixels — that is a card that ships a visual diff, not a foundation.
- **Severity and status stay separate nodes** even where the value is identical today, so
  a verdict colour can never be repainted by a status change.
- **No client-side verdict derivation was introduced.** No `.tsx`, no backend, no rule,
  no severity meaning, no copy, no route, no component behaviour was touched.

---

## 2. Commits

| Commit | Subject |
|---|---|
| `987830a5fd0f3645fe65a4c1c645fbac4f597e82` | `fix(g0): one declaration per compatibility alias, and the missing type roles` |
| *(see below)* | `docs(g0): pixel, mutation and gate evidence for the token foundation` |

Files in `987830a` — `web/src/styles/itsoc.css`, `web/src/index.css`,
`docs/STAGE_F_REPORTS/G0-evidence/capture-visuals.mjs`. All inside the allowlist.
Staged by explicit path; **no `git add -A`, no merge, no push.**

---

## 3. Acceptance evidence

### (1) Token contract — explicit, documented, both themes

Static A/B against base `bdbd496`, resolving every custom property through its alias
chain per theme:

```
dark   before 48  after 197   CHANGED 0   ADDED 149   REMOVED 0
light  before 48  after 197   CHANGED 0   ADDED 149   REMOVED 0
```

**All 96 pre-existing token values (48 names × 2 themes) resolve byte-identically to
base.** Nothing changed, nothing was removed; 149 names were added (the scales and roles).

### (2) Guards, and proof they bite

`web/src/test/design-tokens.test.ts` (7 tests, new) plus strengthened
`c4-themes.test.tsx` and `shadow-tokens.test.tsx` assert: complete canonical role set once
per theme, **both-theme parity**, shared scales only on bare `:root`, **alias direction**
(legacy → semantic, never the reverse), no dependency cycles, `index.css` holds only
adapters, and severity ≠ status.

**Negative control — 7 mutations, each applied to the working tree, run, then reverted**
(`docs/STAGE_F_REPORTS/G0-evidence/mutation/token-guard-mutation-proof.json`):

| Mutation | Guard fired with |
|---|---|
| re-duplicate `--bg` in the light block | `legacy aliases must flow legacy -> semantic …` |
| delete `--severity-info` from light only | `Token --info does not resolve to a role present in both themes` |
| point `--surface-canvas` back at `--bg` | alias-direction **and** `custom-property alias cycles` |
| move `--space-11` into the dark block | `shared scale contract violations` |
| point `--warn` at `--severity-high` | `expected ['--severity-high'] to equal ['--status-warning']` |
| give `index.css` a literal `--background` | `Tailwind adapter contract violations` |
| re-add a competing `--shadow` in `index.css` | `--shadow must not have a competing index.css owner` |

`baselineGreenBeforeMutations: true`, `allGuardsFired: true`,
`restoredGreenAfterMutations: true`. CSS files verified back to their exact HEAD hashes
(`badcd64b…`, `11f14e82…`) after the run.

**No existing assertion was weakened.** `c4-themes`' both-theme check was *strengthened*
from "the literal name appears in both blocks" to "the token **resolves transitively**
through its alias chain to a role present in both themes" — which is what the mutation
above proves it now catches.

### (3) Pixel evidence — real production SPA, real run data

Every capture: `npm run build` → `web/dist` served by **`console/serve.py`** with its real
`/api/*` routes, fed by a real `log_analyzer.py --rules-only` run over
`tests/eval/cases/pos_bruteforce_compromise.log` (7/7 lines parsed, 0 unparsed, 2 findings,
detector 2 / llm 0). `mockedApi: false`, `stagedComponentState: false`, `mockup: false`,
`ITSOC_OEM=0`. **24 route states × 2 real themes = 48 states**, 1500×1000, en-GB, UTC,
Chrome 152.0.7977.76 headless, srgb. Each saved image is the second of two byte-identical
consecutive screenshots after fonts loaded and the network went quiet.

#### A confound was found and removed

The committed baseline (`9ddbde6`) was photographed in a **different worktree**
(`…/log-analyzer/g0-visual-baseline`); this dispatch runs in `…/g0-integration`. The
Alerts screen honestly renders the **absolute path** of the missing triage model, so the
paragraph rewraps purely because the directory name is a different length. That is an
environment delta, not a CSS delta.

Rather than explain it away, the base CSS was **re-photographed inside this worktree**
(`before-local`, photographing `itsoc.css 7f6cd192…` / `index.css ede52255…`, i.e. the
exact `bdbd496` files — recorded as hashes in the manifest). Four comparisons:

| Comparison | Identical | Changed | Changed px | Unexplained |
|---|---|---|---|---|
| **PRIMARY** `before-local` vs `after` (base CSS vs new CSS, same worktree) | 47/48 | 1 | 11 | **0** |
| **CORROBORATION** `before-local` vs `after-repeat` | **48/48** | **0** | **0** | **0** |
| **CONTROL** `after` vs `after-repeat` (*identical CSS both sides*) | 47/48 | 1 | 11 | 1 *(by design)* |
| CROSS-WORKTREE committed `baseline` vs `after` | 44/48 | 4 | 17214 | 0 *(path rewrap, annotated)* |

#### The one unstable region, identified — not masked, not restaged

`dark:/integrations`, 11 pixels, max channel delta **3**, at antialiased gradient edges.
Proven to be renderer non-determinism, not the change:

1. The **control** — same post-change CSS on both sides — reproduces the **same 11
   coordinates** with the same bounds. The delta appears with no CSS change at all.
2. `before-local/dark/integrations.png` and `after-repeat/dark/integrations.png` are
   **byte-identical** (`78de89d8f05f4ee996b066b04489edaae903351ed52c70f92775bdee2132ada8`)
   **despite being built from different CSS.** The route renders in one of two states;
   which state a run lands in is independent of the stylesheet.

Recorded in `diff-annotations.json` with that evidence. The pixels are left exactly as the
browser produced them.

**Verdict: `ZERO VISUAL DELTA ATTRIBUTABLE TO THE CHANGE`**, and on the corroboration pair,
a literal `ZERO VISUAL DELTA` — 48/48 byte-identical PNGs.

#### Evidence paths

| Artifact | Path |
|---|---|
| Side-by-side, **light** | `docs/STAGE_F_REPORTS/G0-evidence/diff/side-by-side-light.png` |
| Side-by-side, **dark** | `docs/STAGE_F_REPORTS/G0-evidence/diff/side-by-side-dark.png` |
| Primary diff inventory | `docs/STAGE_F_REPORTS/G0-evidence/visual-diff-inventory.json` |
| Corroboration inventory | `…/visual-diff-inventory-corroboration.json` |
| Noise control inventory | `…/visual-noise-control.json` |
| Cross-worktree inventory | `…/visual-diff-inventory-crossworktree.json` |
| Annotations (+ evidence) | `…/diff-annotations.json`, `…/diff-annotations-crossworktree.json` |
| Raw captures | `…/before-local/`, `…/after/`, `…/after-repeat/`, `…/baseline/` |
| Capture manifests | `…/{baseline,before-local,after,after-repeat}-manifest.json` |
| Harnesses | `…/capture-visuals.mjs`, `…/diff-visuals.mjs` |

Sheet layout: one row per route state, **left = before, right = after**, same viewport.

Regenerate a secondary comparison with, e.g.:

```sh
G0_BEFORE_LABEL=after G0_AFTER_LABEL=after-repeat G0_DIFF_DIR=diff-control \
G0_INVENTORY=visual-noise-control.json G0_ANNOTATIONS=none.json \
node docs/STAGE_F_REPORTS/G0-evidence/diff-visuals.mjs
```

#### Two harness bugs found and fixed

- `capture-visuals.mjs` hardcoded `…/G0-evidence/baseline` as its write path, so a
  `--label after` run **silently overwrote the committed baseline**. Caught immediately
  (`git status`), baseline restored from git and re-verified — all 48 committed captures
  match their recorded sha256. The path is now label-derived, and a `writeEvidence()`
  guard **refuses** any write outside the run's own label tree.
- Manifests now record the **sha256 of each photographed working-tree artifact**, because
  the working tree is what vite builds — not necessarily what `commit` points at. This is
  what makes the `before-local` run provable rather than merely asserted.

### (4) Gate

`scripts/gate.sh --web` → **GATE GREEN, 23/23** (20 Python + `web_vitest` + `web_build` +
`detector_freeze`). Evidence: `gate-logs/20260908-211937/`.

**Vitest: 45 files / 323 tests, all passing.**

Increase accounted for exactly — **+1 file, +10 tests, nothing removed**:

| File | Base | HEAD |
|---|---|---|
| `design-tokens.test.ts` (new) | 0 | 7 |
| `c4-themes.test.tsx` | 10 | 11 |
| `shadow-tokens.test.tsx` | 3 | 5 |

### (5) SELECTOR-NULL

Both detectors in `web/src/test/approvals.test.tsx` pass on the unmodified tree (suite
12/12). They are **not vacuous** — the test itself asserts the advisory chip *is* rendered,
that the rail has `buttons.length > 0`, and that the authoritative region really carries
`ELIGIBLE · rb-block-ip` and `.cap.authoritative`.

Bite proven by negative control: planting
`<button data-testid="approval-approve">` into the **advisory** `CopilotRail` header makes
it fail —

```
AssertionError: expected <button …(1)></button> to be null
Test Files 1 failed (1);  Tests 1 failed | 11 passed (12)
```

File restored byte-for-byte (`git status` clean for that path); **not committed**.
Recorded in `…/mutation/selector-null-bite-proof.json`.

### (6) Hygiene

- `git diff --check` — clean.
- Allowlist — clean for this dispatch's commits (see §5 for one inherited exception).
- Detector sha256 — unchanged, verified before and after and by the gate.
- `web/package.json` / `web/package-lock.json` — **byte-identical to base**
  (`git diff --stat bdbd496 HEAD --` on both: empty). No `web/dist` committed.

---

## 4. Setup

Orca setup is still configured as `pnpm install` and, as expected, is not what this repo
uses. `npm --prefix web install` ran clean; `git status` confirmed **package.json and
package-lock.json unchanged**.

**Resolved versions: vite `5.4.21` (declared `^5.4.9`), vitest `3.2.7` (declared `^3.2.6`).**

---

## 5. Unfinished, and things the next card should know

1. **Out-of-allowlist file inherited from the earlier dispatch.**
   `web/src/test/shadow-tokens.test.tsx` was modified in `9ee2f22`, before this dispatch,
   and is **not** on this dispatch's allowlist. I did not edit it — the five failures were
   fixed in the CSS so that file's existing contract passes as written. Flagging it
   because `git diff bdbd496..HEAD` is therefore not allowlist-clean for the branch as a
   whole, only for my commits.
2. **Dead compatibility branch in `shadow-tokens.test.tsx`.** It still carries a
   pre-G0 branch guarded by `if (tokenOccurrences(itsocCss, "--elevation-card").length === 0)`,
   which can no longer be reached now that `--elevation-card` exists. Harmless but dead;
   it should be deleted by a card that owns that file.
3. **The new type/spacing scales have no call sites yet** (5 of 198 tokens are referenced
   from the shell). That is deliberate — see §1.4 — but it means the scales are guarded by
   the contract tests rather than by rendering. G1–G6 adopting them is what will exercise
   them.
4. **`dark:/integrations` is bistable in headless Chrome** at 11 pixels. Any future card
   doing pixel work on that route should expect it and use the same control method rather
   than chasing it.
5. **The committed `baseline/` tree is cross-worktree** and so is not directly comparable
   to captures taken here. `before-local/` is the comparable "before". I left `baseline/`
   in place rather than deleting another dispatch's committed evidence.
6. **Not attempted:** any change to component markup, API/data logic, verdicts, copy,
   routes, or severity meaning — all explicitly out of scope.

---

*Generated for CARD G0. Detector freeze verified. Gate green 23/23.*
