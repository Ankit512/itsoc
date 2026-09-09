# G0 repair card — visual-evidence acceptance chain

**Branch:** `Ankit512/g0-integration` · **Base for this card:** `35883bf8d2743f58735d4afb0a8dd3ae14467250`,
verified an ancestor of HEAD before any edit, in the existing worktree
`/Users/ankit/orca/workspaces/log-analyzer/g0-integration`.
**Umbrella base:** `bdbd496c5b082b92eec09af8554600561e132b84`.
**Detector:** `anomaly_detector.py` sha256
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — verified before work,
after work, and by the gate's own `detector_freeze` check. Not read, not edited.

**Outcome: repaired. Comparator guards independently shown red-capable; the new
comparable frozen-payload A/B evidence is green; `scripts/gate.sh --web` GATE GREEN 23/23.**

This card answers `debug-review.md`, which returned **FAILED** on G0's acceptance evidence
(not on its token implementation). Every HIGH, MEDIUM and LOW finding is addressed below.

---

## 0. Preconditions, verified before any edit

| Check | Result |
|---|---|
| `git merge-base --is-ancestor 35883bf HEAD` | ancestor ✓ |
| Branch | `Ankit512/g0-integration` ✓ |
| `git status` | clean ✓ |
| `anomaly_detector.py` sha256 | `364577c5…b577a4a876` ✓ |
| `web/package.json` vs `bdbd496` | `cd0b9180…2bba6062` both sides — unchanged ✓ |
| `web/package-lock.json` vs `bdbd496` | `634ebbd8…29996011` both sides — unchanged ✓ |

---

## 1. HIGH — the comparator could return green for non-comparable or incomplete inputs

### What was wrong

`diff-visuals.mjs` computed `captureSettingsMatch` and `sameRunData`, recorded them in the
inventory, and then **chose its verdict from pixels alone**. Separately, a route/theme state
present on only one side was recorded as `only-in-before` / `only-in-after` and then
**excluded** from `changed` — so an incomplete matrix could also report `ZERO VISUAL DELTA`.

Both committed green inventories failed the script's own comparability condition. Reproduced
on the pre-repair tree exactly as the review reported:

```text
visual-diff-inventory.json                false false ZERO VISUAL DELTA ATTRIBUTABLE TO THE CHANGE …
visual-diff-inventory-corroboration.json  false false ZERO VISUAL DELTA
visual-noise-control.json                 false false VISUAL DELTA PRESENT …
```

### What changed

Six conditions are now decided **from the manifests, before a single pixel is decoded**, and
each rejects the run with **exit status 2** and the verdict
`COMPARISON REJECTED — the two sides are not comparable; no pixel verdict was computed`:

| Guard | Rejects |
|---|---|
| `manifest-schema` | a manifest that is not the hash-complete schema (`schemaVersion` 2, per-artifact sha256, `workingTreeDirtyPaths`, `frozenPayload`) — i.e. one that cannot prove which stylesheet it photographed |
| `capture-settings` | differing viewport, locale, timezone, browser version, colour profile, detector hash, or **report payload hash** |
| `duplicate-id` | the same route/theme id listed twice in one manifest |
| `route-matrix` | any id set other than exactly **24 routes × 2 themes = 48 states**, or a `summary.routeStates`/`summary.themes` that disagrees |
| `missing-pair` | an id present on only one side |
| `dimensions` | a declared image that is not 1500×1000, re-checked against the **decoded** PNGs after the pixel loop |

A rejected run still writes its inventory — the rejection is evidence — but it never reports
green. The old `only-in-*` path is now an unreachable `throw`, kept so a future refactor
cannot resurrect the silent-exclusion behaviour.

The expected 24-route × 2-theme matrix is stated in `diff-visuals.mjs` **independently of**
`capture-visuals.mjs`. If a future harness edit drops or renames a route, the two statements
disagree and the comparison is refused rather than quietly reporting a green 46-state matrix.

### Proof each guard bites

`guard-negative-controls.mjs` copies the two real manifests into a temporary directory,
injects **one** defect per control, and runs the comparator against the copy via
`G0_MANIFEST_DIR`. The repository evidence tree is never written to, so there is no window in
which committed evidence is mutated and no restore step that could fail.

Evidence: `guard-negative-control-proof.json` (sha256 `647ba3d0c9642b7d…`), subject
`diff-visuals.mjs`, ten negative controls plus one positive control.

| Control | Guard | Exit | Fired |
|---|---|---|---|
| different report payload on the two sides | `capture-settings` | 2 | ✓ |
| different viewport on the two sides | `capture-settings` | 2 | ✓ |
| one state listed twice | `duplicate-id` | 2 | ✓ |
| `dark:integrations` present on one side only | `missing-pair` | 2 | ✓ |
| a route dropped from both sides (23×2) | `route-matrix` | 2 | ✓ |
| a whole theme dropped (24×1) | `route-matrix` | 2 | ✓ |
| a capture declared 1400×1000 | `dimensions` | 2 | ✓ |
| pre-repair `schemaVersion: 1` | `manifest-schema` | 2 | ✓ |
| artifacts recorded as bare paths | `manifest-schema` | 2 | ✓ |
| `frozenPayload` removed | `manifest-schema` | 2 | ✓ |
| **positive control — unmodified manifests** | — | **0** | accepted, real verdict computed |

`allTargetedGuardsFired: true`, `positiveControlAccepted: true`,
`allGuardsProvenRedCapable: true`. The positive control matters: without it the negative
controls would only prove the script can say no.

**The guards bite on the real committed history.** Run against the superseded
`before-local` vs `after` pair — the review's headline false green — the comparator now exits
**2** with 11 blockers, including
`report.sha256: "5d7e627b…" vs "e0d20d79…"`.

---

## 2. MEDIUM — the same-CSS control did not prove what CSS it photographed

### What was wrong

`after-manifest.json` stored `photographedTreeArtifacts` as bare path strings and had no
`workingTreeDirtyPaths`, so its "same post-change CSS" claim was an assertion. Its
`sameRunData` was `false`, contradicting the annotation's "identical run data" claim.

### What changed — one frozen payload, four captures, one worktree

Each capture run previously called `log_analyzer.py` afresh, so the two sides never served
the same bytes (`generated_at` alone differs) and were never legitimately comparable.
`capture-visuals.mjs` gains `--frozen-report`: one rules-only report is generated once,
committed, and reused verbatim on every side.

**Frozen payload:** `frozen-run/frozen-rules-only-report.json`, sha256
`7930245ace6bfa8bf6d5d794c857e4f6cc622acacf5b93ba4623facc5c9f0113` — a real
`python3 log_analyzer.py --input tests/eval/cases/pos_bruteforce_compromise.log --rules-only`
run: 7/7 lines parsed, 0 unparsed, 2 findings, both from rules. **All four captures record
this identical hash.**

Four production captures, all in **this** worktree, all `mockedApi: false`,
`stagedComponentState: false`, `mockup: false`, `ITSOC_OEM=0`, 1500×1000, en-GB, UTC,
headless Chrome, srgb, `web/dist` served by `console/serve.py`:

| Run | Stylesheet photographed | `itsoc.css` | `index.css` | Dirty paths recorded |
|---|---|---|---|---|
| `before-frozen` | **base** (`bdbd496`) | `7f6cd192…` | `ede52255…` | `M web/src/index.css`, `M web/src/styles/itsoc.css`, … |
| `before-frozen-repeat` | **base** | `7f6cd192…` | `ede52255…` | same two `M` entries |
| `after-frozen` | **candidate** (HEAD) | `11f14e82…` | `badcd64b…` | none for CSS |
| `after-frozen-repeat` | **candidate** | `11f14e82…` | `badcd64b…` | none for CSS |

Base-vs-candidate is therefore **proven by hash, not asserted**: the two base runs carry the
exact `bdbd496` file hashes with those files named as dirty, and the two candidate runs carry
the HEAD hashes with a clean CSS tree.

### Renderer noise is real, and is reported honestly

The renderer is not byte-deterministic at this viewport. Rather than explain that away, both
stylesheets were photographed **twice**, giving two same-stylesheet control pairs. Their raw,
**unannotated** results are the noise floor:

| Comparison | Stylesheets | Identical | Changed | Changed px | Verdict |
|---|---|---|---|---|---|
| **PRIMARY A/B** `before-frozen` → `after-frozen` | base vs candidate | 43/48 | 5 | **40** | ZERO VISUAL DELTA ATTRIBUTABLE TO THE CHANGE |
| **CORROBORATION A/B** `before-frozen` → `after-frozen-repeat` | base vs candidate | 41/48 | 7 | **65** | ZERO VISUAL DELTA ATTRIBUTABLE TO THE CHANGE |
| **CONTROL** `after-frozen` → `after-frozen-repeat` | **identical candidate CSS** | 42/48 | 6 | **49** | VISUAL DELTA PRESENT *(unannotated, by design)* |
| **CONTROL** `before-frozen` → `before-frozen-repeat` | **identical base CSS** | 43/48 | 5 | **60** | VISUAL DELTA PRESENT *(unannotated, by design)* |

Both same-CSS controls move **more** pixels than the primary A/B. The controls are
deliberately fed an empty annotation set (`diff-annotations-none.json`): annotating the noise
floor away would destroy the evidence it exists to provide.

### The attribution is measured, not asserted

`attribution-analysis.mjs` decides per state whether a primary delta is attributable to the
stylesheet, using two independent tests. A delta counts as attributable only if it fails
**both**:

- **shared-render** — some base run and some candidate run are byte-identical. If the
  candidate stylesheet can produce a frame the base stylesheet also produced, the stylesheet
  is not what distinguishes them.
- **control-covered** — every coordinate that moved in the primary pair also moves in a
  same-stylesheet control pair. A coordinate that moves with no CSS change at all cannot be
  evidence that CSS changed it.

Result (`visual-attribution-analysis.json`, sha256 `6498a0aaca361c15…`):

```text
states                              48
statesWithPrimaryDelta               5
totalPrimaryChangedPixels           40
totalBaseControlChangedPixels       60      (base CSS twice)
totalCandidateControlChangedPixels  49      (candidate CSS twice)
statesWithSharedRender              47
statesWithUncoveredCoordinates       0
statesAttributableToChange           0
```

Per changed state:

| State | primary px | max Δ | base-ctl px | cand-ctl px | uncovered | shared render |
|---|---|---|---|---|---|---|
| `dark:overview` | 2 | 59 | 0 | 12 | **0** | no |
| `light:incidents` | 10 | 37 | 10 | 0 | **0** | yes |
| `light:integrations` | 14 | 1 | 25 | 11 | **0** | yes |
| `light:overview` | 10 | 4 | 10 | 10 | **0** | yes |
| `light:threat-intel` | 4 | 37 | 4 | 0 | **0** | yes |

**Zero uncovered coordinates across all 48 states.** Every pixel that moved between base and
candidate also moves between two runs of the *same* stylesheet, at the same coordinate.

`dark:overview` is the one state with no shared render, so it is stated precisely rather than
waved through: the two moved pixels are `(702,328)` and `(700,330)`. They appear in
`after-frozen` and in **neither** base run **nor** in `after-frozen-repeat`. Because two runs
of the *identical* candidate stylesheet disagree at exactly those two coordinates with the
same magnitude, the pixels are not a function of the stylesheet. The corroboration pair
(`before-frozen` → `after-frozen-repeat`) does not contain them at all.

The same analysis run on the corroboration pair
(`visual-attribution-analysis-corroboration.json`, sha256 `2bf3f2d498485362…`) also reports
`statesWithUncoveredCoordinates: 0`, `statesAttributableToChange: 0`.

### Which pair is canonical

**`before-frozen` vs `after-frozen` is the canonical G0 visual evidence**, corroborated by
`before-frozen` vs `after-frozen-repeat` and bounded by the two same-stylesheet controls.

`baseline/`, `before-local/`, `after/`, `after-repeat/` and their manifests and inventories
are retained as **superseded history**. They are pre-repair `schemaVersion: 1` artifacts and
the current comparator **rejects every pair built from them** (exit 2). They are not deleted
— they are another dispatch's committed evidence and the record of how the defect was found
— but no acceptance claim rests on them. `G0-worker.md` §3(3) is marked SUPERSEDED in place.

### Canonical evidence paths

| Artifact | Path | sha256 |
|---|---|---|
| Frozen run payload | `frozen-run/frozen-rules-only-report.json` | `7930245ace6bfa8b…` |
| Primary inventory | `visual-diff-inventory-frozen.json` | `d41d60807d8135e0…` |
| Corroboration inventory | `visual-diff-inventory-frozen-corroboration.json` | `f1b61da1d4c695de…` |
| Control (candidate CSS ×2) | `visual-noise-control-frozen.json` | `7c70ddea3da62789…` |
| Control (base CSS ×2) | `visual-noise-control-frozen-base.json` | `83c09e1e5a29cb68…` |
| Attribution analysis | `visual-attribution-analysis.json` | `6498a0aaca361c15…` |
| Attribution (corroboration) | `visual-attribution-analysis-corroboration.json` | `2bf3f2d498485362…` |
| Guard negative-control proof | `guard-negative-control-proof.json` | `647ba3d0c9642b7d…` |
| Shadow-contract mutation proof | `mutation/shadow-contract-mutation-proof.json` | `c29b323457a8648c…` |
| **Side-by-side, light** (3048×24400) | `diff-frozen/side-by-side-light.png` | `255fd7d19938dcba…` |
| **Side-by-side, dark** (3048×24400) | `diff-frozen/side-by-side-dark.png` | `4a58cec6e10f4902…` |
| Per-state diff overlays | `diff-frozen/*.png` (5 changed states) | — |
| Capture manifests | `{before,after}-frozen{,-repeat}-manifest.json` | schemaVersion 2 |
| Raw captures | `before-frozen/`, `before-frozen-repeat/`, `after-frozen/`, `after-frozen-repeat/` | 52 PNGs each |

Sheets are one row per route state, **left = before (base CSS), right = after (candidate
CSS)**, same viewport, both themes.

Reproduce:

```sh
node docs/STAGE_F_REPORTS/G0-evidence/capture-visuals.mjs \
  --expected-commit <HEAD> --label after-frozen \
  --frozen-report docs/STAGE_F_REPORTS/G0-evidence/frozen-run/frozen-rules-only-report.json

G0_BEFORE_LABEL=before-frozen G0_AFTER_LABEL=after-frozen \
G0_DIFF_DIR=diff-frozen G0_INVENTORY=visual-diff-inventory-frozen.json \
G0_ANNOTATIONS=diff-annotations-frozen.json \
node docs/STAGE_F_REPORTS/G0-evidence/diff-visuals.mjs

node docs/STAGE_F_REPORTS/G0-evidence/attribution-analysis.mjs \
  --base before-frozen --base-repeat before-frozen-repeat \
  --candidate after-frozen --candidate-repeat after-frozen-repeat

node docs/STAGE_F_REPORTS/G0-evidence/guard-negative-controls.mjs \
  --before before-frozen --after after-frozen
```

---

## 3. MEDIUM — umbrella ratification for `web/src/test/shadow-tokens.test.tsx`

**Ratified.** The dispatch for this repair card explicitly expanded and ratified the
integration umbrella allowlist to include `web/src/test/shadow-tokens.test.tsx`, for this
**non-behavioral test-path change**, and this card records that ratification as
`GUARDRAILS.md:12` requires.

**Rationale.** The file was changed by `9ee2f22` — legitimate work from a parallel test
stream, not an unauthorized behavioral change — but no card owned the path, so the branch as
a whole was not allowlist-clean and the dead branch below could not be removed. This card is
granted ownership of the path. The change is confined to test assertions: no product source,
no runtime behaviour, no copy, no route, no severity meaning.

## 4. LOW — the dead pre-G0 branch in the shadow test

`shadow-tokens.test.tsx` fell back to the old duplicate-token assertions when
`--elevation-card` was absent. G0's canonical contract requires that token and
`design-tokens.test.ts` enforces it, so the branch was unreachable on any conforming tree
while preserving a contradictory obsolete contract.

The branch is removed. The surviving contract was **strengthened, not weakened**: each of the
six canonical elevation/focus roles must have **exactly one** owner in **each** theme, and
that owner must hold its own value rather than passing the whole value through to another
custom property. Referencing a colour token *inside* the value stays legal — the elevations
legitimately `color-mix` against `--text-primary`.

Proven red-capable (`mutation/shadow-contract-mutation-proof.json`), each mutation applied to
the working tree and reverted:

| Mutation | Guard fired with |
|---|---|
| dark `--elevation-card` → `var(--elevation-popover)` | `--elevation-card dark must own its value, not pass it through: expected 'var(--elevation-popover)' not to match …` |
| delete light `--elevation-card` | `--elevation-card light ownership: expected [] to have a length of 1 but got +0` |

`baselineGreenBeforeMutations: true`, `allGuardsFired: true`,
`restoredGreenAfterMutations: true`, `fileRestoredExactly: true` — `itsoc.css` back to
`11f14e82f6f4fa5aa019e16b23ab5aadf9642867831457d3d5c1bee591040e79`.

Test count is unchanged (the dead branch lived inside an existing test):
`shadow-tokens.test.tsx` remains **5 tests**; the three token suites remain **23 tests**.

*A first attempt at this assertion was wrong and is not shipped: it required the value to
contain no `var(` at all, which the elevations legitimately violate via `color-mix(… ,
var(--text-primary) …)`. It failed on the real CSS and was corrected to the pass-through form
above before commit.*

## 5. LOW — stale provenance claims

| Location | Was | Now |
|---|---|---|
| `G0-worker.md:105` | evidence commit `*(see below)*` | `f45fb1b3fb971afa33536b9c76a56ec1a46347c0`, plus `35883bf…` for the review commit |
| `G0-worker.md` §3(3) | four green pixel comparisons | marked **SUPERSEDED**, with why each pair was inadmissible |
| `G0-worker.md` §5.2 | "dead branch … should be deleted by a card that owns that file" | marked resolved by this card |
| `G0-worker.md` §5.5 | `before-local/` is the comparable "before" | superseded by `before-frozen/` |
| `web/tailwind.config.ts:20` | severity "values live in index.css per theme" | `--sev-*` are compatibility aliases onto per-theme `--severity-*` in the `itsoc.css` registry |
| `web/tailwind.config.ts:29` | "`--shadow` var in index.css" | `--shadow` is an alias in `itsoc.css` onto `--elevation-card` |
| `web/src/store/ui.ts:22` | "`[data-theme=light]` override in index.css" | override lives in `styles/itsoc.css`, which owns the registry since G0 |

---

## 6. Preservation and scope

- **All 96 pre-existing resolved token values preserved.** Independently re-verified for this
  card with a resolver written from scratch (comment-stripping, brace-depth-aware, resolving
  each name transitively through its alias chain in production import order):
  `dark base 48 → head 197, CHANGED 0, MISSING 0, ADDED 149`; `light` identical. **96/96.**
  This reproduces the debug reviewer's independent numbers exactly.
- **No CSS was touched by this card.** `git diff 35883bf HEAD -- web/src/index.css
  web/src/styles/itsoc.css` is empty, so the token result cannot have moved.
- **No runtime UI behaviour, copy or route change.** The only non-evidence edits are two
  comment corrections (`tailwind.config.ts`, `store/ui.ts`) and test assertions.
- **No package changes.** `web/package.json` and `web/package-lock.json` byte-identical to
  `bdbd496`.
- **No engine or backend change.** `anomaly_detector.py` frozen and unread; no
  `console/`, no rule, no severity, no verdict path touched.
- **Hygiene.** `apply_patch`-style exact-match edits throughout; explicit `git add <path>`
  only, never `git add -A`; no merge, no push.

## 7. Verification runs

| Check | Result |
|---|---|
| `vitest run design-tokens + c4-themes + shadow-tokens` | **3 files, 23 tests passed** |
| SELECTOR-NULL: `vitest run src/test/approvals.test.tsx` | **1 file, 12 tests passed** |
| `npm run build` (inside every capture run) | passed ×4, `web/dist/index.html` produced each time |
| `scripts/gate.sh --web` | **GATE GREEN — 23/23** (20 Python + `web_vitest` + `web_build` + `detector_freeze`) |
| Gate vitest totals | **45 files, 323 tests, all passing** |
| Detector sha256 after the gate | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |

Gate evidence: `gate-logs/20260909-091711/`, and re-run on the exact committed tree as
`gate-logs/20260909-092227/` — **GATE GREEN 23/23, 45 files / 323 tests** both times. The
second run exists because the first predated this report and the evidence commit; no source
file references `docs/STAGE_F_REPORTS/`, so the gate result could not have depended on them,
and the re-run confirms it directly.

### Nondeterminism, reported honestly

The debug review's gate run (`gate-logs/20260909-083551/`) was **red**: `web_vitest` failed
because `web/src/test/integrations.test.tsx:126` timed out at 20 s in the full suite, while
passing in isolation and on an immediate rerun. **That flake did not recur in this card's
gate run** — 45/45 files and 323/323 tests passed on the first attempt. It is a test
budget/reliability signal, not a G0 defect, and it is not fixed by this card. A future card
should raise that test's budget or make it deterministic; until then a red gate on that file
alone should be re-run before being believed.

The four capture runs are themselves subject to the renderer non-determinism quantified in
§2. The claim proven here is **not** "the renderer is deterministic" — it is that every pixel
that moved between the base and candidate stylesheets also moves between two runs of the same
stylesheet. A single A/B pair could not have established that, which is why four captures
were taken.

### Residual limits

Only the committed Chrome build, 1500×1000, `deviceScaleFactor: 1`, two themes and the
enumerated 24 route states were examined. Other browsers, device pixel ratios, operating
systems, accessibility rendering modes, and dynamic behaviour beyond the stabilised capture
points remain outside this evidence. The new type and spacing scales still have no call sites
(5 of 198 tokens are referenced from the shell); they are guarded by the contract tests, not
by rendering, exactly as G0 intended.
