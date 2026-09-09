# G0 debug / attack review

**Review verdict: FAILED — repair the acceptance evidence before accepting G0.**

Reviewed branch `Ankit512/g0-integration` at the coordinator-supplied target
`f45fb1b3fb971afa33536b9c76a56ec1a46347c0`, with base
`bdbd496c` verified as an ancestor. This was a review-only pass: no product or
test implementation was retained. The token implementation itself passed the
focused attacks and I found no attributable product pixel regression, but the
committed visual-evidence pipeline can produce a green verdict for captures it
explicitly says are not comparable. That is a material acceptance defect.

## Phase 1 — deterministic red-capable loops

### Token-contract loop

Green command:

```sh
npm --prefix web exec -- vitest run \
  src/test/design-tokens.test.ts \
  src/test/c4-themes.test.tsx \
  src/test/shadow-tokens.test.tsx --reporter=dot
```

Result: 3 files and 23 tests passed.

I then changed the canonical compatibility declaration at
`web/src/styles/itsoc.css:240` from `--bg:var(--surface-canvas)` to
`--bg:#ff00ff` with `apply_patch`. The same command failed with three useful
errors: `--bg` was not both-theme safe, a referenced `--bg` was not
theme-safe, and the exact alias contract reported
`--bg must alias --surface-canvas; found #ff00ff at itsoc.css:240`.
I restored with `apply_patch`; the file's sha256 was
`11f14e82f6f4fa5aa019e16b23ab5aadf9642867831457d3d5c1bee591040e79`
both before and after, the diff was empty, and the same 23 tests passed again.

This loop is fast, deterministic, and red-capable for the exact token-drift
risk.

### Real-browser pixel loop

I changed the dark canonical `--surface-canvas` at
`web/src/styles/itsoc.css:142` from `#09090b` to conspicuous `#ff00ff`, then
ran the production capture harness against the exact target:

```sh
node docs/STAGE_F_REPORTS/G0-evidence/capture-visuals.mjs \
  --expected-commit f45fb1b3fb971afa33536b9c76a56ec1a46347c0 \
  --label debug-mutation

G0_BEFORE_LABEL=before-local \
G0_AFTER_LABEL=debug-mutation \
G0_DIFF_DIR=debug-mutation-diff \
G0_INVENTORY=debug-mutation-inventory.json \
G0_ANNOTATIONS=debug-none.json \
node docs/STAGE_F_REPORTS/G0-evidence/diff-visuals.mjs
```

The harness built the real Vite application, generated a real rules-only
report, served it through `console/serve.py`, used no mocked API or staged
mockup, and captured all 24 route states in both themes. The mutation caused
26/48 states and 17,231,842 pixels to change. Dark Overview alone changed
257,425/1,500,000 pixels (17.1617%, maximum channel delta 246), while
consecutive captures were stable. This proves the method detects a real visual
delta rather than merely comparing filenames or manifest labels.

I restored the CSS with `apply_patch`; its sha256 returned exactly to
`11f14e82f6f4fa5aa019e16b23ab5aadf9642867831457d3d5c1bee591040e79`.
The temporary mutation captures were moved out of the repository to
`/tmp/g0-debug-artifacts.2gXPO7`, the normal source was rebuilt successfully,
and no transient product diff remains.

## Findings

### HIGH — the visual comparator can return green for non-comparable or incomplete inputs

**Affected code:**

- `docs/STAGE_F_REPORTS/G0-evidence/diff-visuals.mjs:249-260` defines equal
  capture settings (including `report.sha256`) as the comparability condition.
- `diff-visuals.mjs:359-363` records `captureSettingsMatch` and `sameRunData`.
- `diff-visuals.mjs:378-382` nevertheless chooses the verdict using only pixel
  changes and annotations; settings mismatch is ignored.
- Independently, `diff-visuals.mjs:274-276` records a missing side as
  `only-in-before` or `only-in-after`, but `diff-visuals.mjs:350-382` excludes
  that entry from `changed` and from the verdict. An incomplete route matrix
  can therefore also report `ZERO VISUAL DELTA`.

**Exact current-tree reproduction:**

```sh
node -e 'for (const f of [
  "docs/STAGE_F_REPORTS/G0-evidence/visual-diff-inventory.json",
  "docs/STAGE_F_REPORTS/G0-evidence/visual-diff-inventory-corroboration.json",
  "docs/STAGE_F_REPORTS/G0-evidence/visual-noise-control.json"
]) { const j=require("./"+f); console.log(f,
  j.comparison.captureSettingsMatch,
  j.comparison.sameRunData,
  j.summary.verdict) }'
```

Observed:

```text
visual-diff-inventory.json false false ZERO VISUAL DELTA ATTRIBUTABLE TO THE CHANGE ...
visual-diff-inventory-corroboration.json false false ZERO VISUAL DELTA
visual-noise-control.json false false VISUAL DELTA PRESENT ...
```

All three comparisons use different report hashes. The committed primary and
corroboration artifacts therefore carry green verdicts despite failing the
script's own comparability condition. The missing-pair path is an additional
source-level false-green vector even though the current manifests happen to
contain all 48 expected IDs.

**Impact:** the headline result can approve visual preservation without equal
run data, and can approve a comparison that silently lost a route/theme side.
This directly defeats the requested protection against false pixel-equality
evidence.

**Repair:** make capture-setting mismatches, duplicate IDs, missing IDs,
dimension mismatches, and an unexpected route/theme count fatal/non-green
before interpreting pixels. Recapture base/candidate/control from one frozen
report byte sequence, or explicitly normalize only fields proven irrelevant
while retaining a hash of the actual UI-consumed payload.

### MEDIUM — the claimed same-CSS control does not prove what CSS it photographed

**Affected evidence:**

- `after-manifest.json:11-17` stores `photographedTreeArtifacts` as bare path
  strings and has no `workingTreeDirtyPaths` field.
- The current harness schema at `capture-visuals.mjs:835-845` requires each
  photographed path plus its sha256 and records dirty paths.
- `diff-annotations.json:11-13` claims the control used the same post-change
  CSS and identical run data. The first claim is not self-proving on the
  `after` side and the second is contradicted by `sameRunData: false`.
- `G0-worker.md:237-239` says manifests now record actual working-tree hashes,
  but the committed `after` manifest predates and does not satisfy that claim.

**Exact reproduction:**

```sh
node -e 'const s=require("./docs/STAGE_F_REPORTS/G0-evidence/after-manifest.json").source;
console.log(typeof s.photographedTreeArtifacts[0], "workingTreeDirtyPaths" in s)'
```

Observed: `string false`.

The independently checked pixels are consistent with an 11-pixel Chrome
bistability, not a product regression: primary changed only
`dark:integrations` (11 pixels), corroboration was 48/48 identical, and the
control changed the same 11 coordinates. The exact coordinate sets in primary
and control are equal:

```text
(372,323) (523,318) (554,601) (554,618) (555,600) (555,619)
(674,323) (689,617) (1000,825) (1002,823) (1103,617)
```

Also, `before-local/dark/integrations.png` and
`after-repeat/dark/integrations.png` are genuinely byte-identical at sha256
`78de89d8f05f4ee996b066b04489edaae903351ed52c70f92775bdee2132ada8`,
and those two manifests do carry base/candidate CSS hashes. The evidence is
suggestive, but the claimed same-CSS control and same-data premise are not
established by the committed artifacts. Repair by recapturing the `after`
side with the hash-complete schema and frozen run data, then regenerate all
inventories and annotations.

### MEDIUM — branch acceptance lacks required ratification for the shadow-test diff

`web/src/test/shadow-tokens.test.tsx` was changed by `9ee2f22`, whose diff is
limited to the three token-test files, but the integration umbrella did not
include the shadow-test path. `G0-worker.md:297-302` acknowledges that the
branch as a whole is not allowlist-clean. `GUARDRAILS.md:12` requires explicit,
logged orchestrator ratification before accepting a non-behavioral
out-of-allowlist diff; no such ratification is present in the committed G0
evidence.

This appears to be legitimate work from a prior parallel test stream rather
than an unauthorized behavioral change, so the repair is procedural: record
explicit umbrella ratification for the path (or move it to a separately owned
repair card) before G0 acceptance. Do not silently reinterpret the integration
allowlist after the fact.

### LOW — the shadow test keeps a dead pre-G0 branch

At `web/src/test/shadow-tokens.test.tsx:130-145`, the test falls back to the old
duplicate-token assertions only if `--elevation-card` is absent. The canonical
G0 contract now requires that token, and the independent design-token suite
enforces it, so this branch is unreachable on a conforming tree. It does not
create a current coverage gap, but it preserves a contradictory obsolete
contract and makes future failures harder to read. Remove it in a card that
owns this test file.

### LOW — committed report and source comments contain stale provenance claims

- `G0-worker.md:105` leaves the final evidence commit as `*(see below)*` even
  though the exact reviewed commit is `f45fb1b3fb971afa33536b9c76a56ec1a46347c0`.
- `web/tailwind.config.ts:20` says severity values live in `index.css`, and
  line 29 says `--shadow` is themed there; G0 moved those roles to the
  `itsoc.css` registry.
- `web/src/store/ui.ts:22` still says the light theme override lives in
  `index.css`; it now lives in `itsoc.css`.

Reproduction:

```sh
rg -n '\(see below\)|values live in index\.css|--shadow var in index\.css|override in index\.css' \
  docs/STAGE_F_REPORTS/G0-worker.md web/tailwind.config.ts web/src/store/ui.ts
```

These are documentation-integrity issues, not runtime defects.

## Independent clean checks

- An independent recursive token resolver evaluated the base and target in
  production CSS import order for both themes: base 48, target 197, missing 0,
  pre-existing values changed 0, added 149 in each theme. Across both themes,
  all 96 pre-existing theme/name values were preserved.
- The canonical role declarations are parity-complete: 46 names in dark and
  46 in light with identical sets and no duplicate ownership. All 35 legacy
  aliases have one owner and point legacy-to-canonical; no canonical role
  points back to a legacy alias. The combined graph has no cycles or unresolved
  references.
- All four committed capture manifests have exactly 48 unique expected
  route/theme IDs. Every PNG exists, is 1500x1000, and hashes to its manifest
  value. The app declares 23 explicit routes plus a wildcard, and the harness
  covers 24 states (including one wildcard exemplar) in both themes.
- Independent PNG decoding reproduced the primary, corroboration, and control
  pixel counts and the 11 coordinates above. Package manifests are byte-equal
  to base. The production runtime, no-mock flags, detector hash, viewport,
  locale, timezone, browser version, and color profile match; only the report
  hashes fail the declared comparability check.
- `npm --prefix web test -- --run src/test/approvals.test.tsx --reporter=dot`
  passed 12/12. The SELECTOR-NULL tests are non-vacuous at
  `approvals.test.tsx:143-168`: they establish both the advisory chip/buttons
  and the eligible authoritative surface while requiring the opposite-class
  controls to be absent. The committed negative mutation proof records the
  expected 1-fail/11-pass bite.
- Detector sha256 remained frozen at the gate-verified value recorded in the
  final verification section below.

## Gate behavior and residual limitations

`scripts/gate.sh --web` preserved output in
`gate-logs/20260909-083551/`. All 20 Python checks, `web_build`, and
`detector_freeze` passed, but the gate was red because
`web/src/test/integrations.test.tsx:126` timed out at 20 seconds in the full
suite (44 files passed, 1 failed; 322 tests passed, 1 failed). Isolation then
passed that file 9/9 in 14.24 seconds, and an immediate full-suite rerun passed
45/45 files and 323/323 tests in 37.59 seconds. This is a nondeterministic test
budget/reliability signal, not evidence of a deterministic G0 behavior defect;
the first red gate must nevertheless remain visible.

The conspicuous mutation proves broad pixel sensitivity, but it does not prove
that every one-pixel change is detected under every renderer. Only the
committed Chrome build, 1500x1000 viewport, two themes, and enumerated 24 route
states were examined. Dynamic behavior beyond the stabilized capture points,
other browsers, device pixel ratios, operating systems, and accessibility
rendering modes remain outside this review.

## Final verification

The authoritative detector sha256 measured before report creation was:

```text
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876
```

This review's final staging and commit verification follows report creation;
only this file is permitted to be staged.
