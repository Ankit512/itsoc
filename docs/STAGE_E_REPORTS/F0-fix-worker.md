# CARD F0-FIX — runbook Steps render as a numbered, semantically intact list

**Branch:** `Ankit512/f0-steps-numbering`
**Base:** `944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46`
**Tier:** light — frontend only. Zero engine, zero backend files.

---

## 1. Base check — a real failure, then a clean pass

The first base guard **FAILED**, and the reverse check **SUCCEEDED**:

```
git merge-base --is-ancestor 944c47e HEAD   -> FAIL
git merge-base --is-ancestor HEAD 944c47e   -> OK      (worktree merely STALE)
HEAD at that moment: b836114, 40 commits behind the base
```

Per the card I stopped **before the first edit** and reported. The decisive detail was not the
count: the missing commits included `4cb5b17 feat(web): make runbook cards legible to a
non-builder (F0)` — the very commit that introduces `RunbookCard.tsx`. The defect's code did not
exist in the tree, so any "fix" made there would have been a fix to nothing.

The coordinator had reset the worktree while I was checking; I had reported the pre-reset state.
Re-verified before touching anything, and no fast-forward was run:

```
HEAD = 944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46
git merge-base --is-ancestor 944c47e HEAD   -> OK
working tree clean
```

**Detector freeze**, verified before and after the work, unchanged and never edited:

```
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876  anomaly_detector.py
```

---

## 2. The defect had TWO causes, not one

The card diagnosed `display:flex`. That is real, and it is half of it. Reproduced in real Chromium
against the running app, the pre-fix `<ol>` computes:

```
tag OL | olDisplay flex | olListStyleType none | liDisplay list-item | markerText normal
```

`olListStyleType: none` is **not** explained by the flex rule — nothing in the runbook CSS sets it.
It comes from Tailwind's preflight, pulled in by `@tailwind base` in `src/index.css`, which resets
`ol,ul{ list-style:none; margin:0; padding:0 }`. `main.tsx` imports `index.css` **before**
`styles/itsoc.css`, so the reset lands on every `<ol>` the app renders unless a later rule states a
marker explicitly. The old rule never did — it only had to look right, and under `display:flex`
nothing was painted either way, so the second cause stayed invisible behind the first.

This matters for the accessibility framing the card asks for. `list-style:none` on an `<ol>` is what
makes Safari/VoiceOver drop list semantics, so the **ordering** is lost to that reader. Un-flexing
alone would have restored the visual gutter in no browser at all — the list would have rendered just
as bare, and the screen-reader defect would have survived untouched. Both causes had to go.

---

## 3. The fix, and why this is the right seam

One rule in `web/src/styles/itsoc.css` (§12a5, the F0 runbook-card subsection). **No markup change
was needed** — `RunbookCard.tsx` already renders a correct `<ol class="is-rb-steps__list">` of
`<li class="is-rb-steps__item">`. The bug was never in the semantics; it was that the stylesheet
overrode them. Fixing it in CSS is the seam where the damage was done, and it keeps the component
untouched, so `RunbookCard.tsx` is **not** in this diff.

```css
.is-rb-steps__list{ margin:0; padding-left:17px; display:block; list-style:decimal outside; }
.is-rb-steps__item{ font-size:11.5px; line-height:1.55; color:var(--ink2); }
.is-rb-steps__item + .is-rb-steps__item{ margin-top:3px; }
```

- `display:block` — stops blockifying the `<li>` children, so a `::marker` box is generated.
- `list-style:decimal outside` — states the marker explicitly, so the preflight reset cannot win.
  The markers land in the `padding-left:17px` gutter the old rule already reserved for them.
- `margin-top:3px` — carries the 3px rhythm that flex `gap` used to provide.

**Nothing else on the card was touched**: no colour is named (the ordinal inherits
`color: var(--ink2)` from the item, a token defined in both theme blocks, so both themes stay
legible without a new token), no `::marker` rule, and no change to the copy, the disclosure, the
badges, or the honest fallback.

**Spacing is provably unchanged**, measured in the browser on the true-original CSS vs. the fix:

| | list height | gap between items |
|---|---|---|
| true original (`gap:3px`) | 92.1px | 3px |
| fixed (`margin-top:3px`)  | 92.1px | 3px |

---

## 4. What the new test actually proves — and what it does not

`web/src/test/runbook-card.test.tsx` gains a `F0-FIX` block of 4 tests (15 → 20 in the file).

The point of the card is that the 15 existing F0 tests passed for this defect's **entire life**,
because every one of them asserts structure — an `<ol>` exists, it holds N `listitem` roles. All of
that is true of a list with no visible markers. So the new tests assert the computed/rendered result
instead, and **each was verified by reverting the fix and watching it fail**:

| counterfactual stylesheet | result |
|---|---|
| original (`display:flex`, marker from preflight) | **2 tests fail** |
| partial fix (unflexed, marker still left to preflight) | **1 test fails** |
| the fix | 20/20 pass |

That second row is the one worth stating: a plausible half-fix, which looks right in a quick glance
at the diff, is caught.

One more measurement makes the card's point concretely. I stashed my changes and ran the suite as it
stood on the base commit — i.e. the **broken** stylesheet, unfixed: **290 passed (290), zero
failures.** The pre-existing suite is fully green on the defect. That is the gap these 5 tests
close.

**Honest limits of the environment.** Vitest runs in jsdom, which does not lay out or paint. It
generates no `::marker` box, so **no assertion here reads an actual painted "1."**. Within that
limit the two causes are asserted at the strongest level each admits, and the two are *not* the same
level:

- **Cause 1 is asserted on computed style.** jsdom does perform the cascade for `display`, resolved
  from the real bytes of `itsoc.css` read off disk — not from anything restated in the test file.
  `getComputedStyle(ol).display` must not be any flex/grid value.
- **Cause 2 is asserted on the CSS source**, and this is a deliberate downgrade I want on the
  record. I first wrote it as a computed assertion (`listStyleType` must not be `none`) and it
  **passed against the broken partial-fix stylesheet**. jsdom's cascade propagates `display` but not
  `list-style-type`: `getComputedStyle` returns the UA default `decimal` whatever the stylesheets
  say. The computed assertion was vacuous, so I replaced it with one that parses the shipped
  `.is-rb-steps__list` rule and requires it to declare a counting `list-style` of its own. That
  assertion is not vacuous — it is exactly what fails on the partial fix.

So the tests prove **both suppression mechanisms are gone from the shipped stylesheet and stay
gone**. They do **not** prove the final pixel. That is what §5 is for.

The honest bounded fallback is also locked, under the real stylesheet: an undescribed runbook must
still show its note and must have **no `list` element at all** — not a list that merely happens to
be empty.

---

## 5. Screenshot evidence — real running app, both themes

Real Chromium (Playwright 1.62.1) against the real console: `console/serve.py --report` over a
rules-only analysis of `samples/OpenSSH_2k.log`, at `http://127.0.0.1:8765/incidents`, incident
`inc-2c9769961239` (HIGH, `auth_bruteforce`, entity `103.99.0.122`), whose Response panel surfaces
the shipped runbook **`rb-block-ip` — "Block source IP at the perimeter"**. Real data, no mockup, no
fixture card. Files in `docs/STAGE_E_REPORTS/F0-fix-evidence/`:

| | dark | light |
|---|---|---|
| before (steps close-up) | `before-dark-steps-closeup.png` | `before-light-steps-closeup.png` |
| after (steps close-up) | `after-dark-steps-closeup.png` | `after-light-steps-closeup.png` |
| after (whole card) | `after-dark-runbook-card.png` | `after-light-runbook-card.png` |
| before (whole card) | `before-dark-runbook-card.png` | `before-light-runbook-card.png` |

What the browser reported at capture time, in both themes:

```
before: olDisplay flex  | olListStyleType none    | olHeight 92.1  -> no marker painted, gutter empty
after : olDisplay block | olListStyleType decimal | olHeight 92.1  -> "1." and "2." painted in the gutter
```

The before/after pair is framed identically and the list geometry is the same 92.1px in both, so the
only difference between the two images is the presence of the ordinals. The whole-card shots confirm
the badge, the four plain-language rows, the reversibility line and the closed `Rule detail`
disclosure are unchanged.

*(An earlier "before" capture measured 95.1px because the staged pre-fix stylesheet still carried my
new `margin-top` rule alongside the old `gap`. Those images were discarded and re-taken against the
exact original rule; the 92.1px figures above are from the corrected pair.)*

---

## 6. Green outputs

```
npm --prefix web test        43 files, 295 passed (295)        # was 290; +5 new, 0 changed
npm --prefix web run build   tsc --noEmit + vite build  OK
tests/eval/run_eval.py       20/20, TP 16, FP 0, FN 0, precision 1.000, recall 1.000, f1 1.000
console/test_console.py      PASSED (all suites green)
shasum -a 256 anomaly_detector.py
                             364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876
git diff --check             clean
```

No existing test was edited in intent. The one pre-existing line I touched is mechanical: my new
fallback test reuses `UNDESCRIBED.stepsNote`, typed `string | null`, which `tsc --noEmit` rejected
inside `toHaveTextContent`; it is now null-checked first. No assertion changed meaning.

## 7. Allowlist audit

```
 M web/src/styles/itsoc.css
 M web/src/test/runbook-card.test.tsx
?? docs/STAGE_E_REPORTS/F0-fix-evidence/   (8 PNGs only)
+  docs/STAGE_E_REPORTS/F0-fix-worker.md
```

Every path is on the allowlist. `web/src/components/RunbookCard.tsx` was **not** modified (§3),
`web/src/test/c4-themes.test.tsx` needed no change, and nothing under `console/`, `tools/`, the
engine, `runbooks.py` or the eligibility path was touched. `web/dist` was rebuilt repeatedly for the
screenshots but is gitignored (`.gitignore:68`) and tracks nothing.

## 8. Deviations

1. **Orca setup did not install web dependencies** — `web/node_modules` was absent. Ran
   `npm --prefix web install` myself (exit 0), as instructed.
2. **No LLM endpoint** in this environment (`localhost:11434` refused), so `serve.py --input` could
   not complete a run. Produced the report with `log_analyzer.py --rules-only` and served it with
   `serve.py --report`. Rules own severity and correlation, so the runbook eligibility and the card
   under test are identical either way; only advisory explanations are absent, and none appear on
   this card.
3. **No Chrome extension** available for the browser tooling, so screenshots were captured with
   Playwright-driven Chromium instead. Still the real built app served by the real backend.
