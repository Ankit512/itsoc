# F0-FIX accepted — the steps are a real numbered list, in both themes

**Accepted:** 2026-09-03. **Task:** `task_c5347ee3033c`. **Dispatch:** `ctx_1dd66e0b1d3e`.
**Worker commit:** `82e5e3e` (base `944c47e`). **Local merge:** `54a012f`. **Push:** none.
Worker report: `docs/STAGE_E_REPORTS/F0-fix-worker.md`. Evidence: `docs/STAGE_E_REPORTS/F0-fix-evidence/`.

This closes the one F0 acceptance bar left unmet, found by the F0-EV evidence card.

## The card's diagnosis was half the cause — the worker found the other half

F0-EV and the card both identified `display:flex` on `.is-rb-steps__list`. That is cause one. The
worker found cause two: **Tailwind's preflight sets `ol,ul{ list-style:none }`**, loaded via
`@tailwind base` in `index.css` before `itsoc.css`. Both verified by the coordinator —
`main.tsx` imports `index.css` ahead of `itsoc.css`, and `tailwindcss/src/css/preflight.css:308`
does set `list-style: none`.

**Un-flexing alone would have left the steps bare**, and would have left the Safari/VoiceOver
semantics defect entirely untouched, because `list-style:none` on an `<ol>` is what drops list
semantics for that reader. A fix that addressed only the documented cause would have looked correct,
passed a naive test, and shipped the accessibility half of the defect intact.

The fix states both: `display:block` and `list-style:decimal outside`. `RunbookCard.tsx` was
**not touched** — its markup was already a correct `<ol>`/`<li>`, so CSS was the seam where the
damage was done. The old `gap:3px` rhythm is preserved verbatim as `.is-rb-steps__item + .is-rb-steps__item{ margin-top:3px }`,
and the worker measured spacing byte-identical in-browser (92.1px list, 3px gap, before and after),
so nothing around it shifts.

## The test — and the worker catching its own vacuous assertion

The card's stated point was that F0's tests passed for the defect's entire life because they assert
structure, never rendered result. The worker confirmed this by measurement: **the old suite scores
290/290 against the broken stylesheet.**

It added 5 tests and verified each by reverting — including against a *partial* fix that unflexes
but leaves the marker to the preflight. In doing so it caught a vacuous assertion of its own:
its first computed-style check on `list-style-type` **passed against the broken partial fix**,
because jsdom's cascade propagates `display` but not `list-style-type` and `getComputedStyle`
returns the UA default `decimal` regardless of stylesheets.

So the limits are stated exactly, in both the test file and the report: jsdom never paints a
`::marker`, so nothing asserts a painted "1."; cause 1 is asserted on computed style, cause 2 on the
CSS source — the assertion that actually fails on the partial fix. Catching a test that passes for
the wrong reason, by counterfactual, is the discipline this card was written to produce.

## Evidence

Real running app — rules-only OpenSSH_2k run served by `serve.py`, incident `inc-2c9769961239`,
shipped runbook `rb-block-ip` — before/after, light and dark, card and close-up. Coordinator read
the after images directly: steps render as `1.` and `2.` in **both** themes.

## Coordinator gates on merged main

web **301/301** across 43 files; `npm run build` green; `tests/eval/run_eval.py` 20/20 F1 1.000 FP 0;
detector sha256 `364577c5…577a4a876` unchanged. Allowlist clean — `itsoc.css`, the test file, the
report and eight evidence images; `RunbookCard.tsx` provably untouched; no engine, backend,
`runbooks.py` or eligibility path in the diff. Branch never pushed.

## Deviations, recorded

Orca setup left `web/node_modules` missing, so the worker installed them itself. No LLM endpoint
available, so it drove the app with `--rules-only` plus `serve.py --report`. No Chrome extension, so
screenshots came from Playwright-driven Chromium against the real built app — still the real running
UI, not a mockup.

## Standing note

F0's acceptance bar is now met in full. The broader finding stands and is not closed by this card:
a suite that asserts structure while the rendered result is broken proves less than its pass rate
suggests — the same shape as line-level recall reading 1.000 while a rule class sat at 0.5833.
