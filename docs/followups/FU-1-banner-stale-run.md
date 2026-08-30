# FU-1 · Banner over a stale dashboard

**Tier:** any. **Branch:** `fix/banner-stale-run` (suggested).
**Source:** owner ruling 2026-08-30, after the Antigravity pixel pass on `fix/shadow-tokens`.
**Does not block** the shadow-tokens merge (`c2f7e75`).

## Problem

The unrecognized-format banner and the populated Overview KPIs can tell two different stories at once.

Observed on the pixel-pass capture `honesty_unrecognized_banner_dark.png`:

- A dashed banner: *"Log format not recognized — 0 lines parsed (0 of 2,000 lines recognized). No rule evaluated a single line, so this run is not evidence the log is clean."*
- A toast: `ingest: sample-unrecognized.log` / `0 lines parsed · unrecognized format`.
- The run switcher and provenance strip still named `sample-2.log` · **19 lines parsed**.
- KPI block still showed **11 findings**.

Each piece is honest in isolation. Together they contradict: the banner says this view is not evidence the log is clean; the KPIs are the previous successful run.

Cause is compositional, not a fake-green: `useJobs` records the latest ingest; `/api/overview` and `/api/console_state` still describe the selected run. After a failed/unrecognized upload that does not become the selected run (or whose queries have not replaced the previous run), both surfaces render.

## Fix (prescribed)

A **context line on the KPI block** when the latest ingest failed:

> showing previous run — latest upload unrecognized

The banner and the populated dashboard then stop contradicting each other. Do not fabricate zeros. Do not swap the selected run silently. Do not drop the banner.

## Allowlist

- `web/src/pages/Overview.tsx` (KPI block context line)
- `web/src/store/jobs.ts` and/or `web/src/components/IngestNotifier.tsx` only if the Overview needs a reliable "latest ingest unrecognized, current run is previous" signal
- `web/src/test/unrecognized-honesty.test.tsx` (and a new test if the existing ones cannot express "banner + previous-run KPIs")

Do not edit `anomaly_detector.py`. Do not change severity or verdict.

## Acceptance

- [ ] When the latest ingest is unrecognized **and** the selected run is still a previous parsed run, the KPI block carries the context line above.
- [ ] When the selected run *is* the unrecognized one, existing behaviour stands: banner first, counts explained as zero-because-unparsed (`Overview.tsx` already has that paragraph).
- [ ] A test covers both states. Mutation: drop the context line → the new test fails.
- [ ] Detector sha unchanged.
