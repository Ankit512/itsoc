# P2 · FU-1 and FU-2 closed

**When:** 2026-08-30. **Authority:** OPEN-12(a) — owner 2026-08-30, orchestrator-ratified, logged.
**Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` unchanged.

## FU-2 · Copilot footer copy — `fix/copilot-footer-copy`

Confirming grep (`web/src` + `docs/design`):

- Live footer (product + tests + incident mockup): `Rules set severity. I interpret & explain — I don't decide.`
  - `CopilotRail.tsx:753`, `Incidents.tsx:646`, `copilot-rail.test.tsx`, `overview.test.tsx`, `design_itsoc_incident_rca.html`, v3/dc mockups.
- TOKENS.md was the remaining *declared* footer that said `I explain & prioritize`. Amended to the live string.
- Outlier, not in this card: `design_itsoc_overview.html` still says `Rules set the severity. I explain & prioritize` (extra "the", old wording).

Commit `e4b0712`. Merge `326b436`.

## FU-1 · Banner over stale dashboard — `fix/banner-stale-run`

KPI block grows one line, only when `useJobs.current` is `done` + `unrecognized` **and** the selected run is still parsed:

> showing previous run — latest upload unrecognized

When the selected run itself is unrecognized, existing banner + "nothing was parsed" copy stands; the new line is absent. Tests cover both states.

Commit `a3bdf32`. Merge `93fbd4c`. web **206/206** + `npm run build` green.

## Deviations

None. Allowlists held. No detector edit.
