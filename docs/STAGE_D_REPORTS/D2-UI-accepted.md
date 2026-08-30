# D2-UI accepted — Detection Efficacy surface on Reports

**When:** 2026-08-30. **Worker:** Antigravity `task_b19bfdc1ab74` / `ctx_f79973dc53f1` / `dc16aa2`.
**Merge:** `22bb8d5`. **Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.
**Delivery:** `delivery_356e1cd699ed` / `msg_91db306ae0a5`.

Orca listed the first D2-UI dispatch as failed (`agent_prompt_stalled` after workspace-trust). Accept is on the worktree + mailbox, not that flag.

## Independent verification

| Check | Result |
|---|---|
| Allowlist | `web/src/lib/api.ts`, `web/src/pages/Reports.tsx`, `web/src/test/efficacy-surface.test.tsx` only |
| Nav | 12-screen roster unchanged; surface lives on Reports, no extra item |
| Scope sentence | exact `measured against synthetic ground-truth scenarios; not a claim about production traffic.` on the panel (grep) |
| Client scores | no `precision * recall` / F1 math in `Reports.tsx`; table renders `sc.totals.{precision,recall,f1}` pass-through |
| Miss count | `sc.totals.missed_lines ?? sc.misses.length` (API fields, not recomputed F1) |
| Idle | n/a copy *No efficacy harness run yet — run one to measure synthetic scenarios*; no fabricated 1.000 |
| Running / error | honest; no table fill |
| Done | table rows match fixture JSON; miss list shows verbatim `line` / `raw` / `why` |
| Empty misses | *no missed malicious lines* plus the scope sentence |
| Vitest (worktree) | 215/215 (41 files); efficacy-surface 9/9; reports 5/5 |
| `npm run build` | tsc + vite OK |
| Eval | 19/19 |
| `console/test_console.py` (worktree, pre-D2-API base) | EXIT=0 |
| Screenshots | `/tmp/itsoc-d2/screenshots/01_idle_light.png` … `06_error_light.png` (idle/populated/running/error; light+dark for idle+populated) |
| Live `/api/efficacy` | worker marked **NOT TESTED** (API was on the parallel D2-API branch). Honest. D2-API is now on `main`. |

## Logged deviations

- Worktree branch name `Ankit512/d2-efficacy-surface` also exists as `feat/d2-efficacy-surface` at the same `dc16aa2`.
- Screenshots were taken against a live Reports page that already had one saved report on disk; efficacy states were mocked. Not a fabricated score.

## Next

D2 (API + UI) is complete. **D3** (battle-card + CITATIONS provenance) is unblocked. P4 waits on D3. Parked stays parked.
