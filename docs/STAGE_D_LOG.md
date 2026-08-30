# ITSOC Stage D — Execution Log

Owner-activated 2026-08-30 via `ITSOC_POST_C_EXECUTION_PROMPT.md`.
Priority order is binding: P1 → P2 → P3 → P4. P5 is report-only.

Detector freeze: `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.
Push policy: Q1 revised to **push now, as backup.**

Codex / Antigravity scoreboard (card count · accepted / rejected) starts at P3.

---

## P1 · Push the backlog — ACCEPTED 2026-08-30

Report: `docs/STAGE_D_REPORTS/P1-push.md`.
`origin/main` = local `main` = `e63b091` at P1 close (later `1209bc5` after this report landed). Force-pushes: none.

## P2 · FU-1 and FU-2 — ACCEPTED 2026-08-30 (OPEN-12(a))

Report: `docs/STAGE_D_REPORTS/P2-followups.md`.
- FU-2 `e4b0712` / merge `326b436` — TOKENS.md footer aligned to the live product string after confirming grep.
- FU-1 `a3bdf32` / merge `93fbd4c` — KPI context line; web 206/206.

## P3 · D0 dispatched 2026-08-30 — ACCEPTED same day

Dispatch report: `docs/STAGE_D_REPORTS/D0-dispatch.md`.
Acceptance: `docs/STAGE_D_REPORTS/D0-accepted.md`.
Codex `43ff064` / merge `985ff4c`. 5/5 tests, eval 19/19, detector frozen.
Scoreboard: Codex 1/1 accepted · Antigravity 0 (D2 reserved). D1 next.

## P3 · D1 + MG-1 dispatched 2026-08-30 — not yet accepted

Report: `docs/STAGE_D_REPORTS/D1-dispatch.md`.
- D1 Claude `task_a609091f477e` / `ctx_e6fb6835cfbe` (restricted harness).
- MG-1 Codex `task_88228fcccd15` / `ctx_8081dd574295` (pre-migration fixture; evens scoreboard).
Setup skipped on both (pnpm hook unused). Parked stays parked. D2/D3/P4 not started.

## P3 · MG-1 accepted 2026-08-30

`docs/STAGE_D_REPORTS/MG-1-accepted.md`. Codex `d5f3da5` / merge `721f7e5`.
`check_audit` rc 0 with no live db; full `test_console.py` EXIT=0; mutation holds.

## P3 · D1 accepted 2026-08-30

`docs/STAGE_D_REPORTS/D1-accepted.md`. Claude `482dbd4` / merge `58a73df`.
13/13 including adversarial miss + import-graph mutation guard.

Scoreboard: Codex 2/2 accepted · Claude 1/1 accepted · Antigravity 0 (D2 next).

## P3 · D2 dispatched 2026-08-30 — not yet accepted

Report: `docs/STAGE_D_REPORTS/D2-dispatch.md`.
- D2-API Claude `task_97782a9db4a7` / `ctx_8ac86e539478` (heartbeat implementing).
- D2-UI Antigravity `task_b19bfdc1ab74`: Orca `agent_prompt_stalled` after workspace-trust; spec landed and the agent is working. Accept on worktree delivery, not the failed flag.

## P3 · D2-API accepted 2026-08-30

`docs/STAGE_D_REPORTS/D2-API-accepted.md`. Claude `53000fa` / merge `5d3720b`.
`check_efficacy_api` rc 0; eval 19/19. D2-UI still in flight.

## P3 · D2-UI accepted 2026-08-30 — D2 complete

`docs/STAGE_D_REPORTS/D2-UI-accepted.md`. Antigravity `dc16aa2` / merge `22bb8d5`.
Vitest 215/215; scope sentence grepped; no client F1 math; screenshots in `/tmp/itsoc-d2/screenshots/`.
Live `/api/efficacy` marked NOT TESTED by the worker (API was parallel; now on main).
Scoreboard: Codex 2/2 · Claude 2/2 · Antigravity 1/1. D3 next.
