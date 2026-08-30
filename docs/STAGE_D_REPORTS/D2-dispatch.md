# D2 dispatch — efficacy surface

**When:** 2026-08-30. **Run:** `run_2a9045b4270b`.
Frozen contract: GET/POST `/api/efficacy` (idle/running/done/error; `run` is harness JSON pass-through; scope sentence travels with the artefact).

## Cards

| Card | Worker | Dispatch | Worktree | State |
|---|---|---|---|---|
| **D2-API** | Claude | `task_97782a9db4a7` / `ctx_8ac86e539478` | `d2-efficacy-api` | **accepted** `53000fa` / merge `5d3720b`. |
| **D2-UI** | Antigravity | `task_b19bfdc1ab74` / `ctx_f79973dc53f1` | `d2-efficacy-surface` | **accepted** `dc16aa2` / merge `22bb8d5`. Orca first-attempt flag stayed failed; delivery was on the worktree. |

`--setup skip` on both (pnpm hook unused).

D2-UI first attempt (`task_886afc49c826`) died at `codex-trust-workspace` on the trust TUI. Enter accepted trust; a second `agy` terminal went idle; retry-of the first dispatch was rejected; a new task was started; prompt-inject stalled; worker kept going.

## Scoreboard after this dispatch

| Worker | Accepted | In flight |
|---|---|---|
| Codex | 2 (D0, MG-1) | 0 |
| Claude | 2 (D1, D2-API) | 0 |
| Antigravity | 1 (D2-UI) | 0 |

D3 next. P4 superseded (Docker instead of OPNsense). Parked stays parked.
