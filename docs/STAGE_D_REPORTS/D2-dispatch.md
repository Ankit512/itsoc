# D2 dispatch — efficacy surface

**When:** 2026-08-30. **Run:** `run_2a9045b4270b`.
Frozen contract: GET/POST `/api/efficacy` (idle/running/done/error; `run` is harness JSON pass-through; scope sentence travels with the artefact).

## Cards

| Card | Worker | Dispatch | Worktree | State |
|---|---|---|---|---|
| **D2-API** | Claude | `task_97782a9db4a7` / `ctx_8ac86e539478` | `d2-efficacy-api` | `input_accepted`, heartbeat `implementing`. `serve.py` + `efficacy_api.py` dirty. |
| **D2-UI** | Antigravity | `task_b19bfdc1ab74` / `ctx_f79973dc53f1` | `d2-efficacy-surface` | Orca marked **failed** (`agent_prompt_stalled` after a workspace-trust prompt). **Spec landed**; agent is reading Reports/api and running vitest. Same class as the first Antigravity stall: check delivery, not the Orca failed flag. |

`--setup skip` on both (pnpm hook unused).

D2-UI first attempt (`task_886afc49c826`) died at `codex-trust-workspace` on the trust TUI. Enter accepted trust; a second `agy` terminal went idle; retry-of the first dispatch was rejected; a new task was started; prompt-inject stalled; worker kept going.

## Scoreboard after this dispatch

| Worker | Accepted | In flight |
|---|---|---|
| Codex | 2 (D0, MG-1) | 0 |
| Claude | 1 (D1) | 1 (D2-API) |
| Antigravity | 0 | 1 (D2-UI, Orca-failed but delivering) |

D3 / P4 not started. Parked stays parked.
