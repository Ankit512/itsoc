# Stage E activation and first dispatch

**When:** 2026-09-02. **Run:** `run_9214da4ebb53`. **Policy:** local merges only; no push.

## State

Stage E is active. E0, E6, and the newly immediate F0 are dispatched in separate child worktrees from local `main` commit `5978d719d59807a6e626e919df15468160b30e16`.

## Step 0 — repository gate

- `git fetch origin && git checkout main && git merge --ff-only origin/main`: passed.
- Gate point: local `HEAD` = `origin/main` = `b83611484233496231aebbfff092ae98cdbee438`.
- Stage E register initialization: `e65d670`.
- Updated owner scope applied byte-for-byte from `/Users/ankit/Downloads/ITSOC_STAGE_E_ACTION_CARDS.md`: `5978d71`.
- Current local `main` is two commits ahead of `origin/main`; no feature branch was changed and nothing was pushed.

## Step 1 — inputs

- `CLAUDE.md`: present and read.
- `docs/ITSOC_STAGE_E_ACTION_CARDS.md`: present, read, then updated from the owner download; SHA-256 `9e8da0b91378b74981d0bebba4e59a37559fa1184c6cd7af6c0a980cd3cc2c93`.
- `GUARDRAILS.md`: present; no bootstrap required.
- Stage E log, open-items register, and reports directory initialized.
- `anomaly_detector.py`: `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`, exact freeze.

## Step 2 — full gate evidence

| Command | Result |
|---|---|
| `sha256sum anomaly_detector.py` | exact frozen SHA-256 |
| `npm --prefix web run build` | exit 0; TypeScript and Vite build passed |
| `npm --prefix web test` | exit 0; 43 files, 251 tests passed |
| `python3 tests/eval/run_eval.py` | exit 0; 20/20, precision 1.000, recall 1.000, F1 1.000 |
| `python3 console/test_console.py` | exit 0; all checks green |
| `python3 tests/test_intake.py` | exit 0; 4 tests passed; ResourceWarnings visible |
| `python3 console/test_fsafe.py` | exit 0; 10 checks passed |
| `python3 itsoc_mcp/test_mcp.py` | exit 0; 131 passed, 0 failed |
| `python3 threat_intel/test_threat_intel.py` | exit 0; green with 3 documented cache-fixture skips and visible credential-mode warnings |

No pytest was run. Output was not redirected or discarded.

## Step 3 — worker tiers

- Claude Code: present, `2.1.252`.
- Codex: present, `codex-cli 0.149.1`.
- Antigravity: absent.
- Gemini: absent.

Per the routing rule, absent Antigravity and Gemini work routes up to Claude Code. This is the single absence log for the run.

## Dispatch

| Card | Eligible pool note | Task / dispatch | Branch / worktree |
|---|---|---|---|
| E0 | Claude only: store schema, lifecycle, migration, audit, eligibility adjacency | `task_011af4e0ea34` / `ctx_b09c48a3291c` | `feat/e0-disposition-capture` / `e0-disposition-capture` |
| E6 | Claude only: guard and verdict/eligibility adjacency | `task_ae693acfc187` / `ctx_eeeeb1190457` | `feat/e6-stage-e-wall` / `e6-stage-e-wall` |
| F0 | Antigravity + Gemini preferred but absent; routed up to Claude; Codex ineligible for this light-tier card | `task_2da0cfc5cfa8` / `ctx_ca8144f63b88` | `feat/f0-runbook-legibility` / `f0-runbook-legibility` |

All three task and dispatch records were verified in Orca. All worktrees start at `5978d719d59807a6e626e919df15468160b30e16`; allowlists are disjoint. E0 is the only store/migration card in flight.
