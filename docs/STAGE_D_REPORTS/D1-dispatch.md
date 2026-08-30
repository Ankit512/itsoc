# D1 dispatch + rider 1 (migration fixture)

**When:** 2026-08-30. **Run:** `run_2a9045b4270b`.
**Setup:** `--setup skip` on both (repo hook is `pnpm install`; pnpm is not on PATH; both cards are Python-only. D0 already proved the hook fails and is unused here).

Owner: dispatch D1. Sequencing D1 → D2 → D3 → P4. Parked stays parked.

## Cards

| Card | Worker | Dispatch | Worktree | Why |
|---|---|---|---|---|
| **D1** efficacy harness | **Claude** (restricted tier) | `task_a609091f477e` / `ctx_e6fb6835cfbe` | `d1-efficacy-harness` | Verdict-adjacent diff logic; subprocess seam to `log_analyzer.py --rules-only`; must not import detector internals. |
| **MG-1** pre-migration fixture | **Codex** | `task_88228fcccd15` / `ctx_8081dd574295` | `mg1-pre-migration-fixture` | Test-side, spec-bounded. Evens the scoreboard while Antigravity waits on D2. |

Both `input_accepted`. Not reviewed yet.

## Rider 1 — migration gate (ruled, not D1)

**Pre-migration fixture, not SKIP.** C1-T1 precedent: a vacuous pass proves nothing; a gate that cannot run guards nothing.

Fixture: `tests/fixtures/pre-migration-soc/` — sqlite with the seven pre-`audit_index` tables (non-empty), plus `cases.json` with an incident-less case and a multi-incident-linked case. Gate copies it, runs `init_db()`, asserts additive `+audit_index`. If infeasible without product-code, worker stops; SKIP is owner fallback, not first choice.

## Rider 2 — D1 by-attack acceptance

1. Adversarial miss: test manifest marks a **benign** line malicious; harness must report that miss, not reconcile it away.
2. Import-graph test: `tools/efficacy_harness.py` and every first-party import must not reach `anomaly_detector`, `log_analyzer`, or `tests/eval`. Pipeline is a subprocess.

## Scoreboard after this dispatch

| Worker | Dispatched (phase) | Accepted | In flight |
|---|---|---|---|
| Codex | 2 (D0, MG-1) | 1 (D0) | 1 (MG-1) |
| Claude | 1 (D1) | 0 | 1 (D1) |
| Antigravity | 0 | 0 | 0 (D2 reserved) |
