# D0 accepted — generator promotion

**When:** 2026-08-30. **Worker:** Codex `task_f16ed2ca7392` / `ctx_85c74e21f2d5` / commit `43ff064`.
**Merge:** `985ff4c` (orchestrator-verified). **Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.

## Independent verification (not the worker's claim)

| Check | Result |
|---|---|
| `python3 -m unittest tools.test_attack_generator` | 5/5 |
| `tests/eval/run_eval.py` | 19/19, F1 = 1.000, eval tree unedited |
| Detector sha | unchanged |
| Isolation | default output `tools/efficacy_data/`; `ValueError` if output resolves under `tests/eval/`; eval corpus does not mention `attack_generator` / `efficacy_` |
| Manifests | every malicious line: `{line, raw, why}` with `raw` equal to the generated log line |
| Templates | `INC-4a7f` (203.0.113.44 → server-01), `failure-success`, `error-burst` × four formatters |
| Allowlist | `.gitignore`, `tools/attack_generator.py`, `tools/test_attack_generator.py` |

## Deviations (logged, not blockers)

1. **Reconstructed instead of copying.** The gitignored original lived only on the integration disk. Coordinator told Codex to copy it. Codex rewrote a smaller module. Required D0 templates and the isolation bar still hold.
2. **Dropped extra scenarios** `port_scan` and `credential_spray` from the untracked original. Card said keep extras if they still work; not in the required three.
3. **Repo setup `pnpm install` failed** (`pnpm: command not found`). Agent still delivered. D0 does not need Node.
4. **worker-release** after done: `tab_not_found` / `release_unknown` (terminal already disconnected). Fenced with `worker-abandon`. No process action.

## Scoreboard

Codex 1 dispatched / 1 accepted. Antigravity 0 (D2 still reserved). D1 not started.
