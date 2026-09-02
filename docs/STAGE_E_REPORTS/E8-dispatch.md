# E8 dispatch — frozen paired-system efficacy referee

**Dispatched:** 2026-09-02. **Run:** `run_9214da4ebb53`. **Task:** `task_af321cc0bcc3`. **Dispatch:** `ctx_e58af9c7a6d8`.

- Worker tier: Claude Code for verdict-adjacent harness extension and, because Gemini is absent and already routed up once for this run, the paired Reports/battle-card publication.
- Branch: `feat/e8-frozen-referee`.
- Worktree: `/Users/ankit/orca/workspaces/log-analyzer/e8-frozen-referee`.
- Exact base: accepted local `main` at `e46d974559f8cda1a513fe918f6d580b85633abf`.
- Allowlist: existing efficacy harness/tests/API/Reports types+surface test, battle card and citations, plus `docs/STAGE_E_REPORTS/E8-worker.md`. Detector, rules, eval corpus, model/training, decision, and dependency files are excluded.
- Referee contract: rules and learned-confirmed findings pass through the identical scoring/diff path; fresh benchmark seeds and entities must be asserted disjoint from the actual E7a sidecar; both systems list misses verbatim and carry one run id plus model provenance.
- Isolation contract: independent finding collections, a model-kill rerun with byte-identical rule numbers/misses, non-vacuous paired-system differences, and honest model-unavailable output rather than zero scores.
- Publication contract: side-by-side per-scenario metrics and misses in Reports and the battle card, standing synthetic-scope sentence retained, plus `the learned model is advisory; these numbers are why.`
- Acceptance requires a clean-environment fresh train and benchmark, seed-overlap and model-kill mutation failures observed/restored, focused and full Python/web gates, frozen detector hash, allowlist audit, and a local commit only.
- After acceptance, the referee logic, its tests, and benchmark seed selection are frozen. E7b modifiers may not edit them.
