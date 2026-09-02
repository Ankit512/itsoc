# E7a Codex test-only dispatch

**Dispatched:** 2026-09-02. **Run:** `run_9214da4ebb53`. **Task:** `task_ad6e978dc5ba`. **Dispatch:** `ctx_9d10053d48fd`.

- Worker tier: Codex, satisfying the action card's independent feature-extraction test assignment.
- Branch: `test/e7a-feature-contract`.
- Worktree: `/Users/ankit/orca/workspaces/log-analyzer/e7a-feature-contract`.
- Exact base: merged local `main` at `8337490c90e11e034432a6cc2d9b8f980b21556a`.
- Scope is test-only. Allowed paths are exactly `tests/test_e7a_feature_contract.py` and `docs/STAGE_E_REPORTS/E7a-codex-tests.md`.
- Contract: batch deterministic feature checks across representative shapes, seeds, and all three classes; exhaustive forbidden-field poisoning; shared train/inference feature identity; three-class prediction contract; every unavailable/corrupt artifact mode; byte-identical rule-owned finding, incident, eligibility, and case data across advisory attach/model kill; no advisory persistence or protected-projection ingress.
- Required gates: the new stdlib test, Stage E wall, full console, eval, frozen detector hash, and diff hygiene. No implementation changes, no worker merge, no push.
