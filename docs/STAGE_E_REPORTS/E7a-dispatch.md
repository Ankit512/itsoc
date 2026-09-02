# E7a dispatch — learned triage model v1 and render

**Dispatched:** 2026-09-02. **Run:** `run_9214da4ebb53`. **Task:** `task_64d5ccd160ec`. **Dispatch:** `ctx_c8ce5df92642`.

- Worker tier: Claude Code for training pipeline, guard integration, and unavailable-state behavior. Antigravity and Gemini are absent and already routed up/logged once for this run.
- Branch: `feat/e7a-model-v1`.
- Worktree: `/Users/ankit/orca/workspaces/log-analyzer/e7a-model-v1`.
- Exact base: accepted local `main` at `e7f68313dcec3b6eef2ae0af8d3ee16b341e40ab`.
- Existing first subtask: the owner-promoted attack generator and eval-isolation guard were already accepted in prior work. Reverification passed 5/5 generator tests and 13/13 harness tests; E7a may extend seeded/near-miss coverage without duplicating the promotion.
- Model contract: real analyzer subprocess over generator manifests; real dispositions may join as labels; unlabeled store events are context only and never receive invented labels; stratified CV plus balanced weights; exact seeds and counts in a sidecar.
- Wall: one shared rule-owned `features()` function for train/inference; no advisory/disposition/priority/eligibility/execution leakage; learned result is visible advice only. Missing sklearn/model is an honest unavailable state with no fabricated opinion.
- Rendering: Findings and Incidents show `AI TRIAGE · LEARNED, ADVISORY`, including disagreement and unavailable states. E1 remains the non-prose precedent overlap display; no E4 prose.
- Required evidence: real mutation failure, kill-the-model survival, training under ten minutes, unit/full gates, exact detector hash. Local merge only after independent review; no push.
