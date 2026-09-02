# ITSOC Stage E — Execution Log

Owner-activated 2026-09-02 via `ITSOC_STAGE_E_ORCHESTRATOR_PROMPT_LEAN.md`.
Build order: E0 + E6 → E1 → E7a → E8 → E7b → E9.

Detector freeze: `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.
Model/advisory output is fenced from severity, eligibility, priority, and execution.

---

## Activation, gate, and first dispatch — 2026-09-02

Report: `docs/STAGE_E_REPORTS/activation-dispatch.md`.

- Step 0: local `main` matched `origin/main` at `b836114`; Stage E register commits then advanced local `main` to `5978d71`. No push.
- Step 1: required inputs present; detector freeze exact; Guardrails already present; Stage E registers created.
- Step 2: all required gates passed. Web 43/43 files, 251/251 tests; eval 20/20, F1 1.000; console, intake, fsafe, MCP, and threat-intel suites green.
- Step 3: Claude Code 2.1.252 and Codex 0.149.1 present. Antigravity and Gemini absent; both tiers route up to Claude Code for this run and are logged here once.
- Owner update: `docs/ITSOC_STAGE_E_ACTION_CARDS.md` replaced byte-for-byte from the 2026-09-02 download (`9e8da0b…cc2c93`), adding Track F and immediate F0. The orchestrator prompt still governs mechanics, including E7a → frozen E8 → independently graded E7b rounds → E9.
- Dispatched: E0 `task_011af4e0ea34` / `ctx_b09c48a3291c`; E6 `task_ae693acfc187` / `ctx_eeeeb1190457`; F0 `task_2da0cfc5cfa8` / `ctx_ca8144f63b88`.

## E6 accepted — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E6-accepted.md`.

- Accepted worker commit `6285a0f` and merged locally as `9a61c0f`; no push.
- Independent gates: Stage E wall 30/30, full console suite green, referee eval 20/20 with F1 1.000, frozen detector hash exact.
- Accepted the AST import/call wall as the precise implementation of the requested grep guard: executable coupling fails without comment/string false positives.
- `graphify update .` succeeded after merge.

## E0 and F0 accepted — 2026-09-02

Reports: `docs/STAGE_E_REPORTS/E0-accepted.md` and `docs/STAGE_E_REPORTS/F0-accepted.md`.

- E0 accepted from worker commits `622f540` and `f8cc279`; merged locally as `684c373`; no push.
- E0 evidence: full console suite including 34 new checks, eval 20/20 with F1 1.000, build green, eligibility unchanged and disposition-blind, frozen detector hash exact.
- F0 accepted from worker commit `4cb5b17`; merged locally as `01c88dc`; no push and no engine/backend changes.
- F0 evidence: runbook and theme coverage green, full console suite, eval 20/20 with F1 1.000, build green, frozen detector hash exact.
- A parallel acceptance run timed out in the same untouched Integrations test on both branches under resource contention; its isolated rerun passed 9/9. The combined-main sequential suite then passed 43/43 files and 266/266 tests.
- `graphify update .` succeeded after both merges.

## E1 dispatched — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E1-dispatch.md`.

- Task `task_4a6f228d1ce6`, dispatch `ctx_c8fdfcc07fbf`, Claude Code.
- Branch `feat/e1-precedent-index` in its own worktree, exact accepted-main base `7bd6796`.
- Contract retains the E6 rank signature and advisory wall; E1 is deterministic recall only. No push or worker merge.

## E1 accepted — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E1-accepted.md`.

- Accepted worker commit `9f34421`; merged locally as `739683f`; no push.
- Independent gates: Stage E wall 48/48, full console green, web 43/43 files and 271/271 tests, build green, eval 20/20 with F1 1.000, frozen detector hash exact.
- 2,500-incident end-to-end query: best 18.1 ms, median 18.7 ms of 7, with a clock-free posting-cost assertion proving the query does not scan the whole store.
- Disposition joins only after deterministic ranking; advisory/disposition poisoning cannot reorder results. Explanations are recomputable from each match's shared facts.
- `graphify update .` completed. Graphify reported one TSX parser warning on `Incidents.tsx`; the authoritative TypeScript build passed.

## E7a dispatched — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E7a-dispatch.md`.

- Existing generator/isolation prerequisite reverified: 5/5 generator tests and 13/13 harness tests.
- Task `task_64d5ccd160ec`, dispatch `ctx_c8ce5df92642`, Claude Code, branch `feat/e7a-model-v1`.
- Exact accepted-main base `e7f6831`. One shared rule-owned feature extractor; seeded provenance; stratified CV; balanced weighting; learned advice only.
- Missing dependency/model must remain an honest visible unavailable state. Mutation and kill-model evidence are mandatory. No push or worker merge.
