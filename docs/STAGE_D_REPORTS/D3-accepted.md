# D3 accepted — battle-card + CITATIONS provenance

**When:** 2026-08-30. **Worker:** Codex `task_04b490e78a68` / `ctx_c78fdf042039` / `1fd91a4`.
**Merge:** `277daaa`. **Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.
**Delivery:** `delivery_4ad65fd77105` / `msg_147124a816c6`.

## Independent verification

| Check | Result |
|---|---|
| Allowlist | `docs/BATTLECARD_TORQ.md`, `docs/research/CITATIONS.md`, `tests/test_battlecard_efficacy.py` |
| Scope sentence | exact string on §3.1a |
| arXiv C-1 | `~3.8%` and `2604.19533` unrounded; not inverted |
| Separate from eval | §3.2 Evaluation Detection Score unchanged; harness called out as a different measurement |
| Scenario vs per-rule | "do not mean every individual rule achieved perfect recall" |
| C-2 | repo evidence: reproduce command, `58a73df`, run date, scenario ids, 0 misses / 0 FPs |
| `tests.test_battlecard_efficacy` | 3/3 (re-runs harness; table rows match live JSON) |
| Eval | 19/19 |

Logged: commit message contains a literal `\n\n`; not a claim defect. Audited tree is `06a7b98` (measurement base) plus harness landing `58a73df`.

## Ceiling framing (required addition, self-ratified 2026-08-30)

All-1.0 across three scenarios with zero misses is a ceiling. The battle-card block and the Reports harness surface now state explicitly: these scenarios are drawn from the same attack classes the rules were written for — the expected result is perfection, and its value is regression proof (any future score below 1.0 is a detected regression), not a general-efficacy claim. Frozen `scope` JSON field unchanged.

## Next

P3 complete (D0–D3). P4 superseded (ratified). Floor stood down. Parked items remain parked; nothing further without a new scope doc from the owner.
