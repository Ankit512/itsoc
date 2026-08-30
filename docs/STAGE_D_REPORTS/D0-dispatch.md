# D0 dispatch — generator promotion

**When:** 2026-08-30. **Run:** `run_2a9045b4270b`. **Task:** `task_f16ed2ca7392`. **Dispatch:** `ctx_85c74e21f2d5`.
**Worker:** Codex in isolated worktree `d0-attack-generator`.
**Input:** accepted (`stage: input_accepted`). Not yet reviewed.

## Assignment split (peer tiers)

| Card | Worker | Why |
|---|---|---|
| **D0** generator promotion, templates, isolation tests | **Codex** | Distributable code unit + batch tests. No browser. |
| **D1** harness runner (generate → real pipeline → diff vs manifest) | Claude/orchestrator (restricted: pipeline, never detector internals) — not dispatched yet |
| **D2** Reports/Experimental surface + pixel/theme evidence | **Antigravity** | Driven browser / visual evidence. Balances D0's Codex load. Not dispatched until D0–D1 accepted. |
| **D3** battle-card + CITATIONS provenance | **Codex** | Doc integration. After D2 numbers exist. |

Scoreboard at dispatch: Codex 1 in-flight · Antigravity 0 (D2 reserved). Equal volume is measured over the phase, not per card.

## D0 card (summary)

Promote `tools/attack_generator.py` across the recorded bar: tests + isolation (output is fixture data; nothing it produces may enter `tests/eval/` scoring). Templates: INC-4a7f-shape brute-force (`203.0.113.44` → `server-01`), failure→success compromise, error-burst. Manifest names every malicious line, verbatim. Do not import the detector. Do not merge.

## Standing cautions

- Codex recommendations are inputs to acceptance; orchestrator greps the tree before merge.
- Antigravity `agent_prompt_stalled` is prompt-acceptance, not agent failure — check delivery first (logged at post-C closeout).
