# Post-C checklist closeout

**Run:** Orca `run_708480b9400f` (Grok coordinator). **Closed:** 2026-08-30.
**Owner rulings** executed the same day. Nothing here was merged without an explicit gate.
**Detector freeze throughout:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.

Workers: Codex (`task_5a8b9b06b3a9` / `ctx_3c296e2d0fa4`) reviewed the parked items.
Antigravity (`task_dac893c17de0` / `ctx_95f14b535302`) ran the live pixel pass.

## Merges (local `main`, not pushed)

| Branch | Merge commit | Ruling |
|---|---|---|
| `fix/shadow-tokens` | `c2f7e75` | merge; two caveats filed as FU-1 / FU-2, not blockers |
| `fix/gate-hygiene` | `eec463d` | merge; uncharacterised `test_console.py` exit=1 stays open and honest |

## Filed follow-ups (not implemented in this closeout)

- `docs/followups/FU-1-banner-stale-run.md` — KPI context line when the latest ingest failed over a previous run.
- `docs/followups/FU-2-copilot-footer-copy.md` — one honesty-footer string; grep the tree before picking.

## `tools/attack_generator.py`

Owner: **keep as a dev tool, untracked/gitignored.** Codex isolation reasoning stands: stdlib-only, no detector import, synthetic fixtures useful for a future efficacy harness, would contaminate eval if treated as a score.

**Promotion bar** (also in `.gitignore` next to the path): product status requires tests plus an explicit isolation rule keeping it out of any eval path. Closes the foreign-work inventory item for this file.

## Parked auth WIP

`feat/redesign-integration` (`71782ef`) stays parked, not killed. Directionally right; Codex's four findings are disqualifying as-is. Acceptance bar is `PARKED.md` on that branch. It only comes back through that list.

## Stage D

Not dispatched. It gets a scope doc from the owner before anything runs.

---

## Incident · Antigravity `agent_prompt_stalled`

`orca orchestration worker-start --agent antigravity --worktree current` against `task_dac893c17de0` returned `state=failed`, `failedStage=dispatch_input`, `lastError=agent_prompt_stalled` (~40s after terminal create `term_0fda549f-b9e1-43e0-828e-a7d843138597`).

What stalled: **Orca's prompt-acceptance detector**, not the agent. The spec had already landed in the TUI (the card text was in the terminal tail; the worker was reading `App.tsx` / `itsoc.css` and starting Playwright). The worker continued and later delivered `worker_done` with `outcome=succeeded`; the task flipped from `failed` to `completed`. Outcome is fine. An injection-flagged stall on an agent driving a browser is still worth the line.

Page-content injection: **not observed.** The audited pages are the itsoc console (Overview, Incidents, Approvals, overlays). Their copy is honesty banners, KPI labels, and the copilot footer. The worker's output is a structured visual-audit report plus screenshots under `/tmp/itsoc-checklist/`. Nothing in those pages appears as an instruction in that output; the stall predates any page navigation.

## Audit-accuracy · verbatim copy claim

Antigravity reported a verbatim match to TOKENS.md's `"I explain & prioritize"`. The copilot-drawer capture shows `"I interpret & explain"`. Same defect class as C4-A2 (a 100% conformance claim that a tree grep disproved). Filed on FU-2. Grep-the-tree applies to copy claims.
