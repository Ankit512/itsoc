# GUARDRAILS.md — standing doctrine (Stages C/D/E)

1. Rules own severity, correlation, priority, eligibility; LLM/model output is advisory everywhere, never a control signal or gate input.
2. Honest surfaces: failures visible, empty states empty, timeouts said, audit chain reports its own breaks, no invented data.
3. The detector is frozen; its sha check is a tripwire on every branch.
4. Egress: logs/errors/displays/exceptions carry redacted+credential-masked forms; the wire carries minimum values; credentials are token/cert/key, config-file only, never argv or logs.
5. Delivery is the liveness signal; counters never justify a stall call. Diagnose: delivered? -> memory -> inbox. Reassign, never respawn; a recovered slot takes a new card.
6. An audit is a claim about a tree — grep the tree first (copy claims included). Evidence produced against the wrong tree is the screenshot form of the reconstructed audit: honest-looking, procedurally clean, and false. It is likeliest on cards whose whole purpose is evidence, because those are the cards where nobody re-checks the tree.
7. Security is accepted by attack: mutate -> observe failure -> restore, diff-proven. A guard never seen to fail is not yet a guard.
8. Out-of-allowlist defects: fix at an owned seam or report; never edit foreign components. Read any worktree; write only your own.
9. No `git add -A` — stage explicit paths. Verification commands never discard output. Every card carries a `base:` (a commit the worktree MUST contain) alongside its `branch:`, and the base is verified twice: by the orchestrator at dispatch, from actual worktree provenance and never assumed to land on current main; and by the worker pre-edit, with `git merge-base --is-ancestor <base> HEAD`. The base check is what stops work. The branch-name check is a WARNING only — workspace naming conventions must never generate a stop, because a guard that alarms on cosmetics trains workers to override alarms. Evidence-producing cards verify additionally that the specific artefacts they are evidencing exist at HEAD before capturing anything: grep-the-tree extends to photograph-the-tree.
10. Non-behavioral out-of-allowlist diffs: orchestrator ratification explicitly expands the card's allowlist (recorded on the card) before acceptance, and is logged; behavioral ones halt for the owner.
11. Prep anytime; execution strictly in order; running ahead is a deviation, not efficiency.
12. A constraint that must outlive its card is written into the artefact it constrains. Gating asks stand alone: full text inline, every time.
