# ITSOC Stage E — Closeout

**Stage:** E — "legible intelligence". **Closed:** 2026-09-03. **Run:** `run_9214da4ebb53`.
**Merges:** local only. **Pushes:** none. **Detector:** frozen and unchanged throughout —
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.

39 commits from the accepted E7a base `e46d974`. 32 reports under `docs/STAGE_E_REPORTS/`.

## The model, in four columns

The stage's story is one table. Each column was measured by the frozen referee, and every number
below was reproduced independently by the coordinator before acceptance.

| | E7a (shipped) | R1 | **R2 (current)** |
|---|---|---|---|
| Finding-level learned recall | 0.9444 (85/90) | 0.9111 (82/90) | **1.0000 (90/90)** |
| `ioc_observed` per-rule recall | 0.5833 (7/12) | — | **1.0 (12/12)** |
| Dropped true findings | 5 | 8 | **0** |
| Learned false positives, every format | 0 | 0 | **0** |
| Line-level learned misses | 0 | 0 | **0** |
| `criticality_rank` importance | 0.4146 | absent | 0.2026 |
| Suppression flips | 33/84 | 0/84 | 33/84 |
| True-detection flips | 28/85 | 0/82 | 30/90 |

R1 eliminated the backwards gradient but regressed recall; R2 fixed recall completely and halved the
gradient. Neither dominated both. R2 is current under the standing publication rule.

## Phases

| Card | Outcome |
|---|---|
| E0 · disposition capture, E1 · precedent index, E6 · Stage E wall | accepted (pre-existing at activation) |
| E7a · learned triage model v1 + independent test card | accepted |
| **E8 · frozen paired-system efficacy referee** | accepted; benchmark seeds frozen, rules vs learned scored through one path |
| **E8 leakage interrogation** (coordinator-run) | leakage cleared on four grounds; surfaced a publication defect and a second finding |
| **E8m · metrics amendment** | accepted; finding-level recall, format-scoped FP totals, criticality counterfactual |
| **E8m2 · scorecard + freeze amendment** | accepted; per-rule recall, benchmark scenario tuple pinned |
| **E7b R1 · modifier** | honest partial, **not merged** — defects eliminated, recall regressed |
| **E7b R2 · modifier** | **PASS**, merged and current |
| F0 · runbook legibility | accepted earlier; dispatch-dedup check prevented a duplicate |
| **F0-EV · screenshot evidence** | accepted; found the steps-numbering defect |
| **F0-FIX** | accepted; two causes, not one |
| **HK1 · worktree base root-cause** | accepted; systemic tooling defect fixed and proven |
| **E9 · retrain automation** | rejected once, then accepted on demonstrated evidence |

## What the stage actually established

**The wall works, observed rather than asserted.** The benchmark caught the advisory model
confidently wrong on the highest-stakes case in the corpus — five threat-intel `ioc_observed`
findings on the crown-jewel host, labelled `benign-expected` at up to 0.992 confidence. Every rule
verdict stood untouched. The model's error changed an advisory label and nothing else. That is the
argument for the wall, in measured numbers rather than in principle.

**One defect family, found four times.** A suite that asserts *structure* while the *rendered result*
is broken proves less than its pass rate suggests:

- line-level recall read 1.000 while `ioc_observed` sat at 0.5833;
- fifteen F0 component tests passed for a rendering defect's entire life;
- the old runbook suite scored 290/290 against the broken stylesheet;
- E9's first report claimed `succeeded` with every refusal demonstration deferred.

Each was closed by measuring the thing itself: per-rule recall published beside the aggregate, a test
asserting the rendered marker, refusals demonstrated by attack.

**The final diagnosis was a repair, not a renegotiation.** R2's fix was to make the model's feature
function agree with the rules' own taxonomy: `ioc_observed` had matched no family regex, fallen into
`rule_family_other` beside every `infra_unknown_*` rule, and inherited a `benign-expected` label it
carried on zero of its 42 training rows. The E7a feature contract came through byte-unchanged.

**We know the price of the thing we did not do.** Two rounds, different levers, converged on an
identical cost for closing the criticality gradient: eight true `infra_unknown_high` detections.

## Register final state

| Item | Status |
|---|---|
| **OPEN-15** — backwards criticality gradient | **OPEN, parked.** Halved not eliminated (importance 0.4146 → 0.2026); closing it costs 8 true detections under the current record projection, measured twice independently. Needs a richer projection or a different lever — model research, not automation. Better addressed once real dispositions exist via E0/E2. Stated in the E8 interrogation report so the published record matches reality. |
| `tests/test_battlecard_efficacy.py` stale assertion | Known pre-existing failure, proven byte-identical at base, head and main across three cards. Expects three scenarios from a harness returning six across three seeds. Not in the standing gate set — which is why it rotted unnoticed. Untouched: outside every card's allowlist. |

## GUARDRAILS delta

Seven commits. Additions this stage:

- **6 —** evidence produced against the wrong tree is the screenshot form of the reconstructed audit. Claims that justify **stopping** get measured like claims that justify shipping. **Owner premises are grepped like worker claims, before dispatch.**
- **9 —** every card carries a `base:`, verified twice; the stale-vs-diverged reverse-ancestor diagnostic; the orchestrator resets a clean worktree at dispatch; branch-name checks demoted to warnings; evidence cards verify their subject exists at HEAD; grading worktrees must be `--detach`.
- **5 —** completion labels are honest surfaces: `succeeded` with acceptance evidence missing is a false label.
- **Orchestrator prompt** — standing card setup preamble (base check, silent `npm install`, freeze verification, branch-name warning).

## Deviations and coordinator errors, recorded

- **Eight consecutive worktrees created on a stale base.** Root-caused by HK1: Orca resolved from `refs/remotes/origin/main`, which the standing do-not-push doctrine had frozen at the last push, 2026-09-02 08:31:11. Fixed via `orca repo set-base-ref --ref main`; proven by a fresh worktree landing on current main with no reset. Guardrail 9 retained as the detector.
- **The coordinator's `update-ref` mitigation was wrong** and the worker rejected it: the remote genuinely was at that commit, so the suggestion would have made the ref confidently wrong rather than honestly behind.
- **A false premise in an owner ruling was caught before dispatch** — there was no stored benchmark manifest; the referee generates at runtime. E8's freeze was real as seed-pinning only; E8m2 made it real.
- **Coordinator: grading worktree checked out on a live branch**, so an evaluation merge advanced `main` with a misleading message. Re-synced and amended; now a guardrail.
- **Coordinator: duplicate waiter** armed via a stray `&`, sending one waiter's output to `/dev/null`. No delivery lost; deliveries replay until acked.
- Orca setup failed on every worktree this stage; `npm --prefix web install` is now standing setup rather than a repeated deviation.

## Standing line

**A demonstration that fails is the most valuable outcome available — a real defect found by attack,
not a failure of the card.**

## Post-closeout addendum — the CB mini-scope (owner-authorized, outside the stage)

Three items after the stage closed, each on an explicit owner ruling.

| Item | Outcome |
|---|---|
| **Push to origin** | done — `origin/main` current. Also removed the stale-worktree-base root cause at source: Orca resolves from `origin/main`, which our own no-push doctrine had frozen. |
| **CB-0 · advisory family fence** | accepted, `9d5ec4a`. `ai<Something>` fenced by **class**, not enumeration. Wall 101 → 126. |
| **CB-1 · Copilot × learned triage** | accepted. Four behaviours, four attacks reproduced independently, plus a fake-system-turn vector the card did not name. Web 301 → 313 tests. |

**What CB-1 added to the argument.** The wall was already observed rather than asserted. CB-1 showed
the same principle holds one layer up: a learned answer is returned **terminally** and never handed to
the LLM, because a paraphrase of a stored confidence is a second, drifting number. Same reasoning as
the option-3 exclusion — *two computations of one stored fact drift* — applied to prose instead of to
display. The worker reached it unprompted, which is the better sign.

**And it produced one more premise failure.** The CB-1 card asserted four `ai*` fields were fenced;
two of them do not exist. Logged as **OPEN-16**, and as a coordinator error under guardrail 6 — the
second time in this family that `ADVISORY_KEYS` was reasoned about from its name instead of its
contents.

## Status

Stage E is closed. The fleet stands down. Reactivation requires a new scope doc.
