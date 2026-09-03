# E7b round 2 — graded: PASS

**Graded:** 2026-09-03. **Task:** `task_c4c9cf449f9e`. **Dispatch:** `ctx_573da9d1477e`.
**Worker commits:** `adfd888`, `3d0774d` (base `944c47e`). **Local merge:** `76c8a10`. **Push:** none.
Worker report: `docs/STAGE_E_REPORTS/E7b-r2-worker.md`.

## Verdict — PASS

Finding-level recall **rose to 1.0000 and false-positive suppression held exactly**. The stated
success bar is met. Round 2 becomes the current model under the standing publication rule.

## Measured on the frozen referee, all four formats, verified by the coordinator

| | E7a (shipped) | R1 | **R2** |
|---|---|---|---|
| Finding-level learned recall | 0.9444 (85/90) | 0.9111 (82/90) | **1.0000 (90/90)** |
| `ioc_observed` per-rule recall | 0.5833 (7/12) | — | **1.0 (12/12)** |
| Dropped true findings | 5 | 8 | **0** |
| Learned FPs, every format | 0 | 0 | **0** |
| Rules FPs (all formats) | 84 | 84 | 84 |
| Line-level learned misses | 0 | 0 | 0 |
| `criticality_rank` importance | 0.4146 | absent | 0.2026 |
| Suppression flips | 33/84 | 0/84 | 33/84 |
| True-detection flips | 28/85 | 0/82 | 30/90 |

Every rule class now sits at 1.0 finding-level recall. The per-rule breakdown E8m2 added is what
makes that statement checkable rather than an aggregate assertion.

## The diagnosis — better than round 1's, and better than the brief

Round 1 concluded `criticality_rank` was a label proxy and removed it. Round 2 found the actual
mechanism: **`ioc_observed` matched no family regex**, so it fell into `rule_family_other` together
with every `infra_unknown_*` rule, where the two share one indistinguishable vector shape. The IOC
finding therefore inherited `infra_unknown_high`'s `benign-expected` label — despite `ioc_observed`
carrying that label on **zero of its 42 training rows**.

The fix is to name the family the rules already name: `ioc` added to `_THREAT_RE`, matching the
grouping at `rule_context.py:303` (`atype.startswith("threat_") or atype in ("ioc_observed", …)`),
which the coordinator verified. The model's feature function had been disagreeing with the rules'
own taxonomy.

**No feature key was added, removed or reordered**, so `tests/test_e7a_feature_contract.py` is
byte-unchanged — confirmed by an empty diff. Round 2 needed no contract amendment at all, where
round 1 needed the pre-authorised one.

## The E8m2 pin proved itself on a real case

Round 2 appended one generator scenario, `near-miss-auth-crown` — a false positive **on** the crown
jewel, breaking the criticality/label coupling in the training data. Verified by the coordinator:

- The frozen benchmark measured exactly the six frozen scenarios; `scenarioSetIsFrozen: true`. The
  seventh scenario did **not** enter the benchmark.
- The existing six are **byte-identical**: 72 artefact pairs (6 scenarios × 4 formats × 3 seeds)
  hashed before and after — **0 differing, 0 missing**.

Round 2's own report notes that on its pre-E8m2 base the new scenario *did* enter the harness default
list. That is the freeze hole E8m2 closed, observed independently from the other side.

## The criticality gradient — halved, not eliminated, and honestly reported

Importance fell 0.4146 → 0.2026, but suppression flips are unchanged at 33/84 and true-detection
flips read 30/90 against 28/85. The worker disclosed this plainly rather than presenting a clean win.

**The flip increase is arithmetic, not regression.** Of the 5 recovered findings, 3 are robust at
crown-jewel and 2 are criticality-sensitive: 28 + 2 = 30 exactly. **No previously-robust detection
became fragile**, and the proportion is flat (0.3294 → 0.3333).

Round 2 also measured the cost of eliminating the proxy outright — a benign-expected scenario on a
standard host takes importance to 0.0465 and suppression flips to 0/84, but **costs eight true
`infra_unknown_high` detections**. That is the same eight round 1 lost by deleting the feature.
**Two independent rounds, different approaches, converged on the identical cost.** That makes the
recall/gradient trade a measured property of the current record projection, not one round's artefact.
Round 2 refused the trade and shipped neither rejected scenario.

## Coordinator gates on merged main

Harness 69/69 with sklearn **and** without; feature contract 10 passed / 67 subtests;
`tools/test_train_triage.py` 35 passed / 17 subtests (was 23, both new guards verified non-vacuous by
negative control); `console/test_console.py` 0 FAIL; `tests/eval/run_eval.py` 20/20 F1 1.000 FP 0;
Stage E wall 101/101; web 301/301 across 43 files; `npm run build` green; detector sha256
`364577c5…577a4a876` unchanged; frozen referee untouched; allowlist clean; branch never pushed.

## Coordinator process note

The grading worktree was created with `git worktree add -f … main`, which checked `main` out a
second time, so the evaluation merge advanced `main` itself and left the primary worktree's files
out of sync with the moved HEAD. Content was correct throughout; the commit message was not. The
tree was re-synced (nothing untracked, nothing stashed, no work at risk) and the message amended to a
real acceptance. Recorded because the merge label would otherwise read "grade: merge r2 for
evaluation" in the permanent history of an accepted card. Grading worktrees must be detached, not
checked out on a live branch.

## Disposition

**Merged and current.** Round 2 is strictly better than the shipped E7a model on recall, per-rule
recall and dropped findings; equal on suppression and misses; better on criticality importance; and
neutral on flips once the arithmetic is accounted for. Under the standing publication rule it
replaces the E8-published model.

**Open, and not closed by this round:** the backwards criticality gradient persists at halved
importance. Both rounds independently measured that eliminating it costs eight true detections under
the current record projection. Closing it needs a richer projection or a different lever, not another
pass at feature selection.
