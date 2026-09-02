# E8m accepted — metrics amendment to the frozen efficacy referee

**Accepted:** 2026-09-02. **Task:** `task_4425dd303a37`. **Dispatch:** `ctx_4c703b40e9b1`.
**Worker commits:** `c4ac20d`, `b6d0d24` on `feat/e8m-metrics-amend` (base `9d01bd9`).
**Local merge:** `5de9511`. **Push:** none. Worker report: `docs/STAGE_E_REPORTS/E8m-worker.md`.

Owner-authorized amendment running BEFORE any E7b modifier. Additive publication only.

## The constraint, verified independently

The amendment was allowed to add metrics and forbidden to move one. I verified this myself rather
than accepting the worker's walker: I built a detached worktree at the base commit, ran the
benchmark there and at the amended head **against the same model artifact**, flattened both JSON
documents to leaf key paths and compared.

| | Result |
|---|---|
| Key paths before / after | 3,615 / 3,861 |
| **Removed** | **0** |
| **Changed, non-volatile** | **1** — `provenance.branch`, an artefact of my base worktree being detached HEAD, not a value change |
| Changed, volatile (expected) | 40 — `run_id`, `run_date`, `commit`, `tree` |
| Added | 246 leaf paths, all additive |

`BENCHMARK_SEEDS` remains `(20270302, 20270303, 20270304)` and `ASSERTED_ENTITY_KINDS` remains
`ip, user, host, port, change_window`; the remap constants, the freshness assertion and the
signatures of `score`, `diff`, `assert_fresh`, `finding_hits`, `remap_scenario` and
`benchmark_token_map` are untouched.

## The three amendments, reproduced

Every ground-truth number from the leakage interrogation reproduces exactly on my own clean run.

**(a) Finding-level recall, first-class beside line-level, both labelled with their denominators.**
`finding_level_recall.learned` = **0.9444**, `true_findings_kept` 85, `true_findings_total` 90,
denominator "findings that cite at least one malicious line"; `line_level_recall_denominator` =
"manifest malicious lines". `learned_total_dropped_true_findings` = **5**, and each is published
verbatim under `dropped_true_findings` with its `rule_id`, `label`, `confidence`, `severity`,
`summary` and the full cited malicious line including `raw` and `why` — the same treatment misses
get. The five are all `ioc_observed` on `bnch-server-01` in `INC-4a7f`, `benign-expected`, top
confidence **0.992**. This class of absorption can no longer be invisible.

**(b) False-positive totals scoped by format.** `false_positive_totals` publishes rules **84** as
the headline across all four formatters with every format as a labelled subset — canonical 21,
jsonlog 21, rfc3164 24, rfc5424 18 — the learned system 0 in every one, and a `scope` sentence
naming the formats measured. A canonical-only run honestly reports its scope as canonical rather
than claiming 84.

**(c) The criticality sensitivity as a named finding, computed live.** `criticality_sensitivity` is
marked `kind: counterfactual`, carries the full feature-importance table with
`criticality_rank` at **0.4146**, and publishes both populations:

| Population | Total | Flipping | Robust | Kept at low / standard / crown-jewel |
|---|---|---|---|---|
| Suppressions | 84 | 33 | 51 | 33 / 33 / 0 |
| True detections | 85 | 28 | 57 | 85 / 85 / 57 |

The `kept_at` breakdown publishes the direction rather than asserting it: 85 true detections are
kept at low and standard, 57 at crown-jewel. The model is more willing to dismiss a finding on a
more critical asset. It is computed on every run through a `_ForcedCriticality` org-context shim
inside the harness, needing no edit anywhere else.

## Coordinator gates on merged main

Harness tests **57/57** with sklearn 1.7.2 **and** with it absent; `console/test_console.py` 0 FAIL;
`tests/eval/run_eval.py` 20/20, F1 1.000, 0 false positives; web **290/290** across 43 files;
`npm run build` green; detector sha256 `364577c5…577a4a876` unchanged; allowlist clean with no
forbidden file touched; branch never pushed.

## Pre-existing failure, verified pre-existing

`tests/test_battlecard_efficacy.py::test_canonical_harness_scenario_totals_appear_in_battlecard`
fails. I confirmed it fails **identically at the base commit, at the amended head, and on main**, so
E8m did not cause it. Its assertion is stale: it expects exactly three scenarios
(`INC-4a7f`, `failure-success`, `error-burst`) from a harness that has returned six scenarios
across three seeds since the negative scenarios were added. It is not in the standing gate set —
which is why it rotted unnoticed — and it was outside E8m's allowlist, so reporting rather than
fixing it was correct.

## Re-freeze

The referee is re-frozen as of this acceptance, now including the finding-level recall path, the
format-scope path, the criticality counterfactual, and their tests. E7b modifiers may not edit them.
E7b round 1 is unblocked.
