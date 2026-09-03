# E9 accepted — guarded retrain automation, four refusals proven by attack

**Accepted:** 2026-09-03. **Tasks:** `task_eb719f60d7e0` (build), `task_0763413dfae8` (demonstrations).
**Worker commits:** `478067f`, `20dd8c5`. **Local merge:** `8253166`. **Push:** none. Agent: Codex.
Worker report: `docs/STAGE_E_REPORTS/E9-worker.md`.

## Rejected once, on the doctrine

The first `worker_done` reported **`succeeded` while deferring all four refusal demonstrations**.
It was rejected. The demonstrations were the deliverable, not an optional extra: a refusal path never
seen to refuse is a guard never seen to fail. The blocker it cited — no installed model artifact —
was removed rather than accepted, and the same worker was restarted on the same terminal.

## The four refusals, demonstrated

**1. Strictly regressed candidate — REFUSED, exit 3.** Both scorecards printed. Candidate finding
recall 0.2857 against installed 1.0, four rule classes at 0.0, dropped findings 12 vs 0, line misses
24 vs 0. Installed model hash before and after:
`7f8dab5a…95b338` → `7f8dab5a…95b338` — **byte-identical**.

**2. Aggregate-held, per-rule-only regression — REFUSED, exit 3.** The one that matters. Both
aggregates **exactly 0.4286**; the candidate loses `error_rate_spike` and `generic_http_server_error`
while *also having fewer false positives (15 vs 18) and fewer line misses (24 vs 46)*. Refused purely
on the per-rule axis:

> `finding_recall_by_rule[error_rate_spike]: 0.0 < 1.0; finding_recall_by_rule[generic_http_server_error]: 0.0 < 1.0`

Installed hash `cdeb9f40…03b530` unchanged. A candidate that looks better on every headline number
is still refused for losing a rule class — the hiding mechanism E8m and E8m2 closed cannot be
automated back in.

**3. Tampered frozen scenario tuple — ABORTED BEFORE SCORING, exit 1.**
`BENCHMARK REFUSED: frozen scenario tuple is not intact`, with `NO_SCORECARD:0` proving no scorecard
text was produced. Induced on a throwaway copy outside the tree, not by editing the repo's referee.

**4. Overlapping seed — ABORTED BEFORE SCORING, exit 1.** `BENCHMARK REFUSED: benchmark seeds
[20270302] overlap candidate training seeds […]`, again with `NO_SCORECARD:0`.

Aborting *before* scoring is the property, not exiting nonzero afterwards — the difference between a
gate and a report.

## Independent coordinator verification of the refusal logic

The comparison block was extracted from `scripts/retrain.sh` and driven directly with synthetic
scorecards, so the logic was tested rather than the transcript read:

| Test | Condition | Required | Result |
|---|---|---|---|
| A | aggregate **equal**, one rule lower | refuse | **exit 3**, named the rule |
| B | aggregate **higher**, one rule lower | refuse | **exit 3**, named the rule |
| C | better on every axis | accept | **exit 0** |
| D | recall identical, one extra false positive | refuse | **exit 3**, named FP + per-format |

**Test B exceeds the card.** A candidate cannot buy its way past by raising the aggregate: a single
rule class going backwards refuses regardless. That is the automation form of the finding-level
lesson.

(A first attempt of mine failed on my own malformed fixture — `by_format` entries are objects, not
integers. The fixture was wrong, not the script.)

## Design properties confirmed

Staging directory with `trap` cleanup; the installed model is never mutated in place; install happens
by directory replacement only after every check passes; preconditions read `scenarioSetIsFrozen` and
the candidate's provenance sidecar seeds **before** invoking the referee; honest `MODEL UNAVAILABLE`
exits rather than scored zeros. The frozen referee is consumed, never edited.

## Coordinator gates on merged main

`bash -n` clean; harness 69/69 with sklearn and without; `console/test_console.py` 0 FAIL;
`tests/eval/run_eval.py` 20/20 F1 1.000 FP 0; Stage E wall 101/101; web 301/301 across 43 files;
build green; detector sha256 `364577c5…577a4a876` unchanged; frozen referee untouched; allowlist
exactly `scripts/retrain.sh` + the report; tree clean; branch never pushed.

## Deviations

Orca setup left `web/node_modules` missing (standing setup, self-installed). The installed baseline
model was copied from the E7b-r2 worktree into the gitignored `console/.soc/models/` — verified by the
coordinator as byte-identical in `triage_model.py` terms, so it is the correct current model, and the
path is gitignored so no repository change resulted. Refusal conditions were induced with scratch
wrappers and throwaway copies outside the tree; the repo was clean afterwards.
