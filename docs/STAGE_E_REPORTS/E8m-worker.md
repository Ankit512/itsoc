# E8m — owner-authorised metrics amendment to the frozen efficacy referee (worker report)

**Branch:** `feat/e8m-metrics-amend`, cut at exactly `9d01bd90435527b44877b184f9558fe90c94f49d`
— the local `main` HEAD at cut time, verified with `git rev-parse main` /
`git rev-parse HEAD` and a clean `git status` before the first edit. (`main` has since
advanced with coordinator-owned docs only — `ef3786e`, `b0c0d32`, `8831320`, `f9676ff` —
none of which touch a file on this card's allowlist.)

**Detector freeze:** `anomaly_detector.py` sha256
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — verified **before**
the first edit and **after** the last. Unchanged.

## Governance posture

This is an **additive publication amendment**. `BENCHMARK_SEEDS`, the benchmark-only token
remap, the freshness assertion, `score()`, `_ratio()` and `diff()` are all untouched, and
no measured value moved. That is not asserted — it is proved by a before/after diff of two
real runs, below.

## What shipped

### (a) Finding-level recall, published as a first-class metric beside line-level recall

Recall has always had two denominators; only one was published.

* **Line-level recall** — over the manifest's malicious **lines**.
* **Finding-level recall** — over the **findings that cite at least one malicious line**.

Both are now published **for both systems**, each **labelled with its denominator**, in
the JSON (`finding_level_recall`, per-system `finding_recall`,
`line_level_recall_denominator`, `recall_note`), in `render()`
(`recall(lines)=` / `recall(findings)=` on every system line, plus a run-level block),
through `console/efficacy_api.py` (still pure pass-through), and on Reports (a
`Recall, with its denominator` block plus two new labelled table columns).

`finding_level_recall()` deliberately lives **outside** `score()` so the frozen scorer's
output is byte-identical; it reuses the file's single `_ratio()`, so the
"one metric implementation" test still passes unchanged.

**Ground truth reproduced exactly.** On the frozen seeds across all four formatters:

| System | line-level recall | finding-level recall |
| :--- | ---: | ---: |
| rules | 1.000 | **1.000 (90 / 90)** |
| learned | 1.000 | **0.9444 (85 / 90)** |

The learned system drops **5** findings that cite real malicious lines — all
`ioc_observed`, all on the crown-jewel host in `INC-4a7f`, all predicted
`benign-expected`, confidence up to **0.992**:

| scenario | format | seed | label | confidence | cited malicious line |
| :--- | :--- | ---: | :--- | ---: | ---: |
| `INC-4a7f` | `rfc3164` | 20270302 | benign-expected | 0.992 | 2 |
| `INC-4a7f` | `rfc5424` | 20270302 | benign-expected | 0.9318 | 2 |
| `INC-4a7f` | `rfc5424` | 20270303 | benign-expected | 0.9318 | 2 |
| `INC-4a7f` | `rfc3164` | 20270304 | benign-expected | 0.7262 | 2 |
| `INC-4a7f` | `rfc5424` | 20270304 | benign-expected | 0.7262 | 2 |

Line-level recall stays 1.000 only because all five cite line 2, which kept findings also
cover. **That absorption is what this card exists to end.** Every such finding is now
listed **verbatim** — `dropped_true_findings`, carrying the rule id, severity, summary,
the advisory label and confidence that dropped it, and the manifest's own `raw`/`why` for
every malicious line it cited — printed by `render()` with the same weight as a miss and
rendered on Reports in the same section as the miss lists. A scenario that dropped nothing
says so explicitly; the section is never simply omitted.

On the `canonical`-only default run nothing is dropped and finding-level recall is a
measured **1.000 (21 / 21)** for both systems. That is honest, and it is exactly why the
all-format run is the headline in §(b).

### (b) False-positive totals labelled with format scope

`false_positive_totals` publishes the **headline across every format the run measured**,
with **each single format as an explicitly labelled subset**, plus a `format_scope_note`
stating that a bare count is not publishable. `render()` appends the scope to both totals
lines and prints each subset; Reports renders a scoped totals block and appends the scope
to the header counts.

| format scope | rule FPs | learned FPs |
| :--- | ---: | ---: |
| **all four formatters (headline, 72 runs)** | **84** | **0** |
| subset — `canonical` (18 runs) | 21 | 0 |
| subset — `rfc3164` | 24 | 0 |
| subset — `rfc5424` | 18 | 0 |
| subset — `jsonlog` | 21 | 0 |

The E8 figure of **21** is the `canonical` subset and is correct as measured; it was simply
unlabelled. The suppression claim is **stronger** than published, not weaker.

**Deliberate non-change:** the harness's default format list stays `canonical`, and so does
`console/efficacy_api.py`'s. Changing either would have moved the default run's measured
values from 21 to 84 and broken the byte-identical requirement. The all-format headline is
therefore published as a recorded measurement in the battle card with its exact reproduce
command, while the code guarantees only that **no count is ever printed without its scope**.

### (c) The criticality sensitivity as a named first-class finding

Computed **live on every run** — not recorded prose. `criticality_sensitivity()` re-scores
every finding through the shipped model with `criticality_rank` forced across its whole real
domain (`low`, `standard`, `crown-jewel`) and every other feature held exactly as measured.

The seam is `_ForcedCriticality`, an org context answering one criticality for every asset.
It satisfies the only method `train_triage.record_from_report_finding` asks of an org
context, so **no trainer, model loader, `org_context` module or shipped config file is
edited or read differently** — and `console/org_context.json` is never touched.

`criticality_rank` importance is read off the loaded estimator itself
(`feature_importances_` aligned with the sidecar's `featureKeys`), never asserted from a
document; an estimator that exposes none publishes `available: false` with a reason.

| population (all four formatters) | total | robust | flips | kept at `low` / `standard` / `crown-jewel` |
| :--- | ---: | ---: | ---: | ---: |
| true detections (kept, citing malicious lines) | 85 | 57 | **28** | 85 / 85 / **57** |
| suppressions (dropped, citing nothing) | 84 | 51 | **33** | 33 / 33 / **0** |

`criticality_rank` importance: **0.4146**, the largest of 21 features.

**Direction, stated plainly: the model is more willing to dismiss a finding on a more
critical asset.** Raising a host to `crown-jewel` flips **28 of 85** true detections from
KEPT to DROPPED; lowering `crown-jewel` flips **33 of 84** suppressions from DROPPED to
KEPT. It is driven by an org-config value, not by log evidence.

**These are counterfactuals.** The block is marked `kind: "counterfactual"` in the JSON,
rendered under an explicit "a counterfactual, not a measurement" heading on Reports, and
carries `CRITICALITY_SENSITIVITY_NOTE`, which states that the benchmark hosts have fixed
criticality and every published number stands exactly as measured.

## Before/after: every previously published value is byte-identical

Two pairs of **real** runs, same trained model artifact (sha256
`0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765`, identical to the E8
acceptance model), same frozen seeds, one at the pristine base tree and one after the
amendment. Compared with a walker that asserts every path present in BEFORE exists in AFTER
with an identical JSON serialisation, and reports new keys separately.

| pair | changed values | added keys (distinct paths) |
| :--- | ---: | ---: |
| `canonical` (18 runs) | **0** | 11 |
| all four formatters (72 runs) | **0** | 11 |

The added paths, and nothing else:

```
criticality_sensitivity            learned.dropped_true_findings
false_positive_totals              learned.finding_recall
finding_level_recall               rules.dropped_true_findings
format_scope_note                  rules.finding_recall
learned_total_dropped_true_findings
line_level_recall_denominator
recall_note
```

**Normalised fields, listed explicitly:** `run_date`, `run_id`,
`provenance.{commit,tree,branch,worktreeDirty}`, `model.path`, and the per-scenario
`run_date`/`run_id`. These are timestamps, git identity and an absolute path — they differ
between any two runs at any two commits and carry no measured value. Nothing else was
excluded from the comparison.

The rendered text was checked too: all **36** (canonical) and **144** (all-format)
`RULES`/`LEARNED` system lines are identical once the two additive edits are removed
(`recall=` relabelled to `recall(lines)=`, and the new `recall(findings)=` /
"findings citing a malicious line" fragments stripped) — **0** lines whose preserved
content differs.

## Honesty rules, all still binding and all still held

* `precision_defined` / `recall_defined` are unchanged and still drive `n/a`; the new
  finding-level recall carries its own `recall_defined` and follows the same rule.
* The scope, ceiling and advisory sentences are byte-identical and asserted by test.
* The existing miss lists are unchanged, verbatim, and still printed.
* Rules own severity; the model writes none. A dropped advisory removes no rule finding
  and changes no verdict — what it changes is what a *metric* reports, which is the whole
  reason it is now published.
* Real data or an honest `n/a`: with no model there is no finding-level learned recall, no
  dropped list, no counterfactual and no learned false-positive total — each is `null` or
  `available: false` with a reason. Asserted in the harness suite, the console suite and
  the web suite.

## Test and gate results

| gate | result |
| :--- | :--- |
| `tools/test_efficacy_harness.py`, **with** scikit-learn 1.7.2 (clean venv) | **57 passed** (was 37; +20 E8m) |
| `tools/test_efficacy_harness.py`, **without** scikit-learn (stdlib `python3`) | **57 passed** |
| `console/test_console.py` (stdlib `python3`, model absent) | **0 `[FAIL]`, exit 0, "checks green"** |
| `console/test_console.py` (venv, model present — exercises the model-available branch) | **0 `[FAIL]`, "all checks green"** |
| `tests/eval/run_eval.py` | **20 passed / 0 failed**, precision 1.000, recall 1.000, F1 1.000, FP 0 |
| `tests/test_stage_e_wall.py` | **101/101 — wall intact** |
| `npm --prefix web test` | **43 files, 290 tests passed** (was 282; +8 E8m) |
| `npm --prefix web run build` (`tsc --noEmit && vite build`) | ✅ built |
| detector sha256 | `364577c5…7a4048933eb796a87fe1bac8f087eb577a4a876` — **unchanged** |
| `git diff --check` | clean (exit 0) |
| before/after byte-identical proof | **0 changed values** on both pairs |

### Clean-environment benchmark

Fresh `python3 -m venv` + `pip install -r requirements.txt` → scikit-learn **1.7.2** on
Python 3.13. `tools/train_triage.py` (defaults) → 434 rows
(`confirmed` 224 / `false-positive` 126 / `benign-expected` 84), 5 stratified folds,
macro-F1 mean **0.9568**, artifact sha256
`0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765` — **bit-identical to
the E8 acceptance model**, so every number here is directly comparable to E8's.

* default `canonical` run: run id `efficacy-123b72051d07`, run date `2026-09-02T21:54:33+00:00`.
* all-format headline run: run id `efficacy-dc1c67b07dde`, run date `2026-09-02T21:54:36+00:00`.
* commit `c4ac20d775b35e48a684b4b84baebb2015608b08`, tree
  `ea43605c28469094759b76fa19d22b2c21d3cc79`, **worktree clean**.

`c4ac20d` is the amendment commit itself; this report's recorded run ids are landed by the
follow-up docs commit on top of it, the same two-commit pattern E8 used. Re-running
`python3 tools/efficacy_harness.py` at `c4ac20d` reproduces run
`efficacy-123b72051d07` byte-for-byte apart from the run id/date, which are derived from
the wall clock.

### Allowlist audit

Files changed on this branch — all within the card's allowlist, nothing else:

```
console/efficacy_api.py
console/test_console.py
docs/BATTLECARD_TORQ.md
docs/STAGE_E_REPORTS/E8m-worker.md
docs/research/CITATIONS.md
tools/efficacy_harness.py
tools/test_efficacy_harness.py
web/src/lib/api.ts
web/src/pages/Reports.tsx
web/src/test/efficacy-surface.test.tsx
```

No `anomaly_detector.py`, no rule, no eval corpus or fixture, no
`console/triage_model.py`, no `tools/train_triage.py`, no `tools/attack_generator.py`, no
`org_context` module or config, no `requirements.txt`, and no
`docs/STAGE_E_REPORTS/E8-*.md`. Committed with explicit paths; never `git add -A`.
No push, no merge.

## Deviations and things the reviewer should know

1. **Branch name.** The dispatch worktree was on `Ankit512/e8m-metrics-amend` at
   `b836114` (an ancestor of `main`). Rather than stop, I created
   `feat/e8m-metrics-amend` at the exact local `main` HEAD `9d01bd9` as the card's base
   requirement specifies, and verified both before the first edit. All work is on that
   branch.

2. **The 0.9444 appears on the all-format run, not the default run.** `canonical` alone
   drops nothing (21/21). The five absorbed findings occur only under `rfc3164` and
   `rfc5424`. I did **not** change the default format list, because doing so would have
   moved the default run's published false-positive total from 21 to 84 and violated the
   byte-identical requirement. The all-format run is therefore published as the headline
   measurement in the battle card and C-2a with its exact reproduce command, and the code
   guarantees the scope label on every count. This is the one place where the card's
   "publish 84 as the headline" is satisfied by a recorded measurement rather than by a
   default-run value, and it is deliberate.

3. **The criticality sensitivity is computed live, not recorded**, and it reproduces the
   interrogation's 28/85 and 33/84 exactly. It costs roughly 3× the model-inference time
   (the default run went from ~2.5 s to ~4 s wall; the all-format run ~6.3 s to ~11 s).

4. **Pre-existing, unrelated failure left untouched:** `tests/test_battlecard_efficacy.py::
   test_canonical_harness_scenario_totals_appear_in_battlecard` fails at the base commit
   and at the main checkout — it still asserts the three pre-E7a scenarios and a row format
   the battle card stopped using. That file is **not** on this card's allowlist and the
   failure is not caused by this branch (verified by running it at
   `/Users/ankit/Projects/log-analyzer`). The other two tests in that file — the scope /
   ceiling / C-2 guardrails — **pass**.

5. **`console/efficacy_api.py` is still a pure pass-through.** Its only change is the
   docstring recording the amended contract; it computes nothing, chooses no seed and reads
   no model. Asserted by the existing console checks, which still pass unchanged.
