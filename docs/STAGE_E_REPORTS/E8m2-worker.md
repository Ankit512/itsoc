# E8m2 — per-finding-type recall, and the benchmark's scenario list pinned

Second owner-authorized amendment to the frozen efficacy referee. Like E8m before it,
this is **additive publication and safety only**. Nothing that was published moved.

## Branch, head, base

| | |
| :--- | :--- |
| branch | `Ankit512/e8m2-scorecard-pin` (the name is a warning; nothing was pinned to a scorecard) |
| base required | `944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46` |
| head at commit | the E8m2 commit on this branch, sitting directly on `944c47e` (`git log --oneline -1`) |
| detector sha256, before **and** after | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — unchanged |

### Base check — it failed first, and that was correct

The card's guard was run before any edit, and it **failed**:

```
$ git rev-parse HEAD
b83611484233496231aebbfff092ae98cdbee438
$ git merge-base --is-ancestor 944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46 HEAD
-> FAILS
$ git merge-base --is-ancestor HEAD 944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46
-> SUCCEEDS
```

The reverse check succeeding means **stale, not divergent** — the diagnostic the card names.
`b836114` was 44 commits behind `944c47e`, and those 44 commits include `c4ac20d` /
`5de9511` / `f5fe072`: the E8m metrics amendment **this card is an amendment to**. Building
E8m2 there would have reimplemented or conflicted with E8m. No file was touched; the worker
escalated and waited. The coordinator reset the worktree, and the guard was then re-run by
the worker itself:

```
$ git rev-parse HEAD
944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46
$ git merge-base --is-ancestor 944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46 HEAD
-> SUCCEEDS
$ git status --porcelain
(clean)
```

No fast-forward was performed by the worker.

## Allowlist audit

Modified, all on the allowlist:

```
console/efficacy_api.py                |  38 +++++-
console/test_console.py                |  78 +++++++++++
tools/efficacy_harness.py              | 233 ++++++++++++++++++++++++++++++++-
tools/test_efficacy_harness.py         | 223 +++++++++++++++++++++++++++++++
web/src/lib/api.ts                     |  30 +++++
web/src/pages/Reports.tsx              |  89 ++++++++++++-
web/src/test/efficacy-surface.test.tsx | 153 +++++++++++++++++++++-
docs/STAGE_E_REPORTS/E8m2-worker.md    (this file)
```

Untouched, as required: `anomaly_detector.py`, every rule module, the eval corpus,
`console/triage_model.py`, `tools/train_triage.py`, `tools/attack_generator.py`,
`org_context`, dependencies, and every other `docs/STAGE_E_REPORTS/*.md`. Audited by path
after the fact — no forbidden path appears in `git status`.

---

## (1) Per-finding-type recall — the losing rule class is now readable

**The defect.** Finding-level recall was published only in aggregate. That is how E7a's five
crown-jewel `ioc_observed` dismissals hid behind a line-level `1.000`, and how E7b round 1's
eight `infra_unknown_high` drops read only as an aggregate `0.9111`. An aggregate says a
system is losing; it does not say *what*.

**What is published now.** Finding-level recall **broken down by `rule_id`**, for each
system, each row with its own denominator — that rule's findings citing at least one
malicious line — alongside the existing aggregate:

* per scenario, per system: `scenarios[].{rules,learned}.finding_recall_by_rule`
* per run: `finding_level_recall.by_rule[rule_id].{rules,learned,true_findings_total,learned_dropped_true_findings}`,
  plus `finding_level_recall.by_rule_note`

**The denominator is always the RULES system's count for that rule** — the reference
collection both systems are scored against, never a system's own surviving subset. So a class
the learned system drops entirely reads `0.0` in its own row rather than disappearing along
with its denominator.

**The verbatim `dropped_true_findings` list is untouched and still published in full**, per
scenario and per run, with each cited malicious line's real `raw`/`why`. The breakdown is a
reading aid over that list, never a replacement — asserted in the harness suite, the console
suite and the web suite, and stated in `BY_RULE_RECALL_NOTE` itself.

**It works, on the real benchmark.** The all-format acceptance run:

```
aggregate learned finding-level recall = 0.9444  (85/90), 5 dropped

  auth_bruteforce            rules 1.0 (12/12)   learned 1.0     (12/12)   dropped 0
  auth_bruteforce_success    rules 1.0 (12/12)   learned 1.0     (12/12)   dropped 0
  error_rate_spike           rules 1.0  (9/9)    learned 1.0      (9/9)    dropped 0
  generic_auth_failure       rules 1.0 (24/24)   learned 1.0     (24/24)   dropped 0
  generic_http_server_error  rules 1.0 (12/12)   learned 1.0     (12/12)   dropped 0
  infra_unknown_high         rules 1.0  (9/9)    learned 1.0      (9/9)    dropped 0
  ioc_observed               rules 1.0 (12/12)   learned 0.5833   (7/12)   dropped 5
```

A reader of the old aggregate saw `0.9444` and had to parse a verbatim list to learn that the
model is losing **42% of one class — `ioc_observed`, the crown-jewel class E7a's interrogation
found**. That row now states it. (The canonical-only run drops nothing, so every row there is
`1.0`; the breakdown is published anyway, so an all-`1.0` table is a measurement rather than
an omission.)

**Honesty rules held.** A rule that produced no finding citing a malicious line has no
finding-level recall to measure and is **absent** from the breakdown rather than published as
a `0/0`; the note says so. With no model, every per-rule `learned` cell is `null` and every
per-rule dropped count is `null` — an honest gap, never a zero. Run-level rows sum
kept/total pairs and recompute the ratio; they never average ratios.

## (2) The benchmark's scenario list is pinned

**The freeze hole.** `efficacy_harness.py` defaulted the benchmark to `generator.SCENARIOS`.
Any scenario added to `tools/attack_generator.py` therefore silently changed what the frozen
benchmark measured, making before/after numbers incomparable. The referee owned the seeds and
not the subject.

**The fix.** `BENCHMARK_SCENARIOS` sits directly beside `BENCHMARK_SEEDS` and contains
**exactly today's six scenarios** in the generator's own declaration order:

```python
BENCHMARK_SCENARIOS = (
    "INC-4a7f", "failure-success", "error-burst",
    "near-miss-auth", "near-miss-errors", "benign-maintenance",
)
```

`benchmark_scenarios()` returns that tuple and is what the CLI defaults to
(`console/efficacy_api.py` defaults to it too, so a console-triggered run is the same
benchmark). The only thing read from the generator is whether every frozen scenario still
*exists* there: one that no longer does raises `BenchmarkProvenanceError` and refuses the
run — a lost scenario is a hard failure, not a silently shorter benchmark. A caller may still
measure any generator scenario by naming it explicitly with `--scenario`; that is an opt-in,
and the run publishes `benchmark.scenarioSetIsFrozen: false` and the frozen list beside what
it measured, so it cannot be read as the benchmark.

**Asserted.** `test_a_generator_scenario_added_later_does_not_move_the_benchmark` installs a
generator exposing an extra scenario, confirms the generator really does expose it, and
asserts the benchmark's scenario set and the CLI default are unchanged.
`test_the_pin_does_not_touch_the_seeds_or_the_freshness_assertion` asserts `BENCHMARK_SEEDS`,
the single `assert_fresh` and the single `BENCHMARK_SEEDS` assignment are all still intact.
The remap, the freshness assertion, `score()`, `_ratio()` and `diff()` were not touched.

---

## Byte-identical evidence: every published value comes out unchanged

Two pairs of **real** runs. BEFORE was produced from a pristine `git worktree` of
`944c47e` (not a stash and not a revert), against the **same** trained model artifact, the
same frozen seeds, and the same formats. Compared with a leaf-key-path walker that asserts
every path present in BEFORE exists in AFTER with an identical JSON serialisation, and reports
new keys separately.

| pair | leaves BEFORE → AFTER | **changed** | **removed** | added (distinct key paths) |
| :--- | :--- | ---: | ---: | ---: |
| `canonical` (18 runs) | 3817 → 4114 | **0** | **0** | 142 |
| all four formatters (72 runs) | 13314 → 14314 | **0** | **0** | 165 |

The added paths, and nothing else (collapsed over `rule_id` and list index):

```
benchmark.frozenScenarios
benchmark.scenarioSetIsFrozen
benchmark.scenarioNote
finding_level_recall.by_rule.*
finding_level_recall.by_rule_note
scenarios[].rules.finding_recall_by_rule.*
scenarios[].learned.finding_recall_by_rule.*
```

**Normalised fields, listed explicitly:** `run_date`, `run_id`,
`provenance.{commit,tree,branch,worktreeDirty}`, and `model.{path,file}` — plus the
per-scenario `run_date`/`run_id`. These are timestamps, git identity and absolute paths that
differ between any two runs at any two commits and carry no measured value. **Nothing else
was excluded from the comparison**, and no exclusion was needed: with those normalised, the
changed and removed counts are both zero on both pairs.

The model was retrained in a clean venv and came out at sha256
`0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765` — **byte-identical to the
E8 and E8m acceptance model**, so both halves of each pair were scored by the same artifact.

## Test and gate results

| gate | result |
| :--- | :--- |
| `tools/test_efficacy_harness.py`, **with** scikit-learn 1.7.2 (clean venv) | **69 passed** (was 57; +12 E8m2) |
| `tools/test_efficacy_harness.py`, **without** scikit-learn (stdlib `python3`) | **69 passed** |
| `console/test_console.py` (stdlib `python3`, model absent) | **0 `[FAIL]`, exit 0, "all checks green"** |
| `console/test_console.py` (venv, model present) | **0 `[FAIL]`, exit 0, "all checks green"** |
| `tests/eval/run_eval.py` | **20 passed / 0 failed**, precision 1.000, recall 1.000, F1 1.000, FP 0 |
| `tests/test_stage_e_wall.py` | **101/101 — wall intact** |
| `npm --prefix web test` | **43 files, 296 tests passed** (was 290; +6 E8m2) |
| `npm --prefix web run build` (`tsc --noEmit && vite build`) | ✅ built |
| detector sha256 | `364577c5…4048933eb796a87fe1bac8f087eb577a4a876` — **unchanged** |
| `git diff --check` | clean (exit 0) |
| allowlist audit | no forbidden path in `git status` |
| before/after byte-identical proof | **0 changed, 0 removed** on both pairs |

### `tests/test_battlecard_efficacy.py` — the known pre-existing failure

`test_canonical_harness_scenario_totals_appear_in_battlecard` **FAILS**, and it is not mine.
Proved rather than asserted: the same single test fails with a byte-for-byte identical diff
(18 `+` lines) at the **pristine `944c47e` worktree**, with none of this branch's changes
present. Not fixed, per the card. It was checked at both trees precisely so it could not mask
a regression — the other 2 tests in that file pass at both.

## Deviations

1. **Orca setup failed** — `web/node_modules` was missing. `npm --prefix web install` was run
   by the worker before the web gates (exit 0). Recorded per the card.
2. **Base guard failed on first run** (stale worktree, the seventh consecutive one at
   `b836114`). Escalated and held; the coordinator reset the worktree; the guard was re-run
   green by the worker. Recorded above in full.
3. A throwaway `.venv-e8m2/` and a scratch `git worktree` of `944c47e` were used for the
   clean-environment and BEFORE runs. Neither is tracked; both are outside the commit.

## Standing guarantees, all still held

* Rules own severity and correlation; the LLM and the learned model explain only. Nothing in
  this amendment lets the model change a `sev`, a verdict, or a gate — it changes only what a
  *metric* reports, which is the whole reason it is published.
* Real data or an honest gap. No model → no learned per-rule recall, no per-rule dropped
  count, no aggregate learned recall — `null` with a reason, never a zero standing in.
* The console still computes nothing: `efficacy_api.py` defines no scoring, picks no seed, and
  now picks no scenario set either — it reads the referee's frozen tuple. Asserted by source
  check in `console/test_console.py`.
* The web client still computes nothing: it renders the referee's numbers and derives no
  recall of its own. Asserted by source check in the web suite.
* One `score()`, one `_ratio()`, one `diff()`. The per-rule breakdown reuses
  `finding_level_recall()`, which reuses `_ratio()` — no second metric implementation exists.
