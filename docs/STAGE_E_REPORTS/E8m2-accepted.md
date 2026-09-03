# E8m2 accepted — per-rule finding recall, and the benchmark freeze made real

**Accepted:** 2026-09-03. **Task:** `task_5effc7eaee28`. **Dispatch:** `ctx_a39adf319191`.
**Worker commit:** `d4b44c9` (base `944c47e`). **Local merge:** `5bbf4dd`. **Push:** none.
Worker report: `docs/STAGE_E_REPORTS/E8m2-worker.md`.

Third owner-authorized referee amendment. Additive publication and safety only.

## (1) Per-rule finding recall — it earned itself on the first run

Finding-level recall is now published broken down by `rule_id` per system, each with its own
denominator, beside the untouched verbatim `dropped_true_findings` list. On the frozen benchmark,
all four formats, the aggregate **0.9444 resolves to**:

| rule | learned finding recall | kept |
|---|---|---|
| `ioc_observed` | **0.5833** | 7/12 |
| `auth_bruteforce` | 1.0 | 12/12 |
| `auth_bruteforce_success` | 1.0 | 12/12 |
| `generic_auth_failure` | 1.0 | 24/24 |
| `generic_http_server_error` | 1.0 | 12/12 |
| `error_rate_spike` | 1.0 | 9/9 |
| `infra_unknown_high` | 1.0 | 9/9 |

A single rule class sitting at 58% was invisible inside a 94% aggregate — and `ioc_observed` is the
threat-intel class, on the crown-jewel host, in the flagship scenario. This is precisely the
mechanism that let both the five `ioc_observed` drops and round 1's eight `infra_unknown_high` drops
hide. It cannot recur silently.

## (2) The benchmark freeze is real for the first time

`BENCHMARK_SCENARIOS` is now pinned in the referee beside `BENCHMARK_SEEDS`, holding exactly the six
scenarios in the generator's declaration order, and the benchmark reads the frozen tuple rather than
`generator.SCENARIOS`. Every run publishes `benchmark.frozenScenarios` and
`benchmark.scenarioSetIsFrozen`.

**Verified by attack, both directions, by the coordinator:**

- Injecting a rogue scenario into `generator.SCENARIOS` at runtime leaves the resolved benchmark
  scenario set **unchanged**. A generator addition cannot reach the benchmark.
- Removing a frozen scenario from the generator raises `BenchmarkProvenanceError`: *"the frozen
  benchmark scenario set names scenario(s) the generator no longer produces: error-burst."* The
  benchmark refuses to run rather than silently measure less.

Before E8m2 the freeze covered seeds only; benchmark composition was open. See the correction
appended to `E8-accepted.md`.

## Byte-identical constraint — verified independently

Coordinator ran a pristine detached worktree at `944c47e` and the amended head against the **same
model artifact**, all four formats, and diffed flattened leaf key paths.

| | Result |
|---|---|
| Paths before / after | 13,466 / 14,466 |
| **Changed, non-volatile** | **0** |
| **Removed** | **0** |
| Added | 1,000, all under the new recall/scenario keys |

`BENCHMARK_SEEDS` unchanged; the remap, freshness assertion and existing metric scoring untouched.

## Coordinator gates on merged main

Harness **69/69** with sklearn **and** without (was 57); `console/test_console.py` 0 FAIL;
`tests/eval/run_eval.py` 20/20 F1 1.000 FP 0; `tests/test_stage_e_wall.py` 101/101; web **296/296**
across 43 files (was 290); `npm run build` green; detector sha256 `364577c5…577a4a876` unchanged;
allowlist clean; branch never pushed. `tests/test_battlecard_efficacy.py` still fails its known
stale assertion — the worker proved it byte-identical at the pristine base before leaving it alone.

## Deviations, recorded honestly by the worker

The base guard **failed on first run** (stale at `b836114`, 44 commits behind, missing the E8m
amendment it extends). The worker halted with zero files touched, escalated, and re-ran the guard
green after the coordinator reset — it did not fast-forward itself. Orca setup had failed, so it ran
`npm --prefix web install` itself. Both are now covered by the standing setup preamble.

## Re-freeze

The referee is re-frozen, now including per-rule finding recall, the frozen scenario tuple and its
provenance refusal, and their tests. E7b modifiers may not edit them.
