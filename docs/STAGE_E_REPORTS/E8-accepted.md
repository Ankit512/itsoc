# E8 accepted — frozen paired-system efficacy referee

**Accepted:** 2026-09-02. **Run:** `run_9214da4ebb53`. **Task:** `task_af321cc0bcc3`. **Dispatch:** `ctx_e58af9c7a6d8`.

Dispatch card: `docs/STAGE_E_REPORTS/E8-dispatch.md`. Worker report: `docs/STAGE_E_REPORTS/E8-worker.md`.

## Provenance

Worker commits `aedd02a` and `11fb797` on `feat/e8-frozen-referee`, merged locally as `e5d9a5f`. Nothing was
pushed and the worker did not merge.

The agent turn was interrupted mid-card by a host sleep. The dispatch itself stayed live and the
worktree was intact, so the same worker was resumed rather than replaced. Task and dispatch identity
are therefore continuous, and `worker_done` was sent exactly once.

## The stricter entity rule

The resume tightened the acceptance contract: entity disjointness must cover **every observed
host/user/IP value**, not only the high-cardinality identifiers a fresh seed can separate on its own.

`ASSERTED_ENTITY_KINDS` is `ip, user, host, port, change_window` — every kind
`triage_model.features()` can count. Overlap is asserted at zero on each kind and across kinds.
`attack_generator` pins each scenario to a fixed host and draws usernames from fixed four-value
vocabularies, and fourteen training seeds exhaust them, so seed choice alone could never satisfy
this. A benchmark-only deterministic token remap rewrites the generated logs and the matching
manifest raw values by index, keeping bytes aligned, before the analyzer subprocess sees them. It is
a pure function of the token, lives entirely in the referee, and touches no generator or training
file. Remapped-host criticality is preserved through a benchmark-only org context.

## Independent coordinator verification

Verified directly, not accepted from the worker's report:

| Check | Result |
| --- | --- |
| `anomaly_detector.py` sha256 | `364577c5…577a4a876`, unchanged |
| Branch pushed to any remote | No — absent from every remote ref |
| Files changed vs base | 10, all inside the allowlist |
| Excluded files (detector/rules/eval/model/training/deps) | None touched |
| Working tree | Clean |
| Harness tests, sklearn 1.7.2 present | 37/37 OK |
| Harness tests, sklearn absent | 37/37 OK |
| `console/test_console.py` | 0 FAIL |
| `tests/eval/run_eval.py` | 20/20, precision/recall/F1 1.000, 0 FP |
| `web` vitest | 43/43 files, 282/282 tests |
| `npm run build` | Green |

## Mutation evidence, reproduced

Both failure exercises were re-run by the coordinator rather than taken on trust.

**Seed overlap.** Running the benchmark on training seed `20260902` exits 2:

> BENCHMARK REFUSED: benchmark seeds [20260902] were also TRAINING seeds (sidecar recorded
> [20260902 … 20260915]) — the benchmark would be scoring the model on its own training data.
> Refusing to run.

The refusal reads the model's actual sidecar, confirming the frozen benchmark seeds
`20270302–20270304` are genuinely disjoint from the real E7a training seeds.

**Model kill.** With scikit-learn absent, every rules total and miss list is byte-identical to the
run with the model present. The learned block reports `available: false` with a stated reason and
`totals: null` — an honest unavailable state, not a scored zero.

## Measured result

**Amended 2026-09-02 after the leakage interrogation** (`E8-leakage-interrogation.md`). The
paragraph below is true as measured and misleading as read; the doctrine is honest surfaces, not
honest technicalities. Corrections, which card E8m makes first-class in the published metrics:

- The false-positive total is **format-scoped**: 84 across all four formatters, of which the
  canonical-only subset is the 21 quoted here. The learned system suppressed all 84.
- Learned recall of 1.000 is **line-level**. **Finding-level learned recall is 0.9444 (85 of 90).**
- The model **dropped five `ioc_observed` findings on the crown-jewel host in `INC-4a7f`**, labelling
  them `benign-expected` at confidence up to 0.992. Line-level recall stayed 1.000 only because
  their single cited malicious line is also covered by kept findings. "Matched every positive" does
  not hold at finding level.
- A second headline finding: `criticality_rank` carries 41.5% of model feature importance and its
  direction runs backwards — raising a host to crown-jewel flips 28 of 85 true detections to
  DROPPED. Counterfactual; the published numbers stand as measured.

Rules numbers are unaffected. No verdict, severity, or rule finding moved.

Rules score 1.000 precision/recall/F1 with 0 misses on all three positive scenarios and raise 21
false positives across the three negative scenarios. The learned system matches every positive and
suppresses all 21, also with 0 misses. Both systems pass through the identical `score()`/`diff()`
path, keep deep-independent finding collections, list misses verbatim, and carry one run id plus
model provenance.

Negative scenarios carry `precision_defined`/`recall_defined`, so a 0/0 surfaces as `n/a` rather than
a measured zero. The standing synthetic-scope sentence is retained and the learned model remains
advisory — it never writes or changes a severity.

## Freeze

The referee logic, its tests, and benchmark seed selection are frozen as of this acceptance. E7b
modifiers may not edit them. E7b is unblocked.
