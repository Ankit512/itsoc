# E7b round 1 — graded: honest partial, NOT a pass

**Graded:** 2026-09-02. **Task:** `task_04fa102b33a2`. **Dispatch:** `ctx_966546338f31`.
**Worker commit:** `688c1ee` on `Ankit512/e7b-r1-triage-modifier`, base `f5fe072`. **Not merged. Not pushed.**
Worker report: `docs/STAGE_E_REPORTS/E7b-r1-worker.md`.

## Verdict

Round 1 **eliminated both named defects and held suppression, but regressed aggregate
finding-level recall.** The stated success bar — recall regains ground *without* losing the
false-positive suppression result — is **not met**. This is an honest partial, reported as one by
the worker before I asked.

## Measured on the frozen referee, same seeds, all four formats

Reproduced by the coordinator against the re-frozen referee, byte-identical to main's copy.

| | Before (E7a) | After (R1) | |
|---|---|---|---|
| Finding-level learned recall | 0.9444 (85/90) | **0.9111 (82/90)** | **regressed 0.0333** |
| Dropped true findings | 5 | 8 | worse in aggregate |
| — on the crown-jewel host (`ioc_observed`) | 5 | **0** | **defect 1 eliminated** |
| — new drops (`infra_unknown_high`, `error-burst`) | 0 | 8 | a different rule class |
| `criticality_rank` importance | 0.4146 | **absent** | **defect 2 eliminated** |
| Gradient flips, true detections | 28 / 85 | **0 / 82** | fully robust |
| Gradient flips, suppressions | 33 / 84 | **0 / 84** | fully robust |
| Rules FPs (all formats) | 84 | 84 | unchanged |
| **Learned FPs (all formats)** | 0 | **0** | **suppression HELD** |
| Learned line-level misses | 0 | 0 | unchanged |

Per-format learned false positives are 0 in canonical, rfc3164, rfc5424 and jsonlog both before and
after. The suppression result was not traded away.

## What the round got right

**The root-cause finding is better than the brief it was given.** I reported two defects; the worker
measured that they were **one**. `server-01` is the only crown-jewel asset in the org config, and in
the training set every `benign-expected` row is crown-jewel while every `false-positive` row is
standard. `criticality_rank` was therefore a **label proxy**, not a risk signal — which is why its
gradient ran backwards and why the five `ioc_observed` findings, which score `confirmed` at ≥0.9986
at low and standard, flipped only at crown-jewel.

**It refused the forbidden trade.** A declared cost weighting recovered 0.9444 exactly — but created
7 false positives on the same rule. The worker rejected and reverted it rather than buy recall with
suppression. Verified: `tools/train_triage.py` carries **no diff** from base, so the rejected
experiment left nothing behind.

**The pre-authorised contract amendment is stronger than what it replaced.** The non-vacuity control
moved from `criticality` onto `techniques` → `mitre_technique_count`, a permitted observed fact, so
it still bites; `assertNotIn("criticality_rank", FEATURE_KEYS)` pins the removal; and the old
assertion was flipped to `assertEqual`, proving criticality is now inert in both directions. No
`FORBIDDEN_KEYS` or leakage assertion was touched. Within authorisation, and it hardened the file.

## Coordinator correction — the irreducibility claim is overstated

The worker justified stopping by asserting `infra_unknown_high` is "28/28/28 with an identical
feature vector across all three labels", i.e. undecidable under the frozen record projection. **I
measured this and it does not hold as stated.** Over the 14 training seeds:

- 14 `confirmed`, 14 `false-positive`, 14 `benign-expected` rows — 42 total.
- **9 distinct feature vectors**, not one.
- **4 of 9 vectors are ambiguous**, each mapping to both `benign-expected` and `confirmed`.
- **19 of 42 rows (45%) sit on an ambiguous vector** — the remaining 55% are separable.

The substance is directionally right: there is genuine label ambiguity for this rule under the
current projection, and it is exactly the `benign-expected` vs `confirmed` confusion that produced
the eight drops. But it is **partially reducible, not irreducible**. Round 2 has headroom that round
1 concluded did not exist.

## Gates (coordinator-run, on the round 1 branch)

`tests/test_e7a_feature_contract.py` 10 passed / 67 subtests; `tests/test_stage_e_wall.py` 101/101;
harness tests 57/57 with sklearn **and** without; `console/test_console.py` 0 FAIL;
`tests/eval/run_eval.py` 20/20 F1 1.000 FP 0; `tools/test_train_triage.py` 23 passed; web 290/290
across 43 files. Frozen referee **byte-identical** to main's copy — untouched. Detector sha256
`364577c5…577a4a876` unchanged. Allowlist clean: four files, no forbidden path. Branch never pushed.
`tests/test_battlecard_efficacy.py` still fails its known stale assertion, identically to main.

## Disposition

**Not merged.** Merging would lock in a 0.0333 recall regression on the primary published metric.
Round 1 stands as the first of two independently graded attempts, with its branch intact for
comparison. Round 2 should start from the same base `f5fe072`, not from round 1, so the two attempts
stay independent — and should be told that the `infra_unknown_high` residual is 45% ambiguous rather
than wholly undecidable.
