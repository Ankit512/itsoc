# E7a independent Codex feature-contract tests

Date: 2026-09-02

Branch: `test/e7a-feature-contract`

Exact merged base: `8337490c90e11e034432a6cc2d9b8f980b21556a`

## Scope

This card adds an independent, stdlib-only `unittest` contract suite for the
already-shipped E7a learned triage model. It changes no implementation,
training code, existing test, rule, eval fixture/manifest, detector, web file,
or product documentation. The only changed paths are:

- `tests/test_e7a_feature_contract.py`
- `docs/STAGE_E_REPORTS/E7a-codex-tests.md`

The suite does not import pytest and does not require scikit-learn. Loaded-model
rendering is exercised with estimator stubs; artifact-loader failures patch only
the optional dependency version probe and use temporary files.

## Contract evidence added

`tests/test_e7a_feature_contract.py` contains 10 tests covering:

1. Deterministic feature maps/vectors for three finding shapes and two incident
   shapes, including JSON round trips and positive controls proving permitted
   facts really change the vector.
2. Two real generator/analyzer batches over `INC-4a7f`, `near-miss-auth`, and
   `benign-maintenance`, three seeds (`4100`, `4101`, `4102`), and the three
   classes (`confirmed`, `false-positive`, `benign-expected`). The batches cross
   the real `log_analyzer.py --rules-only` subprocess seam and compare every
   resulting ordered vector exactly.
3. Every member of `FORBIDDEN_KEYS` poisoned singly and all at once. An
   independent category inventory covers disposition, advisory/model output,
   prose, rule/override severity, priority, eligibility, and execution fields;
   the inventory must equal the shipped forbidden set.
4. Train/inference identity and ordering: both modules hold the same function
   objects, training has exactly one `triage_model.feature_vector(...)` call,
   inference has exactly one `feature_vector(...)` call, and production
   `console/` plus `tools/` define no alternate extractor.
5. Stub-only predictions for all three loaded classes with numeric confidence,
   the fixed advisory severity, and explicit visible `agrees`/`disagrees` state.
   A no-probability estimator is refused rather than assigned fake confidence.
6. Honest unavailable results for missing model, missing sidecar, malformed
   sidecar, mismatched feature schema, hash mismatch, corrupt artifact with a
   matching hash, and unavailable scikit-learn. Every case has `aiSeverity`,
   `aiLabel`, `confidence`, `agrees`, and provenance set to `None`.
7. Canonical-byte snapshots of rule-owned finding fields, incident decision and
   analyst-lifecycle fields, runbook eligibility, and a case-shaped record
   before/after loaded advice and kill-the-model behavior.
8. Protected runbook and precedent projections rejecting all model/advisory
   output. Non-vacuous controls prove that changing real severity or rule id
   still changes the appropriate protected result.
9. A temporary real `incidents.json` sync from a deliberately poisoned finding,
   proving no model/advisory output is persisted while rule-owned severity and
   priority remain `HIGH` and `P1`.

## Exact verification commands and results

### Base and branch

```text
$ git rev-parse HEAD
8337490c90e11e034432a6cc2d9b8f980b21556a

$ git branch --show-current
test/e7a-feature-contract

$ git status --short --branch
## test/e7a-feature-contract
```

### New independent suite

```text
$ python3 -m unittest tests.test_e7a_feature_contract -v
test_attach_and_model_kill_leave_rule_incident_and_case_bytes_intact ... ok
test_eligibility_and_protected_projections_reject_model_output ... ok
test_real_generator_batches_repeat_across_three_seeds_and_classes ... ok
test_representative_finding_and_incident_shapes_are_deterministic ... ok
test_every_forbidden_field_is_inert_singly_and_together ... ok
test_model_output_cannot_enter_incident_store ... ok
test_all_three_loaded_classes_have_numeric_visible_contracts ... ok
test_estimator_without_probability_is_refused ... ok
test_train_and_inference_share_the_one_function_and_wire_order ... ok
test_every_artifact_and_dependency_failure_is_honest ... ok

Ran 10 tests in 1.509s
OK
```

The same file was also invoked directly (`python3
tests/test_e7a_feature_contract.py`): 10 tests passed in 1.453s.

### Stage E wall

```text
$ python3 tests/test_stage_e_wall.py
101/101 checks passed
Stage E wall intact.
```

### Full console suite

```text
$ python3 console/test_console.py
PASSED — render + routing + log360 + logcat + iso8601-syslog + auth-csv +
loghub-formats + remote-compute + dashboard-data + layout + all-runs +
soc-overview + soc-subsystems + stream + export + serve-react + store +
efficacy-api + syslog + discovery + ti-oem + evtx + validate-real +
formats-universal + rules-parity + explain-stream + structured-output +
redesign-phase4 + auth + ask-view + copilot-investigate + bruteforce-series +
runbooks + audit-chain + cases->incidents-migration + inc-4a7f-scenario +
investigation-engine + parallel-advisory + org-context-priority +
action-layer-ssh-firewall + sigma-ingest-triage-case-lifecycle +
e0-incident-disposition + e1-precedent-index checks green
```

Exit status: 0. The suite's live Docker connector check reported its documented
honest `BLOCKED (Docker daemon required)` state and the suite still passed.

### Deterministic eval

```text
$ python3 tests/eval/run_eval.py
cases           : 20 passed, 0 failed, 20 total
true positives  : 16
false positives : 0
false negatives : 0
precision       : 1.000
recall          : 1.000
f1              : 1.000
```

### Frozen detector and diff hygiene

```text
$ sha256sum anomaly_detector.py
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876  anomaly_detector.py

$ git diff --check
# no output; exit 0
```

## Gaps

None against this test-only card. The suite deliberately does not train or
benchmark a real model: the request requires loaded prediction tests to use
test stubs only, while E7a's existing training tests and E8 own those separate
concerns.
