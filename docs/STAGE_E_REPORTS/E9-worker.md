# E9 — retrain automation

- Branch: `feat/e9-retrain-automation`
- HEAD: `6b490ead2ced177eda5a240cc36293740c17c55e`
- Base check: `git merge-base --is-ancestor 6b490ead2ced177eda5a240cc36293740c17c55e HEAD` — exit `0`.
- Protected detector checksum before/after: `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.
- Allowlist: added only `scripts/retrain.sh` and this report; no frozen referee, detector, rules, corpus, console model, generator, or training source was edited.

## Design

`scripts/retrain.sh` stages a candidate with `tools/train_triage.py`, then runs the frozen referee against the staged candidate and the currently installed model. Before any benchmark invocation it checks the referee's exact frozen scenario tuple, requires the installed artifact and sidecar, and checks candidate sidecar training seeds against `BENCHMARK_SEEDS`; after each referee run it requires `scenarioSetIsFrozen`, asserted freshness, and a real available model. It compares aggregate and per-rule finding recall, false positives overall and by format, dropped true findings, and line-level misses; any regression prints both JSON scorecards and exits nonzero without touching the installed directory. A passing candidate is copied into a sibling directory and swapped into place only after comparison.

## Verification

The script parses cleanly and the repository whitespace guard is clean:

```text
$ bash -n scripts/retrain.sh
$ git diff --check
```

On this clean checkout there is no installed model artifact, so the required honest failure was exercised:

```text
RETRAIN RUN: 2026-09-03T09:04:09Z
Commit: 6b490ead2ced177eda5a240cc36293740c17c55e
MODEL UNAVAILABLE: installed model artifact or provenance is missing in /Users/ankit/orca/workspaces/log-analyzer/e9-retrain-automation/console/.soc/models
EXIT:1
```

The verified artifact from `e7b-r2-triage-modifier/console/.soc/models/` was copied into the ignored installed path for these attacks, and restored afterward. The following are the exact attack commands and decisive output lines (all scratch model wrappers and the tampered referee copy lived under `/tmp`; no frozen repo file was edited).

### 1. Strictly regressed candidate

```text
$ before=$(shasum -a 256 console/.soc/models/triage_v1.pkl); MODEL_DIR="$PWD/console/.soc/models" PYTHON=/tmp/e9-regress-python.py ./scripts/retrain.sh; rc=$?; after=$(shasum -a 256 console/.soc/models/triage_v1.pkl); echo BEFORE:$before; echo AFTER:$after; echo EXIT:$rc
CANDIDATE SCORECARD
{"dropped_true_findings": 12, "false_positives": 0, "false_positives_by_format": {"canonical": 0}, "finding_recall": 0.2857, "finding_recall_by_rule": {"auth_bruteforce": 1.0, "auth_bruteforce_success": 1.0, "error_rate_spike": 0.0, "generic_auth_failure": 0.0, "generic_http_server_error": 0.0, "infra_unknown_high": 0.0}, "line_misses": 24}
INSTALLED SCORECARD
{"dropped_true_findings": 0, "false_positives": 0, "false_positives_by_format": {"canonical": 0}, "finding_recall": 1.0, "finding_recall_by_rule": {"auth_bruteforce": 1.0, "auth_bruteforce_success": 1.0, "error_rate_spike": 1.0, "generic_auth_failure": 1.0, "generic_http_server_error": 1.0, "infra_unknown_high": 1.0}, "line_misses": 0}
REFUSED REGRESSED CANDIDATE:
finding_recall: 0.2857 < 1.0; finding_recall_by_rule[error_rate_spike]: 0.0 < 1.0; finding_recall_by_rule[generic_auth_failure]: 0.0 < 1.0; finding_recall_by_rule[generic_http_server_error]: 0.0 < 1.0; finding_recall_by_rule[infra_unknown_high]: 0.0 < 1.0; dropped_true_findings increased; line-level misses increased
Installed model left untouched: /Users/ankit/orca/workspaces/log-analyzer/e9-retrain-automation/console/.soc/models
BEFORE:7f8dab5a197a45f9ef8ffb8ffc17a9909f3ae4e64fd4f71f9dcb88938295b338  console/.soc/models/triage_v1.pkl
AFTER:7f8dab5a197a45f9ef8ffb8ffc17a9909f3ae4e64fd4f71f9dcb88938295b338  console/.soc/models/triage_v1.pkl
EXIT:3
```

### 2. Aggregate-held, per-rule-only regression

The installed scratch estimator dropped the auth family; the candidate dropped the error family plus only the single-occurrence auth class. Both aggregate finding recall values are exactly `0.4286`, while the candidate loses `error_rate_spike` and `generic_http_server_error`.

```text
CANDIDATE SCORECARD
{"dropped_true_findings": 12, "false_positives": 15, "false_positives_by_format": {"canonical": 15}, "finding_recall": 0.4286, "finding_recall_by_rule": {"auth_bruteforce": 0.0, "auth_bruteforce_success": 0.0, "error_rate_spike": 0.0, "generic_auth_failure": 1.0, "generic_http_server_error": 0.0, "infra_unknown_high": 1.0}, "line_misses": 24}
INSTALLED SCORECARD
{"dropped_true_findings": 12, "false_positives": 18, "false_positives_by_format": {"canonical": 18}, "finding_recall": 0.4286, "finding_recall_by_rule": {"auth_bruteforce": 0.0, "auth_bruteforce_success": 0.0, "error_rate_spike": 1.0, "generic_auth_failure": 0.0, "generic_http_server_error": 1.0, "infra_unknown_high": 1.0}, "line_misses": 46}
REFUSED REGRESSED CANDIDATE:
finding_recall_by_rule[error_rate_spike]: 0.0 < 1.0; finding_recall_by_rule[generic_http_server_error]: 0.0 < 1.0
Installed model left untouched: /Users/ankit/orca/workspaces/log-analyzer/e9-retrain-automation/console/.soc/models
BEFORE:cdeb9f40256918f925c78b54bc3fc978a19486ac84c2149085a48818ac03b530  console/.soc/models/triage_v1.pkl
AFTER:cdeb9f40256918f925c78b54bc3fc978a19486ac84c2149085a48818ac03b530  console/.soc/models/triage_v1.pkl
EXIT:3
```

### 3. Tampered frozen scenario tuple

Command: copy the repository to `/tmp/e9-tamper.mZh5/repo`, add `"tampered-scenario"` to that copy's `BENCHMARK_SCENARIOS`, then run `MODEL_DIR=/tmp/e9-tamper.mZh5/repo/console/.soc/models PYTHON=/tmp/e9-venv/bin/python /tmp/e9-tamper.mZh5/repo/scripts/retrain.sh`.

```text
RETRAIN RUN: 2026-09-03T09:15:07Z
Commit: 478067f23f8c3419d027b5b23dd2f795f4e17699
BENCHMARK REFUSED: frozen scenario tuple is not intact
EXIT:1
NO_SCORECARD:0
```

### 4. Overlapping seed

Command: `MODEL_DIR="$PWD/console/.soc/models" PYTHON=/tmp/e9-overlap-python.py ./scripts/retrain.sh`, where the scratch trainer wrapper appended benchmark seed `20270302` to the candidate sidecar.

```text
BENCHMARK REFUSED: benchmark seeds [20270302] overlap candidate training seeds [20260902, 20260903, 20260904, 20260905, 20260906, 20260907, 20260908, 20260909, 20260910, 20260911, 20260912, 20260913, 20260914, 20260915, 20270302]
EXIT:1
NO_SCORECARD:0
```

The last two outputs prove no scorecard text was produced (`NO_SCORECARD:0`).

## Deviations

No deviations from the dispatch specification. `tools/train_triage.py` was not touched because its existing `--model-dir` staging path is sufficient.
