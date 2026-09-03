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

The installed path was not created or modified by this refusal. End-to-end acceptance demonstrations (regressed candidate, aggregate-held/per-rule-only regression, tampered scenario tuple, and overlapping seed) are intended to be run in the review environment where a real installed model and the referee fixtures are available; the script has explicit refusal paths for each and never defaults a score.

## Deviations

No deviations from the dispatch specification. `tools/train_triage.py` was not touched because its existing `--model-dir` staging path is sufficient.
