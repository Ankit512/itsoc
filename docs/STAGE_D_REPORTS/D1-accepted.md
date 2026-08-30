# D1 accepted — efficacy harness

**When:** 2026-08-30. **Worker:** Claude `task_a609091f477e` / `ctx_e6fb6835cfbe` / `482dbd4`.
**Merge:** `58a73df`. **Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.

## Independent verification

| Check | Result |
|---|---|
| Allowlist | `tools/efficacy_harness.py`, `tools/test_efficacy_harness.py` only |
| Tests | 13/13 |
| Adversarial miss | benign `scheduled backup completed successfully` (line 9) is reported as a miss with raw/why byte-identical; recall < 1 |
| Import-graph | walker reaches `tools.attack_generator`; fails closed on `anomaly_detector` / `log_analyzer` / `rules_syslog` / `tests.eval`; mutation probe imports those and the walker catches them |
| Seam | `subprocess.run` + `--rules-only` |
| Isolation | output under `tests/eval/` raises `ValueError` |
| Eval | 19/19 |

Scope sentence is on every result: *measured against synthetic ground-truth scenarios; not a claim about production traffic.*

## Next

D2 (Antigravity) is unblocked. D3 and P4 wait. Parked stays parked.
