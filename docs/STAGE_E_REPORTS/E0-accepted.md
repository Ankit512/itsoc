# E0 acceptance — disposition capture

**Accepted:** 2026-09-02. **Branch:** `feat/e0-disposition-capture`. **Worker commits:** `622f540`, `f8cc279`. **Local merge:** `684c373`. **Push:** none.

## Outcome

E0 is accepted and merged locally. Incident close transitions can capture `confirmed`, `false-positive`, or `benign-expected` with an optional bounded reason. The values are stored additively, preserved across incident resync and case migration, included in generated reports, and shown as a History chip plus append-only audit entries.

The lifecycle endpoint is the only value-setting surface. Invalid values, orphan reasons, and dispositions on non-close transitions are rejected. Closing without a disposition remains legal and honestly renders as none recorded; reopening clears the current value while retaining the audit event. These are compatible, non-fabricating interpretations of the additive card.

## Independent acceptance evidence

| Check | Result |
|---|---|
| branch and allowlist audit | clean branch; only E0-allowlisted files changed |
| `python3 console/test_console.py` | full suite green, including 34 E0 disposition checks |
| `python3 tests/eval/run_eval.py` | 20/20; precision, recall, F1 all 1.000 |
| `npm --prefix web run build` | passed |
| worker full web run | 43/43 files, 255/255 tests passed |
| combined-main full web run after E0 + F0 | 43/43 files, 266/266 tests passed |
| `sha256sum anomaly_detector.py` | exact frozen SHA-256 `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |
| eligibility audit | closed three-argument signature; no disposition in rule-owned projection; identical non-vacuous answers for every disposition |
| `graphify update .` after merge | succeeded; graph rebuilt |

An independent parallel run initially timed out in one untouched Integrations test while two complete Vitest suites and builds competed for resources. The same test file passed 9/9 in isolation, and the combined-main full suite then passed 266/266 sequentially. This is classified as test-runner resource contention, not a product regression.
