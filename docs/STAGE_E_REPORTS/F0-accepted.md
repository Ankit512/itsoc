# F0 acceptance — runbook legibility

**Accepted:** 2026-09-02. **Branch:** `feat/f0-runbook-legibility`. **Worker commit:** `4cb5b17`. **Local merge:** `01c88dc`. **Push:** none.

## Outcome

F0 is accepted and merged locally. Runbook cards now explain what each shipped runbook does, when it fires, what evidence it needs, its real ordered steps, and reversibility in plain language. Raw ids, severity floors, trigger ids, and verbatim ineligibility machinery are retained in a native disclosure that is closed by default.

The copy is a bounded client-side transcription because the existing recommendation API does not expose step or rollback definitions and backend changes were forbidden. Real runbooks render their actual one- or two-step definitions rather than fabricated padding; unknown ids get an explicit undescribed fallback with no guessed steps. An eligible card uses the same closed disclosure under `Rule detail`, preserving existing raw-rule access without placing schema vocabulary on the default surface. These are accepted implementation judgments within the card's honesty and no-engine constraints.

## Independent acceptance evidence

| Check | Result |
|---|---|
| branch and allowlist audit | clean branch; only F0-allowlisted files changed; no engine/backend file touched |
| targeted component coverage | 15 runbook-card tests and 9 theme tests green |
| `python3 console/test_console.py` | full suite green |
| `python3 tests/eval/run_eval.py` | 20/20; precision, recall, F1 all 1.000 |
| `npm --prefix web run build` | passed |
| worker full web run | 43/43 files, 262/262 tests passed |
| combined-main full web run after E0 + F0 | 43/43 files, 266/266 tests passed |
| `sha256sum anomaly_detector.py` | exact frozen SHA-256 `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |
| `graphify update .` after merge | succeeded; graph rebuilt |

An independent parallel run initially timed out in one untouched Integrations test under resource contention. Its isolated rerun passed 9/9 and the sequential combined-main suite passed 266/266.
