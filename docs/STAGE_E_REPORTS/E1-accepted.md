# E1 acceptance — deterministic precedent index

**Accepted:** 2026-09-02. **Branch:** `feat/e1-precedent-index`. **Worker commit:** `9f34421`. **Local merge:** `739683f`. **Push:** none.

## Outcome

E1 is accepted and merged locally. A stored-incident inverted index ranks matches by overlap of rule ids, observed host/user/IP values, ATT&CK technique ids, and asset criticality. Self and zero-overlap records are omitted. Every row carries the matched fact values and an explanation recomputable from those values, with the prior incident disposition joined only after ranking. Incidents now has a deterministic Precedents panel with honest empty and unreachable states.

The E6 interface remains closed at `rank(incident, candidates)`. AST guards prove that the ranker imports only `inspect` and `re`, calls no model/network/subprocess/clock/random primitive, drops all advisory and disposition keys before ranking, and leaves eligibility unchanged.

## Independent acceptance evidence

| Check | Result |
|---|---|
| branch and allowlist audit | clean branch; exactly the ten E1-allowlisted paths changed |
| `python3 tests/test_stage_e_wall.py` | 48/48 passed |
| `python3 console/test_console.py` | full suite green, including all E0 and E1 checks |
| 2,500-incident query | best 18.1 ms, median 18.7 ms of 7; 200 ms budget passed; clock-free cost check scores exactly 100/2,500 candidates for the one-token probe |
| `npm --prefix web test` | 43/43 files, 271/271 tests passed |
| `npm --prefix web run build` | passed |
| `python3 tests/eval/run_eval.py` | 20/20; precision, recall, F1 all 1.000 |
| `sha256sum anomaly_detector.py` | exact frozen SHA-256 `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |
| `graphify update .` after merge | completed; graph rebuilt with one TSX parser warning despite the authoritative TypeScript build passing |

No detector, severity, priority, eligibility, execution, runbook-engine, eval-fixture, manifest, or dependency file changed.
