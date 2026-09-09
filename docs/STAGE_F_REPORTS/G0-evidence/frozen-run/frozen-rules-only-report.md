# Log Analysis Report

**Source:** `tests/eval/cases/pos_bruteforce_compromise.log`  
**Generated:** 2026-09-09T07:54:30.407069+00:00  
**Model:** qwen3:8b  
**Chunks analyzed:** 0  
**Total findings:** 2 (2 rule-based, 0 model)

## Severity breakdown

- **CRITICAL**: 1
- **MEDIUM**: 1

## Rule-based findings (authoritative)

### [CRITICAL] Brute-force then SUCCESSFUL login for 'admin' from 198.51.100.11 — likely account compromise
- **Rule:** `auth_bruteforce_success`
- **Source:** detector
- **Category:** rule_detection
- **Confidence:** high
- **Evidence:** `6x auth failed for 'admin' from 198.51.100.11 (lines 1-6); then auth SUCCESS at line 7`
- **Why the rule fired:** Multiple failed logins immediately followed by a success from the same source strongly indicates a successful brute-force / credential-stuffing compromise.
- **Analyst explanation:** _not generated — open this finding in the console to explain it_

### [MEDIUM] Authentication failure detected (6 occurrences) _(x6)_
- **Rule:** `generic_auth_failure`
- **Source:** detector
- **Category:** rule_detection
- **Confidence:** high
- **Evidence:** `auth failed for user 'admin' from 198.51.100.11 (invalid password) | source lines: 1-6`
- **Why the rule fired:** Deterministic high-signal pattern matched 6 log record(s). Severity is rule-derived and recurrence-aware.
- **Analyst explanation:** _not generated — open this finding in the console to explain it_

## Additional findings (model + analyzer)

None — the model surfaced nothing beyond the pre-flagged anomalies.
