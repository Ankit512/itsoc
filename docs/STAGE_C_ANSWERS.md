# Stage C — Owner Answers

_Recorded by the Stage C orchestrator. **Secrets are never recorded here — paths only, never values.**_

## Blocking

**Q1 · Push authority — ANSWERED: (c) Never.**
Everything stays local. Nothing reaches GitHub during this run. Owner reaffirmed explicitly:
"The two unpushed local commits are acknowledged; stacking Stage C on them is fine and consistent
with the never-push default." Stage C branches stack on local `main` (2 commits ahead of `origin/main`).

**Q2 · OPNsense VM (Phase C3) — OPEN.**
Not answered at kickoff. Not required until C3. The orchestrator will STOP and re-ask before C3 begins.
If still unanswered then, C3 builds against the abstract connector with a mock and the live end-to-end
acceptance item is marked **BLOCKED — VM required** (never claimed as passed).

**Q3 · Step-up identity for approvals — OPEN.**
Not answered at kickoff. Not required until C3. The orchestrator will STOP and re-ask before C3 begins.
No passphrase will ever appear in chat, this file, task cards, or logs.

## Defaults (applied — no override given)

- **Q4 · Worker CLIs.** Codex/Gemini assumed present. If a tier is unavailable at dispatch, its work
  routes UP to Claude Code agents and the substitution is logged — no stop.
- **Q5 · Org-context seed.** `server-01 -> crown-jewel`; all other observed assets -> `standard`.
- **Q6 · Repo rename.** `log-anomaly-detector -> itsoc` is OUT of scope for this run.
  (Would require push authority (a) or (b) anyway; Q1 is (c).)

## Pre-flight rulings (owner, 2026-08-28)

- **Blocker 1 (`tests/test_intake.py` red on clean main) -> (A) scoped pre-C0 repair.** New card
  **C0-T0** at the front of the C0 sequence. Fix the honest behavior the test asserts; do not silence
  the test. No change may touch severity/verdict paths in `log_analyzer.py` — drift there is a STOP.
  If the change turns out to be severity-affecting, that is a STOP, not a `manifest.json` edit.
- **Blocker 2 (`fsafe.py` absent) -> (A) port, (B) fallback.** Port `console/fsafe.py` from
  `archive/itsoc-main-pre-pivot` (`c36d03d`), adapting imports only. If adaptation exceeds trivial
  import fixes, abandon the port, write a minimal new `console/fsafe.py`, and log why. Folded into
  **C0-T2**; allowlist expanded.
- **Sequence.** C0-T0 -> full environment gate requiring **8/8** -> C0-T1 -> C0-T2 -> C0-T3 -> C0-T4.
  The repair rides on `stage-c/c0-foundations`; no separate branch.
- **Spec absence** is working-as-intended; the build doc governs alone.
- **pytest substitution (logged once).** `pytest` is not installed and will NOT be installed mid-run.
  Wherever the orchestrator prompt says "pytest", the green-bar is the repo's canonical suites per
  CLAUDE.md §6: `python3 tests/eval/run_eval.py`, `python3 console/test_console.py`,
  `python3 tests/test_intake.py` (unittest, run directly), plus `cd web && npx vitest run` and
  `npm run build`.
- **Routing conflict resolved.** The C0 phase note ("all Claude Code, no fan-out") supersedes §3's
  Gemini assignment for the terminology sweep *within C0*. §3 applies if a sweep recurs in a later phase.
