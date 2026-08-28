# ITSOC Stage C — Execution Log

_Written by the Stage C orchestrator. Autonomous mode: each phase's stop-and-report is appended here
as a log entry rather than a pause. Hard stops still stop and go to the owner._

**Standing substitution (logged once, per owner ruling):** `pytest` is not installed on this machine and
is NOT installed mid-run. Wherever the orchestrator prompt says "pytest", the green-bar is the repo's
canonical suites per CLAUDE.md §6: `tests/eval/run_eval.py`, `console/test_console.py`,
`tests/test_intake.py` (unittest, run directly), `web` vitest, and `npm run build`.

**Push policy:** Q1 = (c) never. Nothing is pushed. All work is local on `stage-c/c0-foundations`,
which stacks on a local `main` that is itself 2 commits ahead of `origin/main` (owner-acknowledged).

---

## Phase C0 — Foundations

Branch `stage-c/c0-foundations`. Opening commit `c5249b2` (build doc + orchestrator prompt + kickoff
sheet + `docs/STAGE_C_ANSWERS.md`) per the autonomous-mode first action.

### C0-T0 · intake / run() reconciliation — **ACCEPTED** (commit `c963b20`, Claude Code worker)

Owner-authorized pre-C0 repair (Blocker 1, ruling (A)).

**Finding — `run()` was NOT honest by default; the owner's branch (3) was the correct path.**
`log_analyzer.run()` ingested via `log_analyzer.load_log_file()`, whose documented behavior is that it
"NEVER converts a readable file into 'unsupported format'": when `normalize.load()` recognized 0
records it fell through to `detect_input_format()` -> `"text"` -> `parse_text_stream()`, which accepts
every non-blank line as a record. Measured pre-fix on `neg_unrecognized_format.log`:
`Format: generic_text — 11/11 line(s) parsed`, `lines_parsed=11`, `findings=0`. Because
`console/adapter.py:448-451` derives `unrecognized` as `lines_parsed == 0 and lines_unparsed > 0`,
that produced a **fake-green "0 findings / 11 lines parsed"** report on a file no rule understood —
a direct guardrail-4 violation. Empty input was worse: `run()` returned rc 2 and wrote **no report at
all**, so intake then died reading a `report.json` that never existed.

**Fix (minimal, seam-reusing).** `formats_universal.py` already implemented
`load_log_file(path, mode="honest"|"force")` with exactly the required semantics and was already
covered by `console/test_console.py` — but was an orphan, never wired into `log_analyzer`. The change
is one import, one optional parameter (`unrecognized_mode: str = None`), one empty-file carve-out, and
one dispatch. `scripts/intake.py` and `tests/test_intake.py` needed **no edit** — the call site was
already correct; only the callee was missing. Default `None` keeps every existing caller on the
historical loader byte-for-byte.

Post-fix, measured: `neg_unrecognized_format` -> `Format: unknown — 0/11 parsed, 11 unparsed`;
`neg_empty` -> `Input log is empty … (this is NOT an all-clear)`, `Format: empty — 0/0 parsed`.

**Hard constraint honored.** god read the full diff: ingestion only. No rule, severity, correlation or
verdict path is touched. `tests/eval/manifest.json` diff is empty. No severity change occurred, so the
STOP condition did not trigger.

**Diff:** `log_analyzer.py` only — 1 file, +24 / -4.

| # | Acceptance | Result (god-verified independently, not claimed) |
|---|---|---|
| a | `tests/test_intake.py` | **PASS** — `Ran 4 tests` / `OK` (was 3 errors) |
| b | `tests/eval/run_eval.py` | **PASS** — 17 passed / 0 failed; 0 FP, 0 FN; p/r/f1 = 1.000 |
| c | `console/test_console.py` | **PASS** — all 27 check groups green |
| d | vitest | **PASS** — 26 files, 107/107 |
| e | `npm run build` | **PASS** — built in 5.40s (only the pre-existing >500 kB chunk advisory) |
| f | detector sha | **PASS** — `364577c5…a4a876` unchanged |
| g | diff inside allowlist | **PASS** — `log_analyzer.py` only |
| h | `manifest.json` untouched | **PASS** — empty diff |

### Environment gate re-run — **8 / 8 GREEN** (owner-required before C0-T1)

`main`-equivalent branch state ✓ · clean tree ✓ · detector `364577c5…a4a876` ✓ · `npm run build` ✓ ·
vitest 107/107 ✓ · `run_eval` 17/17 f1 1.000 ✓ · `console/test_console.py` PASSED ✓ ·
`tests/test_intake.py` 4/4 ✓ — the check that failed at pre-flight is now green.

### Findings carried forward (NOT auto-absorbed — recommended follow-up cards, no tripwire fired)

1. **The dishonest ingestion default still ships.** C0-T0 made honesty *available*, not default.
   `run()` still force-parses unrecognized input for any caller that does not pass
   `unrecognized_mode="honest"` — currently only `scripts/intake.py` passes it; `tools/model_ab.py:146`
   does not. *Orchestrator correction to the worker's report:* `console/serve.py` does **not** call
   `log_analyzer.run()` (its line 898 is only a comment referencing it), so the console is not affected
   *via run()*; the console hydrates through `adapter.load_console_records` -> `log_analyzer.load_log_file`,
   which is the same force-parsing loader — so an equivalent gap does exist on the console path, by a
   different route. Flipping the default repo-wide would move eval/console expectations and is out of
   C0-T0's allowlist. **Recommend a dedicated card; owner decision.**
2. **`formats_universal.DEFAULT_MODE` contradicts its own docstring.** Line 47 resolves to `"force"`
   when `LOG_ANALYZER_UNRECOGNIZED_MODE` is unset, while lines 24/35/592 twice state the default is
   `"honest"` and call it "the repo guardrail". Latent today (intake passes `mode` explicitly), but it
   is an inconsistency inside a guardrail-bearing module. **Recommend a ticket.**
3. Honest mode makes `run()` return `None` rather than `2` for an empty file (it now writes a report,
   which is what the test demands). Scoped to `unrecognized_mode == "honest"`, so no existing exit-code
   contract changed.
4. Pre-existing `ResourceWarning: unclosed file` noise from `normalize.py:226/229/251/254`. Not
   introduced here, outside the allowlist.
