#!/usr/bin/env bash
#
# scripts/gate.sh — the canonical pre-merge gate (CLAUDE.md §6, §7).
#
# WHY THIS FILE EXISTS
# --------------------
# During the Stage C closeout, `console/test_console.py` returned exit=1 once and
# the cause was permanently unrecoverable, because the ad-hoc gate command that
# ran it redirected its output to /dev/null. A gate that discards its own
# evidence is worse than no gate: it converts a real failure into an unanswerable
# question. See docs/STAGE_C_CLOSEOUT.md §7 and docs/PROJECT_STATUS.md.
#
# The rules this script enforces on itself:
#   1. NEVER redirect a gate's output to /dev/null. Every byte of stdout and
#      stderr is teed to the terminal AND written to gate-logs/<stamp>/<name>.log.
#   2. NEVER let a pipeline mask an exit code. `tee` always exits 0, so a naive
#      `cmd | tee f` reports success for a failing cmd. We use PIPESTATUS[0]
#      (with pipefail belt-and-braces) to recover the REAL status.
#   3. NEVER stop at the first red. Every gate runs, so one failure does not hide
#      the state of the others; the script exits non-zero if ANY gate failed.
#   4. NEVER round a skip up to a pass. A gate that could not run is reported as
#      SKIP and is listed separately from the passes.
#
# COVERAGE (GS-1, 2026-09-06)
# ---------------------------
# Those four rules were sound and are unchanged. The defect was COVERAGE: this
# gate ran 3 of the repository's 18 Python suites, so two of them
# (console/test_auth_security.py and tests/test_battlecard_efficacy.py) had been
# failing for an unknown length of time with nobody looking. An unlisted suite
# is exactly how a suite rots, so the fifth rule is:
#
#   5. NEVER leave a suite unlisted. Every Python suite in the repository is
#      either run below or named in the DELIBERATELY OUT block at the bottom
#      with its reason. Adding a suite means adding a line here.
#
# INVOCATION MODE IS LOAD-BEARING (a real finding, GS-1)
# -----------------------------------------------------
# `tools/test_attack_generator.py` and `tools/test_efficacy_harness.py` do
# `from tools import ...`, which needs the REPO ROOT on sys.path. Launching them
# as FILES puts `tools/` on sys.path instead of the root, so they die with
# `ModuleNotFoundError: No module named 'tools'` — a suite that passes or fails
# purely by how it was launched. The cause is sys.path, not the tests (proved:
# `PYTHONPATH=. python3 tools/test_attack_generator.py` also passes). This gate
# therefore launches them EXPLICITLY as modules, `python3 -m tools.<name>`, from
# the repo root. That choice is deliberate and documented, not incidental.
#
# Usage:
#   scripts/gate.sh            # every python suite + detector freeze (~70s)
#   scripts/gate.sh --web      # also run the web/ vitest + build gates
#
set -u -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 99

STAMP="$(date +%Y%m%d-%H%M%S)"
LOGDIR="$ROOT/gate-logs/$STAMP"
mkdir -p "$LOGDIR"

RUN_WEB=0
[ "${1:-}" = "--web" ] && RUN_WEB=1

# The frozen detector hash from CLAUDE.md §1.
FROZEN_SHA="364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876"

PASSED=(); FAILED=(); SKIPPED=()

# run_gate <name> <command...>
#
# Streams the command's combined output to the terminal and to a log file, then
# records the command's OWN exit status -- not tee's.
run_gate() {
    local name="$1"; shift
    local log="$LOGDIR/$name.log"
    echo ""
    echo "=== GATE: $name ==="
    echo "    log: $log"
    # 2>&1 folds stderr into stdout so a traceback is captured, not lost.
    # PIPESTATUS[0] is the real status of "$@"; tee's own 0 is discarded.
    "$@" 2>&1 | tee "$log"
    local rc=${PIPESTATUS[0]}
    echo "--- $name exit=$rc ---" | tee -a "$log"
    if [ "$rc" -eq 0 ]; then
        PASSED+=("$name")
    else
        FAILED+=("$name (exit=$rc, evidence: $log)")
    fi
    return "$rc"
}

skip_gate() {
    local name="$1" why="$2"
    echo ""
    echo "=== GATE: $name === SKIP: $why"
    echo "SKIPPED: $why" > "$LOGDIR/$name.log"
    SKIPPED+=("$name ($why)")
}

echo "Gate run $STAMP — evidence under $LOGDIR"

# --- Every Python suite in the repository. Ordered fast-first so a cheap,
# --- obvious break surfaces early; rule 3 means all of them run regardless.
# --- Wall-clock measured 2026-09-06 on the GS-1 branch and noted per line.

# Engine / corpus
run_gate "run_eval"              python3 tests/eval/run_eval.py                 || true   # 0.1s
run_gate "validate_real_selftest" python3 tests/eval/validate_real.py --selftest || true  # 0.1s
run_gate "threat_intel"          python3 threat_intel/test_threat_intel.py      || true   # 0.3s

# Console / backend
run_gate "test_auth_security"    python3 console/test_auth_security.py          || true   # 0.3s
run_gate "test_copilot_workspace" python3 console/test_copilot_workspace.py     || true   # 0.1s
run_gate "test_overview"         python3 console/test_overview.py               || true   # 0.2s
run_gate "test_fsafe"            python3 console/test_fsafe.py                  || true   # 0.8s
run_gate "test_mcp"              python3 itsoc_mcp/test_mcp.py                  || true   # 0.1s

# Workflow / contract suites
run_gate "test_intake"           python3 tests/test_intake.py                   || true   # 0.1s
run_gate "test_audit_drift"      python3 tests/test_audit_drift.py              || true   # 0.1s
run_gate "test_ti_oem_egress"    python3 tests/test_ti_oem_egress.py            || true   # 0.1s
run_gate "test_stage_e_wall"     python3 tests/test_stage_e_wall.py             || true   # 0.8s
run_gate "test_e7a_feature_contract" python3 tests/test_e7a_feature_contract.py || true   # 1.5s
run_gate "test_battlecard_efficacy"  python3 tests/test_battlecard_efficacy.py  || true   # 2.5s
run_gate "test_approvals"        python3 tests/test_approvals.py                || true   # 3.5s

# tools/ — MUST be `-m` from the repo root; see "INVOCATION MODE" above.
run_gate "test_attack_generator" python3 -m tools.test_attack_generator         || true   # 0.1s
run_gate "test_train_triage"     python3 -m tools.test_train_triage             || true   # 2.5s
run_gate "test_efficacy_harness" python3 -m tools.test_efficacy_harness         || true   # 4.7s

# The two slow ones, last: they dominate wall clock but both stay in the DEFAULT
# gate. 51s of a ~70s run is a price worth paying for a gate that is complete;
# a --full flag here would just recreate the coverage hole this card closed.
run_gate "test_console"          python3 console/test_console.py                || true   # 20s
run_gate "test_recommend"        python3 tests/test_recommend.py                || true   # 31s

if [ "$RUN_WEB" -eq 1 ]; then
    if [ -d "$ROOT/web/node_modules" ]; then
        run_gate "web_vitest" npm --prefix web test  -- --run || true
        run_gate "web_build"  npm --prefix web run build      || true
    else
        skip_gate "web_vitest" "web/node_modules absent — run 'npm --prefix web ci' first"
        skip_gate "web_build"  "web/node_modules absent — run 'npm --prefix web ci' first"
    fi
fi

# --- CLAUDE.md §7: the detector freeze. Verified, never assumed. ---
echo ""
echo "=== GATE: detector_freeze ==="
ACTUAL_SHA="$(shasum -a 256 anomaly_detector.py | awk '{print $1}')"
{
    echo "expected $FROZEN_SHA"
    echo "actual   $ACTUAL_SHA"
} | tee "$LOGDIR/detector_freeze.log"
if [ "$ACTUAL_SHA" = "$FROZEN_SHA" ]; then
    PASSED+=("detector_freeze")
else
    FAILED+=("detector_freeze (HASH MISMATCH — anomaly_detector.py was modified)")
fi

# --- Summary. Loud, and pointing at the evidence. ---
echo ""
echo "================ GATE SUMMARY ($STAMP) ================"
for g in "${PASSED[@]:-}";  do [ -n "$g" ] && echo "  PASS  $g"; done
for g in "${SKIPPED[@]:-}"; do [ -n "$g" ] && echo "  SKIP  $g"; done
for g in "${FAILED[@]:-}";  do [ -n "$g" ] && echo "  FAIL  $g"; done
echo "  evidence: $LOGDIR"
echo ""
echo "  DELIBERATELY OUT of this gate (rule 5 — named, never silently unlisted):"
echo "    tests/eval/validate_real.py (full mode) — scores the detector against an"
echo "      OPERATOR-SUPPLIED real log plus a hand-labelled ground-truth file, and"
echo "      asserts nothing; it reports metrics. Its --selftest, which does assert,"
echo "      IS in the gate above."
echo "    web/src/test (vitest) and the web build — in the gate behind --web, since"
echo "      they need web/node_modules; absent, they SKIP loudly (never a pass)."
echo "======================================================="

if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "GATE RED — ${#FAILED[@]} failing. Output above is preserved in $LOGDIR."
    exit 1
fi
echo "GATE GREEN."
exit 0
