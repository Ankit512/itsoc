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
# Usage:
#   scripts/gate.sh            # python gates + detector freeze
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

run_gate "run_eval"       python3 tests/eval/run_eval.py            || true
run_gate "test_console"   python3 console/test_console.py           || true
run_gate "threat_intel"   python3 threat_intel/test_threat_intel.py || true

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
echo "======================================================="

if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "GATE RED — ${#FAILED[@]} failing. Output above is preserved in $LOGDIR."
    exit 1
fi
echo "GATE GREEN."
exit 0
