#!/usr/bin/env bash
set -Eeuo pipefail

# Scheduled, read-only-until-accepted retraining.  The candidate is always
# trained and benchmarked in a private directory; the installed directory is
# replaced only after the referee scorecard passes every guard below.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYTHON=${PYTHON:-python3}
MODEL_DIR=${MODEL_DIR:-"$ROOT/console/.soc/models"}
RUN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/retrain.XXXXXX")
STAGING="$RUN_ROOT/candidate"
CANDIDATE_JSON="$RUN_ROOT/candidate.json"
INSTALLED_JSON="$RUN_ROOT/installed.json"
mkdir -p "$STAGING"
trap 'rm -rf "$RUN_ROOT"' EXIT

echo "RETRAIN RUN: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Commit: $($PYTHON -c 'import subprocess; print(subprocess.check_output(["git","rev-parse","HEAD"], text=True).strip())' 2>/dev/null || echo unavailable)"

# This check is deliberately before training and before any benchmark number.
"$PYTHON" - "$ROOT" "$STAGING" "$MODEL_DIR" <<'PY'
import json, sys
from pathlib import Path
root, staging, installed = map(Path, sys.argv[1:])
sys.path.insert(0, str(root))
from tools import efficacy_harness as referee

expected = ("INC-4a7f", "failure-success", "error-burst", "near-miss-auth",
            "near-miss-errors", "benign-maintenance")
if tuple(referee.BENCHMARK_SCENARIOS) != expected:
    raise SystemExit("BENCHMARK REFUSED: frozen scenario tuple is not intact")
if not (installed / "triage_v1.pkl").is_file() or not (installed / "triage_v1.provenance.json").is_file():
    raise SystemExit(f"MODEL UNAVAILABLE: installed model artifact or provenance is missing in {installed}")
print("Preconditions: frozen scenario tuple intact; scenarioSetIsFrozen required")
PY

echo "Training candidate in staging: $STAGING"
"$PYTHON" "$ROOT/tools/train_triage.py" --model-dir "$STAGING"

# Read the sidecar and prove seed disjointness before invoking the referee.
"$PYTHON" - "$ROOT" "$STAGING" "$MODEL_DIR" <<'PY'
import json, sys
from pathlib import Path
root, staging, installed = map(Path, sys.argv[1:])
sys.path.insert(0, str(root))
from tools import efficacy_harness as referee

def seeds(directory):
    path = directory / "triage_v1.provenance.json"
    if not path.is_file():
        raise SystemExit(f"MODEL UNAVAILABLE: provenance sidecar missing: {path}")
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        raise SystemExit(f"MODEL UNAVAILABLE: unreadable provenance sidecar: {exc}")
    generated = (data.get("dataset") or {}).get("generated") or {}
    values = generated.get("seedsUsed") or data.get("seedsUsed") or []
    if not values:
        raise SystemExit("BENCHMARK REFUSED: candidate sidecar records no training seeds")
    return {int(value) for value in values}

candidate = seeds(staging)
overlap = sorted(candidate & set(referee.BENCHMARK_SEEDS))
if overlap:
    raise SystemExit(f"BENCHMARK REFUSED: benchmark seeds {overlap} overlap candidate training seeds {sorted(candidate)}")
if not (installed / "triage_v1.pkl").is_file() or not (installed / "triage_v1.provenance.json").is_file():
    raise SystemExit(f"MODEL UNAVAILABLE: installed model artifact or provenance is missing in {installed}")
print(f"Preconditions: candidate training seeds {sorted(candidate)} are disjoint from benchmark seeds {list(referee.BENCHMARK_SEEDS)}")
PY

run_benchmark() {
  local dir=$1 out=$2 log=$3
  set +e
  "$PYTHON" "$ROOT/tools/efficacy_harness.py" --model-dir "$dir" --json "$out" >"$log" 2>&1
  local status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    echo "BENCHMARK ABORTED (exit $status):"
    sed -n '1,240p' "$log"
    return "$status"
  fi
  "$PYTHON" - "$out" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
bench = data.get("benchmark") or {}
if bench.get("scenarioSetIsFrozen") is not True:
    raise SystemExit("BENCHMARK REFUSED: scenarioSetIsFrozen is not true")
if (data.get("freshness") or {}).get("asserted") is not True:
    raise SystemExit("BENCHMARK REFUSED: benchmark freshness was not asserted")
if (data.get("model") or {}).get("available") is not True:
    raise SystemExit("MODEL UNAVAILABLE: benchmark did not load a real model")
PY
}

run_benchmark "$STAGING" "$CANDIDATE_JSON" "$RUN_ROOT/candidate.out"
run_benchmark "$MODEL_DIR" "$INSTALLED_JSON" "$RUN_ROOT/installed.out"

# Compare only measured values.  Missing per-rule values are zero (a dropped
# rule class), and any worse value is a refusal, even when aggregate recall is
# unchanged.
set +e
"$PYTHON" - "$CANDIDATE_JSON" "$INSTALLED_JSON" <<'PY'
import json, sys
from pathlib import Path
c, i = [json.loads(Path(p).read_text()) for p in sys.argv[1:]]
for label, data in (("CANDIDATE", c), ("INSTALLED", i)):
    print(f"{label}: run_id={data.get('run_id')} commit={(data.get('provenance') or {}).get('commit')} model_sha={(data.get('model') or {}).get('sha256')}")
def learned(s): return s.get("learned") or {}
def scorecard(s):
    fr = s.get("finding_level_recall") or {}
    by = fr.get("by_rule") or {}
    rules = {k: ((v.get("learned") or {}).get("recall") or 0.0) for k,v in by.items()}
    fp = (s.get("false_positive_totals") or {}).get("learned")
    fmt = {k: (v.get("learned") or 0) for k,v in (s.get("false_positive_totals") or {}).get("by_format", {}).items()}
    return {"finding_recall": (fr.get("learned") or {}).get("recall") or 0.0,
            "finding_recall_by_rule": rules, "false_positives": fp or 0,
            "false_positives_by_format": fmt,
            "dropped_true_findings": s.get("learned_total_dropped_true_findings") or 0,
            "line_misses": s.get("learned_total_misses") or 0}
cs, ins = scorecard(c), scorecard(i)
print("CANDIDATE SCORECARD")
print(json.dumps(cs, indent=2, sort_keys=True))
print("INSTALLED SCORECARD")
print(json.dumps(ins, indent=2, sort_keys=True))
fail = []
for key in ("finding_recall",):
    if cs[key] < ins[key]: fail.append(f"{key}: {cs[key]} < {ins[key]}")
for rule in sorted(set(cs["finding_recall_by_rule"]) | set(ins["finding_recall_by_rule"])):
    if cs["finding_recall_by_rule"].get(rule, 0.0) < ins["finding_recall_by_rule"].get(rule, 0.0):
        fail.append(f"finding_recall_by_rule[{rule}]: {cs['finding_recall_by_rule'].get(rule, 0.0)} < {ins['finding_recall_by_rule'].get(rule, 0.0)}")
if cs["false_positives"] > ins["false_positives"]: fail.append("false_positives increased")
for fmt in sorted(set(cs["false_positives_by_format"]) | set(ins["false_positives_by_format"])):
    if cs["false_positives_by_format"].get(fmt, 0) > ins["false_positives_by_format"].get(fmt, 0): fail.append(f"false_positives_by_format[{fmt}] increased")
if cs["dropped_true_findings"] > ins["dropped_true_findings"]: fail.append("dropped_true_findings increased")
if cs["line_misses"] > ins["line_misses"]: fail.append("line-level misses increased")
if fail:
    print("REFUSED REGRESSED CANDIDATE:")
    print("; ".join(fail))
    raise SystemExit(3)
print("CANDIDATE ACCEPTED: no measured regression")
PY
compare_status=$?
set -e
if [[ $compare_status -ne 0 ]]; then
  echo "Installed model left untouched: $MODEL_DIR"
  exit "$compare_status"
fi

# Commit only after all checks. Directory replacement prevents a partially
# written candidate from being observed as the installed model.
"$PYTHON" - "$STAGING" "$MODEL_DIR" <<'PY'
import os, shutil, sys
from pathlib import Path
staging, target = map(Path, sys.argv[1:])
parent = target.parent
replacement = parent / (target.name + ".accepted")
backup = parent / (target.name + ".previous")
if replacement.exists(): shutil.rmtree(replacement)
shutil.copytree(staging, replacement)
if backup.exists(): shutil.rmtree(backup)
os.replace(target, backup)
try:
    os.replace(replacement, target)
except Exception:
    os.replace(backup, target)
    raise
print(f"Installed candidate atomically at {target}")
PY
exit 0
