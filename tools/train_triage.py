#!/usr/bin/env python3
"""train_triage.py — E7a. Train the local second-opinion triage model.

    python3 tools/train_triage.py                 # full local train
    python3 tools/train_triage.py --dry-run       # build the dataset, train nothing
    python3 tools/train_triage.py --seed 7 --variants 8

WHAT THIS IS
------------
A small, local, per-installation classifier that gives an ADVISORY second
opinion on a finding or an incident. It is never wired into a verdict. Its whole
job is to be visible beside the rules and to disagree out loud when it does.

WHERE THE DATA COMES FROM (and where it does NOT)
------------------------------------------------
1. `tools/attack_generator.py` writes deterministic, seeded, ground-truth
   scenarios into an isolated directory (never `tests/eval/`).
2. Each generated log is ingested through the **real** analyzer as a SUBPROCESS
   (`log_analyzer.py --rules-only`). This module never imports
   `anomaly_detector`, `log_analyzer`, `rules_syslog` or `rule_context`; the
   subprocess boundary is the only seam, exactly as the efficacy harness does it.
3. Each resulting finding is labelled from the scenario's declared ground truth
   plus the manifest's line-level citations (`efficacy_harness.finding_hits`) —
   never from what the detector "seems to think".
4. Real closed incidents from the local store (`console/.soc/incidents.json`)
   join the set as labelled rows, using the analyst's own E0 disposition. An
   incident with NO disposition is skipped. No label is ever invented.
5. The local event store (`console/.soc/soc_history.db`) is read ONLY as
   observed context — a row count recorded in the provenance sidecar. Not one
   unlabelled event becomes a training row.

WHAT IT WRITES
--------------
`console/.soc/models/triage_v1.pkl` plus `triage_v1.provenance.json` — the
sidecar carrying the exact seeds, the actual dataset counts, the feature list,
the cross-validation fold scores as measured, and the artifact's sha256. Both
live under `console/.soc/`, which is gitignored.

Features come from the ONE shared `console/triage_model.py:features()`, so the
vector this trains on is bit-for-bit the vector inference scores.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(REPO_ROOT), str(REPO_ROOT / "console")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import org_context  # noqa: E402  (stdlib-only asset criticality config)
import triage_model  # noqa: E402  (the ONE shared feature function)
from tools import attack_generator as generator  # noqa: E402
from tools import efficacy_harness as harness  # noqa: E402

ANALYZER = REPO_ROOT / "log_analyzer.py"
EVAL_DIR = REPO_ROOT / "tests" / "eval"
DEFAULT_SEED = 20260902
DEFAULT_VARIANTS = 14
# Two formats, not four: the record a finding produces is format-independent by
# construction (the parser normalises before the rules run), so the extra two
# would multiply the subprocess count without adding a distinguishable row.
DEFAULT_FORMATS = ("canonical", "rfc3164")

INCIDENT_STORE = REPO_ROOT / "console" / ".soc" / "incidents.json"
EVENT_STORE = REPO_ROOT / "console" / ".soc" / "soc_history.db"


def _assert_isolated(path: Path) -> Path:
    """Refuse any training output under the evaluation corpus."""
    resolved = Path(path).expanduser().resolve()
    try:
        resolved.relative_to(EVAL_DIR.resolve())
    except ValueError:
        return resolved
    raise ValueError(f"refusing training output inside evaluation corpus: {resolved}")


# --------------------------------------------------------------------------
# dataset construction
# --------------------------------------------------------------------------

def run_analyzer(log_path: Path, output_prefix: Path) -> dict:
    """Ingest one log through the REAL pipeline, as a subprocess."""
    completed = subprocess.run(
        [sys.executable, str(ANALYZER), "--input", str(log_path),
         "--output", str(output_prefix), "--rules-only"],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    report = output_prefix.with_suffix(".json")
    if completed.returncode != 0 or not report.exists():
        raise RuntimeError(
            f"analyzer failed for {log_path.name} (exit {completed.returncode})\n"
            f"{completed.stdout}\n{completed.stderr}")
    return json.loads(report.read_text(encoding="utf-8"))


def label_for_finding(finding: dict, manifest: dict) -> str:
    """The ground-truth analyst class for one finding. Declared, never guessed.

    * A scenario whose ground truth has NO malicious lines (near-miss or
      authorised-maintenance) hands every finding its declared class: a
      near-miss finding is a `false-positive`, a maintenance finding is
      `benign-expected`.
    * In a positive scenario, a finding that cites at least one manifest-labelled
      malicious line is `confirmed`; one that cites none is a genuine
      `false-positive` against that same ground truth.
    """
    declared = str(manifest.get("scenario_class") or "confirmed")
    malicious = list(manifest.get("malicious_lines") or [])
    if not malicious:
        return declared
    return "confirmed" if harness.finding_hits(finding, malicious) else "false-positive"


def record_from_report_finding(finding: dict, manifest: dict, org) -> dict:
    """The rule-owned projection a report finding contributes to training.

    Only keys `triage_model.features()` reads are copied across, and each one is
    a fact the rules or the parser produced. No prose, no severity, no
    disposition, no priority.
    """
    host = str(manifest.get("host") or "")
    return {
        "rule_id": finding.get("rule_id") or finding.get("category") or "",
        "source": finding.get("source"),
        "occurrences": finding.get("occurrences", 1),
        "entities": finding.get("entities") or {},
        "timeline": finding.get("timeline") or [],
        "host": host,
        "criticality": org.get_criticality(host),
    }


def record_from_incident(incident: dict, org) -> dict:
    """The same projection for a stored incident (E1 hoisted these facts)."""
    return {
        "ruleIds": incident.get("ruleIds") or [],
        "occurrences": incident.get("findingCount") or 1,
        "findingCount": incident.get("findingCount") or 0,
        "entityValues": incident.get("entityValues") or [],
        "entity": incident.get("entity"),
        "entityKind": incident.get("entityKind"),
        "techniques": incident.get("techniques") or [],
        "firstSeen": incident.get("firstSeen"),
        "lastSeen": incident.get("lastSeen"),
        "criticality": incident.get("criticality")
        or org.get_criticality(incident.get("entity")),
    }


def generated_rows(seed: int, variants: int, formats, scenarios, workdir: Path,
                   org, verbose: bool = True) -> tuple[list, dict]:
    """(rows, stats) from the generator → real analyzer subprocess → labels."""
    rows: list[dict] = []
    seeds_used: list[int] = []
    logs = 0
    findings = 0
    for variant in range(variants):
        variant_seed = seed + variant
        seeds_used.append(variant_seed)
        for scenario in scenarios:
            for format_name in formats:
                log_path, manifest_path = generator.generate(
                    scenario, format_name, workdir, variant_seed)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                report = run_analyzer(log_path, workdir / f"{log_path.stem}-report")
                logs += 1
                for finding in report.get("findings") or []:
                    findings += 1
                    rows.append({
                        "record": record_from_report_finding(finding, manifest, org),
                        "label": label_for_finding(finding, manifest),
                        "origin": "generated",
                        "scenario": scenario,
                        "format": format_name,
                        "seed": variant_seed,
                    })
        if verbose:
            print(f"  seed {variant_seed}: {len(rows)} labelled row(s) so far",
                  flush=True)
    stats = {
        "seedBase": seed,
        "seedsUsed": seeds_used,
        "scenarios": list(scenarios),
        "formats": list(formats),
        "logsIngested": logs,
        "findingsSeen": findings,
        "rows": len(rows),
    }
    return rows, stats


def disposition_rows(org, store_path: Path = INCIDENT_STORE) -> tuple[list, dict]:
    """Labelled rows from REAL closed incidents. Undispositioned = skipped.

    Read straight off the store's JSON so this CLI never imports the console's
    incident derivation (which would pull in the analyzer). The disposition is
    the label and is never a feature — `triage_model.FORBIDDEN_KEYS` names every
    disposition key and the leakage test proves they cannot move the vector.
    """
    stats = {"storePresent": store_path.is_file(), "storedIncidents": 0,
             "dispositioned": 0, "undispositionedSkipped": 0, "rows": 0,
             "byLabel": {}}
    if not store_path.is_file():
        return [], stats
    try:
        store = json.loads(store_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        stats["storeUnreadable"] = True
        return [], stats
    if not isinstance(store, dict):
        return [], stats
    rows = []
    for incident in store.values():
        if not isinstance(incident, dict):
            continue
        stats["storedIncidents"] += 1
        label = str(incident.get("disposition") or "")
        if label not in triage_model.LABELS:
            stats["undispositionedSkipped"] += 1
            continue
        stats["dispositioned"] += 1
        stats["byLabel"][label] = stats["byLabel"].get(label, 0) + 1
        rows.append({
            "record": record_from_incident(incident, org),
            "label": label,
            "origin": "incident-disposition",
            "incidentId": incident.get("id"),
        })
    stats["rows"] = len(rows)
    return rows, stats


def observed_event_store(db_path: Path = EVENT_STORE) -> dict:
    """Observed context ONLY: how many events the local store holds.

    Not one of these rows becomes a training row and not one of them is
    labelled. The count is recorded so the provenance sidecar can state what
    else was on this machine at training time, honestly, including zero.
    """
    context = {"path": str(db_path), "present": db_path.is_file(),
               "events": 0, "usedForTraining": False,
               "note": "read as observed context only; no label is inferred for "
                       "an unlabelled event"}
    if not db_path.is_file():
        return context
    import sqlite3
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            context["events"] = int(
                connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        finally:
            connection.close()
    except sqlite3.Error as exc:
        context["error"] = str(exc)
    return context


# --------------------------------------------------------------------------
# training
# --------------------------------------------------------------------------

def _label_counts(rows) -> dict:
    counts = {}
    for row in rows:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    return dict(sorted(counts.items()))


def train(rows, seed: int, folds: int):
    """Fit the classifier and report cross-validation honestly.

    Stratified k-fold, balanced sample weights on every fit (the classes are not
    balanced and pretending otherwise would flatter the majority class), and the
    per-fold scores reported as measured — including a fold that scored badly.
    """
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import f1_score
    from sklearn.utils.class_weight import compute_sample_weight

    X = [triage_model.feature_vector(row["record"]) for row in rows]
    y = [row["label"] for row in rows]
    counts = _label_counts(rows)
    smallest = min(counts.values())
    usable_folds = max(2, min(folds, smallest))
    cv_note = ""
    if usable_folds != folds:
        cv_note = (f"requested {folds} folds; the smallest class has {smallest} "
                   f"row(s), so {usable_folds} stratified folds were used.")

    splitter = StratifiedKFold(n_splits=usable_folds, shuffle=True,
                               random_state=seed)
    fold_scores = []
    for index, (train_idx, test_idx) in enumerate(splitter.split(X, y), 1):
        X_train = [X[i] for i in train_idx]
        y_train = [y[i] for i in train_idx]
        X_test = [X[i] for i in test_idx]
        y_test = [y[i] for i in test_idx]
        weights = compute_sample_weight("balanced", y_train)
        model = GradientBoostingClassifier(random_state=seed)
        model.fit(X_train, y_train, sample_weight=weights)
        predicted = model.predict(X_test)
        fold_scores.append({
            "fold": index,
            "rows": len(y_test),
            "accuracy": round(float(sum(int(a == b) for a, b in
                                        zip(predicted, y_test)) / len(y_test)), 4),
            "macroF1": round(float(f1_score(y_test, predicted, average="macro",
                                            zero_division=0)), 4),
            "balancedMacroF1": round(float(f1_score(
                y_test, predicted, average="macro", zero_division=0,
                sample_weight=compute_sample_weight("balanced", y_test))), 4),
        })

    final = GradientBoostingClassifier(random_state=seed)
    final.fit(X, y, sample_weight=compute_sample_weight("balanced", y))

    macro = [s["macroF1"] for s in fold_scores]
    accuracy = [s["accuracy"] for s in fold_scores]
    cv = {
        "strategy": "StratifiedKFold(shuffle=True)",
        "folds": usable_folds,
        "requestedFolds": folds,
        "note": cv_note,
        "classWeighting": "sklearn compute_sample_weight('balanced') on every "
                          "fit, training folds and final model alike",
        "perFold": fold_scores,
        "macroF1Mean": round(statistics.fmean(macro), 4),
        "macroF1Min": round(min(macro), 4),
        "macroF1Max": round(max(macro), 4),
        "accuracyMean": round(statistics.fmean(accuracy), 4),
    }
    return final, cv


def save(model, provenance, model_dir: Path):
    import pickle
    model_dir.mkdir(parents=True, exist_ok=True)
    path = model_dir / triage_model.MODEL_NAME
    with open(path, "wb") as handle:
        pickle.dump(model, handle, protocol=pickle.HIGHEST_PROTOCOL)
    provenance["modelSha256"] = triage_model.sha256_file(path)
    prov_path = model_dir / triage_model.PROVENANCE_NAME
    prov_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    return path, prov_path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_dataset(seed, variants, formats, scenarios, workdir, verbose=True):
    org = org_context.load_org_context()
    rows, gen_stats = generated_rows(seed, variants, formats, scenarios,
                                     workdir, org, verbose=verbose)
    real_rows, disp_stats = disposition_rows(org)
    rows.extend(real_rows)
    dataset = {
        "generated": gen_stats,
        "incidentDispositions": disp_stats,
        "observedEventStore": observed_event_store(),
        "totalRows": len(rows),
        "byLabel": _label_counts(rows),
        "byOrigin": {origin: sum(1 for r in rows if r["origin"] == origin)
                     for origin in sorted({r["origin"] for r in rows})},
    }
    return rows, dataset


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help=f"base training seed (default {DEFAULT_SEED})")
    parser.add_argument("--variants", type=int, default=DEFAULT_VARIANTS,
                        help="seeded variants per scenario/format")
    parser.add_argument("--folds", type=int, default=5,
                        help="stratified cross-validation folds")
    parser.add_argument("--format", action="append", dest="formats",
                        choices=sorted(generator.FORMATTERS))
    parser.add_argument("--scenario", action="append", dest="scenarios",
                        choices=sorted(generator.SCENARIOS))
    parser.add_argument("--model-dir", type=Path, default=triage_model.MODEL_DIR)
    parser.add_argument("--work-dir", type=Path, default=None,
                        help="where generated logs/reports go (default: a temp dir)")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and report the dataset; train and write nothing")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    formats = tuple(args.formats or DEFAULT_FORMATS)
    scenarios = tuple(args.scenarios or generator.SCENARIOS)
    verbose = not args.quiet
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    if verbose:
        print(f"Building dataset — seed {args.seed}, {args.variants} variant(s), "
              f"{len(scenarios)} scenario(s), {len(formats)} format(s).")
        print("Ingestion: log_analyzer.py --rules-only (subprocess). The frozen "
              "detector is never imported here.")

    temp = None
    try:
        if args.work_dir:
            workdir = _assert_isolated(args.work_dir)
            workdir.mkdir(parents=True, exist_ok=True)
        else:
            temp = tempfile.TemporaryDirectory(prefix="train-triage-")
            workdir = Path(temp.name)
        rows, dataset = build_dataset(args.seed, args.variants, formats,
                                      scenarios, workdir, verbose=verbose)
    finally:
        if temp is not None:
            temp.cleanup()

    if verbose:
        print("\nDataset:")
        print(json.dumps(dataset, indent=2, sort_keys=True))

    if not rows:
        print("\nNo labelled rows were produced — nothing is trained and no "
              "model is written. This is an honest empty, not a failure to hide.")
        return 1
    counts = dataset["byLabel"]
    if len(counts) < 2:
        print(f"\nOnly one class present ({counts}) — a classifier trained on "
              "it would be a constant, so nothing is trained or written.")
        return 1

    if args.dry_run:
        print("\n--dry-run: dataset built, nothing trained, nothing written.")
        return 0

    if triage_model.sklearn_version() is None:
        print("\nscikit-learn is not installed. It is an OPTIONAL dependency:\n"
              "    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n"
              "Nothing was written. The console keeps working and renders the "
              "honest 'model unavailable' advisory state.")
        return 2

    if verbose:
        print(f"\nTraining GradientBoostingClassifier (random_state={args.seed}) "
              f"on {len(rows)} row(s) …")
    model, cv = train(rows, args.seed, args.folds)
    duration = round(time.monotonic() - started, 2)

    provenance = {
        "card": "E7a",
        "model": "sklearn.ensemble.GradientBoostingClassifier",
        "modelFile": triage_model.MODEL_NAME,
        "trainedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "startedAt": started_at,
        "trainDurationSeconds": duration,
        "seed": args.seed,
        "seedsUsed": dataset["generated"]["seedsUsed"],
        "variants": args.variants,
        "featureKeys": list(triage_model.FEATURE_KEYS),
        "featureCount": len(triage_model.FEATURE_KEYS),
        "labels": list(triage_model.LABELS),
        "labelSource": {
            "generated": "tools/attack_generator.py manifest ground truth "
                         "(scenario_class + malicious_lines line citations)",
            "incident-disposition": "analyst E0 disposition on a stored incident; "
                                    "undispositioned incidents are skipped",
        },
        "datasetRows": dataset["totalRows"],
        "dataset": dataset,
        "crossValidation": cv,
        "pipeline": "attack_generator -> log_analyzer.py --rules-only "
                    "(subprocess) -> triage_model.features()",
        "sklearnVersion": triage_model.sklearn_version(),
        "python": sys.version.split()[0],
        "wall": "ADVISORY ONLY. This model never writes sev, ruleSev, incident "
                "severity, priority, runbook eligibility or any execution state.",
        "scope": "trained on synthetic ground-truth scenarios plus whatever real "
                 "dispositions this installation has recorded; not a claim about "
                 "production traffic.",
    }
    path, prov_path = save(model, provenance, Path(args.model_dir))
    triage_model.reset_cache()

    print(f"\nTrained in {duration}s.")
    print(f"  model      {path}")
    print(f"  provenance {prov_path}")
    print(f"  rows       {dataset['totalRows']}  {dataset['byLabel']}")
    print(f"  CV         {cv['folds']} stratified fold(s), macro-F1 "
          f"mean={cv['macroF1Mean']} min={cv['macroF1Min']} max={cv['macroF1Max']}")
    for fold in cv["perFold"]:
        print(f"    fold {fold['fold']}: rows={fold['rows']} "
              f"accuracy={fold['accuracy']} macroF1={fold['macroF1']} "
              f"balancedMacroF1={fold['balancedMacroF1']}")
    if cv["note"]:
        print(f"    note: {cv['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
