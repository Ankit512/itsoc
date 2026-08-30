#!/usr/bin/env python3
"""Measure detector efficacy against the synthetic ground truth.

Pipeline: generate a labelled log with :mod:`tools.attack_generator`, ingest it
through the **real** analyzer as a subprocess (``log_analyzer.py --rules-only``),
then diff the findings against the manifest and report precision/recall/F1 per
scenario and per rule together with the verbatim list of missed malicious lines.

Isolation rules this module obeys:

* it never imports ``anomaly_detector``, ``log_analyzer``, ``rules_syslog`` or
  anything under ``tests/eval`` — the analyzer is driven by subprocess, which is
  the only seam between this measurement code and the frozen detector;
* it refuses to write anywhere under ``tests/eval/``;
* misses are reported verbatim.  A malicious line the detector did not flag is
  always listed, whatever it looks like.  Nothing is reconciled away.

Every number is scoped: it is measured against synthetic ground-truth scenarios;
it is not a claim about production traffic.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import attack_generator as generator  # noqa: E402  (path guard first)

ANALYZER = REPO_ROOT / "log_analyzer.py"
EVAL_DIR = REPO_ROOT / "tests" / "eval"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "tools" / "efficacy_data"

SCOPE_SENTENCE = (
    "measured against synthetic ground-truth scenarios; "
    "not a claim about production traffic."
)
# Travels with the artefact beside SCOPE_SENTENCE. Does not replace it, and is
# not a JSON `scope` field — that contract stays the original sentence.
CEILING_SENTENCE = (
    "These scenarios are drawn from the same attack classes the rules were "
    "written for — the expected result is perfection, and its value is "
    "regression proof (any future score below 1.0 is a detected regression), "
    "not a general-efficacy claim."
)

_LINE_RANGE = re.compile(r"lines?\s*:?\s*(\d+)\s*(?:-|–|—|to)\s*(\d+)", re.IGNORECASE)
_LINE_LIST = re.compile(r"lines?\s*:?\s*(\d+(?:\s*,\s*\d+)*)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# citation extraction
# --------------------------------------------------------------------------- #

def cited_line_numbers(finding: dict[str, Any]) -> set[int]:
    """Line numbers a finding cites explicitly.

    Two sources, both explicit citations made by the detector itself:
    ``timeline[].line`` entries, and line references written into the
    ``evidence``/``summary`` prose (``lines 2-6``, ``line 7``, ``lines 2, 4``).
    Nothing is inferred beyond what the finding actually states.
    """
    lines: set[int] = set()
    for step in finding.get("timeline") or []:
        if isinstance(step, dict) and isinstance(step.get("line"), int):
            lines.add(step["line"])
    prose = " ".join(
        str(finding.get(key) or "") for key in ("evidence", "summary")
    )
    for start, end in _LINE_RANGE.findall(prose):
        low, high = int(start), int(end)
        if low <= high:
            lines.update(range(low, high + 1))
    for group in _LINE_LIST.findall(prose):
        for number in re.findall(r"\d+", group):
            lines.add(int(number))
    return lines


def cites_raw(finding: dict[str, Any], raw: str) -> bool:
    """True when the finding quotes the source line verbatim."""
    needle = raw.strip()
    if not needle:
        return False
    haystack = " ".join(
        str(finding.get(key) or "") for key in ("evidence", "summary")
    )
    return needle in haystack


def finding_hits(finding: dict[str, Any], malicious: Sequence[dict[str, Any]]) -> set[int]:
    """Manifest line numbers this single finding accounts for."""
    numbers = cited_line_numbers(finding)
    hits: set[int] = set()
    for entry in malicious:
        line = entry["line"]
        if line in numbers or cites_raw(finding, entry["raw"]):
            hits.add(line)
    return hits


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #

def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def score(
    true_positives: int,
    false_positives: int,
    lines_detected: int,
    malicious_total: int,
) -> dict[str, float | int]:
    """Precision over findings, recall over malicious lines, F1 of the two.

    Precision answers "how many findings pointed at real ground truth"; recall
    answers "how much of the ground truth was reached".
    """
    precision = _ratio(true_positives, true_positives + false_positives)
    recall = _ratio(lines_detected, malicious_total)
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0
    )
    return {
        "true_positive_findings": true_positives,
        "false_positive_findings": false_positives,
        "malicious_lines": malicious_total,
        "malicious_lines_detected": lines_detected,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# --------------------------------------------------------------------------- #
# pipeline
# --------------------------------------------------------------------------- #

def assert_isolated(path: Path) -> Path:
    """Refuse any harness output under the evaluation corpus."""
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(EVAL_DIR.resolve())
    except ValueError:
        return resolved
    raise ValueError(f"refusing harness output inside evaluation corpus: {resolved}")


def run_analyzer(log_path: Path, output_prefix: Path) -> dict[str, Any]:
    """Ingest one log through the real pipeline, as a subprocess."""
    completed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER),
            "--input",
            str(log_path),
            "--output",
            str(output_prefix),
            "--rules-only",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    report = output_prefix.with_suffix(".json")
    if completed.returncode != 0 or not report.exists():
        raise RuntimeError(
            f"analyzer failed for {log_path.name} (exit {completed.returncode})\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    return json.loads(report.read_text(encoding="utf-8"))


def diff(manifest: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Diff a report's findings against one manifest's ground truth."""
    malicious = list(manifest.get("malicious_lines") or [])
    findings = list(report.get("findings") or [])

    hit_lines: set[int] = set()
    per_rule: dict[str, dict[str, Any]] = {}
    false_positives: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = str(finding.get("rule_id") or finding.get("category") or "unattributed")
        bucket = per_rule.setdefault(
            rule_id, {"hit_lines": set(), "true_positive_findings": 0, "false_positive_findings": 0}
        )
        hits = finding_hits(finding, malicious)
        if hits:
            hit_lines |= hits
            bucket["hit_lines"] |= hits
            bucket["true_positive_findings"] += 1
        else:
            bucket["false_positive_findings"] += 1
            false_positives.append(
                {
                    "rule_id": rule_id,
                    "severity": finding.get("severity"),
                    "summary": finding.get("summary"),
                    "evidence": finding.get("evidence"),
                }
            )

    # A miss is reported verbatim, exactly as the manifest labelled it.
    misses = [
        {"line": entry["line"], "raw": entry["raw"], "why": entry["why"]}
        for entry in malicious
        if entry["line"] not in hit_lines
    ]

    rules = {}
    for rule_id, bucket in sorted(per_rule.items()):
        rules[rule_id] = {
            "lines_covered": sorted(bucket["hit_lines"]),
            **score(
                bucket["true_positive_findings"],
                bucket["false_positive_findings"],
                len(bucket["hit_lines"]),
                len(malicious),
            ),
        }

    totals = score(
        sum(bucket["true_positive_findings"] for bucket in per_rule.values()),
        len(false_positives),
        len(hit_lines),
        len(malicious),
    )
    totals["missed_lines"] = len(misses)
    totals["findings"] = len(findings)

    return {
        "scenario": manifest.get("scenario"),
        "format": manifest.get("format"),
        "line_count": manifest.get("line_count"),
        "totals": totals,
        "per_rule": rules,
        "misses": misses,
        "false_positives": false_positives,
        "scope": SCOPE_SENTENCE,
    }


def evaluate(
    scenarios: Iterable[str],
    formats: Iterable[str],
    workdir: Path,
) -> dict[str, Any]:
    """Generate, ingest and diff every requested scenario/format pair."""
    target = assert_isolated(workdir)
    target.mkdir(parents=True, exist_ok=True)
    run_date = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    results = []
    for scenario in scenarios:
        for format_name in formats:
            log_path, manifest_path = generator.generate(scenario, format_name, target)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            report = run_analyzer(log_path, target / f"{log_path.stem}-report")
            entry = diff(manifest, report)
            entry["run_date"] = run_date
            entry["log"] = log_path.name
            results.append(entry)

    return {
        "run_date": run_date,
        "scope": SCOPE_SENTENCE,
        "pipeline": "log_analyzer.py --rules-only (subprocess)",
        "scenarios": results,
        "total_misses": sum(len(entry["misses"]) for entry in results),
        "total_false_positives": sum(len(entry["false_positives"]) for entry in results),
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render(summary: dict[str, Any]) -> str:
    lines = [
        f"Efficacy harness — run {summary['run_date']}",
        f"Scope: {summary['scope']}",
        CEILING_SENTENCE,
        f"Pipeline: {summary['pipeline']}",
        "",
    ]
    for entry in summary["scenarios"]:
        totals = entry["totals"]
        lines.append(
            f"[{entry['scenario']} / {entry['format']}] "
            f"precision={totals['precision']} recall={totals['recall']} f1={totals['f1']} "
            f"({totals['malicious_lines_detected']}/{totals['malicious_lines']} malicious lines, "
            f"{totals['false_positive_findings']} false positive finding(s))"
        )
        for rule_id, rule in entry["per_rule"].items():
            lines.append(
                f"    rule {rule_id}: precision={rule['precision']} "
                f"recall={rule['recall']} f1={rule['f1']}"
            )
        if entry["misses"]:
            lines.append(f"    MISSED {len(entry['misses'])} malicious line(s):")
            for miss in entry["misses"]:
                lines.append(f"      line {miss['line']}: {miss['raw']}")
                lines.append(f"        why: {miss['why']}")
        else:
            lines.append("    no missed malicious lines")
        for false_positive in entry["false_positives"]:
            lines.append(
                f"    FALSE POSITIVE [{false_positive['rule_id']}] {false_positive['summary']}"
            )
        lines.append("")
    lines.append(
        f"Totals: {summary['total_misses']} missed malicious line(s), "
        f"{summary['total_false_positives']} false positive finding(s)."
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", choices=generator.SCENARIOS, action="append", dest="scenarios",
        help="scenario to measure (repeatable; default: all)",
    )
    parser.add_argument(
        "--format", choices=generator.FORMATTERS, action="append", dest="formats",
        help="log format to generate (repeatable; default: canonical)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None,
        help=f"where to write generated logs and reports (default: a temp dir; {DEFAULT_OUTPUT_DIR} is gitignored)",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write the full result as JSON")
    args = parser.parse_args(argv)

    scenarios = args.scenarios or list(generator.SCENARIOS)
    formats = args.formats or ["canonical"]

    try:
        if args.output_dir is None:
            with tempfile.TemporaryDirectory(prefix="efficacy-harness-") as tmp:
                summary = evaluate(scenarios, formats, Path(tmp))
        else:
            summary = evaluate(scenarios, formats, args.output_dir)
    except ValueError as exc:
        parser.error(str(exc))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(render(summary))
    if args.json is not None:
        destination = assert_isolated(args.json)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nJSON: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
