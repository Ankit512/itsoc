"""Promotion-bar tests for the efficacy harness.

Deliberately NOT under ``tests/eval/`` — the harness measures the evaluation
corpus's subject, it is not part of the corpus.
"""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path

from tools import efficacy_harness as harness

REPO_ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_IMPORTS = ("anomaly_detector", "log_analyzer", "rules_syslog")


def _resolve_first_party(module: str) -> Path | None:
    """Repo-local file backing a dotted module name, or None if not first-party."""
    parts = module.split(".")
    candidate = REPO_ROOT.joinpath(*parts).with_suffix(".py")
    if candidate.is_file():
        return candidate
    package = REPO_ROOT.joinpath(*parts, "__init__.py")
    if package.is_file():
        return package
    return None


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import — resolve against the file's package
                base = ".".join(path.relative_to(REPO_ROOT).parts[:-1])
                node_module = f"{base}.{node.module}" if node.module else base
            else:
                node_module = node.module or ""
            if node_module:
                names.add(node_module)
                names.update(f"{node_module}.{alias.name}" for alias in node.names)
    return names


def walk_import_graph(entry: Path) -> set[str]:
    """Every module name reachable from ``entry``, recursing through repo-local files."""
    seen_files = {entry}
    pending = [entry]
    modules: set[str] = set()
    while pending:
        current = pending.pop()
        for module in _imported_modules(current):
            modules.add(module)
            resolved = _resolve_first_party(module)
            if resolved is not None and resolved not in seen_files:
                seen_files.add(resolved)
                pending.append(resolved)
    return modules


class ImportGraphTests(unittest.TestCase):
    """The subprocess is the seam. Nothing in the harness's import graph may
    reach the frozen detector or the evaluation corpus."""

    def test_import_graph_never_reaches_the_detector_or_the_eval_corpus(self) -> None:
        modules = walk_import_graph(REPO_ROOT / "tools" / "efficacy_harness.py")
        self.assertIn("tools.attack_generator", modules)  # the graph really was walked
        for module in modules:
            head = module.split(".")[0]
            self.assertNotIn(
                head, FORBIDDEN_IMPORTS,
                f"{module} is imported; the analyzer must only be reached by subprocess",
            )
            self.assertFalse(
                module.startswith("tests.eval") or module == "tests",
                f"{module} is imported; the harness must not touch the evaluation corpus",
            )

    def test_walker_would_catch_a_forbidden_import(self) -> None:
        """Mutation guard: the walker is not vacuously passing."""
        with tempfile.TemporaryDirectory(prefix="efficacy-probe-") as tmp:
            probe = Path(tmp) / "probe.py"
            probe.write_text("import anomaly_detector\nfrom tests.eval import run_eval\n", encoding="utf-8")
            modules = walk_import_graph(probe)
        self.assertIn("anomaly_detector", modules)
        self.assertIn("tests.eval", modules)

    def test_harness_source_shells_out_to_the_analyzer(self) -> None:
        source = (REPO_ROOT / "tools" / "efficacy_harness.py").read_text(encoding="utf-8")
        self.assertIn("subprocess.run", source)
        self.assertIn("--rules-only", source)


class AdversarialMissTests(unittest.TestCase):
    """A mislabelled benign line must still be reported as a miss.

    Ground truth is ground truth: the harness measures the detector against the
    manifest, it does not adjudicate the manifest.  If the harness ever filtered
    misses that "look benign", this test fails.
    """

    BENIGN_RAW = "2026-08-30T05:00:20Z INFO server-09 scheduled backup completed successfully"

    def _adversarial_corpus(self, directory: Path) -> tuple[Path, dict]:
        lines = ["2026-08-30T05:00:00Z INFO server-09 sshd service ready"]
        lines += [
            f"2026-08-30T05:00:{offset + 1:02d}Z WARN server-09 "
            f"Failed password for root from 192.0.2.77 port {51000 + offset} ssh2"
            for offset in range(7)
        ]
        lines.append(self.BENIGN_RAW)
        log_path = directory / "adversarial.log"
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        manifest = {
            "scenario": "adversarial-mislabel",
            "format": "canonical",
            "line_count": len(lines),
            "malicious_count": 8,
            "malicious_lines": (
                [
                    {"line": number, "raw": lines[number - 1], "why": "genuine credential-guessing failure"}
                    for number in range(2, 9)
                ]
                + [{
                    "line": 9,
                    "raw": self.BENIGN_RAW,
                    "why": "deliberately mislabelled benign line — the detector cannot flag it",
                }]
            ),
        }
        return log_path, manifest

    def test_mislabelled_benign_line_is_reported_verbatim_as_a_miss(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-adversarial-") as tmp:
            directory = Path(tmp)
            log_path, manifest = self._adversarial_corpus(directory)
            report = harness.run_analyzer(log_path, directory / "adversarial-report")
            result = harness.diff(manifest, report)

        missed_lines = [miss["line"] for miss in result["misses"]]
        self.assertIn(9, missed_lines, "the mislabelled benign line was reconciled away")

        miss = next(entry for entry in result["misses"] if entry["line"] == 9)
        self.assertEqual(miss["raw"], self.BENIGN_RAW)
        self.assertEqual(
            miss["why"],
            "deliberately mislabelled benign line — the detector cannot flag it",
        )
        self.assertEqual(result["totals"]["missed_lines"], len(result["misses"]))
        self.assertLess(result["totals"]["recall"], 1.0)
        self.assertEqual(result["totals"]["malicious_lines"], 8)


class DiffTests(unittest.TestCase):
    MANIFEST = {
        "scenario": "unit",
        "format": "canonical",
        "line_count": 3,
        "malicious_count": 2,
        "malicious_lines": [
            {"line": 2, "raw": "line two raw", "why": "first"},
            {"line": 3, "raw": "line three raw", "why": "second"},
        ],
    }

    def test_timeline_line_number_counts_as_a_citation(self) -> None:
        report = {"findings": [{"rule_id": "r1", "timeline": [{"line": 2}], "evidence": "", "summary": ""}]}
        result = harness.diff(self.MANIFEST, report)
        self.assertEqual([miss["line"] for miss in result["misses"]], [3])
        self.assertEqual(result["totals"]["recall"], 0.5)
        self.assertEqual(result["totals"]["precision"], 1.0)

    def test_verbatim_raw_in_evidence_counts_as_a_citation(self) -> None:
        report = {"findings": [{"rule_id": "r1", "evidence": "observed: line three raw", "timeline": []}]}
        result = harness.diff(self.MANIFEST, report)
        self.assertEqual([miss["line"] for miss in result["misses"]], [2])

    def test_line_range_in_evidence_counts_as_a_citation(self) -> None:
        report = {"findings": [{"rule_id": "r1", "evidence": "source lines: 2-3", "timeline": []}]}
        result = harness.diff(self.MANIFEST, report)
        self.assertEqual(result["misses"], [])
        self.assertEqual(result["totals"]["recall"], 1.0)

    def test_finding_matching_no_malicious_line_is_a_false_positive(self) -> None:
        report = {
            "findings": [
                {"rule_id": "r1", "timeline": [{"line": 2}], "evidence": "", "summary": ""},
                {"rule_id": "r2", "timeline": [{"line": 1}], "evidence": "", "summary": "quiet boot"},
            ]
        }
        result = harness.diff(self.MANIFEST, report)
        self.assertEqual(len(result["false_positives"]), 1)
        self.assertEqual(result["false_positives"][0]["rule_id"], "r2")
        self.assertEqual(result["totals"]["precision"], 0.5)
        self.assertEqual(result["per_rule"]["r2"]["false_positive_findings"], 1)

    def test_no_findings_yields_zero_recall_and_every_line_missed(self) -> None:
        result = harness.diff(self.MANIFEST, {"findings": []})
        self.assertEqual([miss["line"] for miss in result["misses"]], [2, 3])
        self.assertEqual(result["totals"]["recall"], 0.0)
        self.assertEqual(result["totals"]["f1"], 0.0)

    def test_every_result_carries_scenario_and_scope(self) -> None:
        result = harness.diff(self.MANIFEST, {"findings": []})
        self.assertEqual(result["scenario"], "unit")
        self.assertEqual(
            result["scope"],
            "measured against synthetic ground-truth scenarios; "
            "not a claim about production traffic.",
        )


class IsolationTests(unittest.TestCase):
    def test_output_inside_the_eval_corpus_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            harness.assert_isolated(REPO_ROOT / "tests" / "eval" / "efficacy")

    def test_output_outside_the_eval_corpus_is_allowed(self) -> None:
        self.assertTrue(harness.assert_isolated(REPO_ROOT / "tools" / "efficacy_data").is_absolute())


class EndToEndTests(unittest.TestCase):
    def test_all_scenarios_run_through_the_real_pipeline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-e2e-") as tmp:
            summary = harness.evaluate(list(harness.generator.SCENARIOS), ["canonical"], Path(tmp))
            self.assertFalse(
                list(Path(REPO_ROOT / "tests" / "eval").glob("*.manifest.json")),
                "harness output leaked into the evaluation corpus",
            )
        self.assertEqual(len(summary["scenarios"]), len(harness.generator.SCENARIOS))
        for entry in summary["scenarios"]:
            self.assertIn(entry["scenario"], harness.generator.SCENARIOS)
            self.assertTrue(entry["run_date"].startswith("20"))
            self.assertIn("not a claim about production traffic", entry["scope"])
            self.assertEqual(entry["totals"]["recall"], 1.0)
        rendered = harness.render(summary)
        self.assertIn("not a claim about production traffic", rendered)
        self.assertIn(harness.CEILING_SENTENCE, rendered)
        self.assertEqual(summary["scope"], harness.SCOPE_SENTENCE)
        json.dumps(summary)  # the artefact must be serialisable


if __name__ == "__main__":
    unittest.main(verbosity=2)
