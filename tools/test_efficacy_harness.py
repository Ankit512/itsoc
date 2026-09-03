"""Promotion-bar tests for the efficacy harness.

Deliberately NOT under ``tests/eval/`` — the harness measures the evaluation
corpus's subject, it is not part of the corpus.
"""

from __future__ import annotations

import ast
import copy
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
        seeds = [harness.BENCHMARK_SEEDS[0]]
        with tempfile.TemporaryDirectory(prefix="efficacy-e2e-") as tmp:
            summary = harness.evaluate(
                list(harness.generator.SCENARIOS), ["canonical"], Path(tmp),
                seeds=seeds, model_dir=Path(tmp) / "no-model-here")
            self.assertFalse(
                list(Path(REPO_ROOT / "tests" / "eval").glob("*.manifest.json")),
                "harness output leaked into the evaluation corpus",
            )
        self.assertEqual(len(summary["scenarios"]), len(harness.generator.SCENARIOS))
        for entry in summary["scenarios"]:
            self.assertIn(entry["scenario"], harness.generator.SCENARIOS)
            self.assertTrue(entry["run_date"].startswith("20"))
            self.assertIn("not a claim about production traffic", entry["scope"])
            # Recall is only DEFINED where the scenario has malicious lines.
            # The three positive scenarios must still be a clean sweep; the
            # near-miss / benign-expected scenarios have no recall at all and
            # must say so rather than publish a 0.0 that reads as a failure.
            if entry["totals"]["recall_defined"]:
                self.assertEqual(entry["totals"]["recall"], 1.0, entry["scenario"])
            else:
                self.assertEqual(entry["totals"]["malicious_lines"], 0)
        rendered = harness.render(summary)
        self.assertIn("not a claim about production traffic", rendered)
        self.assertIn(harness.CEILING_SENTENCE, rendered)
        self.assertIn(harness.ADVISORY_SENTENCE, rendered)
        self.assertEqual(summary["scope"], harness.SCOPE_SENTENCE)
        self.assertEqual(summary["advisory"], harness.ADVISORY_SENTENCE)
        json.dumps(summary)  # the artefact must be serialisable


# ---------------------------------------------------------------------------
# E8 — the frozen referee
# ---------------------------------------------------------------------------

class _StubEstimator:
    """An estimator that always predicts one label, with full confidence.

    Injected so the paired-system machinery can be exercised without depending
    on what a particular trained artifact happens to think — and so the
    "the two systems CAN differ" tests are provably non-vacuous.
    """

    classes_ = ("benign-expected", "confirmed", "false-positive")

    def __init__(self, label: str) -> None:
        self.label = label

    def predict_proba(self, vectors):
        index = self.classes_.index(self.label)
        row = [0.0] * len(self.classes_)
        row[index] = 1.0
        return [list(row) for _ in vectors]


def _stub_model(label: str) -> harness.LearnedSystem:
    return harness.LearnedSystem(_StubEstimator(label), {"trainedAt": "stub"})


def _fake_provenance(seeds, scenarios=("INC-4a7f",), formats=("canonical",)) -> dict:
    return {"dataset": {"generated": {"seedsUsed": list(seeds),
                                      "scenarios": list(scenarios),
                                      "formats": list(formats)}}}


def _ingest(scenarios, seeds, directory: Path):
    """Generate → remap → real analyzer, exactly as `evaluate` does it."""
    pairs = []
    for seed in seeds:
        for scenario in scenarios:
            log_path, manifest_path = harness.generator.generate(
                scenario, "canonical", directory, seed)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            text, manifest, _map = harness.remap_scenario(log_path, manifest, set())
            bench = directory / f"{log_path.stem}-bench.log"
            bench.write_text(text, encoding="utf-8")
            pairs.append((manifest,
                          harness.run_analyzer(bench, directory / f"{bench.stem}-r")))
    return pairs


class FrozenSeedTests(unittest.TestCase):
    """The referee owns benchmark seed selection, and says so in one place."""

    def test_default_benchmark_seeds_are_disjoint_from_the_e7a_training_window(self) -> None:
        self.assertTrue(harness.BENCHMARK_SEEDS)
        self.assertFalse(
            set(harness.BENCHMARK_SEEDS) & set(harness.E7A_TRAINING_SEEDS),
            "the default benchmark seed set overlaps the E7a training seeds",
        )

    def test_seed_selection_lives_only_in_the_harness(self) -> None:
        """A later grader must be able to see a moved seed in ONE file."""
        for relative in ("console/efficacy_api.py", "web/src/pages/Reports.tsx"):
            source = (REPO_ROOT / relative).read_text(encoding="utf-8")
            for seed in harness.BENCHMARK_SEEDS:
                self.assertNotIn(str(seed), source,
                                 f"{relative} names a benchmark seed; the "
                                 "referee must own seed selection")

    def test_one_metric_implementation_only(self) -> None:
        source = (REPO_ROOT / "tools" / "efficacy_harness.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("def score("), 1)
        self.assertEqual(source.count("def _ratio("), 1)
        self.assertEqual(source.count("def diff("), 1)
        # The F1 arithmetic appears exactly once, so neither system can drift.
        self.assertEqual(source.count("2 * precision * recall"), 1)


class FreshnessAssertionTests(unittest.TestCase):
    """Seed and entity overlap are HARD failures, and the checks are not vacuous."""

    def test_a_shared_seed_is_refused(self) -> None:
        shared = harness.E7A_TRAINING_SEEDS[0]
        with tempfile.TemporaryDirectory(prefix="efficacy-overlap-") as tmp:
            derived = harness.training_entities(
                _fake_provenance(harness.E7A_TRAINING_SEEDS), Path(tmp))
            with self.assertRaises(harness.BenchmarkProvenanceError) as caught:
                harness.assert_fresh([shared, 20270302], {}, derived)
        self.assertIn(str(shared), str(caught.exception))
        self.assertIn("TRAINING seeds", str(caught.exception))

    def test_a_shared_entity_is_refused_even_with_disjoint_seeds(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-entity-") as tmp:
            derived = harness.training_entities(
                _fake_provenance(harness.E7A_TRAINING_SEEDS), Path(tmp))
            trained_user = derived["entities"]["user"][0]
            with self.assertRaises(harness.BenchmarkProvenanceError) as caught:
                harness.assert_fresh(list(harness.BENCHMARK_SEEDS),
                                     {"user": [trained_user]}, derived)
        self.assertIn(trained_user, str(caught.exception))

    def test_overlap_is_caught_across_entity_kinds(self) -> None:
        """A benchmark HOST that equals a training USERNAME is still a leak."""
        with tempfile.TemporaryDirectory(prefix="efficacy-cross-") as tmp:
            derived = harness.training_entities(
                _fake_provenance(harness.E7A_TRAINING_SEEDS), Path(tmp))
            trained_user = derived["entities"]["user"][0]
            with self.assertRaises(harness.BenchmarkProvenanceError):
                harness.assert_fresh(list(harness.BENCHMARK_SEEDS),
                                     {"host": [trained_user]}, derived)

    def test_a_sidecar_without_generator_provenance_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-noprov-") as tmp:
            with self.assertRaises(harness.BenchmarkProvenanceError) as caught:
                harness.training_entities({"seedsUsed": []}, Path(tmp))
        self.assertIn("does not record the generator seeds", str(caught.exception))

    def test_every_feature_entity_kind_is_asserted(self) -> None:
        """No kind features() can count may be quietly exempted."""
        for kind in ("ip", "user", "host", "port"):
            self.assertIn(kind, harness.ASSERTED_ENTITY_KINDS)

    def test_a_real_run_is_entity_disjoint_on_every_kind(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-fresh-") as tmp:
            directory = Path(tmp)
            derived = harness.training_entities(
                _fake_provenance(harness.E7A_TRAINING_SEEDS,
                                 scenarios=sorted(harness.generator.SCENARIOS),
                                 formats=("canonical", "rfc3164")), directory)
            excluded = {v for values in derived["entities"].values() for v in values}
            accumulated: dict = {}
            for seed in harness.BENCHMARK_SEEDS:
                for scenario in harness.generator.SCENARIOS:
                    log_path, manifest_path = harness.generator.generate(
                        scenario, "canonical", directory, seed)
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    text, manifest, _m = harness.remap_scenario(
                        log_path, manifest, excluded)
                    harness._merge_entities(
                        accumulated, harness.log_entities(text, manifest))
            benchmark = harness._sorted_entities(accumulated)
            freshness = harness.assert_fresh(
                list(harness.BENCHMARK_SEEDS), benchmark, derived)

        self.assertTrue(benchmark["host"] and benchmark["user"]
                        and benchmark["ip"] and benchmark["port"],
                        "the entity inventory is empty — the check would be vacuous")
        for kind in harness.ASSERTED_ENTITY_KINDS:
            self.assertEqual(freshness["assertedEntityOverlap"][kind], [], kind)


class BenchmarkRemapTests(unittest.TestCase):
    """The remap is benchmark-only, deterministic, and never drifts the truth."""

    def _one(self, directory: Path, scenario: str = "INC-4a7f", seed: int | None = None):
        seed = harness.BENCHMARK_SEEDS[0] if seed is None else seed
        log_path, manifest_path = harness.generator.generate(
            scenario, "canonical", directory, seed)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return log_path, manifest

    def test_manifest_raw_stays_byte_aligned_with_the_remapped_log(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-remap-") as tmp:
            directory = Path(tmp)
            for scenario in harness.generator.SCENARIOS:
                log_path, manifest = self._one(directory, scenario)
                text, remapped, _map = harness.remap_scenario(log_path, manifest, set())
                lines = text.splitlines()
                self.assertEqual(len(lines), remapped["line_count"])
                for entry in remapped["malicious_lines"]:
                    self.assertEqual(entry["raw"], lines[entry["line"] - 1],
                                     f"{scenario} line {entry['line']} drifted")

    def test_the_remap_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-det-") as tmp:
            directory = Path(tmp)
            log_path, manifest = self._one(directory)
            first = harness.remap_scenario(log_path, manifest, set())
            second = harness.remap_scenario(log_path, manifest, set())
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[2], second[2])

    def test_every_generator_entity_value_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-replaced-") as tmp:
            directory = Path(tmp)
            for scenario in harness.generator.SCENARIOS:
                log_path, manifest = self._one(directory, scenario)
                original = harness.log_entities(
                    log_path.read_text(encoding="utf-8"), manifest)
                text, remapped, mapping = harness.remap_scenario(
                    log_path, manifest, set())
                after = harness.log_entities(text, remapped)
                for kind in harness.ASSERTED_ENTITY_KINDS:
                    self.assertFalse(
                        set(original[kind]) & set(after[kind]),
                        f"{scenario}: {kind} survived the remap unchanged")
                    self.assertEqual(len(original[kind]), len(after[kind]),
                                     f"{scenario}: {kind} count changed")
                self.assertTrue(mapping)

    def test_a_token_may_not_land_on_an_excluded_training_value(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-excl-") as tmp:
            directory = Path(tmp)
            log_path, manifest = self._one(directory)
            entities = harness.log_entities(
                log_path.read_text(encoding="utf-8"), manifest)
            natural = harness.benchmark_token_map(entities, ())
            blocked = set(natural.values())
            avoided = harness.benchmark_token_map(entities, blocked)
        self.assertFalse(set(avoided.values()) & blocked)
        self.assertEqual(sorted(avoided), sorted(natural))

    def test_the_remap_does_not_change_what_the_rules_do(self) -> None:
        """Freshness must not buy itself a different detector behaviour."""
        def signature(report):
            return sorted(
                (finding.get("rule_id") or finding.get("category"),
                 finding.get("severity"), finding.get("occurrences"),
                 len(finding.get("timeline") or []))
                for finding in report.get("findings") or [])

        with tempfile.TemporaryDirectory(prefix="efficacy-neutral-") as tmp:
            directory = Path(tmp)
            for scenario in harness.generator.SCENARIOS:
                log_path, manifest = self._one(directory, scenario)
                before = harness.run_analyzer(log_path, directory / f"{scenario}-pre")
                text, _remapped, _map = harness.remap_scenario(log_path, manifest, set())
                bench = directory / f"{scenario}-bench.log"
                bench.write_text(text, encoding="utf-8")
                after = harness.run_analyzer(bench, directory / f"{scenario}-post")
                self.assertEqual(signature(before), signature(after), scenario)

    def test_the_benchmark_host_keeps_its_configured_criticality(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-org-") as tmp:
            org = harness.benchmark_org_context(
                {"server-01": "bnch-server-01"}, Path(tmp))
        self.assertEqual(org.get_criticality("bnch-server-01"),
                         org.get_criticality("server-01"))
        self.assertEqual(org.get_criticality("bnch-server-01"), "crown-jewel")


class RuleInvarianceTests(unittest.TestCase):
    """Scoring the model may not move a single rule number."""

    SCENARIOS = ("INC-4a7f", "near-miss-auth", "benign-maintenance")

    def _rules_only(self, results):
        return json.dumps([entry["rules"] for entry in results],
                          indent=2, sort_keys=True)

    def test_rule_numbers_are_byte_identical_with_and_without_a_model(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-invariance-") as tmp:
            directory = Path(tmp)
            pairs = _ingest(self.SCENARIOS, harness.BENCHMARK_SEEDS[:1], directory)
            before = json.dumps(pairs, indent=2, sort_keys=True)

            with_model = harness.score_manifests(pairs, _stub_model("false-positive"))
            # the model is now KILLED — same pairs, same manifests, no model
            killed = harness.score_manifests(pairs, None, "model removed")

        self.assertEqual(self._rules_only(with_model), self._rules_only(killed))
        self.assertEqual(before, json.dumps(pairs, indent=2, sort_keys=True),
                         "scoring mutated the ingested reports or manifests")
        # ... and the run was not vacuous: the learned half really did differ.
        self.assertTrue(with_model[0]["learned"]["available"])
        self.assertFalse(killed[0]["learned"]["available"])

    def test_a_real_model_kill_leaves_the_rules_untouched(self) -> None:
        """The shipped loader is what fails, and it fails honestly."""
        with tempfile.TemporaryDirectory(prefix="efficacy-kill-") as tmp:
            directory = Path(tmp)
            pairs = _ingest(("INC-4a7f",), harness.BENCHMARK_SEEDS[:1], directory)
            stubbed = harness.score_manifests(pairs, _stub_model("confirmed"))
            with self.assertRaises(Exception) as caught:
                harness.LearnedSystem.load(directory / "no-model-here")
            killed = harness.score_manifests(pairs, None, str(caught.exception))

        self.assertEqual(self._rules_only(stubbed), self._rules_only(killed))
        # The reason depends on this installation — no scikit-learn, or no
        # artifact at the pointed-at directory. Both are the shipped loader's
        # own words, and both must be a NAMED reason rather than a silent gap.
        reason = killed[0]["learned"]["reason"]
        self.assertTrue(
            "no trained model at" in reason
            or "scikit-learn is not installed" in reason, reason)

    def test_the_learned_pass_cannot_write_into_the_rules_findings(self) -> None:
        manifest = {"scenario": "unit", "format": "canonical", "line_count": 2,
                    "malicious_count": 1,
                    "malicious_lines": [{"line": 2, "raw": "raw two", "why": "w"}]}
        report = {"findings": [{"rule_id": "r1", "timeline": [{"line": 2}],
                                "evidence": "", "summary": "", "severity": "HIGH"}]}
        snapshot = json.dumps(report, sort_keys=True)
        entry = harness.score_pair(manifest, report, _stub_model("false-positive"))
        self.assertEqual(snapshot, json.dumps(report, sort_keys=True))
        self.assertEqual(entry["rules"]["totals"]["recall"], 1.0)
        self.assertEqual(entry["learned"]["totals"]["recall"], 0.0)


class PairedDifferenceTests(unittest.TestCase):
    """The paired systems must be ABLE to differ — proven by mutation."""

    MANIFEST = {
        "scenario": "unit", "format": "canonical", "line_count": 3,
        "scenario_class": "confirmed", "malicious_count": 2,
        "malicious_lines": [
            {"line": 2, "raw": "line two raw", "why": "first"},
            {"line": 3, "raw": "line three raw", "why": "second"},
        ],
    }
    REPORT = {"findings": [
        {"rule_id": "r1", "timeline": [{"line": 2}, {"line": 3}],
         "evidence": "", "summary": "", "severity": "HIGH"},
        {"rule_id": "r2", "timeline": [{"line": 1}], "evidence": "",
         "summary": "quiet boot", "severity": "LOW"},
    ]}

    def test_a_model_that_confirms_everything_reproduces_the_rules_exactly(self) -> None:
        entry = harness.score_pair(self.MANIFEST, self.REPORT, _stub_model("confirmed"))
        self.assertEqual(entry["learned"]["totals"], entry["rules"]["totals"])
        self.assertEqual(entry["learned"]["misses"], entry["rules"]["misses"])
        self.assertEqual(entry["learned"]["false_positives"],
                         entry["rules"]["false_positives"])

    def test_a_model_that_rejects_everything_differs_from_the_rules(self) -> None:
        entry = harness.score_pair(self.MANIFEST, self.REPORT,
                                   _stub_model("false-positive"))
        self.assertNotEqual(entry["learned"]["totals"], entry["rules"]["totals"])
        self.assertEqual(entry["rules"]["totals"]["recall"], 1.0)
        self.assertEqual(entry["learned"]["totals"]["recall"], 0.0)
        # every malicious line is now a LEARNED miss, verbatim
        self.assertEqual([miss["raw"] for miss in entry["learned"]["misses"]],
                         ["line two raw", "line three raw"])
        self.assertEqual([miss["why"] for miss in entry["learned"]["misses"]],
                         ["first", "second"])
        # ... while the rules missed nothing
        self.assertEqual(entry["rules"]["misses"], [])

    def test_a_benign_expected_prediction_is_model_negative_too(self) -> None:
        entry = harness.score_pair(self.MANIFEST, self.REPORT,
                                   _stub_model("benign-expected"))
        self.assertEqual(entry["learned"]["findings"], 0)
        self.assertEqual(len(entry["learned"]["misses"]), 2)
        self.assertEqual(harness.MODEL_POSITIVE_LABELS, ("confirmed",))
        self.assertEqual(sorted(harness.MODEL_NEGATIVE_LABELS),
                         ["benign-expected", "false-positive"])

    def test_dropping_a_false_positive_earns_the_learned_system_precision(self) -> None:
        """The difference cuts both ways, not just downward."""
        class _OnlyR2IsWrong(_StubEstimator):
            def __init__(self):
                super().__init__("confirmed")
                self.seen = 0

            def predict_proba(self, vectors):
                self.seen += 1
                label = "confirmed" if self.seen == 1 else "false-positive"
                index = self.classes_.index(label)
                row = [0.0] * len(self.classes_)
                row[index] = 1.0
                return [list(row) for _ in vectors]

        model = harness.LearnedSystem(_OnlyR2IsWrong(), {})
        entry = harness.score_pair(self.MANIFEST, self.REPORT, model)
        self.assertEqual(entry["rules"]["totals"]["precision"], 0.5)
        self.assertEqual(entry["learned"]["totals"]["precision"], 1.0)
        self.assertEqual(entry["learned"]["totals"]["recall"], 1.0)
        self.assertEqual(entry["learned"]["misses"], [])


class HonestUnavailableTests(unittest.TestCase):
    """A missing model is an honest gap, never a zero and never a fabrication."""

    def test_an_unavailable_model_publishes_no_number_at_all(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-unavailable-") as tmp:
            summary = harness.evaluate(
                ["INC-4a7f"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "definitely-not-a-model-dir")

        self.assertFalse(summary["model"]["available"])
        self.assertTrue(summary["model"]["reason"])
        self.assertIsNone(summary["learned_total_misses"])
        self.assertIsNone(summary["learned_total_false_positives"])
        self.assertFalse(summary["freshness"]["asserted"])
        for entry in summary["scenarios"]:
            learned = entry["learned"]
            self.assertFalse(learned["available"])
            self.assertIsNone(learned["totals"])
            self.assertIsNone(learned["misses"])
            self.assertTrue(learned["reason"])
            # the rules half is still fully measured
            self.assertEqual(entry["rules"]["totals"]["recall"], 1.0)
        self.assertIn("UNAVAILABLE", harness.render(summary))

    def test_every_published_number_carries_its_provenance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-prov-") as tmp:
            summary = harness.evaluate(
                ["INC-4a7f"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        self.assertTrue(summary["run_id"].startswith("efficacy-"))
        self.assertTrue(summary["run_date"].startswith("20"))
        self.assertIn("commit", summary["provenance"])
        self.assertEqual(summary["benchmark"]["seeds"],
                         [harness.BENCHMARK_SEEDS[0]])
        self.assertTrue(summary["benchmark"]["entities"]["host"])
        self.assertEqual(summary["scope"], harness.SCOPE_SENTENCE)
        self.assertEqual(summary["advisory"], harness.ADVISORY_SENTENCE)
        for entry in summary["scenarios"]:
            self.assertEqual(entry["run_id"], summary["run_id"])


# ---------------------------------------------------------------------------
# E8m — the additive amendment
# ---------------------------------------------------------------------------

class FindingLevelRecallTests(unittest.TestCase):
    """Recall has two denominators. Both are published, both are labelled."""

    MANIFEST = {
        "scenario": "unit",
        "format": "canonical",
        "line_count": 3,
        "malicious_count": 1,
        "malicious_lines": [{"line": 2, "raw": "line two raw", "why": "the only one"}],
    }
    # Two findings cite the SAME single malicious line. Dropping one of them
    # costs NOTHING at line level and half the findings at finding level — the
    # exact absorption E8m exists to make visible.
    FINDINGS = [
        {"rule_id": "keeper", "timeline": [{"line": 2}], "evidence": "", "summary": "kept"},
        {"rule_id": "ioc_observed", "severity": "MEDIUM", "timeline": [{"line": 2}],
         "evidence": "", "summary": "the absorbed one"},
    ]

    def test_finding_level_recall_names_its_denominator(self) -> None:
        result = harness.finding_level_recall(85, 90)
        self.assertEqual(result["recall"], 0.9444)
        self.assertEqual(result["true_findings_kept"], 85)
        self.assertEqual(result["true_findings_total"], 90)
        self.assertTrue(result["recall_defined"])
        self.assertEqual(result["denominator"],
                         "findings that cite at least one malicious line")

    def test_an_absent_denominator_is_undefined_not_a_measured_zero(self) -> None:
        result = harness.finding_level_recall(0, 0)
        self.assertEqual(result["recall"], 0.0)
        self.assertFalse(result["recall_defined"])

    def test_a_dropped_finding_costs_finding_recall_but_not_line_recall(self) -> None:
        """The defect, reproduced in the small."""
        model = _stub_model("confirmed")
        model.opinion = (                                    # type: ignore[method-assign]
            lambda finding, manifest, org=None: {
                "rule_id": finding.get("rule_id"),
                "rule_severity": finding.get("severity"),
                "label": "confirmed" if finding["rule_id"] == "keeper"
                         else "benign-expected",
                "confidence": 0.992,
                "model_positive": finding["rule_id"] == "keeper",
                "advisory_severity": None,
                "agrees": None,
            })
        entry = harness.score_pair(
            self.MANIFEST, {"findings": copy.deepcopy(self.FINDINGS)}, model)

        learned = entry["learned"]
        # line-level recall is untouched: the kept finding still covers line 2
        self.assertEqual(learned["totals"]["recall"], 1.0)
        self.assertEqual(learned["misses"], [])
        # finding-level recall is not
        self.assertEqual(learned["finding_recall"]["recall"], 0.5)
        self.assertEqual(learned["finding_recall"]["true_findings_kept"], 1)
        self.assertEqual(learned["finding_recall"]["true_findings_total"], 2)
        # and the loss is listed VERBATIM, like a miss
        dropped = learned["dropped_true_findings"]
        self.assertEqual(len(dropped), 1)
        self.assertEqual(dropped[0]["rule_id"], "ioc_observed")
        self.assertEqual(dropped[0]["label"], "benign-expected")
        self.assertEqual(dropped[0]["confidence"], 0.992)
        self.assertEqual(dropped[0]["summary"], "the absorbed one")
        self.assertEqual(dropped[0]["cited_malicious_lines"],
                         [{"line": 2, "raw": "line two raw", "why": "the only one"}])

    def test_the_rules_system_publishes_its_finding_recall_too(self) -> None:
        entry = harness.score_pair(
            self.MANIFEST, {"findings": copy.deepcopy(self.FINDINGS)}, None)
        rules = entry["rules"]
        self.assertEqual(rules["finding_recall"]["recall"], 1.0)
        self.assertEqual(rules["finding_recall"]["true_findings_total"], 2)
        self.assertEqual(rules["dropped_true_findings"], [])

    def test_a_suppressed_false_positive_is_not_a_dropped_true_finding(self) -> None:
        """Dropping a finding that cited nothing earns precision; it is not a loss."""
        findings = [{"rule_id": "noise", "timeline": [{"line": 1}],
                     "evidence": "", "summary": "quiet boot"}]
        decisions = [{"rule_id": "noise", "label": "false-positive",
                      "confidence": 0.9, "model_positive": False}]
        self.assertEqual(
            harness.dropped_true_findings(
                findings, decisions, self.MANIFEST["malicious_lines"]),
            [])

    def test_both_recalls_are_labelled_wherever_either_is_rendered(self) -> None:
        model = _stub_model("confirmed")
        with tempfile.TemporaryDirectory(prefix="efficacy-labels-") as tmp:
            summary = harness.evaluate(
                ["INC-4a7f"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        self.assertEqual(summary["line_level_recall_denominator"],
                         "manifest malicious lines")
        self.assertEqual(summary["finding_level_recall"]["denominator"],
                         "findings that cite at least one malicious line")
        self.assertIn("malicious LINES", summary["recall_note"])
        self.assertIn("cite at least one malicious line", summary["recall_note"])
        text = harness.render(summary)
        self.assertIn("recall(lines)=", text)
        self.assertIn("recall(findings)=", text)
        self.assertIn("Line-level recall is over manifest malicious lines", text)
        del model


class FormatScopeTests(unittest.TestCase):
    """A false-positive count with no format scope is not a publishable number."""

    def test_the_total_is_scoped_and_every_format_is_a_labelled_subset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-scope-") as tmp:
            summary = harness.evaluate(
                ["near-miss-auth"], ["canonical", "rfc3164"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        totals = summary["false_positive_totals"]
        self.assertEqual(totals["formats"], ["canonical", "rfc3164"])
        self.assertIn("canonical", totals["scope"])
        self.assertIn("rfc3164", totals["scope"])
        self.assertEqual(set(totals["by_format"]), {"canonical", "rfc3164"})
        self.assertEqual(
            totals["rules"],
            sum(bucket["rules"] for bucket in totals["by_format"].values()))
        # the headline still equals the legacy total: no measured value moved
        self.assertEqual(totals["rules"], summary["total_false_positives"])

    def test_no_false_positive_total_is_rendered_bare(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-bare-") as tmp:
            summary = harness.evaluate(
                ["near-miss-auth"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        text = harness.render(summary)
        for line in text.splitlines():
            if "false positive finding(s)" in line and line.startswith(
                    ("Rules totals:", "Learned totals:")):
                self.assertIn("all formats measured in this run", line)
        self.assertIn("subset `canonical` only", text)


class CriticalitySensitivityTests(unittest.TestCase):
    """The counterfactual is a first-class published finding, and says so."""

    def test_forcing_criticality_needs_no_edit_outside_the_harness(self) -> None:
        forced = harness._ForcedCriticality("crown-jewel")
        self.assertEqual(forced.get_criticality("anything-at-all"), "crown-jewel")
        self.assertEqual(forced.get_criticality(None), "crown-jewel")

    def test_the_whole_real_domain_is_forced(self) -> None:
        self.assertEqual(harness.CRITICALITY_DOMAIN,
                         ("low", "standard", "crown-jewel"))

    def test_a_model_whose_decision_follows_criticality_is_reported_as_flipping(self) -> None:
        """A stub whose opinion depends ONLY on criticality, so the count is
        provably the counterfactual and not an artefact of the real model."""
        manifest = FindingLevelRecallTests.MANIFEST
        findings = [
            {"rule_id": "ioc_observed", "timeline": [{"line": 2}],
             "evidence": "", "summary": "cites the malicious line"},
            {"rule_id": "noise", "timeline": [{"line": 1}],
             "evidence": "", "summary": "cites nothing"},
        ]
        model = _stub_model("confirmed")

        def opinion(finding, mani, org=None):
            crit = org.get_criticality("host") if org is not None else "standard"
            keeps = finding["rule_id"] == "ioc_observed"
            if crit == "crown-jewel":
                keeps = not keeps          # the whole decision inverts
            return {"rule_id": finding["rule_id"], "rule_severity": None,
                    "label": "confirmed" if keeps else "benign-expected",
                    "confidence": 1.0, "model_positive": keeps,
                    "advisory_severity": None, "agrees": None}

        model.opinion = opinion            # type: ignore[method-assign]
        report = {"findings": copy.deepcopy(findings)}
        entry = harness.score_pair(manifest, report, model)
        sens = harness.criticality_sensitivity(
            [(manifest, report)], [entry], model)

        self.assertTrue(sens["available"])
        self.assertEqual(sens["kind"], "counterfactual")
        self.assertEqual(sens["feature"], "criticality_rank")
        detections = sens["populations"]["true_detections"]
        suppressions = sens["populations"]["suppressions"]
        self.assertEqual(detections["total"], 1)
        self.assertEqual(detections["flipping"], 1)
        self.assertEqual(detections["robust"], 0)
        # direction, read straight off the bands
        self.assertEqual(detections["kept_at"],
                         {"low": 1, "standard": 1, "crown-jewel": 0})
        self.assertEqual(suppressions["total"], 1)
        self.assertEqual(suppressions["flipping"], 1)
        self.assertEqual(suppressions["kept_at"],
                         {"low": 0, "standard": 0, "crown-jewel": 1})

    def test_the_counterfactual_does_not_move_the_measured_run(self) -> None:
        """Re-scoring must not write back into anything published."""
        manifest = FindingLevelRecallTests.MANIFEST
        report = {"findings": copy.deepcopy(FindingLevelRecallTests.FINDINGS)}
        model = _stub_model("confirmed")
        entry = harness.score_pair(manifest, report, model)
        before = json.dumps(entry, sort_keys=True)
        before_report = json.dumps(report, sort_keys=True)
        harness.criticality_sensitivity([(manifest, report)], [entry], model)
        self.assertEqual(json.dumps(entry, sort_keys=True), before)
        self.assertEqual(json.dumps(report, sort_keys=True), before_report)

    def test_it_is_published_as_a_counterfactual_never_as_a_measurement(self) -> None:
        self.assertIn("COUNTERFACTUAL", harness.CRITICALITY_SENSITIVITY_NOTE)
        self.assertIn("stands exactly as measured",
                      harness.CRITICALITY_SENSITIVITY_NOTE)
        self.assertIn("MORE willing to dismiss",
                      harness.CRITICALITY_SENSITIVITY_NOTE)

    def test_no_model_publishes_an_honest_gap_not_a_zero(self) -> None:
        sens = harness.criticality_sensitivity([], [], None, "sklearn is absent")
        self.assertFalse(sens["available"])
        self.assertEqual(sens["reason"], "sklearn is absent")
        self.assertIsNone(sens["populations"])
        self.assertIsNone(sens["feature_importance"])
        with tempfile.TemporaryDirectory(prefix="efficacy-sens-gap-") as tmp:
            summary = harness.evaluate(
                ["INC-4a7f"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        self.assertFalse(summary["criticality_sensitivity"]["available"])
        self.assertIsNone(summary["learned_total_dropped_true_findings"])
        self.assertIsNone(summary["finding_level_recall"]["learned"])
        self.assertIn("Criticality sensitivity: UNAVAILABLE",
                      harness.render(summary))

    def test_feature_importance_is_read_off_the_artefact_or_declared_absent(self) -> None:
        model = _stub_model("confirmed")      # no feature_importances_
        importance = harness.feature_importance(model)
        self.assertFalse(importance["available"])
        self.assertIsNone(importance["criticality_rank"])
        self.assertTrue(importance["reason"])


class AmendmentIsAdditiveTests(unittest.TestCase):
    """E8m may publish more. It may not move anything E8 published."""

    def test_the_frozen_referee_constants_are_unmoved(self) -> None:
        self.assertEqual(harness.BENCHMARK_SEEDS, (20270302, 20270303, 20270304))
        self.assertEqual(harness.E7A_TRAINING_SEEDS, tuple(range(20260902, 20260916)))
        self.assertEqual(harness.MODEL_POSITIVE_LABELS, ("confirmed",))
        self.assertEqual(harness.MODEL_NEGATIVE_LABELS,
                         ("false-positive", "benign-expected"))
        self.assertEqual(harness.ASSERTED_ENTITY_KINDS,
                         ("ip", "user", "host", "port", "change_window"))

    def test_still_exactly_one_metric_implementation(self) -> None:
        source = (REPO_ROOT / "tools" / "efficacy_harness.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("def score("), 1)
        self.assertEqual(source.count("def _ratio("), 1)
        self.assertEqual(source.count("def diff("), 1)
        self.assertEqual(source.count("2 * precision * recall"), 1)

    def test_score_still_returns_exactly_the_frozen_keys(self) -> None:
        self.assertEqual(
            sorted(harness.score(3, 1, 5, 6)),
            sorted(["true_positive_findings", "false_positive_findings",
                    "malicious_lines", "malicious_lines_detected",
                    "precision", "recall", "f1",
                    "precision_defined", "recall_defined"]))
        self.assertEqual(harness.score(3, 1, 5, 6)["precision"], 0.75)
        self.assertEqual(harness.score(3, 1, 5, 6)["recall"], 0.8333)

    def test_the_standing_sentences_are_intact(self) -> None:
        self.assertEqual(
            harness.SCOPE_SENTENCE,
            "measured against synthetic ground-truth scenarios; "
            "not a claim about production traffic.")
        self.assertIn("regression proof", harness.CEILING_SENTENCE)
        self.assertEqual(harness.ADVISORY_SENTENCE,
                         "the learned model is advisory; these numbers are why.")

    def test_the_amendment_adds_keys_and_moves_no_existing_value(self) -> None:
        """Score one run twice and compare against the pre-amendment key set."""
        with tempfile.TemporaryDirectory(prefix="efficacy-additive-") as tmp:
            summary = harness.evaluate(
                ["INC-4a7f"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        for key in ("run_id", "run_date", "scope", "ceiling", "advisory",
                    "pipeline", "systems", "interpretation", "metric_note",
                    "provenance", "benchmark", "freshness", "model",
                    "scenarios", "total_misses", "total_false_positives",
                    "learned_total_misses", "learned_total_false_positives"):
            self.assertIn(key, summary, f"E8 published `{key}`; it must survive")
        entry = summary["scenarios"][0]
        for key in ("scenario", "format", "line_count", "totals", "per_rule",
                    "misses", "false_positives", "scope", "rules", "learned"):
            self.assertIn(key, entry)
        # the rules half is still perfect on the frozen seed, unchanged by E8m
        self.assertEqual(entry["rules"]["totals"]["recall"], 1.0)
        self.assertEqual(entry["rules"]["totals"]["precision"], 1.0)
        self.assertEqual(summary["total_misses"], 0)


class PerRuleFindingRecallTests(unittest.TestCase):
    """E8m2 (1). Finding-level recall, broken down by rule class.

    The defect this closes: an aggregate cannot say WHICH rule class a system
    is losing. E7a's five crown-jewel `ioc_observed` dismissals sat behind a
    line-level 1.000; E7b round 1's eight `infra_unknown_high` drops read only
    as an aggregate 0.9111. The breakdown is published IN ADDITION to the
    verbatim dropped list, never instead of it.
    """

    def test_the_denominator_is_the_reference_collection_per_rule(self) -> None:
        reference = {
            "rule_a": {"true_positive_findings": 4, "false_positive_findings": 1},
            "rule_b": {"true_positive_findings": 2, "false_positive_findings": 0},
        }
        system = {"rule_a": {"true_positive_findings": 3}}   # rule_b gone entirely
        by_rule = harness.finding_recall_by_rule(reference, system)
        self.assertEqual(by_rule["rule_a"]["true_findings_kept"], 3)
        self.assertEqual(by_rule["rule_a"]["true_findings_total"], 4)
        self.assertEqual(by_rule["rule_a"]["recall"], 0.75)
        # A class the system dropped ENTIRELY reads 0.0 against the reference
        # denominator — it does not vanish from the table with it.
        self.assertEqual(by_rule["rule_b"]["true_findings_kept"], 0)
        self.assertEqual(by_rule["rule_b"]["true_findings_total"], 2)
        self.assertEqual(by_rule["rule_b"]["recall"], 0.0)
        self.assertTrue(by_rule["rule_b"]["recall_defined"])

    def test_a_rule_with_no_true_finding_is_absent_not_a_published_zero(self) -> None:
        """0/0 is not a measurement. It is left out, and the note says so."""
        reference = {"fp_only": {"true_positive_findings": 0,
                                 "false_positive_findings": 3}}
        self.assertEqual(harness.finding_recall_by_rule(reference, reference), {})
        self.assertIn("absent from the breakdown", harness.BY_RULE_RECALL_NOTE)

    def test_the_run_level_breakdown_sums_pairs_never_averages_ratios(self) -> None:
        """One 1/1 scenario and one 0/9 scenario is 1/10, not 0.5."""
        merged = harness.merge_finding_recall_by_rule([
            {"r": {"true_findings_kept": 1, "true_findings_total": 1}},
            {"r": {"true_findings_kept": 0, "true_findings_total": 9}},
        ])
        self.assertEqual(merged["r"]["true_findings_kept"], 1)
        self.assertEqual(merged["r"]["true_findings_total"], 10)
        self.assertEqual(merged["r"]["recall"], 0.1)

    def test_a_class_dropped_wholesale_is_visible_while_the_aggregate_is_not(self) -> None:
        """The whole point, on real ingested scenarios.

        A model that drops exactly one rule class must read 0.0 for that class
        while the aggregate stays high — which is the number that hid the E7a
        and E7b regressions.
        """
        class _OneRuleKiller:
            """Drops every finding of one rule; keeps the rest."""

            classes_ = ("benign-expected", "confirmed", "false-positive")

            def __init__(self, victim: str) -> None:
                self.victim = victim
                self.rule_ids: list[str] = []

            def predict_proba(self, vectors):
                rows = []
                for rule_id in self.rule_ids:
                    keep = rule_id != self.victim
                    row = [0.0, 1.0, 0.0] if keep else [0.0, 0.0, 1.0]
                    rows.append(row)
                self.rule_ids = []
                return rows

        with tempfile.TemporaryDirectory(prefix="efficacy-by-rule-") as tmp:
            directory = Path(tmp)
            pairs = _ingest(("INC-4a7f",), harness.BENCHMARK_SEEDS[:1], directory)
            reference = harness.diff(pairs[0][0], {"findings": pairs[0][1]["findings"]})
            victim = sorted(
                rule_id for rule_id, bucket in reference["per_rule"].items()
                if bucket["true_positive_findings"] > 0)[0]
            others = [rule_id for rule_id in reference["per_rule"]
                      if rule_id != victim
                      and reference["per_rule"][rule_id]["true_positive_findings"] > 0]
            self.assertTrue(others, "need a second true-finding rule to be non-vacuous")

            estimator = _OneRuleKiller(victim)
            model = harness.LearnedSystem(estimator, {"trainedAt": "stub"})
            original_opinion = model.opinion

            def opinion(finding, manifest, org=None):
                estimator.rule_ids.append(
                    str(finding.get("rule_id") or finding.get("category")
                        or "unattributed"))
                return original_opinion(finding, manifest, org)

            model.opinion = opinion                     # type: ignore[method-assign]
            scored = harness.score_manifests(pairs, model)

        learned = scored[0]["learned"]
        by_rule = learned["finding_recall_by_rule"]
        self.assertEqual(by_rule[victim]["recall"], 0.0,
                         "the dropped class must read 0.0 in its own row")
        self.assertGreater(by_rule[victim]["true_findings_total"], 0)
        for rule_id in others:
            self.assertEqual(by_rule[rule_id]["recall"], 1.0)
        # ... and the aggregate, on its own, would have hidden it.
        self.assertGreater(learned["finding_recall"]["recall"], 0.0)
        # The verbatim list is still there, still naming the same rule.
        self.assertTrue(learned["dropped_true_findings"])
        self.assertEqual({item["rule_id"] for item in learned["dropped_true_findings"]},
                         {victim})

    def test_the_rules_system_publishes_its_own_row_at_one(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-by-rule-rules-") as tmp:
            pairs = _ingest(("INC-4a7f",), harness.BENCHMARK_SEEDS[:1], Path(tmp))
            scored = harness.score_manifests(pairs, _stub_model("confirmed"))
        by_rule = scored[0]["rules"]["finding_recall_by_rule"]
        self.assertTrue(by_rule, "the rules system publishes a breakdown too")
        for bucket in by_rule.values():
            self.assertEqual(bucket["recall"], 1.0)
            self.assertEqual(bucket["true_findings_kept"],
                             bucket["true_findings_total"])

    def test_no_model_means_no_per_rule_learned_number_is_invented(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-by-rule-gap-") as tmp:
            pairs = _ingest(("INC-4a7f",), harness.BENCHMARK_SEEDS[:1], Path(tmp))
            scored = harness.score_manifests(pairs, None, "model removed")
        self.assertIsNone(scored[0]["learned"]["finding_recall_by_rule"])

    def test_the_run_publishes_the_breakdown_and_renders_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-by-rule-run-") as tmp:
            summary = harness.evaluate(
                ["INC-4a7f"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        by_rule = summary["finding_level_recall"]["by_rule"]
        self.assertTrue(by_rule)
        for rule_id, bucket in by_rule.items():
            self.assertEqual(bucket["rules"]["recall"], 1.0)
            # no model → the learned half of every row is an honest gap
            self.assertIsNone(bucket["learned"])
            self.assertIsNone(bucket["learned_dropped_true_findings"])
            self.assertIn("malicious line", bucket["denominator"])
        text = harness.render(summary)
        self.assertIn("finding-level recall BY RULE CLASS", text)
        for rule_id in by_rule:
            self.assertIn(rule_id, text)
        self.assertIn(harness.BY_RULE_RECALL_NOTE, text)


class FrozenBenchmarkScenarioSetTests(unittest.TestCase):
    """E8m2 (2). The referee owns WHAT is measured, not only at which seeds.

    Before this, the benchmark defaulted to `generator.SCENARIOS`, so adding a
    scenario to `tools/attack_generator.py` silently changed what the frozen
    benchmark measured and made before/after numbers incomparable.
    """

    def test_the_frozen_set_is_exactly_todays_six_scenarios(self) -> None:
        self.assertEqual(
            harness.BENCHMARK_SCENARIOS,
            ("INC-4a7f", "failure-success", "error-burst",
             "near-miss-auth", "near-miss-errors", "benign-maintenance"))
        # ... and it is still what the generator can actually produce.
        self.assertEqual(harness.benchmark_scenarios(), harness.BENCHMARK_SCENARIOS)

    def test_a_generator_scenario_added_later_does_not_move_the_benchmark(self) -> None:
        """THE assertion. An extra generator scenario changes nothing."""
        extended = dict(harness.generator.SCENARIOS)
        extended["a-scenario-added-tomorrow"] = lambda rng: []
        original = harness.generator.SCENARIOS
        try:
            harness.generator.SCENARIOS = extended     # type: ignore[assignment]
            self.assertIn("a-scenario-added-tomorrow", harness.generator.SCENARIOS)
            self.assertEqual(harness.benchmark_scenarios(),
                             harness.BENCHMARK_SCENARIOS)
            self.assertNotIn("a-scenario-added-tomorrow",
                             harness.benchmark_scenarios())
            # and the CLI default — the path the benchmark is actually run by
            parser_default = _cli_default_scenarios()
            self.assertEqual(tuple(parser_default), harness.BENCHMARK_SCENARIOS)
        finally:
            harness.generator.SCENARIOS = original     # type: ignore[assignment]

    def test_a_frozen_scenario_the_generator_lost_is_refused_not_skipped(self) -> None:
        shrunk = {name: fn for name, fn in harness.generator.SCENARIOS.items()
                  if name != "error-burst"}
        original = harness.generator.SCENARIOS
        try:
            harness.generator.SCENARIOS = shrunk       # type: ignore[assignment]
            with self.assertRaises(harness.BenchmarkProvenanceError) as caught:
                harness.benchmark_scenarios()
        finally:
            harness.generator.SCENARIOS = original     # type: ignore[assignment]
        self.assertIn("error-burst", str(caught.exception))

    def test_the_run_publishes_the_frozen_set_beside_what_it_measured(self) -> None:
        with tempfile.TemporaryDirectory(prefix="efficacy-pin-") as tmp:
            summary = harness.evaluate(
                ["INC-4a7f"], ["canonical"], Path(tmp),
                seeds=[harness.BENCHMARK_SEEDS[0]],
                model_dir=Path(tmp) / "no-model")
        benchmark = summary["benchmark"]
        self.assertEqual(benchmark["scenarios"], ["INC-4a7f"])
        self.assertEqual(benchmark["frozenScenarios"],
                         list(harness.BENCHMARK_SCENARIOS))
        # this run deliberately measured a subset, and says so rather than
        # claiming to be the benchmark
        self.assertFalse(benchmark["scenarioSetIsFrozen"])
        self.assertIn("NOT the frozen set", harness.render(summary))

    def test_the_pin_does_not_touch_the_seeds_or_the_freshness_assertion(self) -> None:
        source = (REPO_ROOT / "tools" / "efficacy_harness.py").read_text(encoding="utf-8")
        self.assertEqual(harness.BENCHMARK_SEEDS, (20270302, 20270303, 20270304))
        self.assertEqual(source.count("def assert_fresh("), 1)
        self.assertEqual(source.count("BENCHMARK_SEEDS = "), 1)


def _cli_default_scenarios() -> list[str]:
    """What `main()` would measure with no `--scenario` given.

    Read through the same expression `main()` uses, so the test cannot pass
    while the CLI still defaults to the generator's dictionary.
    """
    return list(harness.benchmark_scenarios())


if __name__ == "__main__":
    unittest.main(verbosity=2)
