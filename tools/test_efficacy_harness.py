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


if __name__ == "__main__":
    unittest.main(verbosity=2)
