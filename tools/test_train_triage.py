"""Promotion-bar tests for the E7a training pipeline and its shared features.

stdlib `unittest` only (no pytest, per the repo's standing rule):

    python3 -m unittest tools.test_train_triage -v

Nothing here needs scikit-learn. The two checks that genuinely require an
estimator are skipped, out loud, when it is not installed — the pipeline's data,
labelling, isolation and leakage properties are all provable without it.
"""

from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(REPO_ROOT), str(REPO_ROOT / "console")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import org_context  # noqa: E402
import triage_model  # noqa: E402
from tools import attack_generator as generator  # noqa: E402
from tools import train_triage as train  # noqa: E402

HAVE_SKLEARN = triage_model.sklearn_version() is not None


class GeneratorCoverageTests(unittest.TestCase):
    """The E7a extension to the generator: seeded variants + the new classes."""

    def test_every_scenario_declares_a_ground_truth_class_and_host(self) -> None:
        self.assertEqual(set(generator.SCENARIOS), set(generator.SCENARIO_CLASS))
        self.assertEqual(set(generator.SCENARIOS), set(generator.SCENARIO_HOST))
        for scenario, label in generator.SCENARIO_CLASS.items():
            self.assertIn(label, triage_model.LABELS, scenario)

    def test_all_three_analyst_classes_are_covered(self) -> None:
        self.assertEqual(set(generator.SCENARIO_CLASS.values()),
                         set(triage_model.LABELS))

    def test_near_miss_and_benign_scenarios_label_zero_malicious_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for scenario, label in generator.SCENARIO_CLASS.items():
                if label == "confirmed":
                    continue
                _log, manifest_path = generator.generate(
                    scenario, "canonical", Path(tmp), 11)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.assertEqual(manifest["malicious_count"], 0, scenario)
                self.assertEqual(manifest["malicious_lines"], [], scenario)
                self.assertEqual(manifest["scenario_class"], label, scenario)

    def test_seeded_variants_are_reproducible_and_actually_vary(self) -> None:
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first = generator.generate("INC-4a7f", "canonical", Path(a), 5)[0].read_bytes()
            same = generator.generate("INC-4a7f", "canonical", Path(b), 5)[0].read_bytes()
            other = generator.generate("INC-4a7f", "canonical", Path(b), 6)[0].read_bytes()
        self.assertEqual(first, same, "same seed must reproduce the same bytes")
        self.assertNotEqual(first, other, "different seeds must differ")

    def test_unseeded_output_is_unchanged_by_the_e7a_extension(self) -> None:
        """The promoted harness fixtures must not have moved."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path, manifest_path = generator.generate(
                "INC-4a7f", "canonical", Path(tmp))
            lines = log_path.read_text(encoding="utf-8").splitlines()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(lines[0], "2026-08-30T02:16:40Z INFO server-01 sshd service ready")
        self.assertEqual(
            lines[1],
            "2026-08-30T02:16:41Z WARN server-01 Failed password for admin "
            "from 203.0.113.44 port 49152 ssh2")
        self.assertEqual(lines[-1], "2026-08-30T02:16:49Z INFO server-01 health check passed")
        self.assertEqual(manifest["malicious_count"], 7)
        self.assertIsNone(manifest["seed"])

    def test_seeded_output_is_still_refused_inside_the_eval_corpus(self) -> None:
        with self.assertRaisesRegex(ValueError, "refusing generated output"):
            generator.generate("near-miss-auth", "canonical",
                               generator.EVAL_DIR / "generated", 3)


class PipelineIsolationTests(unittest.TestCase):
    def test_train_cli_never_imports_the_detector_or_the_analyzer(self) -> None:
        source = Path(train.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree) if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        for forbidden in ("anomaly_detector", "log_analyzer", "rules_syslog",
                          "rule_context", "normalize"):
            self.assertNotIn(forbidden, imported)
        self.assertIn("subprocess", imported,
                      "ingestion must go through the real analyzer as a subprocess")
        self.assertIn("--rules-only", source)

    def test_training_output_is_refused_inside_the_eval_corpus(self) -> None:
        with self.assertRaisesRegex(ValueError, "refusing training output"):
            train._assert_isolated(train.EVAL_DIR / "models")

    def test_the_eval_corpus_is_never_read_by_the_pipeline(self) -> None:
        source = Path(train.__file__).read_text(encoding="utf-8")
        self.assertNotIn("tests/eval/run_eval", source)
        self.assertNotIn("manifest.json\"", source.replace("*.manifest.json", ""))


class LabellingTests(unittest.TestCase):
    def test_a_scenario_with_no_malicious_lines_hands_over_its_declared_class(self) -> None:
        manifest = {"scenario_class": "benign-expected", "malicious_lines": []}
        finding = {"rule_id": "error_rate_spike", "evidence": "lines 2-7"}
        self.assertEqual(train.label_for_finding(finding, manifest), "benign-expected")
        manifest = {"scenario_class": "false-positive", "malicious_lines": []}
        self.assertEqual(train.label_for_finding(finding, manifest), "false-positive")

    def test_in_a_positive_scenario_the_manifest_citations_decide(self) -> None:
        manifest = {
            "scenario_class": "confirmed",
            "malicious_lines": [{"line": 3, "raw": "Failed password", "why": "x"}],
        }
        hit = {"rule_id": "auth_bruteforce", "timeline": [{"line": 3}]}
        miss = {"rule_id": "disk_pressure", "timeline": [{"line": 99}]}
        self.assertEqual(train.label_for_finding(hit, manifest), "confirmed")
        self.assertEqual(train.label_for_finding(miss, manifest), "false-positive")

    def test_every_produced_label_is_in_the_e0_disposition_vocabulary(self) -> None:
        org = org_context.load_org_context()
        with tempfile.TemporaryDirectory() as tmp:
            rows, stats = train.generated_rows(
                seed=4242, variants=1, formats=("canonical",),
                scenarios=tuple(generator.SCENARIOS), workdir=Path(tmp),
                org=org, verbose=False)
        self.assertTrue(rows)
        self.assertEqual(stats["logsIngested"], len(generator.SCENARIOS))
        for row in rows:
            self.assertIn(row["label"], triage_model.LABELS)
            self.assertEqual(row["origin"], "generated")
        self.assertGreaterEqual(len({r["label"] for r in rows}), 2)


class DispositionJoinTests(unittest.TestCase):
    """Real dispositions become labels; unlabelled incidents never do."""

    def _store(self, tmp: Path) -> Path:
        path = tmp / "incidents.json"
        path.write_text(json.dumps({
            "inc-a": {"id": "inc-a", "ruleIds": ["auth_bruteforce"],
                      "entity": "10.0.0.9", "entityKind": "ip",
                      "entityValues": ["10.0.0.9"], "findingCount": 3,
                      "criticality": "crown-jewel", "severity": "HIGH",
                      "disposition": "confirmed"},
            "inc-b": {"id": "inc-b", "ruleIds": ["error_rate_spike"],
                      "entity": "api-01", "entityKind": "host",
                      "findingCount": 1, "severity": "MEDIUM",
                      "disposition": "benign-expected"},
            "inc-c": {"id": "inc-c", "ruleIds": ["port_scan"],
                      "entity": "srv9", "entityKind": "host",
                      "findingCount": 1, "severity": "LOW",
                      "disposition": None},
        }), encoding="utf-8")
        return path

    def test_only_dispositioned_incidents_become_rows(self) -> None:
        org = org_context.load_org_context()
        with tempfile.TemporaryDirectory() as tmp:
            rows, stats = train.disposition_rows(org, self._store(Path(tmp)))
        self.assertEqual(stats["storedIncidents"], 3)
        self.assertEqual(stats["dispositioned"], 2)
        self.assertEqual(stats["undispositionedSkipped"], 1)
        self.assertEqual({r["label"] for r in rows},
                         {"confirmed", "benign-expected"})
        self.assertTrue(all(r["origin"] == "incident-disposition" for r in rows))

    def test_a_missing_store_is_an_honest_zero_not_an_error(self) -> None:
        org = org_context.load_org_context()
        with tempfile.TemporaryDirectory() as tmp:
            rows, stats = train.disposition_rows(org, Path(tmp) / "nope.json")
        self.assertEqual(rows, [])
        self.assertFalse(stats["storePresent"])
        self.assertEqual(stats["rows"], 0)

    def test_the_disposition_is_the_label_and_never_a_feature(self) -> None:
        org = org_context.load_org_context()
        with tempfile.TemporaryDirectory() as tmp:
            rows, _stats = train.disposition_rows(org, self._store(Path(tmp)))
        for row in rows:
            self.assertNotIn("disposition", row["record"])
            poisoned = dict(row["record"], disposition="false-positive",
                            dispositionReason="rank me down")
            self.assertEqual(triage_model.features(poisoned),
                             triage_model.features(row["record"]))

    def test_the_local_event_store_is_observed_context_only(self) -> None:
        context = train.observed_event_store(Path("/nonexistent/soc_history.db"))
        self.assertFalse(context["present"])
        self.assertFalse(context["usedForTraining"])
        self.assertEqual(context["events"], 0)
        self.assertIn("no label is inferred", context["note"])


class SharedFeatureTests(unittest.TestCase):
    """One features() function, and it is the same one on both sides."""

    RECORD = {
        "rule_id": "auth_bruteforce", "source": "detector", "occurrences": 7,
        "entities": {"ip": "203.0.113.44", "user": "admin"},
        "timeline": [{"ts": "2026-08-30T02:16:41+00:00", "line": 2},
                     {"ts": "2026-08-30T02:16:47+00:00", "line": 8}],
        "host": "server-01", "criticality": "crown-jewel",
    }

    def test_train_and_inference_call_the_same_function(self) -> None:
        self.assertIs(train.triage_model.features, triage_model.features)
        source = Path(train.__file__).read_text(encoding="utf-8")
        self.assertIn("triage_model.feature_vector", source)
        self.assertNotIn("def features(", source)

    def test_no_forbidden_key_can_move_the_vector(self) -> None:
        baseline = triage_model.feature_vector(self.RECORD)
        for key in sorted(triage_model.FORBIDDEN_KEYS):
            for value in ("CRITICAL", "P1", True, 42, "confirmed"):
                poisoned = dict(self.RECORD)
                poisoned[key] = value
                self.assertEqual(triage_model.feature_vector(poisoned), baseline,
                                 f"{key}={value!r} leaked into the features")

    def test_the_finding_shape_and_the_incident_shape_both_score(self) -> None:
        incident = {
            "ruleIds": ["auth_bruteforce"], "entity": "203.0.113.44",
            "entityKind": "ip", "entityValues": ["203.0.113.44", "server-01"],
            "findingCount": 3, "criticality": "crown-jewel",
            "firstSeen": "2026-08-30T02:16:41+00:00",
            "lastSeen": "2026-08-30T02:16:47+00:00",
        }
        for record in (self.RECORD, incident):
            vector = triage_model.feature_vector(record)
            self.assertEqual(len(vector), len(triage_model.FEATURE_KEYS))
            self.assertTrue(all(isinstance(v, float) for v in vector))
        self.assertEqual(
            triage_model.features(incident)["criticality_rank"], 2.0)

    def test_features_are_deterministic_and_clock_free(self) -> None:
        self.assertEqual(triage_model.features(self.RECORD),
                         triage_model.features(dict(self.RECORD)))
        source = Path(triage_model.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        top_level = {
            alias.name.split(".")[0]
            for node in tree.body if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("sklearn", top_level,
                         "scikit-learn must stay a lazy, optional import")
        self.assertNotIn("random", top_level)


class ModelArtifactTests(unittest.TestCase):
    def test_a_missing_model_is_unavailable_with_a_named_reason(self) -> None:
        real = triage_model.MODEL_DIR
        try:
            with tempfile.TemporaryDirectory() as tmp:
                triage_model.MODEL_DIR = Path(tmp)
                triage_model.reset_cache()
                out = triage_model.predict({"rule_id": "x"}, "HIGH")
                self.assertFalse(out["modelAvailable"])
                self.assertIsNone(out["aiSeverity"])
                self.assertIsNone(out["confidence"])
                self.assertIsNone(out["agrees"])
                self.assertTrue(out["unavailableReason"])
        finally:
            triage_model.MODEL_DIR = real
            triage_model.reset_cache()

    @unittest.skipUnless(HAVE_SKLEARN, "scikit-learn is an optional dependency")
    def test_a_small_real_train_writes_a_loadable_provenanced_model(self) -> None:
        org = org_context.load_org_context()
        with tempfile.TemporaryDirectory() as work, \
                tempfile.TemporaryDirectory() as models:
            rows, dataset = train.build_dataset(
                seed=777, variants=2, formats=("canonical",),
                scenarios=tuple(generator.SCENARIOS), workdir=Path(work),
                verbose=False)
            self.assertGreater(dataset["totalRows"], 10)
            model, cv = train.train(rows, seed=777, folds=3)
            self.assertEqual(cv["folds"], min(3, min(dataset["byLabel"].values())))
            self.assertEqual(len(cv["perFold"]), cv["folds"])
            for fold in cv["perFold"]:
                self.assertGreaterEqual(fold["macroF1"], 0.0)
                self.assertLessEqual(fold["macroF1"], 1.0)
            provenance = {"featureKeys": list(triage_model.FEATURE_KEYS),
                          "seed": 777, "datasetRows": dataset["totalRows"],
                          "crossValidation": cv}
            path, prov_path = train.save(model, provenance, Path(models))
            self.assertTrue(path.is_file() and prov_path.is_file())

            real = triage_model.MODEL_DIR
            try:
                triage_model.MODEL_DIR = Path(models)
                triage_model.reset_cache()
                out = triage_model.predict(SharedFeatureTests.RECORD, "HIGH")
                self.assertTrue(out["modelAvailable"])
                self.assertIn(out["aiLabel"], triage_model.LABELS)
                self.assertIsInstance(out["confidence"], float)
                self.assertIn(out["status"], ("agrees", "disagrees"))

                # corrupt it: the loader must refuse, not score anyway
                path.write_bytes(path.read_bytes() + b"tamper")
                triage_model.reset_cache()
                refused = triage_model.predict(SharedFeatureTests.RECORD, "HIGH")
                self.assertFalse(refused["modelAvailable"])
                self.assertIn("integrity", refused["unavailableReason"])
            finally:
                triage_model.MODEL_DIR = real
                triage_model.reset_cache()
        self.assertEqual(org.get_criticality("server-01"), "crown-jewel")

    @unittest.skipUnless(HAVE_SKLEARN, "scikit-learn is an optional dependency")
    def test_cross_validation_uses_balanced_weights_and_reports_every_fold(self) -> None:
        source = Path(train.__file__).read_text(encoding="utf-8")
        self.assertIn("StratifiedKFold", source)
        self.assertIn('compute_sample_weight("balanced"', source)


if __name__ == "__main__":
    unittest.main()
