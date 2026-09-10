#!/usr/bin/env python3
"""Independent, stdlib-only contract tests for Stage E card E7a.

These tests treat the merged E7a implementation as a fixed black/grey-box
contract.  They do not train a model, need scikit-learn, or edit the eval
corpus.  Generator batches still cross the real ``log_analyzer.py --rules-only``
subprocess seam so the feature assertions cover records the shipped pipeline
actually produces.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import pickle
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "console"
for _path in (str(ROOT), str(CONSOLE)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import org_context  # noqa: E402
import precedent  # noqa: E402
import runbooks  # noqa: E402
import soc  # noqa: E402
import triage  # noqa: E402
import triage_model  # noqa: E402
from tools import train_triage  # noqa: E402


def canonical_bytes(value) -> bytes:
    """A stable, strict snapshot for JSON-shaped rule/analyst records."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def select(record, keys):
    return {key: record.get(key) for key in keys}


@contextmanager
def isolated_model_dir():
    original = triage_model.MODEL_DIR
    with tempfile.TemporaryDirectory(prefix="e7a-contract-model-") as tmp:
        triage_model.MODEL_DIR = Path(tmp)
        triage_model.reset_cache()
        try:
            yield Path(tmp)
        finally:
            triage_model.MODEL_DIR = original
            triage_model.reset_cache()


def write_sidecar(model_dir: Path, artifact: bytes, *, feature_keys=None,
                  recorded_hash=None, raw_sidecar=None):
    model_path = model_dir / triage_model.MODEL_NAME
    model_path.write_bytes(artifact)
    sidecar_path = model_dir / triage_model.PROVENANCE_NAME
    if raw_sidecar is not None:
        sidecar_path.write_text(raw_sidecar, encoding="utf-8")
    else:
        sidecar_path.write_text(json.dumps({
            "modelSha256": recorded_hash or hashlib.sha256(artifact).hexdigest(),
            "featureKeys": list(
                triage_model.FEATURE_KEYS if feature_keys is None else feature_keys
            ),
        }), encoding="utf-8")
    return model_path, sidecar_path


FINDING = {
    "id": "finding-auth-1",
    "type": "auth_bruteforce",
    "rule_id": "auth_bruteforce",
    "source": "detector",
    "prov": "RULE-CAUGHT",
    "occurrences": 9,
    "lines": [{"n": 2, "raw": "real line 2"},
              {"n": 10, "raw": "real line 10"}],
    "entities": {
        "ip": "203.0.113.44", "user": "admin", "port": 49152,
    },
    "timeline": [
        {"ts": "2026-08-30T02:16:41+00:00", "line": 2},
        {"ts": "2026-08-30T02:18:41+00:00", "line": 10},
    ],
    "host": "server-01",
    "hostDerived": True,
    "criticality": "crown-jewel",
    "mitre": [{"id": "T1110", "name": "Brute Force",
               "tactic": "Credential Access"}],
    "sev": "HIGH",
    "ruleSev": "HIGH",
    "title": "Rule-owned finding display title",
    "ruleWhy": "Rule-owned display explanation",
    "stamp": "2026-08-30T02:16:41+00:00",
    "chips": [{"text": "203.0.113.44"}],
}

INCIDENT = {
    "id": "inc-e7a-contract",
    "runId": "run-e7a-contract",
    "entity": "203.0.113.44",
    "entityKind": "ip",
    "entityValues": ["203.0.113.44", "server-01"],
    "severity": "HIGH",
    "priority": "P1",
    "criticality": "crown-jewel",
    "priorityRationale": "rule severity plus asset criticality",
    "findingIds": ["finding-auth-1"],
    "findingCount": 1,
    "ruleIds": ["auth_bruteforce"],
    "techniques": [{"id": "T1110", "name": "Brute Force",
                    "tactic": "Credential Access"}],
    "firstSeen": "2026-08-30T02:16:41+00:00",
    "lastSeen": "2026-08-30T02:18:41+00:00",
    "state": "investigating",
    "acknowledgedAt": "2026-08-30T02:20:00+00:00",
    "resolvedAt": None,
    "disposition": None,
    "dispositionReason": None,
    "dispositionAt": None,
    "dispositionHistory": [],
    "origin": "rule",
    "cases": ["case-7"],
}

CASE_RECORD = {
    "id": "case-7",
    "title": "Investigate source 203.0.113.44",
    "status": "investigating",
    "notes": "Analyst-entered notes",
    "assignee": "analyst@example.test",
    "createdAt": "2026-08-30T02:21:00+00:00",
    "updatedAt": "2026-08-30T02:22:00+00:00",
    "activity": [{"kind": "note", "text": "reviewed evidence"}],
    "observables": [{"id": "obs-1", "type": "ip",
                     "value": "203.0.113.44"}],
    "attachments": [],
    "links": {"findings": ["finding-auth-1"],
              "incidents": ["inc-e7a-contract"], "cases": []},
}


FIELD_CATEGORIES = {
    "disposition": {
        "disposition", "dispositionReason", "dispositionAt",
        "dispositionHistory",
    },
    "advisory": {
        "aiTriage", "aiSeverity", "aiConfidence", "aiAgrees", "aiLabel",
        "modelSeverity", "modelLabel", "modelConfidence", "advisory",
        "llmSev", "llmWhy", "llm", "modelFindings", "similarityNote",
        "precedentOpinion", "proposalDraft",
    },
    "prose": {
        "title", "summary", "evidence", "rationale", "ruleWhy",
        "explanation", "narrative", "hypothesis", "rca", "prose", "notes",
        "note", "recommended_action", "predicate", "dispositionNote",
    },
    "severity": {
        "sev", "ruleSev", "severity", "severityOverride", "sevOverride",
        "analystSeverity",
    },
    "priority": {"priority", "priorityRationale", "priorityRank"},
    "eligibility": {
        "eligible", "eligibility", "eligibleRunbooks", "ineligibleReason",
    },
    "execution": {
        "executed", "executionState", "approvals", "approvalState",
        "actionState",
    },
}

MODEL_OUTPUT_KEYS = {
    "aiTriage", "aiSeverity", "aiConfidence", "aiAgrees", "aiLabel",
    "modelSeverity", "modelLabel", "modelConfidence", "confidence", "agrees",
    "modelAvailable", "modelProvenance", "unavailableReason",
}


class FeatureDeterminismTests(unittest.TestCase):
    def test_representative_finding_and_incident_shapes_are_deterministic(self):
        records = [
            FINDING,
            dict(FINDING, id="finding-error", type="error_rate_spike",
                 rule_id="error_rate_spike", occurrences=18,
                 entities={"host": "api-01"}, host="api-01",
                 criticality="standard"),
            dict(FINDING, id="finding-threat", type="malware_c2",
                 rule_id="malware_c2", occurrences=1,
                 entities={"ip": "198.51.100.9", "host": "ws-9"},
                 host="ws-9", criticality="low"),
            INCIDENT,
            dict(INCIDENT, id="inc-host", entity="api-01", entityKind="host",
                 entityValues=["api-01"], ruleIds=["error_rate_spike"],
                 findingCount=6, criticality="standard"),
        ]
        first = [triage_model.feature_vector(record) for record in records]
        second = [
            triage_model.feature_vector(json.loads(json.dumps(record)))
            for record in records
        ]
        self.assertEqual(first, second)
        self.assertEqual(len(first), 5)
        self.assertGreaterEqual(len({tuple(vector) for vector in first}), 4)
        for record, vector in zip(records, first):
            with self.subTest(record=record.get("id")):
                feature_map = triage_model.features(copy.deepcopy(record))
                self.assertEqual(tuple(feature_map), triage_model.FEATURE_KEYS)
                self.assertEqual(
                    vector,
                    [float(feature_map[key]) for key in triage_model.FEATURE_KEYS],
                )
                self.assertTrue(all(isinstance(value, float) for value in vector))

        # Non-vacuous controls: permitted facts really do drive the vector.
        self.assertNotEqual(
            triage_model.feature_vector(FINDING),
            triage_model.feature_vector(dict(FINDING, occurrences=90)),
        )
        # E7b AMENDMENT (pre-authorised, guardrail 10). This control used to
        # move `criticality`. E7b removed `criticality_rank` from the feature
        # schema - it carried 0.4146 importance with an INVERTED direction and
        # was the whole cause of the finding-level recall defect - so moving
        # `criticality` can no longer move the vector, and the old control
        # would pass vacuously in the one direction it was written to catch.
        # It is substituted here, NOT weakened: the same INCIDENT record, the
        # same assertion, moved onto another PERMITTED observed fact
        # (`techniques` -> `mitre_technique_count`). The non-vacuity check
        # still bites. No FORBIDDEN_KEYS or leakage assertion is touched.
        self.assertNotEqual(
            triage_model.feature_vector(INCIDENT),
            triage_model.feature_vector(dict(INCIDENT, techniques=[])),
        )
        # And the removal itself is locked down, so it cannot silently return.
        self.assertNotIn("criticality_rank", triage_model.FEATURE_KEYS)
        self.assertEqual(
            triage_model.feature_vector(INCIDENT),
            triage_model.feature_vector(dict(INCIDENT, criticality="low")),
        )

    def test_real_generator_batches_repeat_across_three_seeds_and_classes(self):
        scenarios = ("INC-4a7f", "near-miss-auth", "benign-maintenance")
        expected_labels = {"confirmed", "false-positive", "benign-expected"}
        with tempfile.TemporaryDirectory(prefix="e7a-gen-a-") as tmp_a, \
                tempfile.TemporaryDirectory(prefix="e7a-gen-b-") as tmp_b:
            org = org_context.load_org_context()
            rows_a, stats_a = train_triage.generated_rows(
                4100, 3, ("canonical",), scenarios, Path(tmp_a), org,
                verbose=False,
            )
            rows_b, stats_b = train_triage.generated_rows(
                4100, 3, ("canonical",), scenarios, Path(tmp_b), org,
                verbose=False,
            )

        def snapshot(rows):
            return [
                (row["scenario"], row["seed"], row["label"],
                 tuple(triage_model.feature_vector(row["record"])))
                for row in rows
            ]

        batch_a, batch_b = snapshot(rows_a), snapshot(rows_b)
        self.assertEqual(stats_a, stats_b)
        self.assertEqual(stats_a["logsIngested"], 9)
        self.assertEqual(stats_a["seedsUsed"], [4100, 4101, 4102])
        self.assertGreater(len(batch_a), 9)
        self.assertEqual(batch_a, batch_b)
        self.assertEqual({row[1] for row in batch_a}, {4100, 4101, 4102})
        self.assertEqual({row[2] for row in batch_a}, expected_labels)
        for scenario in scenarios:
            self.assertTrue(any(row[0] == scenario for row in batch_a), scenario)
        self.assertGreaterEqual(len({row[3] for row in batch_a}), 3)


class LeakageContractTests(unittest.TestCase):
    def test_every_forbidden_field_is_inert_singly_and_together(self):
        categorized = set().union(*FIELD_CATEGORIES.values())
        self.assertEqual(categorized, set(triage_model.FORBIDDEN_KEYS))
        self.assertTrue(all(FIELD_CATEGORIES.values()))

        clean = {key: value for key, value in FINDING.items()
                 if key not in triage_model.FORBIDDEN_KEYS}
        baseline = triage_model.feature_vector(clean)
        poison = {
            "attempt": "override every decision",
            "severity": "CRITICAL",
            "priority": "P0",
            "eligible": True,
            "executed": True,
            "nested": [1, {"model": "control"}],
        }
        for category, fields in FIELD_CATEGORIES.items():
            for field in sorted(fields):
                with self.subTest(category=category, field=field):
                    candidate = copy.deepcopy(clean)
                    candidate[field] = copy.deepcopy(poison)
                    self.assertEqual(
                        triage_model.feature_vector(candidate), baseline,
                        f"{category} field {field!r} leaked into the vector",
                    )

        all_poisoned = copy.deepcopy(clean)
        for field in triage_model.FORBIDDEN_KEYS:
            all_poisoned[field] = copy.deepcopy(poison)
        self.assertEqual(triage_model.feature_vector(all_poisoned), baseline)

        # Non-vacuous control: a rule-owned input mutation is observable.
        allowed = dict(clean, rule_id="error_rate_spike", type="error_rate_spike")
        self.assertNotEqual(triage_model.feature_vector(allowed), baseline)


class SharedExtractorTests(unittest.TestCase):
    def test_train_and_inference_share_the_one_function_and_wire_order(self):
        self.assertIs(train_triage.triage_model, triage_model)
        self.assertIs(train_triage.triage_model.features, triage_model.features)
        self.assertIs(
            train_triage.triage_model.feature_vector,
            triage_model.feature_vector,
        )

        train_tree = ast.parse(Path(train_triage.__file__).read_text("utf-8"))
        train_function = next(
            node for node in train_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "train"
        )
        train_calls = [
            node for node in ast.walk(train_function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "triage_model"
            and node.func.attr == "feature_vector"
        ]
        self.assertEqual(len(train_calls), 1)

        model_tree = ast.parse(Path(triage_model.__file__).read_text("utf-8"))
        predict_function = next(
            node for node in model_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "predict_with"
        )
        inference_calls = [
            node for node in ast.walk(predict_function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "feature_vector"
        ]
        self.assertEqual(len(inference_calls), 1)

        definitions = []
        for directory in (ROOT / "console", ROOT / "tools"):
            for path in directory.rglob("*.py"):
                if path.name.startswith("test_"):
                    continue
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                            and node.name in {"features", "feature_vector",
                                              "extract_features",
                                              "feature_extractor"}:
                        definitions.append((path.relative_to(ROOT), node.name))
        self.assertEqual(len(definitions), 2)
        self.assertEqual(set(definitions), {
            (Path("console/triage_model.py"), "features"),
            (Path("console/triage_model.py"), "feature_vector"),
        })

        class CapturingEstimator:
            classes_ = list(triage_model.LABELS)

            def __init__(self):
                self.rows = None

            def predict_proba(self, rows):
                self.rows = rows
                return [[0.8, 0.1, 0.1]]

        estimator = CapturingEstimator()
        expected = triage_model.feature_vector(FINDING)
        triage_model.predict_with(estimator, FINDING, "HIGH")
        self.assertEqual(estimator.rows, [expected])
        self.assertEqual(
            expected,
            [triage_model.features(FINDING)[key]
             for key in triage_model.FEATURE_KEYS],
        )


class PredictionContractTests(unittest.TestCase):
    class StubEstimator:
        classes_ = list(triage_model.LABELS)

        def __init__(self, label, confidence):
            self.label = label
            self.confidence = confidence
            self.rows = None

        def predict_proba(self, rows):
            self.rows = copy.deepcopy(rows)
            remainder = (1.0 - self.confidence) / (len(self.classes_) - 1)
            return [[self.confidence if label == self.label else remainder
                     for label in self.classes_] for _row in rows]

    def test_all_three_loaded_classes_have_numeric_visible_contracts(self):
        expectations = {
            "confirmed": (0.91, "HIGH", True, "agrees"),
            "false-positive": (0.82, "INFO", False, "disagrees"),
            "benign-expected": (0.73, "LOW", False, "disagrees"),
        }
        before = canonical_bytes(FINDING)
        for label, (confidence, severity, agrees, status) in expectations.items():
            with self.subTest(label=label):
                estimator = self.StubEstimator(label, confidence)
                result = triage_model.predict_with(
                    estimator, FINDING, "HIGH",
                    {"trainedAt": "2026-09-02T00:00:00+00:00", "seed": 17,
                     "datasetRows": 33, "modelSha256": "abc",
                     "sklearnVersion": "stub"},
                )
                self.assertTrue(result["modelAvailable"])
                self.assertEqual(result["aiLabel"], label)
                self.assertEqual(result["aiSeverity"], severity)
                self.assertIs(result["agrees"], agrees)
                self.assertEqual(result["status"], status)
                self.assertIsInstance(result["confidence"], float)
                self.assertEqual(result["confidence"], confidence)
                self.assertEqual(
                    estimator.rows, [triage_model.feature_vector(FINDING)],
                )
                self.assertIn("ADVISORY", result["note"])
        self.assertEqual(canonical_bytes(FINDING), before)

    def test_estimator_without_probability_is_refused(self):
        class NoProbability:
            classes_ = list(triage_model.LABELS)

            @staticmethod
            def predict(rows):
                return ["confirmed" for _row in rows]

        with self.assertRaisesRegex(triage_model.ModelUnavailable,
                                    "confidence|probability"):
            triage_model.predict_with(NoProbability(), FINDING, "HIGH")


class UnavailableContractTests(unittest.TestCase):
    def assert_honest_unavailable(self, result, reason_fragment):
        self.assertFalse(result["modelAvailable"])
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["aiSeverity"])
        self.assertIsNone(result["aiLabel"])
        self.assertIsNone(result["confidence"])
        self.assertIsNone(result["agrees"])
        self.assertIsNone(result["modelProvenance"])
        self.assertIn(reason_fragment, result["unavailableReason"].lower())

    def test_every_artifact_and_dependency_failure_is_honest(self):
        opaque_pickle = pickle.dumps({"not": "an estimator"})
        cases = (
            ("missing model", "model", lambda _path: None),
            ("missing sidecar", "provenance",
             lambda path: (path / triage_model.MODEL_NAME).write_bytes(
                 opaque_pickle)),
            ("malformed sidecar", "unreadable",
             lambda path: write_sidecar(path, opaque_pickle,
                                         raw_sidecar="{malformed")),
            ("feature schema mismatch", "feature schema",
             lambda path: write_sidecar(
                 path, opaque_pickle,
                 feature_keys=tuple(reversed(triage_model.FEATURE_KEYS)))),
            ("hash mismatch", "integrity",
             lambda path: write_sidecar(path, opaque_pickle,
                                         recorded_hash="0" * 64)),
            ("corrupt artifact with matching hash", "did not load",
             lambda path: write_sidecar(path, b"this is not a pickle")),
        )
        for name, reason, arrange in cases:
            with self.subTest(name=name), isolated_model_dir() as model_dir:
                arrange(model_dir)
                triage_model.reset_cache()
                with mock.patch.object(triage_model, "sklearn_version",
                                       return_value="stub-installed"):
                    result = triage_model.predict(FINDING, "HIGH")
                self.assert_honest_unavailable(result, reason)

        with isolated_model_dir() as model_dir:
            write_sidecar(model_dir, opaque_pickle)
            triage_model.reset_cache()
            with mock.patch.object(triage_model, "sklearn_version",
                                   return_value=None):
                result = triage_model.predict(FINDING, "HIGH")
            self.assert_honest_unavailable(result, "scikit-learn")


class DecisionWallSnapshotTests(unittest.TestCase):
    @staticmethod
    def loaded_opinion(record, rule_severity):
        return triage_model.predict_with(
            PredictionContractTests.StubEstimator("false-positive", 0.88),
            record, rule_severity,
        )

    def test_attach_and_model_kill_leave_rule_incident_and_case_bytes_intact(self):
        finding = copy.deepcopy(FINDING)
        incident = copy.deepcopy(INCIDENT)
        case = copy.deepcopy(CASE_RECORD)
        finding_before = canonical_bytes(finding)
        incident_before = canonical_bytes(incident)
        case_before = canonical_bytes(case)

        finding_rule_keys = runbooks.RULE_OWNED_FINDING_KEYS
        decision_keys = {
            "severity", "priority", "criticality", "priorityRationale",
            "state", "acknowledgedAt", "resolvedAt", "disposition",
            "dispositionReason", "dispositionAt", "dispositionHistory",
            "origin", "cases",
        }
        finding_projection = canonical_bytes(select(finding, finding_rule_keys))
        incident_decisions = canonical_bytes(select(incident, decision_keys))
        public_case = canonical_bytes(soc._public_case(case))

        with mock.patch.object(triage_model, "predict",
                               side_effect=self.loaded_opinion):
            attached = triage.attach(finding)
            public_loaded = soc._public_incident(incident)
        self.assertIn("aiTriage", attached)
        self.assertTrue(public_loaded["aiTriage"]["modelAvailable"])
        self.assertEqual(canonical_bytes(finding), finding_before)
        self.assertEqual(canonical_bytes(incident), incident_before)
        self.assertEqual(canonical_bytes(case), case_before)
        self.assertEqual(
            canonical_bytes(select(attached, finding_rule_keys)),
            finding_projection,
        )
        self.assertEqual(
            canonical_bytes(select(public_loaded, decision_keys)),
            incident_decisions,
        )

        with isolated_model_dir():
            with mock.patch.object(triage_model, "sklearn_version",
                                   return_value="stub-installed"):
                killed_finding = triage.attach(finding)
                killed_incident = soc._public_incident(incident)
        self.assertFalse(killed_finding["aiTriage"]["modelAvailable"])
        self.assertFalse(killed_incident["aiTriage"]["modelAvailable"])
        self.assertEqual(
            canonical_bytes(select(killed_finding, finding_rule_keys)),
            finding_projection,
        )
        self.assertEqual(
            canonical_bytes(select(killed_incident, decision_keys)),
            incident_decisions,
        )
        self.assertEqual(canonical_bytes(soc._public_case(case)), public_case)
        self.assertEqual(canonical_bytes(finding), finding_before)
        self.assertEqual(canonical_bytes(incident), incident_before)
        self.assertEqual(canonical_bytes(case), case_before)

    def test_eligibility_and_protected_projections_reject_model_output(self):
        finding = copy.deepcopy(FINDING)
        incident = copy.deepcopy(INCIDENT)
        book = runbooks.load_runbooks()["rb-block-ip"]
        baseline_verdict = runbooks.eligible(book, incident, [finding])
        baseline_facts = runbooks._rule_facts(incident, [finding])
        baseline_precedent = precedent.facts(incident)
        self.assertTrue(baseline_verdict["eligible"])

        poisoned_incident = copy.deepcopy(incident)
        poisoned_finding = copy.deepcopy(finding)
        poison = {"severity": "INFO", "eligible": False, "executed": True}
        for key in MODEL_OUTPUT_KEYS | runbooks.ADVISORY_KEYS:
            poisoned_incident[key] = copy.deepcopy(poison)
            poisoned_finding[key] = copy.deepcopy(poison)

        self.assertEqual(
            canonical_bytes(runbooks.eligible(
                book, poisoned_incident, [poisoned_finding])),
            canonical_bytes(baseline_verdict),
        )
        self.assertEqual(
            canonical_bytes(runbooks._rule_facts(
                poisoned_incident, [poisoned_finding])),
            canonical_bytes(baseline_facts),
        )
        self.assertEqual(
            canonical_bytes(precedent.facts(poisoned_incident)),
            canonical_bytes(baseline_precedent),
        )
        projected_incident, projected_findings = runbooks._rule_facts(
            poisoned_incident, [poisoned_finding],
        )
        self.assertFalse(MODEL_OUTPUT_KEYS & set(projected_incident))
        self.assertFalse(MODEL_OUTPUT_KEYS & set(projected_findings[0]))

        # Non-vacuous controls: protected rule facts still control the answer.
        low = dict(incident, severity="INFO")
        self.assertNotEqual(
            canonical_bytes(runbooks.eligible(book, low, [finding])),
            canonical_bytes(baseline_verdict),
        )
        changed_finding = dict(finding, type="unrelated_rule")
        self.assertNotEqual(
            canonical_bytes(runbooks._rule_facts(incident, [changed_finding])),
            canonical_bytes(baseline_facts),
        )


class PersistenceContractTests(unittest.TestCase):
    def test_model_output_cannot_enter_incident_store(self):
        finding = copy.deepcopy(FINDING)
        poison = {
            "advisory": True,
            "aiSeverity": "CRITICAL",
            "aiLabel": "confirmed",
            "confidence": 1.0,
            "agrees": False,
            "executionState": "executed",
        }
        finding["aiTriage"] = copy.deepcopy(poison)
        finding["aiSeverity"] = "CRITICAL"
        finding["aiConfidence"] = 1.0
        state = {"runId": "run-e7a-persistence", "findings": [finding]}
        before = canonical_bytes(state)

        original_soc_dir = soc.SOC_DIR
        try:
            with tempfile.TemporaryDirectory(prefix="e7a-contract-soc-") as tmp:
                soc.SOC_DIR = Path(tmp)
                stored = soc.sync_incidents(state)
                disk = json.loads(
                    (Path(tmp) / "incidents.json").read_text(encoding="utf-8")
                )
        finally:
            soc.SOC_DIR = original_soc_dir

        self.assertEqual(canonical_bytes(state), before)
        self.assertEqual(canonical_bytes(stored), canonical_bytes(disk))
        self.assertTrue(disk, "control: a real derived incident must be stored")

        def keys_in(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key
                    yield from keys_in(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys_in(child)

        persisted_keys = set(keys_in(disk))
        self.assertFalse(MODEL_OUTPUT_KEYS & persisted_keys)
        self.assertFalse(runbooks.ADVISORY_KEYS & persisted_keys)
        only_incident = next(iter(disk.values()))
        self.assertEqual(only_incident["severity"], "HIGH")
        self.assertEqual(only_incident["priority"], "P1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
