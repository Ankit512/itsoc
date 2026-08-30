"""Promotion-bar tests for the isolated synthetic attack generator."""

from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

from tools import attack_generator as generator


class AttackGeneratorTests(unittest.TestCase):
    def test_formatters_are_stable(self) -> None:
        event = generator.Event("2026-08-30T02:16:41Z", "WARN", "server-01", "message")
        self.assertEqual(generator.canonical(event), "2026-08-30T02:16:41Z WARN server-01 message")
        self.assertEqual(generator.rfc3164(event), "Aug 30 02:16:41 server-01 attack-generator: WARN message")
        self.assertEqual(generator.rfc5424(event), "<134>1 2026-08-30T02:16:41Z server-01 attack-generator - - - WARN message")
        self.assertEqual(generator.jsonlog(event), '{"host":"server-01","level":"WARN","message":"message","timestamp":"2026-08-30T02:16:41Z"}')

    def test_every_template_and_formatter_has_exact_manifest_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for scenario in generator.SCENARIOS:
                for format_name in generator.FORMATTERS:
                    log_path, manifest_path = generator.generate(scenario, format_name, Path(tmp))
                    lines = log_path.read_text(encoding="utf-8").splitlines()
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    labelled = manifest["malicious_lines"]
                    expected = generator.SCENARIOS[scenario]()
                    self.assertEqual(manifest["line_count"], len(lines))
                    self.assertEqual(manifest["malicious_count"], sum(e.malicious for e in expected))
                    self.assertEqual(len(labelled), manifest["malicious_count"])
                    self.assertEqual(
                        [(item["line"], item["raw"]) for item in labelled],
                        [(n, lines[n - 1]) for n, event in enumerate(expected, 1) if event.malicious],
                    )
                    self.assertTrue(all(item["why"] for item in labelled))

    def test_generation_is_byte_deterministic_and_does_not_import_detector(self) -> None:
        source = Path(generator.__file__).read_text(encoding="utf-8")
        imported = {
            alias.name for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Import) for alias in node.names
        } | {
            node.module for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertNotIn("anomaly_detector", imported)
        sys.modules.pop("anomaly_detector", None)
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            first = generator.generate("INC-4a7f", "canonical", Path(left))[0].read_bytes()
            second = generator.generate("INC-4a7f", "canonical", Path(right))[0].read_bytes()
        self.assertEqual(first, second)
        self.assertNotIn("anomaly_detector", sys.modules)

    def test_output_is_refused_in_eval_tree(self) -> None:
        with self.assertRaisesRegex(ValueError, "refusing generated output"):
            generator.generate("error-burst", "canonical", generator.EVAL_DIR / "generated")
        self.assertFalse(generator.DEFAULT_OUTPUT_DIR.resolve().is_relative_to(generator.EVAL_DIR.resolve()))

    def test_eval_suite_does_not_import_generator_or_generated_efficacy_data(self) -> None:
        for path in generator.EVAL_DIR.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertNotIn("attack_generator", text, str(path))
                self.assertNotIn("efficacy_", text, str(path))


if __name__ == "__main__":
    unittest.main()
