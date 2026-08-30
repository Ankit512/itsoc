import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BATTLECARD = ROOT / "docs" / "BATTLECARD_TORQ.md"
CITATIONS = ROOT / "docs" / "research" / "CITATIONS.md"
SCOPE = (
    "measured against synthetic ground-truth scenarios; "
    "not a claim about production traffic."
)


class BattlecardEfficacyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.battlecard = BATTLECARD.read_text(encoding="utf-8")
        cls.citations = CITATIONS.read_text(encoding="utf-8")

    def test_scope_and_literature_guardrails_are_present(self):
        self.assertIn(SCOPE, self.battlecard)
        self.assertIn("~3.8%", self.battlecard)
        self.assertIn("2604.19533", self.battlecard)
        # The legacy C-1 and Cut List retain the phrase only to prohibit this
        # unsupported inversion; it is never asserted as an efficacy result.
        self.assertIn('never inverted into "LLMs miss 96%"', self.battlecard)
        self.assertIn('CUT: "LLMs miss 96% of attacks"', self.battlecard)

    def test_repo_evidence_entry_names_harness_and_reproduction_metadata(self):
        self.assertIn("## C-2", self.citations)
        self.assertIn("efficacy_harness", self.citations)
        self.assertTrue(
            "run date" in self.citations.lower()
            or "python3 tools/efficacy_harness.py" in self.citations
        )

    def test_canonical_harness_scenario_totals_appear_in_battlecard(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "harness.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "efficacy_harness.py"),
                    "--json",
                    str(output),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(
            ["INC-4a7f", "failure-success", "error-burst"],
            [scenario["scenario"] for scenario in result["scenarios"]],
        )
        for scenario in result["scenarios"]:
            totals = scenario["totals"]
            row = (
                f'| `{scenario["scenario"]}` | `canonical` | '
                f'{totals["precision"]} | {totals["recall"]} | '
                f'{totals["f1"]} | '
                f'{totals["malicious_lines_detected"]} / '
                f'{totals["malicious_lines"]} | {totals["missed_lines"]} |'
            )
            self.assertIn(row, self.battlecard)


if __name__ == "__main__":
    unittest.main()
