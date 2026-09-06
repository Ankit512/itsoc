import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
# The frozen referee is imported (never edited) so this test asserts against the
# REAL contract — the scenario tuple and seed tuple the benchmark actually owns —
# instead of a hard-coded list that goes stale the next time either moves.
sys.path[:0] = [str(ROOT)]
from tools.efficacy_harness import BENCHMARK_SCENARIOS, BENCHMARK_SEEDS

BATTLECARD = ROOT / "docs" / "BATTLECARD_TORQ.md"
CITATIONS = ROOT / "docs" / "research" / "CITATIONS.md"
SCOPE = (
    "measured against synthetic ground-truth scenarios; "
    "not a claim about production traffic."
)
CEILING = (
    "These scenarios are drawn from the same attack classes the rules were "
    "written for — the expected result is perfection, and its value is "
    "regression proof (any future score below 1.0 is a detected regression), "
    "not a general-efficacy claim."
)


def metric_cell(totals):
    """Render a P / R / F1 cell exactly as the referee renders it.

    Mirrors tools/efficacy_harness.py: where `precision_defined` /
    `recall_defined` is false the number is UNDEFINED, not a measured zero, and
    every surface prints `n/a`. A scenario with no malicious lines has no
    recall — printing 0.0 there would read as a detection failure.
    """
    precision = totals["precision"] if totals.get("precision_defined", True) else "n/a"
    recall = totals["recall"] if totals.get("recall_defined", True) else "n/a"
    f1 = (totals["f1"] if totals.get("precision_defined", True)
          and totals.get("recall_defined", True) else "n/a")
    return f"{precision} / {recall} / {f1}"


class BattlecardEfficacyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.battlecard = BATTLECARD.read_text(encoding="utf-8")
        cls.citations = CITATIONS.read_text(encoding="utf-8")

    def test_scope_and_literature_guardrails_are_present(self):
        self.assertIn(SCOPE, self.battlecard)
        self.assertIn(CEILING, self.battlecard)
        self.assertIn(CEILING, self.citations)
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

    def test_harness_runs_the_frozen_scenario_tuple_once_per_benchmark_seed(self):
        """The benchmark's SHAPE is the invariant, not eighteen literal strings.

        The referee freezes BENCHMARK_SCENARIOS (E8m2) and BENCHMARK_SEEDS (E8).
        A default run is therefore exactly that tuple, in declaration order,
        once per seed, in seed order. Asserting the structure rather than the
        literals means a legitimate scenario or seed addition moves this test
        with the referee instead of breaking it — which is precisely how the
        previous three-scenario, single-seed assertion rotted unnoticed.
        """
        result = self.harness_result()
        self.assertEqual(
            [(scenario, seed)
             for seed in BENCHMARK_SEEDS
             for scenario in BENCHMARK_SCENARIOS],
            [(run["scenario"], run["seed"]) for run in result["scenarios"]],
        )
        # Every default run is the canonical formatter; §3.1a is labelled as a
        # canonical-format measurement and the scope label depends on it.
        self.assertEqual({"canonical"},
                         {run["format"] for run in result["scenarios"]})

    def test_canonical_harness_scenario_totals_appear_in_battlecard(self):
        """§3.1a's published per-scenario table must equal what the harness produces.

        The table aggregates the three benchmark seeds into one row per
        scenario: the count columns sum, and the P / R / F1 cell is identical
        across seeds (it is asserted to be, below — a per-seed divergence would
        make a single published cell a lie, so it is a failure, not an average).
        """
        result = self.harness_result()
        runs_by_scenario = {}
        for run in result["scenarios"]:
            runs_by_scenario.setdefault(run["scenario"], []).append(run)

        rows = {}
        for line in self.battlecard.splitlines():
            if line.startswith("| `") and line.endswith(" |"):
                cells = [cell.strip() for cell in line.strip("|").split("|")]
                if len(cells) == 7:
                    rows.setdefault(cells[0].strip("`"), cells)

        for scenario in BENCHMARK_SCENARIOS:
            with self.subTest(scenario=scenario):
                runs = runs_by_scenario[scenario]
                self.assertEqual(len(BENCHMARK_SEEDS), len(runs))
                self.assertIn(scenario, rows,
                              f"§3.1a publishes no row for `{scenario}`")
                cells = rows[scenario]

                cell = {metric_cell(run["totals"]) for run in runs}
                self.assertEqual(
                    1, len(cell),
                    f"`{scenario}` renders different P/R/F1 per seed ({cell}); "
                    "one published cell cannot represent all three seeds.")

                classes = {run["scenario_class"] for run in runs}
                self.assertEqual({cells[1]}, classes)
                self.assertEqual(cells[2], cell.pop())
                self.assertEqual(
                    int(cells[3]),
                    sum(run["totals"]["false_positive_findings"] for run in runs))
                detected = sum(run["totals"]["malicious_lines_detected"] for run in runs)
                total = sum(run["totals"]["malicious_lines"] for run in runs)
                self.assertEqual(cells[6], f"{detected} / {total}")

                # The learned column is only assertable where a trained model
                # exists. Where it does not, the harness says so honestly and
                # this check reports a skip rather than a fabricated pass.
                if all(run["learned"].get("available") for run in runs):
                    learned = {metric_cell(run["learned"]["totals"]) for run in runs}
                    self.assertEqual(1, len(learned))
                    self.assertEqual(cells[4], learned.pop())
                    self.assertEqual(
                        int(cells[5]),
                        sum(run["learned"]["totals"]["false_positive_findings"]
                            for run in runs))
                else:
                    reason = runs[0]["learned"].get("reason", "no reason given")
                    print(f"  NOTE: learned column unverified for `{scenario}` "
                          f"— {reason}")

    def test_rollup_totals_match_the_harness(self):
        """The §3.1a rollup sentence is a published number; it is checked too."""
        result = self.harness_result()
        runs = len(BENCHMARK_SCENARIOS) * len(BENCHMARK_SEEDS)
        self.assertIn(
            f"**Rollup across {runs} scenario runs "
            f"({len(BENCHMARK_SCENARIOS)} scenarios × {len(BENCHMARK_SEEDS)} seeds):**",
            self.battlecard)
        self.assertIn(
            f"rules — **{result['total_misses']} missed malicious lines, "
            f"{result['total_false_positives']} false-positive findings**",
            self.battlecard)
        # The E8m scope label restates the same canonical-format FP count; the
        # two must not drift apart.
        self.assertIn(
            f"**Scope label (E8m).** The {result['total_false_positives']} "
            f"false positives above are the **`canonical`-format** total for "
            f"those {runs} runs.",
            self.battlecard)

    _harness_result = None

    @classmethod
    def harness_result(cls):
        """One default harness run, shared by the tests that read its output."""
        if cls._harness_result is None:
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
                cls._harness_result = json.loads(output.read_text(encoding="utf-8"))
        return cls._harness_result


if __name__ == "__main__":
    unittest.main()
