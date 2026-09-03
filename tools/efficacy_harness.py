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

E8 turns the harness into a **frozen referee**: it scores TWO explicit systems
— the rules, and the trained learned triage model — over the SAME fresh, seeded
generator scenarios, through the SAME :func:`score`/:func:`diff` path. There is
no second metric implementation anywhere in this file; the learned system is a
different *finding collection* fed to the identical scorer.

The referee owns benchmark seed selection (``BENCHMARK_SEEDS``) and all metric
logic. It reads the model's provenance sidecar before it scores anything, and it
fails hard — never quietly — if the benchmark and the training set share a seed
or a high-cardinality entity.

E8m is an owner-authorised, ADDITIVE amendment to that frozen referee. It moves
no seed, no remap, no freshness assertion and no metric: `score()`, `_ratio()`
and `diff()` are untouched and every number E8 published comes out
byte-identical. What it adds is publication of three things that were always
true and were never printed:

* **finding-level recall** beside line-level recall, for BOTH systems, each
  labelled with its denominator — and the verbatim list of findings a system
  dropped *while they cited malicious lines*, which line-level recall absorbs
  whenever a kept finding covers the same lines;
* **false-positive totals scoped to their formats** — the headline is every
  format the run measured, each single format published as a labelled subset,
  because a bare count is not a publishable number;
* the **criticality counterfactual** — `criticality_rank` re-forced across its
  whole real domain, measured live, published as a first-class finding.

Every number is scoped: it is measured against synthetic ground-truth scenarios;
it is not a claim about production traffic.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

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
        # Whether each ratio had a denominator at all. `_ratio` has always
        # returned 0.0 for 0/0 and that frozen behaviour is unchanged — these
        # two flags carry no arithmetic, they just say when the published 0.0 is
        # an UNDEFINED ratio rather than a measured zero, so a surface can render
        # "n/a" instead of a number that reads like a failure. A scenario with no
        # malicious lines has no recall; a system that produced no findings has
        # no precision.
        "precision_defined": (true_positives + false_positives) > 0,
        "recall_defined": malicious_total > 0,
    }


# The one sentence E8 adds beside SCOPE_SENTENCE. It is not a replacement for
# it and it is not the JSON `scope` field — both contracts stay as they were.
ADVISORY_SENTENCE = "the learned model is advisory; these numbers are why."

# --------------------------------------------------------------------------- #
# the frozen referee — seeds, entities, and what the two systems mean
# --------------------------------------------------------------------------- #
# THE REFEREE OWNS THESE. Neither the trainer, the console, nor the UI chooses a
# benchmark seed; they are frozen here so a later grader can diff this file and
# see immediately whether the benchmark was moved under the numbers.
#
# BENCHMARK_SEEDS were selected by exhaustive search over the generator so that
# every high-cardinality entity they produce (source IPs, change-window ids) is
# absent from every entity the E7a training seeds produce. The search is
# reproducible: generate each scenario at each seed and compare the extracted
# entity sets. The selection is asserted at run time against the model's ACTUAL
# recorded provenance, not against this comment.
BENCHMARK_SEEDS = (20270302, 20270303, 20270304)

# --------------------------------------------------------------------------- #
# E8m2 (2) — the benchmark's SCENARIO LIST is frozen here, not inherited
# --------------------------------------------------------------------------- #
# The benchmark used to default to `generator.SCENARIOS`, so any scenario added
# to `tools/attack_generator.py` silently changed what the frozen benchmark
# measured and made a before/after comparison meaningless. That was a hole in
# the freeze: the referee is supposed to own what is measured, and it did not
# own this. It does now. Adding a scenario to the generator has ZERO effect on
# benchmark output; measuring it requires either an explicit `--scenario` on the
# command line or a deliberate, reviewable edit to this tuple.
#
# These are exactly the six scenarios the benchmark measured before this
# amendment, in the generator's own declaration order, so no published number
# moves.
BENCHMARK_SCENARIOS = (
    "INC-4a7f",
    "failure-success",
    "error-burst",
    "near-miss-auth",
    "near-miss-errors",
    "benign-maintenance",
)

BENCHMARK_SCENARIO_NOTE = (
    "The benchmark's scenario set is frozen in the referee "
    "(`BENCHMARK_SCENARIOS`), not read from the generator. A scenario added to "
    "`tools/attack_generator.py` therefore cannot change what the benchmark "
    "measures, and before/after runs stay comparable; measuring a new scenario "
    "takes an explicit `--scenario` or a deliberate edit to the frozen tuple. "
    "`benchmark.scenarios` is what this run actually measured; "
    "`benchmark.frozenScenarios` is what the frozen set says, and the two "
    "differ only when a caller asked for something else on purpose."
)

# The E7a training sidecar's seed window, recorded here only so the DEFAULT
# benchmark set can be checked for disjointness without a model on disk. The
# binding check always uses the seeds the sidecar actually recorded.
E7A_TRAINING_SEEDS = tuple(range(20260902, 20260916))   # 20260902 .. 20260915

# What "the learned system found something" means. Stated here, carried in the
# artefact, and printed by `render()` — the reader never has to infer it.
MODEL_POSITIVE_LABELS = ("confirmed",)
MODEL_NEGATIVE_LABELS = ("false-positive", "benign-expected")
MODEL_INTERPRETATION = (
    "The two systems are scored on the SAME findings and the SAME manifest "
    "ground truth, through the same score()/diff() path. RULES-system findings "
    "are every finding log_analyzer.py --rules-only produced. LEARNED-system "
    "findings are that same collection after the trained triage model has given "
    "its opinion on each one: a `confirmed` prediction is a MODEL-POSITIVE "
    "finding and is kept; a `false-positive` or `benign-expected` prediction is "
    "MODEL-NEGATIVE and is dropped. Dropping a finding that cited real malicious "
    "lines therefore costs the learned system recall and shows up verbatim in "
    "its miss list; dropping a finding that cited none earns it precision. "
    "The model is never consulted about severity here and never writes one."
)

METRIC_DEFINEDNESS_NOTE = (
    "Precision is over findings and recall is over manifest malicious lines. A "
    "scenario whose ground truth has NO malicious lines has no recall to "
    "measure, and a system that produced no findings has no precision to "
    "measure. The frozen scorer still returns 0.0 there (0/0), so every result "
    "also carries `precision_defined` / `recall_defined`: where those are false "
    "the number is undefined, not a measured zero, and surfaces render n/a."
)

# --------------------------------------------------------------------------- #
# E8m — the amendment: what the frozen metrics did NOT say out loud
# --------------------------------------------------------------------------- #
# Owner-authorised, additive publication only. Nothing below changes
# BENCHMARK_SEEDS, the remap, the freshness assertion, `score()`, `_ratio()` or
# `diff()`. Every number E8 published comes out of this file byte-identical; the
# amendment publishes numbers that were always true and were never printed.

# Recall has always had TWO denominators, and only one of them was published.
# Both are now named wherever either is shown.
RECALL_DENOMINATOR_NOTE = (
    "Recall is published with its denominator, always. LINE-LEVEL recall is "
    "over the manifest's malicious LINES: how much of the labelled ground "
    "truth the system reached. FINDING-LEVEL recall is over the FINDINGS that "
    "cite at least one malicious line: how many of those findings the system "
    "still carries. They differ whenever a system drops a finding whose cited "
    "malicious lines another kept finding also covers — the line stays "
    "detected, the finding is gone, and line-level recall absorbs the loss. "
    "Every such dropped finding is listed verbatim in "
    "`dropped_true_findings`, exactly as a missed line is listed in `misses`."
)

# A false-positive count is meaningless without the formats it was measured
# over: the same seeds raise 21 across `canonical` alone and 84 across all four
# formatters. No count is ever printed here without its format scope.
FORMAT_SCOPE_NOTE = (
    "Every false-positive total is scoped to the formats it was measured over. "
    "The headline total is the sum across ALL formats this run measured; each "
    "single format is published beside it as an explicitly labelled subset. A "
    "bare count with no format scope is not a publishable number."
)

# The criticality counterfactual. This is a FIRST-CLASS published finding, not a
# footnote: `criticality_rank` is the model's single largest feature, and its
# influence runs opposite to operational intuition.
CRITICALITY_DOMAIN = ("low", "standard", "crown-jewel")
CRITICALITY_SENSITIVITY_NOTE = (
    "COUNTERFACTUAL, measured live on this run. Each finding is re-scored with "
    "`criticality_rank` forced across its whole real domain "
    "(low=0, standard=1, crown-jewel=2) and every other feature held exactly as "
    "measured; only the org-config criticality of the finding's host is moved. "
    "A finding is `flipping` when the model's keep/drop decision is not the "
    "same at all three bands. Direction is published as `kept_at`, per band. "
    "The model is MORE willing to dismiss a finding on a MORE critical asset: "
    "raising a host to crown-jewel flips true detections from KEPT to DROPPED, "
    "and lowering crown-jewel flips suppressions from DROPPED to KEPT. That is "
    "driven by an org-config value, not by log evidence. These are "
    "counterfactuals only — the benchmark hosts have fixed criticality and "
    "every published number above stands exactly as measured."
)


class _ForcedCriticality:
    """An org context that answers one criticality for every asset.

    The counterfactual seam. It satisfies the only method
    `train_triage.record_from_report_finding` calls on an org context
    (`get_criticality`), so forcing the feature needs no edit to the trainer,
    the model loader, `org_context`, or the shipped config — and the real org
    context is never mutated.
    """

    def __init__(self, level: str):
        self.level = level

    def get_criticality(self, asset_name: str | None) -> str:   # noqa: ARG002
        return self.level


def finding_level_recall(kept_true: int, reference_true: int) -> dict[str, Any]:
    """Recall over FINDINGS that cite malicious lines, with its denominator.

    Deliberately NOT part of `score()`: the frozen scorer's numbers are
    untouched. This reuses the one `_ratio()` in the file, so there is still a
    single ratio implementation. The denominator is the reference collection —
    every finding the analyzer produced that cited a malicious line — so a
    system that drops one of them scores below 1.0 here even when line-level
    recall stays 1.0.
    """
    return {
        "true_findings_kept": kept_true,
        "true_findings_total": reference_true,
        "recall": _ratio(kept_true, reference_true),
        "recall_defined": reference_true > 0,
        "denominator": "findings that cite at least one malicious line",
    }


def benchmark_scenarios() -> tuple[str, ...]:
    """The frozen benchmark scenario set, checked against the generator.

    E8m2 (2). The referee owns WHAT is measured, not just the seeds it is
    measured at. This returns the frozen tuple and never the generator's
    dictionary, so a scenario added to `tools/attack_generator.py` cannot move
    a benchmark number.

    The one thing it does read from the generator is whether every frozen
    scenario still EXISTS there. A frozen scenario the generator can no longer
    produce is a hard failure, not a silently shorter benchmark — the same
    posture the freshness assertion takes: refuse rather than publish numbers
    that quietly mean something else.
    """
    missing = [name for name in BENCHMARK_SCENARIOS if name not in generator.SCENARIOS]
    if missing:
        raise BenchmarkProvenanceError(
            "the frozen benchmark scenario set names scenario(s) the generator "
            f"no longer produces: {', '.join(missing)}. The benchmark is not "
            "measuring what it says it measures; fix the generator or change "
            "BENCHMARK_SCENARIOS deliberately."
        )
    return BENCHMARK_SCENARIOS


# --------------------------------------------------------------------------- #
# E8m2 (1) — finding-level recall, broken down by rule class
# --------------------------------------------------------------------------- #
# An aggregate finding-level recall hides WHICH rule class a system is losing.
# E7a's five crown-jewel `ioc_observed` dismissals hid behind a line-level
# 1.000; E7b round 1's eight `infra_unknown_high` drops are visible in the
# aggregate only as 0.9111. Per-rule recall makes the losing class readable
# without parsing the verbatim dropped list — which is still published, in full,
# and is still the evidence. This breakdown is IN ADDITION to it, never instead.
BY_RULE_RECALL_NOTE = (
    "Finding-level recall is also published PER RULE CLASS, each with its own "
    "denominator: the findings THAT rule produced that cite at least one "
    "malicious line. The denominator is the rules system's count for that rule "
    "— the reference collection both systems are scored against — so a class "
    "the learned system drops entirely scores 0.0 here while the aggregate "
    "barely moves. A rule that produced no finding citing a malicious line has "
    "no finding-level recall to measure and is absent from the breakdown "
    "rather than published as a 0/0. This is a reading aid over "
    "`dropped_true_findings`, which stays published verbatim and stays the "
    "evidence."
)


def _true_findings_by_rule(per_rule: Mapping[str, Any] | None) -> dict[str, int]:
    """{rule_id: true-positive finding count} out of an existing `per_rule`.

    Reads the numbers `diff()` already computed. Nothing is re-scored here.
    """
    out: dict[str, int] = {}
    for rule_id, bucket in (per_rule or {}).items():
        out[str(rule_id)] = int(bucket.get("true_positive_findings") or 0)
    return out


def finding_recall_by_rule(
    reference_per_rule: Mapping[str, Any] | None,
    system_per_rule: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Per-rule-class finding-level recall, against the reference denominator.

    `reference_per_rule` is always the RULES system's `per_rule` — the
    collection both systems are scored on — so the learned system is measured
    against what the analyzer actually produced for that rule, not against its
    own surviving subset. Reuses :func:`finding_level_recall`, so there is still
    one finding-recall implementation and one `_ratio()`.
    """
    reference = _true_findings_by_rule(reference_per_rule)
    kept = _true_findings_by_rule(system_per_rule)
    return {
        rule_id: finding_level_recall(kept.get(rule_id, 0), total)
        for rule_id, total in sorted(reference.items())
        if total > 0
    }


def merge_finding_recall_by_rule(
    entries: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Sum per-scenario per-rule breakdowns into one run-level breakdown.

    Kept/total are summed per rule class and the ratio is recomputed from the
    summed pair — never an average of ratios, which would weight a one-finding
    scenario the same as a nine-finding one.
    """
    kept: dict[str, int] = {}
    total: dict[str, int] = {}
    for entry in entries:
        for rule_id, bucket in (entry or {}).items():
            kept[rule_id] = kept.get(rule_id, 0) + int(bucket["true_findings_kept"])
            total[rule_id] = total.get(rule_id, 0) + int(bucket["true_findings_total"])
    return {
        rule_id: finding_level_recall(kept.get(rule_id, 0), total[rule_id])
        for rule_id in sorted(total)
        if total[rule_id] > 0
    }


# Every entity kind `triage_model.features()` can count, and every one of them is
# ASSERTED disjoint. Nothing is exempted: hosts and usernames are fixed
# vocabularies in the generator and ports are partly fixed literals, so seed
# choice alone can never separate them — the benchmark-only remap below is what
# makes the assertion satisfiable, and the assertion is what proves the remap
# actually worked.
ASSERTED_ENTITY_KINDS = ("ip", "user", "host", "port", "change_window")

_ENTITY_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ENTITY_USER_RE = re.compile(r"\bfor (\S+) from\b")
_ENTITY_PORT_RE = re.compile(r"\bport (\d+)\b")
_ENTITY_CHANGE_RE = re.compile(r"\bCHG-\d+\b")

# --- the benchmark-only token remap ---------------------------------------
# `attack_generator` pins each scenario to a fixed host, draws usernames from
# fixed four-value vocabularies, and hard-codes some ports. Fourteen training
# seeds exhaust all of them, so a benchmark that only picks fresh SEEDS still
# re-shows the model entities it trained on — and `triage_model.features()`
# counts hosts, users and ports, so that is a real leak, not a cosmetic one.
#
# The referee therefore rewrites the generated benchmark logs — and the matching
# manifest ground truth, by index, so the raw bytes stay aligned — into a
# benchmark-only entity space before the analyzer subprocess ever sees them.
# The map is a pure function of the token, so the same seed produces the same
# bytes forever. Nothing in `tools/attack_generator.py` or
# `tools/train_triage.py` is touched: the remap lives entirely in the referee
# and applies ONLY to the benchmark.
BENCHMARK_TOKEN_TAG = "bnch"
BENCHMARK_PUBLIC_IP_PREFIX = "198.18"     # RFC 2544 benchmarking range
BENCHMARK_PRIVATE_IP_PREFIX = "172.31"    # RFC 1918, untouched by the generator
BENCHMARK_CHANGE_BASE = 7000              # generator draws CHG-1000..CHG-1999
BENCHMARK_PORT_BASE = 33000               # generator draws 40000..60000 + 51xxx
_PRIVATE_IP_PREFIXES = ("10.", "192.168.") + tuple(
    f"172.{octet}." for octet in range(16, 32))


class BenchmarkProvenanceError(RuntimeError):
    """The benchmark is not measuring anything fresh. Never downgraded.

    Raised for a training/benchmark seed overlap or an entity overlap. Unlike a
    missing model — which is an honest *unavailable* result — this is a hard
    failure: a benchmark that reused training data would produce numbers that
    look fine and mean nothing.
    """


def log_entities(text: str, manifest: dict[str, Any] | None = None) -> dict[str, list[str]]:
    """Every entity value one scenario actually puts in front of `features()`.

    Read off the artefacts themselves, never from a label: an IPv4 quad is an
    IP, the name in `for <user> from` is a user, the number in `port <n>` is a
    port, `CHG-nnnn` is a change window, and the host is the one the manifest
    declares — which is literally the value `record_from_report_finding` copies
    into the record `features()` scores. Sorted, so the artefact is stable.
    """
    entities = {
        "ip": sorted(set(_ENTITY_IPV4_RE.findall(text))),
        "user": sorted(set(_ENTITY_USER_RE.findall(text))),
        "port": sorted(set(_ENTITY_PORT_RE.findall(text))),
        "change_window": sorted(set(_ENTITY_CHANGE_RE.findall(text))),
        "host": [],
    }
    host = (manifest or {}).get("host")
    if host:
        entities["host"] = [str(host)]
    return entities


def _merge_entities(into: dict[str, set], found: dict[str, list[str]]) -> None:
    for kind, values in found.items():
        into.setdefault(kind, set()).update(values)


def _sorted_entities(accumulated: dict[str, set]) -> dict[str, list[str]]:
    return {kind: sorted(values) for kind, values in sorted(accumulated.items())}


def _is_private_ip(value: str) -> bool:
    return value.startswith(_PRIVATE_IP_PREFIXES)


def _digest_int(value: str, salt: str) -> int:
    return int(hashlib.sha256(f"{salt}|{value}".encode("utf-8")).hexdigest(), 16)


def _benchmark_ip(value: str, taken: set[str], excluded: set[str]) -> str:
    prefix = (BENCHMARK_PRIVATE_IP_PREFIX if _is_private_ip(value)
              else BENCHMARK_PUBLIC_IP_PREFIX)
    base = _digest_int(value, "ip")
    for probe in range(65536):
        offset = (base + probe) % 65024                     # 254 * 256
        candidate = f"{prefix}.{offset // 254}.{1 + offset % 254}"
        if candidate not in taken and candidate not in excluded:
            return candidate
    raise BenchmarkProvenanceError(
        f"no benchmark-only IP is available for {value!r}")


def _benchmark_number(value: str, salt: str, base: int, span: int,
                      taken: set[str], excluded: set[str],
                      template: str) -> str:
    start = _digest_int(value, salt)
    for probe in range(span):
        candidate = template.format(base + (start + probe) % span)
        if candidate not in taken and candidate not in excluded:
            return candidate
    raise BenchmarkProvenanceError(
        f"no benchmark-only {salt} value is available for {value!r}")


def _benchmark_name(value: str, taken: set[str], excluded: set[str]) -> str:
    for suffix in range(1000):
        candidate = (f"{BENCHMARK_TOKEN_TAG}-{value}" if suffix == 0
                     else f"{BENCHMARK_TOKEN_TAG}{suffix}-{value}")
        if candidate not in taken and candidate not in excluded:
            return candidate
    raise BenchmarkProvenanceError(
        f"no benchmark-only name is available for {value!r}")


def benchmark_token_map(
    entities: dict[str, list[str]],
    excluded: Iterable[str] = (),
) -> dict[str, str]:
    """The deterministic old-token -> benchmark-only-token map for one scenario.

    Pure: same input tokens, same output, forever. `excluded` is every entity
    value derived from the training sidecar — no benchmark token may land on one,
    whatever its kind, so a benchmark host can never collide with a training
    username either.
    """
    blocked = {str(value) for value in excluded}
    taken: set[str] = set()
    mapping: dict[str, str] = {}
    for kind in ("host", "user", "ip", "port", "change_window"):
        for value in entities.get(kind) or []:
            if value in mapping:
                continue
            if kind in ("host", "user"):
                replacement = _benchmark_name(value, taken, blocked)
            elif kind == "ip":
                replacement = _benchmark_ip(value, taken, blocked)
            elif kind == "port":
                replacement = _benchmark_number(
                    value, "port", BENCHMARK_PORT_BASE, 1000, taken, blocked, "{}")
            else:
                replacement = _benchmark_number(
                    value, "chg", BENCHMARK_CHANGE_BASE, 999, taken, blocked,
                    "CHG-{}")
            mapping[value] = replacement
            taken.add(replacement)
    return mapping


def apply_token_map(text: str, mapping: dict[str, str]) -> str:
    """One pass, longest token first, on word boundaries. No double-substitution.

    A single `re.sub` over an alternation means a replacement can never itself
    be rewritten by a later token — which is what keeps the map a bijection on
    the text and the manifest alike.
    """
    if not mapping:
        return text
    pattern = re.compile(
        "|".join(re.escape(token) for token in
                 sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda match: mapping[match.group(0)], text)


def remap_scenario(
    log_path: Path,
    manifest: dict[str, Any],
    excluded: Iterable[str] = (),
) -> tuple[str, dict[str, Any], dict[str, str]]:
    """Rewrite one generated scenario into benchmark-only entity space.

    Ground truth stays aligned BY CONSTRUCTION, not by a parallel substitution:
    the log is rewritten line by line, and each manifest `raw` is then re-read
    out of the rewritten log at the line number the manifest itself records. A
    manifest raw can therefore never drift from the bytes the analyzer ingested.
    """
    original = log_path.read_text(encoding="utf-8")
    mapping = benchmark_token_map(log_entities(original, manifest), excluded)
    lines = original.splitlines()
    remapped_lines = [apply_token_map(line, mapping) for line in lines]
    remapped_text = "\n".join(remapped_lines) + ("\n" if original.endswith("\n") else "")

    remapped = copy.deepcopy(manifest)
    if remapped.get("host"):
        remapped["host"] = mapping.get(str(remapped["host"]), remapped["host"])
    for entry in remapped.get("malicious_lines") or []:
        entry["raw"] = remapped_lines[int(entry["line"]) - 1]
    remapped["benchmark_token_map"] = dict(sorted(mapping.items()))
    return remapped_text, remapped, mapping


def collect_entities(
    scenarios: Iterable[str],
    formats: Iterable[str],
    seeds: Iterable[int],
    workdir: Path,
) -> dict[str, list[str]]:
    """Every entity value the given generator coordinates produce.

    Deterministic by construction: the generator is a pure function of
    (scenario, format, seed), so this re-derives exactly the bytes those
    coordinates produced, whenever it is run. Used for the TRAINING side, where
    the coordinates come from the model's own provenance sidecar.
    """
    target = assert_isolated(workdir)
    target.mkdir(parents=True, exist_ok=True)
    accumulated: dict[str, set] = {}
    for seed in seeds:
        for scenario in scenarios:
            for format_name in formats:
                log_path, manifest_path = generator.generate(
                    scenario, format_name, target, seed)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                _merge_entities(accumulated, log_entities(
                    log_path.read_text(encoding="utf-8"), manifest))
    return _sorted_entities(accumulated)


# --------------------------------------------------------------------------- #
# the model sidecar — read it, then assert against it
# --------------------------------------------------------------------------- #

TRAINING_ENTITY_DERIVATION = (
    "The E7a provenance sidecar records the training seeds, scenarios and "
    "formats but NOT an entity inventory, so the benchmark cannot compare "
    "against a recorded entity list. The referee therefore DERIVES the training "
    "entities from the sidecar's own generator provenance, without touching "
    "training code: for every (scenario, format, seed) triple in "
    "provenance['dataset']['generated'] ({scenarios} x {formats} x {seedsUsed}) "
    "it calls tools/attack_generator.py:generate() into an isolated temp "
    "directory and extracts entity values from the generated log text with "
    "efficacy_harness.log_entities(). attack_generator.generate() is a pure "
    "function of (scenario, format, seed), so these are bit-for-bit the logs "
    "training ingested and the values are observed, never guessed."
)

BENCHMARK_REMAP_NOTE = (
    "Seed choice alone cannot make the benchmark entity-disjoint: "
    "attack_generator pins each scenario to a fixed host, draws usernames from "
    "fixed four-value vocabularies, and hard-codes some ports, all of which the "
    "training seed set exhausts — and triage_model.features() counts hosts, "
    "users and ports. The referee therefore applies a BENCHMARK-ONLY, "
    "deterministic token remap to the generated log lines AND, by line index, "
    "to the manifest ground-truth raw values, before the real analyzer "
    "subprocess runs. Hosts and users become bnch-prefixed names, public IPs "
    "move into 198.18.0.0/15 (RFC 2544 benchmarking) and private IPs into "
    "172.31.0.0/16, ports into 33000-33999 and change windows into CHG-7xxx; "
    "every replacement is a pure function of the source token and is refused if "
    "it lands on any value derived from the training sidecar. No generator or "
    "training file is modified, and the remapped host keeps its source host's "
    "configured criticality through a benchmark-only org-context file, so the "
    "criticality feature is unchanged while the host value is fresh."
)


def training_provenance(provenance: dict[str, Any]) -> dict[str, Any]:
    """The generator coordinates the sidecar says training actually used."""
    generated = ((provenance.get("dataset") or {}).get("generated") or {})
    seeds = [int(s) for s in (generated.get("seedsUsed")
                              or provenance.get("seedsUsed") or [])]
    scenarios = [str(s) for s in (generated.get("scenarios") or [])]
    formats = [str(f) for f in (generated.get("formats") or [])]
    if not seeds or not scenarios or not formats:
        raise BenchmarkProvenanceError(
            "the model provenance sidecar does not record the generator seeds, "
            "scenarios and formats it trained on, so freshness cannot be "
            "proven — refusing to publish a benchmark number against it "
            f"(saw seeds={seeds}, scenarios={scenarios}, formats={formats})."
        )
    return {"seeds": sorted(set(seeds)), "scenarios": scenarios, "formats": formats}


def training_entities(provenance: dict[str, Any], workdir: Path) -> dict[str, Any]:
    """(coordinates, entity values) the model was actually trained on."""
    training = training_provenance(provenance)
    entities = collect_entities(training["scenarios"], training["formats"],
                                training["seeds"], workdir)
    return {"coordinates": training, "entities": entities}


def assert_fresh(
    benchmark_seeds: Sequence[int],
    benchmark_entities: dict[str, list[str]],
    derived: dict[str, Any],
) -> dict[str, Any]:
    """Prove this benchmark is disjoint from the training set. Hard failure.

    Two checks, in order, both against what the sidecar ACTUALLY recorded:

    1. seed disjointness — a shared seed means a benchmark scenario is a
       training row, byte for byte;
    2. entity disjointness across EVERY kind `features()` can count — ip, user,
       host, port and change window. No kind is exempt and no overlap is
       tolerated: a shared value means the model is being re-shown an entity it
       trained on. The benchmark-only remap is what makes this satisfiable; this
       assertion is what proves the remap actually landed.

    `benchmark_entities` are read off the REMAPPED artefacts the analyzer
    actually ingested, never off the pre-remap generator output.
    """
    training = derived["coordinates"]
    shared_seeds = sorted(set(benchmark_seeds) & set(training["seeds"]))
    if shared_seeds:
        raise BenchmarkProvenanceError(
            f"benchmark seeds {shared_seeds} were also TRAINING seeds "
            f"(sidecar recorded {training['seeds']}) — the benchmark would be "
            "scoring the model on its own training data. Refusing to run."
        )

    trained = derived["entities"]
    # Cross-kind, not just same-kind: a benchmark HOST that equals a training
    # USERNAME is still a value the model has seen.
    every_trained_value = {value for values in trained.values() for value in values}
    overlaps = {
        kind: sorted(set(benchmark_entities.get(kind) or []) & every_trained_value)
        for kind in sorted(set(benchmark_entities) | set(trained))
    }
    asserted = {kind: overlaps.get(kind) or [] for kind in ASSERTED_ENTITY_KINDS}
    breached = {kind: values for kind, values in asserted.items() if values}
    if breached:
        raise BenchmarkProvenanceError(
            f"benchmark entities are NOT disjoint from the training entities "
            f"derived from the sidecar: {breached}. The benchmark would be "
            "re-showing the model an entity it trained on. Refusing to run."
        )

    return {
        "trainingSeeds": training["seeds"],
        "trainingScenarios": training["scenarios"],
        "trainingFormats": training["formats"],
        "trainingEntities": trained,
        "benchmarkEntities": benchmark_entities,
        "assertedEntityKinds": list(ASSERTED_ENTITY_KINDS),
        "assertedEntityOverlap": asserted,
        "crossKindOverlap": {kind: values for kind, values in overlaps.items()},
        "entityDerivation": TRAINING_ENTITY_DERIVATION,
        "remap": BENCHMARK_REMAP_NOTE,
    }


def benchmark_org_context(mapping: dict[str, str], workdir: Path):
    """The shipped asset config, re-keyed onto the benchmark's remapped hosts.

    Entity disjointness must not silently change what the model is asked. The
    criticality feature is looked up by exact host name, so a remapped host
    would fall back to the default band and quietly shift the feature vector.
    This copies each tagged asset's OWN entry onto its benchmark name, writes it
    to a file inside the isolated workdir, and loads it through the shipped
    `org_context.load_org_context(path)` seam. `console/org_context.json` is
    never touched, and no criticality is invented — every value is copied from
    the real configuration.
    """
    console = str(REPO_ROOT / "console")
    if console not in sys.path:
        sys.path.insert(0, console)
    import org_context                        # noqa: PLC0415 (stdlib config)

    real = org_context.load_org_context()
    assets = dict(real.assets)
    for original, replacement in mapping.items():
        if original in real.assets:
            assets[replacement] = copy.deepcopy(real.assets[original])
    target = assert_isolated(Path(workdir))
    target.mkdir(parents=True, exist_ok=True)
    path = target / "benchmark_org_context.json"
    path.write_text(json.dumps({
        "version": 1,
        "defaultCriticality": real.default_criticality,
        "assets": assets,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return org_context.load_org_context(path)


class LearnedSystem:
    """A loaded model plus its sidecar. The ONLY thing that answers for it.

    Constructed by :meth:`load` from the shipped ``console/triage_model.py``
    loader — which is the module that owns the integrity check, the feature
    schema check and the honest unavailable reasons. Nothing here re-implements
    any of that, and nothing here invents an opinion.
    """

    def __init__(self, estimator: Any, provenance: dict[str, Any] | None = None):
        self.estimator = estimator
        self.provenance = provenance or {}

    @staticmethod
    def _triage_model():
        """The shipped model module, imported lazily.

        Lazy on purpose: importing the harness must stay stdlib-cheap, and the
        detector-isolation contract is unaffected — triage_model is stdlib-only
        at import time and imports scikit-learn inside a function.
        """
        console = str(REPO_ROOT / "console")
        if console not in sys.path:
            sys.path.insert(0, console)
        import triage_model                    # noqa: PLC0415 (lazy by design)
        return triage_model

    @classmethod
    def load(cls, model_dir: Path | None = None) -> "LearnedSystem":
        """Load the local artifact, or raise the shipped ModelUnavailable."""
        triage_model = cls._triage_model()
        if model_dir is not None:
            triage_model.MODEL_DIR = Path(model_dir)
        triage_model.reset_cache()
        estimator, provenance = triage_model.load_model()
        return cls(estimator, provenance)

    def describe(self) -> dict[str, Any]:
        """The model provenance every published number must carry."""
        triage_model = self._triage_model()
        prov = self.provenance
        return {
            "available": True,
            "reason": None,
            "name": prov.get("model"),
            "file": prov.get("modelFile") or triage_model.MODEL_NAME,
            "path": str(triage_model.model_path()),
            "sha256": prov.get("modelSha256"),
            "trainedAt": prov.get("trainedAt"),
            "trainingSeed": prov.get("seed"),
            "trainingSeeds": [int(s) for s in (prov.get("seedsUsed") or [])],
            "datasetRows": prov.get("datasetRows"),
            "featureCount": prov.get("featureCount"),
            "labels": prov.get("labels"),
            "sklearnVersion": prov.get("sklearnVersion"),
            "card": prov.get("card"),
        }

    def opinion(self, finding: dict[str, Any], manifest: dict[str, Any],
                org: Any = None) -> dict[str, Any]:
        """One advisory opinion on one finding, via the shipped contract.

        The record projection is `tools/train_triage.py:record_from_report_finding`
        — the EXACT function training used — so the vector scored here is the
        vector the model was fitted on. The prediction is
        `triage_model.predict_with`. Neither is re-implemented here.

        `org` is the asset-criticality config the record is resolved against.
        The benchmark passes the benchmark-only context (see
        :func:`benchmark_org_context`) so a remapped host keeps its source
        host's configured criticality; with no `org` the shipped config is used.
        """
        triage_model = self._triage_model()
        from tools import train_triage       # noqa: PLC0415 (lazy: cycle-free)
        import org_context                   # noqa: PLC0415 (stdlib config)

        record = train_triage.record_from_report_finding(
            finding, manifest, org if org is not None
            else org_context.load_org_context())
        advisory = triage_model.predict_with(
            self.estimator, record, finding.get("severity"), self.provenance)
        label = advisory.get("aiLabel")
        return {
            "rule_id": str(finding.get("rule_id") or finding.get("category")
                           or "unattributed"),
            "rule_severity": advisory.get("ruleSeverity"),
            "label": label,
            "confidence": advisory.get("confidence"),
            "model_positive": label in MODEL_POSITIVE_LABELS,
            "advisory_severity": advisory.get("aiSeverity"),
            "agrees": advisory.get("agrees"),
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


def commit_provenance() -> dict[str, Any]:
    """The commit and tree these numbers were produced at, or an honest None."""
    def _git(*args: str) -> str | None:
        try:
            done = subprocess.run(["git", *args], cwd=str(REPO_ROOT),
                                  capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout.strip() if done.returncode == 0 else None

    dirty = _git("status", "--porcelain")
    return {
        "commit": _git("rev-parse", "HEAD"),
        "tree": _git("rev-parse", "HEAD^{tree}"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "worktreeDirty": None if dirty is None else bool(dirty),
    }


def _run_id(run_date: str, seeds: Sequence[int], commit: str | None) -> str:
    """One id for one benchmark run. Every published number carries it."""
    material = f"{run_date}|{','.join(str(s) for s in seeds)}|{commit or 'no-commit'}"
    return f"efficacy-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:12]}"


def learned_findings(
    findings: Sequence[dict[str, Any]],
    manifest: dict[str, Any],
    model: LearnedSystem,
    org: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(model-positive findings, every decision) for one scenario.

    The input findings are DEEP-COPIED first, so the learned pass can neither
    read nor write the collection the rules system is scored on. Nothing is
    recomputed: `diff()` scores the kept collection exactly as it scores the
    rules collection.
    """
    decisions: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    for finding in copy.deepcopy(list(findings)):
        decision = model.opinion(finding, manifest, org)
        decisions.append(decision)
        if decision["model_positive"]:
            kept.append(finding)
    return kept, decisions


def dropped_true_findings(
    findings: Sequence[dict[str, Any]],
    decisions: Sequence[dict[str, Any]],
    malicious: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Findings a system dropped that were citing real malicious lines.

    This is the class of loss line-level recall absorbs: drop a finding whose
    cited malicious lines another kept finding also covers, and the line is
    still "detected" while the finding is gone. Each one is reported verbatim,
    with the manifest's own `raw`/`why` for every line it cited, so it can never
    again be invisible. Nothing is reconciled away.

    `decisions` is positionally aligned with `findings` — that is the contract
    :func:`learned_findings` produces, and it is what makes the drop
    attributable to a specific advisory opinion.
    """
    out: list[dict[str, Any]] = []
    by_line = {entry["line"]: entry for entry in malicious}
    for finding, decision in zip(findings, decisions):
        if decision.get("model_positive"):
            continue
        hits = sorted(finding_hits(finding, malicious))
        if not hits:
            continue                      # a suppressed false positive, not a loss
        out.append({
            "rule_id": decision.get("rule_id"),
            "severity": finding.get("severity"),
            "summary": finding.get("summary"),
            "evidence": finding.get("evidence"),
            "label": decision.get("label"),
            "confidence": decision.get("confidence"),
            "cited_malicious_lines": [
                {"line": line,
                 "raw": by_line[line]["raw"],
                 "why": by_line[line]["why"]}
                for line in hits
            ],
        })
    return out


def feature_importance(model: "LearnedSystem") -> dict[str, Any]:
    """The loaded estimator's own feature importances, or an honest absence.

    Read off the artefact that was actually scored — never asserted from a
    document. A model whose estimator exposes no importances publishes
    ``available: false`` and a reason, not a number.
    """
    keys = list(model.provenance.get("featureKeys") or [])
    values = getattr(model.estimator, "feature_importances_", None)
    if values is None or not keys or len(keys) != len(values):
        return {
            "available": False,
            "reason": ("the loaded estimator exposes no feature_importances_ "
                       "aligned with the sidecar's featureKeys"),
            "by_feature": None,
            "criticality_rank": None,
        }
    by_feature = {key: round(float(value), 4)
                  for key, value in zip(keys, values)}
    return {
        "available": True,
        "reason": None,
        "by_feature": dict(sorted(by_feature.items(),
                                  key=lambda kv: (-kv[1], kv[0]))),
        "criticality_rank": by_feature.get("criticality_rank"),
    }


def criticality_sensitivity(
    pairs: Sequence[tuple[dict[str, Any], dict[str, Any]]],
    results: Sequence[dict[str, Any]],
    model: "LearnedSystem | None",
    unavailable_reason: str | None = None,
) -> dict[str, Any]:
    """Re-score every finding with `criticality_rank` forced across its domain.

    A named, first-class published finding — not a footnote. The measured run
    above is untouched: this holds every other feature exactly as measured and
    moves only the org-config criticality of the finding's host, through the
    :class:`_ForcedCriticality` shim, which is the one method
    ``record_from_report_finding`` asks an org context for. No trainer, model,
    ``org_context`` or shipped config file is edited or read differently.

    Two populations, both defined against the SAME run: `true_detections` are
    the findings the model KEPT that cite malicious lines; `suppressions` are
    the findings it DROPPED that cite none. `kept_at` publishes the direction
    per band, so "more critical ⇒ more willing to dismiss" is readable off the
    numbers rather than asserted.
    """
    if model is None:
        return {
            "available": False,
            "reason": (unavailable_reason
                       or "no learned model was loaded, so there is nothing to "
                          "re-score"),
            "kind": "counterfactual",
            "note": CRITICALITY_SENSITIVITY_NOTE,
            "feature": "criticality_rank",
            "domain": list(CRITICALITY_DOMAIN),
            "feature_importance": None,
            "populations": None,
        }

    forced = {band: _ForcedCriticality(band) for band in CRITICALITY_DOMAIN}
    populations = {
        name: {"total": 0, "robust": 0, "flipping": 0,
               "kept_at": {band: 0 for band in CRITICALITY_DOMAIN}}
        for name in ("true_detections", "suppressions")
    }

    for (manifest, report), entry in zip(pairs, results):
        decisions = (entry.get("learned") or {}).get("decisions") or []
        malicious = list(manifest.get("malicious_lines") or [])
        for finding, decision in zip(list(report.get("findings") or []), decisions):
            hits = finding_hits(finding, malicious)
            kept = bool(decision.get("model_positive"))
            if hits and kept:
                name = "true_detections"
            elif not hits and not kept:
                name = "suppressions"
            else:
                continue                  # a miss or a false positive, scored above
            bucket = populations[name]
            bucket["total"] += 1
            outcomes = {}
            for band, org in forced.items():
                alt = model.opinion(copy.deepcopy(finding), manifest, org)
                outcomes[band] = bool(alt["model_positive"])
                if outcomes[band]:
                    bucket["kept_at"][band] += 1
            if len(set(outcomes.values())) > 1:
                bucket["flipping"] += 1
            else:
                bucket["robust"] += 1

    return {
        "available": True,
        "reason": None,
        "kind": "counterfactual",
        "note": CRITICALITY_SENSITIVITY_NOTE,
        "feature": "criticality_rank",
        "domain": list(CRITICALITY_DOMAIN),
        "feature_importance": feature_importance(model),
        "populations": populations,
    }


def score_pair(
    manifest: dict[str, Any],
    report: dict[str, Any],
    model: LearnedSystem | None,
    unavailable_reason: str | None = None,
    org: Any = None,
) -> dict[str, Any]:
    """Score ONE scenario as two systems, through the one scoring path.

    `report` is never mutated: each system is handed its own deep-independent
    finding collection, and the rules system is scored from its own copy.
    """
    findings = list(report.get("findings") or [])
    malicious = list(manifest.get("malicious_lines") or [])
    rules_entry = diff(manifest, {"findings": copy.deepcopy(findings)})
    # The reference denominator for finding-level recall: every finding the
    # analyzer produced that cited at least one malicious line. The rules system
    # IS that collection, so it scores 1.0 here by construction; the learned
    # system is scored against the same denominator, which is the whole point.
    reference_true_findings = rules_entry["totals"]["true_positive_findings"]
    rules_system = {
        "system": "rules",
        "available": True,
        "reason": None,
        "findings": rules_entry["totals"]["findings"],
        "totals": rules_entry["totals"],
        "per_rule": rules_entry["per_rule"],
        "misses": rules_entry["misses"],
        "false_positives": rules_entry["false_positives"],
        # E8m: published beside line-level recall, for BOTH systems.
        "finding_recall": finding_level_recall(
            reference_true_findings, reference_true_findings),
        # E8m2: the same recall, per rule class. The rules system IS the
        # reference collection, so every class is 1.0 here by construction —
        # published anyway, so the learned column always has a row to sit
        # beside and a reader never has to assume the denominator.
        "finding_recall_by_rule": finding_recall_by_rule(
            rules_entry["per_rule"], rules_entry["per_rule"]),
        # The rules system drops nothing, so this list is empty BY MEASUREMENT,
        # not by omission — it is published either way.
        "dropped_true_findings": [],
    }

    if model is None:
        learned_system: dict[str, Any] = {
            "system": "learned",
            "available": False,
            "reason": unavailable_reason or "no learned model was loaded",
            "findings": None,
            "totals": None,
            "per_rule": None,
            "misses": None,
            "false_positives": None,
            "decisions": None,
            "finding_recall": None,
            "finding_recall_by_rule": None,
            "dropped_true_findings": None,
        }
    else:
        kept, decisions = learned_findings(findings, manifest, model, org)
        learned_entry = diff(manifest, {"findings": kept})
        learned_system = {
            "system": "learned",
            "available": True,
            "reason": None,
            "findings": learned_entry["totals"]["findings"],
            "totals": learned_entry["totals"],
            "per_rule": learned_entry["per_rule"],
            "misses": learned_entry["misses"],
            "false_positives": learned_entry["false_positives"],
            "decisions": decisions,
            "finding_recall": finding_level_recall(
                learned_entry["totals"]["true_positive_findings"],
                reference_true_findings),
            # E8m2: which rule CLASS this system is losing. The denominator is
            # the rules system's per-rule count, so a class dropped entirely
            # reads 0.0 here even when the aggregate barely moves.
            "finding_recall_by_rule": finding_recall_by_rule(
                rules_entry["per_rule"], learned_entry["per_rule"]),
            # A finding this system dropped WHILE it cited malicious lines. It
            # costs finding-level recall and is invisible in line-level recall
            # whenever a kept finding covers the same lines, so it is listed
            # verbatim here exactly as a missed line is listed in `misses`.
            "dropped_true_findings": dropped_true_findings(
                findings, decisions, malicious),
        }

    entry = dict(rules_entry)          # legacy shape: top level IS the rules system
    entry["scenario_class"] = manifest.get("scenario_class")
    entry["seed"] = manifest.get("seed")
    entry["rules"] = rules_system
    entry["learned"] = learned_system
    return entry


def score_manifests(
    pairs: Sequence[tuple[dict[str, Any], dict[str, Any]]],
    model: LearnedSystem | None,
    unavailable_reason: str | None = None,
    org: Any = None,
) -> list[dict[str, Any]]:
    """Score an already-collected list of (manifest, report) pairs.

    This is the seam the rule-invariance test drives: the same pairs can be
    scored with a model and then with the model killed, and the rules half of
    the result must be byte-identical both times.
    """
    return [score_pair(manifest, report, model, unavailable_reason, org)
            for manifest, report in pairs]


def evaluate(
    scenarios: Iterable[str],
    formats: Iterable[str],
    workdir: Path,
    seeds: Sequence[int] | None = None,
    model_dir: Path | None = None,
) -> dict[str, Any]:
    """The paired benchmark: generate fresh seeded scenarios, score two systems.

    Order of operations is deliberate. The model sidecar is READ and the
    freshness assertion runs BEFORE a single score is computed, so a benchmark
    that overlaps the training set fails loudly instead of publishing numbers.
    """
    target = assert_isolated(workdir)
    target.mkdir(parents=True, exist_ok=True)
    run_date = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    scenarios = list(scenarios)
    formats = list(formats)
    seeds = list(BENCHMARK_SEEDS if seeds is None else seeds)
    provenance_git = commit_provenance()
    run_id = _run_id(run_date, seeds, provenance_git["commit"])

    # 1. the model, or the honest reason there is none
    model: LearnedSystem | None = None
    unavailable_reason: str | None = None
    try:
        model = LearnedSystem.load(model_dir)
    except Exception as exc:            # noqa: BLE001 - the reason is published
        unavailable_reason = str(exc) or f"{type(exc).__name__}"

    # 2. the training entity inventory, derived from the sidecar's own
    #    generator provenance — nothing may collide with any of these values
    derived: dict[str, Any] | None = None
    if model is not None:
        derived = training_entities(model.provenance, target / "_training")

    excluded = ({value for values in derived["entities"].values() for value in values}
                if derived else set())

    # 3. generate, then rewrite into benchmark-only entity space BEFORE the
    #    analyzer sees anything. Log and manifest are remapped together, by line
    #    index, so the ground-truth raw bytes stay exactly the ingested bytes.
    prepared: list[dict[str, Any]] = []
    benchmark_accumulated: dict[str, set] = {}
    combined_map: dict[str, str] = {}
    for seed in seeds:
        for scenario in scenarios:
            for format_name in formats:
                log_path, manifest_path = generator.generate(
                    scenario, format_name, target, seed)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                text, manifest, mapping = remap_scenario(log_path, manifest, excluded)
                bench_log = target / f"{log_path.stem}-bench.log"
                bench_log.write_text(text, encoding="utf-8")
                (target / f"{log_path.stem}-bench.manifest.json").write_text(
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
                combined_map.update(mapping)
                _merge_entities(benchmark_accumulated, log_entities(text, manifest))
                prepared.append({"log": bench_log, "manifest": manifest})
    benchmark_entities = _sorted_entities(benchmark_accumulated)

    # 4. freshness — asserted on the REMAPPED artefacts, before anything is
    #    scored, so a benchmark that overlaps training fails loudly instead of
    #    publishing numbers.
    freshness: dict[str, Any]
    if derived is None:
        freshness = {
            "asserted": False,
            "reason": ("no model was loaded, so there is no training provenance "
                       "to assert freshness against"),
            "benchmarkSeeds": seeds,
            "benchmarkEntities": benchmark_entities,
            "remap": BENCHMARK_REMAP_NOTE,
        }
    else:
        freshness = assert_fresh(seeds, benchmark_entities, derived)
        freshness["asserted"] = True
        freshness["benchmarkSeeds"] = seeds
    freshness["tokenMap"] = dict(sorted(combined_map.items()))

    # 5. the benchmark-only asset config, so a remapped host keeps its source
    #    host's configured criticality and the feature vector is not moved by
    #    the freshness work itself
    org = benchmark_org_context(combined_map, target / "_org")

    # 6. ingest through the REAL analyzer, then score both systems
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    logs: list[str] = []
    for item in prepared:
        log_path = item["log"]
        report = run_analyzer(log_path, target / f"{log_path.stem}-report")
        pairs.append((item["manifest"], report))
        logs.append(log_path.name)

    results = score_manifests(pairs, model, unavailable_reason, org)
    for entry, log_name in zip(results, logs):
        entry["run_date"] = run_date
        entry["run_id"] = run_id
        entry["log"] = log_name

    learned_available = model is not None

    # --- E8m: the three additive publications --------------------------------
    # (1) finding-level recall beside line-level, for BOTH systems, each with
    #     its denominator named.
    reference_true = sum(
        entry["rules"]["totals"]["true_positive_findings"] for entry in results)
    learned_true = (
        sum(entry["learned"]["totals"]["true_positive_findings"]
            for entry in results) if learned_available else None)
    all_dropped = ([item for entry in results
                    for item in entry["learned"]["dropped_true_findings"]]
                   if learned_available else None)

    # E8m2 (1): the same finding-level recall, per rule class, summed across
    # scenarios from the per-scenario breakdowns each system already carries.
    rules_by_rule = merge_finding_recall_by_rule(
        [entry["rules"]["finding_recall_by_rule"] for entry in results])
    learned_by_rule = (merge_finding_recall_by_rule(
        [entry["learned"]["finding_recall_by_rule"] for entry in results])
        if learned_available else None)
    # Every rule class the run measured, so the two systems are always read as
    # one table with one denominator per row.
    by_rule = {
        rule_id: {
            "denominator": ("findings this rule produced that cite at least "
                            "one malicious line"),
            "true_findings_total": bucket["true_findings_total"],
            "rules": bucket,
            "learned": ((learned_by_rule or {}).get(rule_id)
                        if learned_available else None),
            # The verbatim drops behind this row's learned number, counted.
            # The list itself stays published in full, unsummarised.
            "learned_dropped_true_findings": (
                sum(1 for item in (all_dropped or [])
                    if item.get("rule_id") == rule_id)
                if learned_available else None),
        }
        for rule_id, bucket in rules_by_rule.items()
    }

    # (2) false-positive totals, never bare: the headline is every format this
    #     run measured, with each single format published as a labelled subset.
    by_format: dict[str, dict[str, Any]] = {}
    for entry in results:
        bucket = by_format.setdefault(
            entry["format"], {"rules": 0, "learned": 0 if learned_available else None})
        bucket["rules"] += len(entry["rules"]["false_positives"])
        if learned_available:
            bucket["learned"] += len(entry["learned"]["false_positives"])

    # (3) the criticality counterfactual, computed live on this run.
    sensitivity = criticality_sensitivity(pairs, results, model,
                                          unavailable_reason)

    return {
        "run_id": run_id,
        "run_date": run_date,
        "scope": SCOPE_SENTENCE,
        "ceiling": CEILING_SENTENCE,
        "advisory": ADVISORY_SENTENCE,
        "pipeline": "log_analyzer.py --rules-only (subprocess)",
        "systems": ["rules", "learned"],
        "interpretation": MODEL_INTERPRETATION,
        "metric_note": METRIC_DEFINEDNESS_NOTE,
        "provenance": provenance_git,
        "benchmark": {
            "seeds": seeds,
            "scenarios": scenarios,
            "formats": formats,
            "generator": "tools/attack_generator.py:generate(scenario, format, dir, seed)",
            "entities": benchmark_entities,
            "remap": BENCHMARK_REMAP_NOTE,
            "assertedEntityKinds": list(ASSERTED_ENTITY_KINDS),
            # E8m2 (2): what the FROZEN set says, beside what this run measured.
            # `scenarios` above is unchanged and is still the measured list.
            "frozenScenarios": list(BENCHMARK_SCENARIOS),
            "scenarioSetIsFrozen": list(scenarios) == list(BENCHMARK_SCENARIOS),
            "scenarioNote": BENCHMARK_SCENARIO_NOTE,
        },
        "freshness": freshness,
        "model": (model.describe() if model is not None else
                  {"available": False, "reason": unavailable_reason,
                   "name": None, "sha256": None, "trainedAt": None,
                   "trainingSeeds": None}),
        "scenarios": results,
        "total_misses": sum(len(entry["rules"]["misses"]) for entry in results),
        "total_false_positives": sum(len(entry["rules"]["false_positives"])
                                     for entry in results),
        "learned_total_misses": (
            sum(len(entry["learned"]["misses"]) for entry in results)
            if learned_available else None),
        "learned_total_false_positives": (
            sum(len(entry["learned"]["false_positives"]) for entry in results)
            if learned_available else None),
        # --- E8m, additive only. Nothing above changed. ----------------------
        "recall_note": RECALL_DENOMINATOR_NOTE,
        "format_scope_note": FORMAT_SCOPE_NOTE,
        "finding_level_recall": {
            "denominator": "findings that cite at least one malicious line",
            "true_findings_total": reference_true,
            "rules": finding_level_recall(reference_true, reference_true),
            "learned": (finding_level_recall(learned_true, reference_true)
                        if learned_available else None),
            "learned_dropped_true_findings": all_dropped,
            # --- E8m2, additive only. Nothing above changed. -------------
            "by_rule_note": BY_RULE_RECALL_NOTE,
            "by_rule": by_rule,
        },
        "line_level_recall_denominator": "manifest malicious lines",
        "false_positive_totals": {
            "formats": formats,
            "scope": ("all formats measured in this run: "
                      + ", ".join(formats)),
            "rules": sum(len(entry["rules"]["false_positives"])
                         for entry in results),
            "learned": (sum(len(entry["learned"]["false_positives"])
                            for entry in results)
                        if learned_available else None),
            "by_format": by_format,
        },
        "learned_total_dropped_true_findings": (
            len(all_dropped) if learned_available else None),
        "criticality_sensitivity": sensitivity,
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def _system_line(label: str, system: dict[str, Any]) -> str:
    if not system.get("available"):
        return f"    {label:<8} UNAVAILABLE — {system.get('reason')}"
    totals = system["totals"]
    precision = totals["precision"] if totals.get("precision_defined", True) else "n/a"
    recall = totals["recall"] if totals.get("recall_defined", True) else "n/a"
    f1 = (totals["f1"] if totals.get("precision_defined", True)
          and totals.get("recall_defined", True) else "n/a")
    fr = system.get("finding_recall") or {}
    finding_recall = (fr.get("recall") if fr.get("recall_defined") else "n/a") \
        if fr else "n/a"
    return (f"    {label:<8} precision={precision} "
            f"recall(lines)={recall} recall(findings)={finding_recall} f1={f1} "
            f"({totals['malicious_lines_detected']}/{totals['malicious_lines']} "
            f"malicious lines, "
            f"{fr.get('true_findings_kept')}/{fr.get('true_findings_total')} "
            f"findings citing a malicious line, "
            f"{totals['false_positive_findings']} false "
            f"positive finding(s), {totals['findings']} finding(s) scored)")


def _miss_lines(label: str, system: dict[str, Any]) -> list[str]:
    if not system.get("available"):
        return []
    misses = system["misses"]
    if not misses:
        return [f"      {label}: no missed malicious lines"]
    out = [f"      {label}: MISSED {len(misses)} malicious line(s):"]
    for miss in misses:
        out.append(f"        line {miss['line']}: {miss['raw']}")
        out.append(f"          why: {miss['why']}")
    return out


def _dropped_lines(label: str, system: dict[str, Any]) -> list[str]:
    """Findings this system dropped while citing malicious lines, verbatim.

    Printed with the same weight as a miss, because it is the same class of
    loss: line-level recall absorbs it, finding-level recall does not.
    """
    if not system.get("available"):
        return []
    dropped = system.get("dropped_true_findings") or []
    if not dropped:
        return [f"      {label}: no findings dropped while citing a malicious line"]
    out = [f"      {label}: DROPPED {len(dropped)} finding(s) that cited "
           "malicious line(s):"]
    for item in dropped:
        out.append(f"        [{item['rule_id']}] severity={item['severity']} "
                   f"model={item['label']} confidence={item['confidence']}")
        out.append(f"          summary: {item['summary']}")
        for cited in item["cited_malicious_lines"]:
            out.append(f"          cited line {cited['line']}: {cited['raw']}")
            out.append(f"            why: {cited['why']}")
    return out


def render(summary: dict[str, Any]) -> str:
    model = summary.get("model") or {}
    lines = [
        f"Efficacy harness — run {summary.get('run_id')} at {summary['run_date']}",
        f"Scope: {summary['scope']}",
        CEILING_SENTENCE,
        ADVISORY_SENTENCE,
        f"Pipeline: {summary['pipeline']}",
    ]
    provenance = summary.get("provenance") or {}
    lines.append(f"Commit: {provenance.get('commit')}  tree: {provenance.get('tree')}"
                 f"  dirty: {provenance.get('worktreeDirty')}")
    benchmark = summary.get("benchmark") or {}
    lines.append(f"Benchmark seeds: {benchmark.get('seeds')}  "
                 f"formats: {benchmark.get('formats')}")
    # E8m2 (2): what was measured, and whether it is the frozen set.
    frozen = benchmark.get("frozenScenarios")
    if frozen is not None:
        pinned = ("the frozen benchmark set" if benchmark.get("scenarioSetIsFrozen")
                  else f"NOT the frozen set — frozen is {frozen}")
        lines.append(f"Benchmark scenarios: {benchmark.get('scenarios')} "
                     f"({pinned})")
    freshness = summary.get("freshness") or {}
    if freshness.get("asserted"):
        lines.append(f"Training seeds (from sidecar): {freshness.get('trainingSeeds')}")
        lines.append(f"Benchmark entities (post-remap): "
                     f"{freshness.get('benchmarkEntities')}")
        lines.append(f"Entity overlap with training, every kind "
                     f"{list(ASSERTED_ENTITY_KINDS)}: "
                     f"{freshness.get('assertedEntityOverlap')} (must be empty)")
    else:
        lines.append(f"Freshness NOT asserted — {freshness.get('reason')}")
    if model.get("available"):
        lines.append(f"Model: {model.get('name')} sha256={model.get('sha256')} "
                     f"trainedAt={model.get('trainedAt')} "
                     f"trainingSeeds={model.get('trainingSeeds')}")
    else:
        lines.append(f"Model: UNAVAILABLE — {model.get('reason')}")
    lines.append("")
    lines.append(f"Interpretation: {summary.get('interpretation')}")
    lines.append("")
    if summary.get("recall_note"):
        lines.append(f"Recall denominators: {summary['recall_note']}")
        lines.append("")
    if summary.get("format_scope_note"):
        lines.append(f"Format scope: {summary['format_scope_note']}")
        lines.append("")

    for entry in summary["scenarios"]:
        lines.append(f"[{entry['scenario']} / {entry['format']} / seed "
                     f"{entry.get('seed')}] ground truth: "
                     f"{entry.get('scenario_class')}")
        lines.append(_system_line("RULES", entry["rules"]))
        lines.append(_system_line("LEARNED", entry["learned"]))
        lines.extend(_miss_lines("RULES", entry["rules"]))
        lines.extend(_miss_lines("LEARNED", entry["learned"]))
        lines.extend(_dropped_lines("LEARNED", entry["learned"]))
        for false_positive in entry["rules"]["false_positives"]:
            lines.append(f"      RULES FALSE POSITIVE [{false_positive['rule_id']}] "
                         f"{false_positive['summary']}")
        lines.append("")

    fps = summary.get("false_positive_totals") or {}
    scope = fps.get("scope") or "format scope unrecorded"
    lines.append(f"Rules totals: {summary['total_misses']} missed malicious "
                 f"line(s), {summary['total_false_positives']} false positive "
                 f"finding(s) [{scope}].")
    if summary.get("learned_total_misses") is None:
        lines.append("Learned totals: UNAVAILABLE — no number is invented.")
    else:
        lines.append(f"Learned totals: {summary['learned_total_misses']} missed "
                     f"malicious line(s), "
                     f"{summary['learned_total_false_positives']} false positive "
                     f"finding(s) [{scope}].")

    # E8m (b): the headline total is every format measured; each single format
    # is printed as an explicitly labelled subset. Never a bare count.
    for format_name, bucket in (fps.get("by_format") or {}).items():
        lines.append(f"  false positives, subset `{format_name}` only: "
                     f"rules {bucket['rules']}, learned "
                     f"{'n/a' if bucket['learned'] is None else bucket['learned']}")

    # E8m (a): the two recalls, each labelled with its denominator.
    flr = summary.get("finding_level_recall") or {}
    if flr:
        rules_fr = flr.get("rules") or {}
        learned_fr = flr.get("learned")
        lines.append("")
        lines.append(f"Line-level recall is over "
                     f"{summary.get('line_level_recall_denominator')}; "
                     f"finding-level recall is over {flr.get('denominator')} "
                     f"({flr.get('true_findings_total')} of them).")
        lines.append(f"  RULES    finding-level recall: "
                     f"{rules_fr.get('recall') if rules_fr.get('recall_defined') else 'n/a'} "
                     f"({rules_fr.get('true_findings_kept')}/"
                     f"{rules_fr.get('true_findings_total')})")
        if learned_fr is None:
            lines.append("  LEARNED  finding-level recall: UNAVAILABLE — "
                         "no number is invented.")
        else:
            lines.append(f"  LEARNED  finding-level recall: "
                         f"{learned_fr.get('recall') if learned_fr.get('recall_defined') else 'n/a'} "
                         f"({learned_fr.get('true_findings_kept')}/"
                         f"{learned_fr.get('true_findings_total')}) — "
                         f"{summary.get('learned_total_dropped_true_findings')} "
                         "finding(s) dropped while citing a malicious line")

        # E8m2 (1): the same recall per rule class, so the losing class is
        # readable without parsing the verbatim dropped list below.
        by_rule = flr.get("by_rule") or {}
        if by_rule:
            lines.append("  finding-level recall BY RULE CLASS "
                         "(denominator: that rule's findings citing a "
                         "malicious line):")
            for rule_id, bucket in by_rule.items():
                rules_cell = bucket["rules"]
                learned_cell = bucket.get("learned")
                if learned_cell is None:
                    learned_text = "learned n/a"
                else:
                    value = (learned_cell["recall"]
                             if learned_cell["recall_defined"] else "n/a")
                    learned_text = (f"learned {value} "
                                    f"({learned_cell['true_findings_kept']}/"
                                    f"{learned_cell['true_findings_total']})")
                    dropped = bucket.get("learned_dropped_true_findings")
                    if dropped:
                        learned_text += f" — {dropped} dropped"
                lines.append(
                    f"    {rule_id}: rules "
                    f"{rules_cell['recall'] if rules_cell['recall_defined'] else 'n/a'} "
                    f"({rules_cell['true_findings_kept']}/"
                    f"{rules_cell['true_findings_total']}), {learned_text}")
            lines.append(f"  {flr.get('by_rule_note')}")

    # E8m (c): the criticality counterfactual, first class.
    sens = summary.get("criticality_sensitivity") or {}
    lines.append("")
    if not sens.get("available"):
        lines.append(f"Criticality sensitivity: UNAVAILABLE — {sens.get('reason')}")
    else:
        importance = sens.get("feature_importance") or {}
        rank = importance.get("criticality_rank")
        lines.append(
            "CRITICALITY SENSITIVITY (counterfactual — the published numbers "
            "above stand as measured):")
        feature_count = len(importance.get("by_feature") or {})
        rank_text = "n/a" if rank is None else str(rank)
        of_text = ("unavailable" if rank is None
                   else f"the largest of {feature_count} features")
        lines.append(f"  `criticality_rank` feature importance: "
                     f"{rank_text} ({of_text})")
        lines.append(f"  domain forced across {sens.get('domain')}")
        for name, bucket in (sens.get("populations") or {}).items():
            lines.append(f"  {name}: {bucket['total']} total — "
                         f"{bucket['robust']} robust, {bucket['flipping']} flip "
                         f"in at least one band")
            lines.append(f"    kept at each band: {bucket['kept_at']}")
        lines.append(f"  {CRITICALITY_SENSITIVITY_NOTE}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", choices=generator.SCENARIOS, action="append", dest="scenarios",
        help=f"scenario to measure (repeatable; default: the frozen benchmark "
             f"set {BENCHMARK_SCENARIOS}). Any scenario the generator can "
             "produce may be measured explicitly, but only the frozen set is "
             "the benchmark.",
    )
    parser.add_argument(
        "--format", choices=generator.FORMATTERS, action="append", dest="formats",
        help="log format to generate (repeatable; default: canonical)",
    )
    parser.add_argument(
        "--seed", type=int, action="append", dest="seeds",
        help=f"benchmark seed (repeatable; default: the frozen {BENCHMARK_SEEDS}). "
             "A seed the model was trained on is refused.",
    )
    parser.add_argument(
        "--model-dir", type=Path, default=None,
        help="directory holding the trained model + provenance sidecar "
             "(default: the shipped console/.soc/models/)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None,
        help=f"where to write generated logs and reports (default: a temp dir; {DEFAULT_OUTPUT_DIR} is gitignored)",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write the full result as JSON")
    args = parser.parse_args(argv)

    # E8m2 (2): the DEFAULT is the referee's frozen set, never the generator's
    # dictionary — adding a scenario there must not move a benchmark number.
    try:
        scenarios = args.scenarios or list(benchmark_scenarios())
    except BenchmarkProvenanceError as exc:
        print(f"BENCHMARK REFUSED: {exc}", file=sys.stderr)
        return 2
    formats = args.formats or ["canonical"]
    seeds = args.seeds or list(BENCHMARK_SEEDS)

    try:
        if args.output_dir is None:
            with tempfile.TemporaryDirectory(prefix="efficacy-harness-") as tmp:
                summary = evaluate(scenarios, formats, Path(tmp), seeds,
                                   args.model_dir)
        else:
            summary = evaluate(scenarios, formats, args.output_dir, seeds,
                               args.model_dir)
    except ValueError as exc:
        parser.error(str(exc))
    except BenchmarkProvenanceError as exc:
        print(f"BENCHMARK REFUSED: {exc}", file=sys.stderr)
        return 2
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
