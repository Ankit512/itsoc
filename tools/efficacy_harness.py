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
    rules_entry = diff(manifest, {"findings": copy.deepcopy(findings)})
    rules_system = {
        "system": "rules",
        "available": True,
        "reason": None,
        "findings": rules_entry["totals"]["findings"],
        "totals": rules_entry["totals"],
        "per_rule": rules_entry["per_rule"],
        "misses": rules_entry["misses"],
        "false_positives": rules_entry["false_positives"],
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
    return (f"    {label:<8} precision={precision} "
            f"recall={recall} f1={f1} "
            f"({totals['malicious_lines_detected']}/{totals['malicious_lines']} "
            f"malicious lines, {totals['false_positive_findings']} false "
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

    for entry in summary["scenarios"]:
        lines.append(f"[{entry['scenario']} / {entry['format']} / seed "
                     f"{entry.get('seed')}] ground truth: "
                     f"{entry.get('scenario_class')}")
        lines.append(_system_line("RULES", entry["rules"]))
        lines.append(_system_line("LEARNED", entry["learned"]))
        lines.extend(_miss_lines("RULES", entry["rules"]))
        lines.extend(_miss_lines("LEARNED", entry["learned"]))
        for false_positive in entry["rules"]["false_positives"]:
            lines.append(f"      RULES FALSE POSITIVE [{false_positive['rule_id']}] "
                         f"{false_positive['summary']}")
        lines.append("")

    lines.append(f"Rules totals: {summary['total_misses']} missed malicious "
                 f"line(s), {summary['total_false_positives']} false positive "
                 "finding(s).")
    if summary.get("learned_total_misses") is None:
        lines.append("Learned totals: UNAVAILABLE — no number is invented.")
    else:
        lines.append(f"Learned totals: {summary['learned_total_misses']} missed "
                     f"malicious line(s), "
                     f"{summary['learned_total_false_positives']} false positive "
                     "finding(s).")
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

    scenarios = args.scenarios or list(generator.SCENARIOS)
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
