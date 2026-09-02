"""Backing store for GET/POST ``/api/efficacy`` (D2).

The console has no efficacy numbers of its own. Every number this module hands
to the UI comes verbatim from :func:`tools.efficacy_harness.evaluate`, which
generates a labelled synthetic log and ingests it through the **real** analyzer
as a subprocess. Nothing here recomputes precision/recall/F1, and nothing here
imports ``anomaly_detector`` — the detector stays behind the harness's
subprocess seam.

Since E8 that run scores **two systems** — the rules and the trained learned
triage model — and this module still passes both straight through. In
particular it does NOT choose benchmark seeds, does not read the model, and
does not decide whether the learned half is available: the frozen referee in
``tools/efficacy_harness.py`` owns seed selection, the freshness assertion
against the model's provenance sidecar, and every metric. A run whose learned
half is unavailable arrives here already carrying its reason, and is passed on
unchanged rather than being filled in.

E8m amends what that run PUBLISHES, and this module's job is unchanged: it
still passes every field through untouched. The run body now also carries, all
of it computed by the referee and none of it by the console:

* ``finding_level_recall`` and ``line_level_recall_denominator`` — the two
  recalls, each labelled with the denominator it is over, for BOTH systems,
  plus ``learned_dropped_true_findings``: the verbatim list of findings the
  learned system dropped WHILE they cited malicious lines;
* ``false_positive_totals`` — the headline total scoped to every format the run
  measured, with each single format as an explicitly labelled subset. The
  console must never render a false-positive count without that scope;
* ``criticality_sensitivity`` — the ``criticality_rank`` counterfactual, marked
  ``kind: "counterfactual"``, published as a first-class finding.

Honest states, in the shape the two D2 cards consume:

* ``idle``    — no harness run has been stored yet; ``run`` is ``None``.
  The UI must say "no harness run yet", never 100% and never zeros-as-clean.
* ``running`` — a run is in flight; ``run`` is still ``None``, so there is no
  partial score to fabricate from.
* ``done``    — ``run`` is the harness JSON, pass-through.
* ``error``   — ``error`` is the real backend reason; ``run`` stays ``None``.

The last completed run is persisted to ``console/.soc/efficacy.json`` (already
gitignored) so a GET survives a browser refresh or a server restart.
"""

from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent

SOC_DIR = HERE / ".soc"                  # monkeypatched to a tmp dir in tests
STORE_NAME = "efficacy.json"

# The scope sentence is part of the frozen contract. It is never written onto a
# run here — the harness supplies it; this copy exists so the suite can assert
# that what the API passes through is byte-for-byte the sentence the UI shows.
SCOPE_SENTENCE = (
    "measured against synthetic ground-truth scenarios; "
    "not a claim about production traffic."
)

_LOCK = threading.Lock()
_STATE = {"status": "idle", "run": None, "error": None}
_LOADED = False


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------

def _store_path():
    return Path(SOC_DIR) / STORE_NAME


def _load_stored():
    try:
        data = json.loads(_store_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("scenarios") is not None else None


def _persist(run):
    try:
        directory = Path(SOC_DIR)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / STORE_NAME).write_text(
            json.dumps(run, indent=1, sort_keys=True), encoding="utf-8")
    except OSError:
        # A run we cannot persist is still a run we measured; the in-memory
        # state stays authoritative for this process rather than being lost.
        pass


def reset(forget_stored=False):
    """Drop the in-process state (tests; also lets a new SOC_DIR be picked up)."""
    global _LOADED
    with _LOCK:
        _STATE.update(status="idle", run=None, error=None)
        _LOADED = False
    if forget_stored:
        try:
            _store_path().unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# the contract
# ---------------------------------------------------------------------------

def snapshot():
    """The GET body: ``{status, run, error}`` and nothing else."""
    global _LOADED
    with _LOCK:
        if not _LOADED and _STATE["status"] == "idle":
            _LOADED = True
            stored = _load_stored()
            if stored is not None:
                _STATE.update(status="done", run=stored, error=None)
        return {"status": _STATE["status"], "run": _STATE["run"], "error": _STATE["error"]}


def _harness_runner(scenarios, formats):
    """Drive the real harness. Imported lazily so the console boots without it,
    and so ``anomaly_detector`` is never pulled into this process."""
    import sys
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from tools import efficacy_harness

    with tempfile.TemporaryDirectory(prefix="efficacy-api-") as tmp:
        return efficacy_harness.evaluate(scenarios, formats, Path(tmp))


def available():
    """(scenarios, formats) the harness can measure, or an honest error."""
    import sys
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from tools import attack_generator
    return list(attack_generator.SCENARIOS), list(attack_generator.FORMATTERS)


def start(scenarios=None, formats=None, runner=None, background=True):
    """Kick off a measurement.

    Returns ``(body, http_status)``: 202 with the running snapshot, 409 if a run
    is already in flight, 400 for an unknown scenario/format, 500 if the harness
    could not even be reached. ``runner`` is the seam the tests inject through;
    it takes ``(scenarios, formats)`` and returns the harness summary dict.
    """
    try:
        known_scenarios, known_formats = available()
    except Exception as exc:                       # harness/generator unavailable
        return {"status": "error", "run": None,
                "error": f"efficacy harness unavailable: {exc}"}, 500

    scenarios = list(scenarios) if scenarios else list(known_scenarios)
    formats = list(formats) if formats else ["canonical"]
    unknown = ([s for s in scenarios if s not in known_scenarios]
               + [f for f in formats if f not in known_formats])
    if unknown:
        return {"status": snapshot()["status"], "run": None,
                "error": f"unknown scenario/format: {', '.join(sorted(set(unknown)))}"}, 400

    with _LOCK:
        if _STATE["status"] == "running":
            return {"status": "running", "run": None,
                    "error": "an efficacy run is already in flight"}, 409
        _STATE.update(status="running", run=None, error=None)

    run = runner or _harness_runner

    def work():
        global _LOADED
        try:
            summary = run(scenarios, formats)
            if not isinstance(summary, dict) or "scenarios" not in summary:
                raise RuntimeError("harness returned no scenarios")
        except Exception as exc:                   # honest failure, never a fake table
            with _LOCK:
                _STATE.update(status="error", run=None,
                              error=f"{type(exc).__name__}: {exc}")
                _LOADED = True
            return
        _persist(summary)
        with _LOCK:
            _STATE.update(status="done", run=summary, error=None)
            _LOADED = True

    if background:
        threading.Thread(target=work, name="efficacy-harness", daemon=True).start()
        return {"status": "running", "run": None, "error": None}, 202

    work()
    settled = snapshot()
    if settled["status"] == "error":
        # A synchronous run that already failed reports the real reason now
        # rather than a 202 the caller would have to poll to disbelieve.
        return {"status": "error", "run": None, "error": settled["error"]}, 500
    return {"status": "running", "run": None, "error": None}, 202
