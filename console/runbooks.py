#!/usr/bin/env python3
"""
runbooks.py — declarative runbook definitions + the STRUCTURAL eligibility engine.

Stage C / C0-T1. Backend only: this module declares what a runbook *is*, loads
and validates the shipped definitions, and answers one question —

    is this incident eligible for this runbook, and if not, what is missing?

Guardrail 1 is the whole point of this module: **rules own eligibility.** The
LLM is advisory everywhere in this repo and can never be an eligibility input.
That is enforced here *structurally*, not by convention:

  * `eligible()` takes exactly three positional-or-keyword parameters —
    `runbook`, `incident`, `findings` — and declares **no** `*args` and no
    `**kwargs`. There is therefore no parameter, named or variadic, through
    which an advisory/LLM/narrative signal could be passed. It is impossible,
    not merely discouraged. `console/test_console.py::check_runbooks` asserts
    this against the real `inspect.signature(eligible)` at runtime.

  * Data smuggling is closed too. Findings in this repo carry advisory fields
    (`llmSev`, `llmWhy`, `explanation`, …) side by side with rule-owned ones.
    Before any predicate runs, `_rule_facts()` projects the incident and its
    member findings through `RULE_OWNED_*` allowlists, so the advisory fields
    are not present in the values the engine ever sees. Mutating them cannot
    change an eligibility outcome.

Nothing here executes anything. No connector is contacted, no approval flow is
implied, no UI is rendered — those are later phases. A runbook step is inert
declarative data until a later card gives it an executor.

Evidence convention: this repo cites evidence as record `{n}` refs — a finding's
`lines[].n` line numbers (see console/adapter.py `_evidence_lines`). The
`record_refs` evidence key means exactly "at least one member finding carries a
real record `{n}` ref", never a reconstruction.

Storage note: PyYAML is NOT importable in this environment and installing it is
out of scope (no new dependency). The shipped `console/runbooks/*.yaml` files are
therefore written in the JSON subset of YAML — valid YAML 1.2 that `json.loads`
parses from the stdlib. `_parse` prefers `yaml.safe_load` when PyYAML is present,
so adding the dependency later changes nothing.

Usage:
  import runbooks
  rbs = runbooks.load_runbooks()
  runbooks.eligible(rbs["rb-block-ip"], incident, findings)
"""

import inspect
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNBOOK_DIR = HERE / "runbooks"

# Severity ordering — same ranking soc.py uses (imported by value, not by
# reference, so this module stays importable standalone).
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

STEP_TYPES = ("action", "notify_draft")

# --- the rule-owned projection -------------------------------------------
# Only these keys reach a predicate. Everything else — crucially every advisory
# field the LLM writes — is dropped before evaluation.
RULE_OWNED_INCIDENT_KEYS = frozenset({
    "id", "entity", "entityKind", "severity", "findingIds",
    "firstSeen", "lastSeen",
})
RULE_OWNED_FINDING_KEYS = frozenset({
    "id", "type", "ruleSev", "sev", "host", "occurrences", "lines",
})
# Named for the test that asserts the allowlists and this set stay disjoint.
ADVISORY_KEYS = frozenset({
    "llmSev", "llmWhy", "explanation", "hypothesis", "narrative", "rca",
    "advisory", "modelFindings", "summary", "prose", "llm",
})

_ADVISORY_WORD_RE = re.compile(
    r"llm|advisory|narrative|hypoth|explan|model|prose|summary|rca",
    re.IGNORECASE)


class RunbookError(ValueError):
    """A runbook definition violated the schema. Raised, never coerced away."""


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------

def _require(cond, msg):
    if not cond:
        raise RunbookError(msg)


def _str_list(value, where):
    _require(isinstance(value, list), f"{where} must be a list")
    for item in value:
        _require(isinstance(item, str) and item.strip(),
                 f"{where} entries must be non-empty strings, got {item!r}")
    return list(value)


def validate_runbook(doc):
    """Validate one parsed runbook document and return it normalized.

    Rejects loudly: a missing field, an unknown field, a wrong type or an
    unknown step type raises RunbookError. Nothing is defaulted into place and
    nothing is coerced — an invalid runbook must not silently become a valid
    one, because a runbook that quietly changed shape is a runbook whose
    eligibility answer cannot be trusted.
    """
    _require(isinstance(doc, dict), "runbook must be a mapping")

    allowed = {"id", "name", "trigger", "preconditions", "steps", "severity_floor"}
    unknown = sorted(set(doc) - allowed)
    _require(not unknown, f"unknown top-level field(s): {unknown}")
    missing = sorted(allowed - set(doc))
    _require(not missing, f"missing required field(s): {missing}")

    _require(isinstance(doc["id"], str) and doc["id"].strip(), "id must be a non-empty string")
    _require(isinstance(doc["name"], str) and doc["name"].strip(), "name must be a non-empty string")

    trig = doc["trigger"]
    _require(isinstance(trig, dict), "trigger must be a mapping")
    _require(set(trig) == {"rule_ids", "entity_types"},
             f"trigger must have exactly rule_ids and entity_types, got {sorted(trig)}")
    _str_list(trig["rule_ids"], "trigger.rule_ids")
    _str_list(trig["entity_types"], "trigger.entity_types")
    _require(trig["rule_ids"], "trigger.rule_ids must not be empty — "
                               "a runbook with no trigger rule could never fire")

    pre = doc["preconditions"]
    _require(isinstance(pre, dict), "preconditions must be a mapping")
    _require(set(pre) == {"required_evidence"},
             f"preconditions must have exactly required_evidence, got {sorted(pre)}")
    _str_list(pre["required_evidence"], "preconditions.required_evidence")

    steps = doc["steps"]
    _require(isinstance(steps, list) and steps, "steps must be a non-empty list")
    for i, step in enumerate(steps):
        where = f"steps[{i}]"
        _require(isinstance(step, dict), f"{where} must be a mapping")
        _require(set(step) == {"type", "connector", "params_template", "rollback"},
                 f"{where} must have exactly type, connector, params_template, "
                 f"rollback — got {sorted(step)}")
        _require(step["type"] in STEP_TYPES,
                 f"{where}.type must be one of {list(STEP_TYPES)}, got {step['type']!r}")
        _require(isinstance(step["connector"], str) and step["connector"].strip(),
                 f"{where}.connector must be a non-empty string")
        _require(isinstance(step["params_template"], dict),
                 f"{where}.params_template must be a mapping")
        # rollback is explicit: a mapping describing the undo, or an explicit
        # null meaning "this step has no rollback". Absent is not allowed —
        # a silently missing rollback would read as "safe" when it is not.
        _require(step["rollback"] is None or isinstance(step["rollback"], dict),
                 f"{where}.rollback must be a mapping or an explicit null")

    floor = doc["severity_floor"]
    _require(isinstance(floor, str) and floor.upper() in SEV_RANK,
             f"severity_floor must be one of {sorted(SEV_RANK)}, got {floor!r}")

    return doc


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def _parse(text, path):
    """Parse a runbook file. PyYAML when available; stdlib JSON otherwise.

    The shipped files are written in the JSON subset of YAML precisely so this
    holds either way. A parse failure is an error, never an empty runbook.
    """
    try:
        import yaml                                   # noqa: F401  (optional)
    except ImportError:
        pass
    else:
        try:
            return yaml.safe_load(text)
        except Exception as exc:                      # pragma: no cover
            raise RunbookError(f"{path.name}: YAML parse error: {exc}") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise RunbookError(
            f"{path.name}: not parseable as the JSON subset of YAML "
            f"(PyYAML is not installed here): {exc}") from exc


def load_runbook(path):
    """Load and validate one runbook file. Raises RunbookError on any violation."""
    path = Path(path)
    doc = validate_runbook(_parse(path.read_text(encoding="utf-8"), path))
    if doc["id"] != path.stem:
        raise RunbookError(
            f"{path.name}: id {doc['id']!r} does not match the filename stem "
            f"{path.stem!r} — ids must be locatable on disk")
    return doc


def load_runbooks(directory=None):
    """Load every runbook in `directory` (default console/runbooks/).

    An empty or absent directory returns `{}` — an honest empty, not a
    fabricated default runbook.
    """
    directory = Path(directory or RUNBOOK_DIR)
    if not directory.is_dir():
        return {}
    out = {}
    for path in sorted(directory.glob("*.yaml")):
        doc = load_runbook(path)
        if doc["id"] in out:
            raise RunbookError(f"duplicate runbook id {doc['id']!r}")
        out[doc["id"]] = doc
    return out


# --------------------------------------------------------------------------
# rule-owned facts
# --------------------------------------------------------------------------

def _rule_facts(incident, findings):
    """Project an incident + its member findings down to rule-owned fields only.

    This is the structural half of guardrail 1. Advisory fields are not
    filtered *after* being considered — they never enter the projection, so no
    predicate downstream can read one even by accident.
    """
    inc = {k: v for k, v in dict(incident or {}).items()
           if k in RULE_OWNED_INCIDENT_KEYS}
    wanted = set(inc.get("findingIds") or [])
    members = []
    for f in list(findings or []):
        f = dict(f or {})
        if wanted and f.get("id") not in wanted:
            continue
        members.append({k: v for k, v in f.items() if k in RULE_OWNED_FINDING_KEYS})
    return inc, members


def evidence_keys(incident, findings):
    """The evidence an incident actually carries, as a set of declarative keys.

    Vocabulary (this is what `preconditions.required_evidence` may name):
      entity                 the incident has a real entity
      entity_kind:<kind>     that entity is of kind <kind> (ip / user / host / rule)
      rule_verdict:<rule_id> a member finding carries that rule's verdict
      record_refs            >=1 member finding cites a real record {n}
      host                   >=1 member finding names a real host
      timestamps             both firstSeen and lastSeen are known
      occurrences            >=1 member finding carries a real occurrence count
    Every key is computed from rule output alone.
    """
    inc, members = _rule_facts(incident, findings)
    keys = set()
    if inc.get("entity"):
        keys.add("entity")
    if inc.get("entityKind"):
        keys.add(f"entity_kind:{inc['entityKind']}")
    if inc.get("firstSeen") and inc.get("lastSeen"):
        keys.add("timestamps")
    for f in members:
        if f.get("type"):
            keys.add(f"rule_verdict:{f['type']}")
        if f.get("host") not in (None, "", "—"):
            keys.add("host")
        try:
            if int(f.get("occurrences") or 0) > 0:
                keys.add("occurrences")
        except (TypeError, ValueError):
            pass
        for line in f.get("lines") or []:
            if isinstance(line, dict) and line.get("n") is not None:
                keys.add("record_refs")
                break
    return keys


# --------------------------------------------------------------------------
# the eligibility engine
# --------------------------------------------------------------------------

def eligible(runbook, incident, findings):
    """Is `incident` eligible for `runbook`? -> {"eligible": bool, "missing": [...]}

    Computed ONLY from rule verdicts and evidence. The signature is closed by
    construction: three parameters, no *args, no **kwargs, so there is no way
    to hand this function an LLM/advisory/narrative signal at all. Guardrail 1
    is a property of the interface here, not a promise in a docstring.

    `missing` names every unmet requirement — trigger rule, entity type,
    severity floor, and each absent piece of required evidence. An ineligible
    incident always says why; it is never silently "not eligible".
    """
    rb = validate_runbook(runbook)
    inc, members = _rule_facts(incident, findings)
    have = evidence_keys(incident, findings)
    missing = []

    fired = {f.get("type") for f in members if f.get("type")}
    wanted_rules = list(rb["trigger"]["rule_ids"])
    if not fired & set(wanted_rules):
        missing.append(
            "trigger.rule_ids: none of " + ", ".join(sorted(wanted_rules)) +
            " present (incident rules: " +
            (", ".join(sorted(fired)) if fired else "none") + ")")

    kinds = list(rb["trigger"]["entity_types"])
    kind = inc.get("entityKind")
    if kinds and kind not in kinds:
        missing.append(
            "trigger.entity_types: entity kind " +
            (repr(kind) if kind else "unknown") +
            " is not one of " + ", ".join(sorted(kinds)))

    floor = rb["severity_floor"].upper()
    sev = str(inc.get("severity") or "").upper()
    if sev not in SEV_RANK:
        missing.append(
            f"severity_floor: incident severity is unknown "
            f"({inc.get('severity')!r}) — cannot clear the {floor} floor")
    elif SEV_RANK[sev] > SEV_RANK[floor]:
        missing.append(
            f"severity_floor: incident is {sev}, below the {floor} floor")

    for key in rb["preconditions"]["required_evidence"]:
        if key not in have:
            missing.append(f"required_evidence: {key}")

    return {"eligible": not missing, "missing": missing}


def match_runbooks(incident, findings, runbooks=None):
    """Every runbook this incident is eligible for, by id. `[]` when none.

    An incident with no matching runbook returns an empty list — the honest
    empty state. There is no fallback runbook and no default-to-eligible.
    """
    books = load_runbooks() if runbooks is None else runbooks
    return sorted(rid for rid, rb in books.items()
                  if eligible(rb, incident, findings)["eligible"])


def evaluate_all(incident, findings, runbooks=None):
    """Every runbook with its full verdict — for surfacing *why* not, honestly."""
    books = load_runbooks() if runbooks is None else runbooks
    return {rid: eligible(rb, incident, findings) for rid, rb in sorted(books.items())}


# --------------------------------------------------------------------------
# the no-override property, available to callers as well as to the test
# --------------------------------------------------------------------------

ELIGIBILITY_PARAMS = ("runbook", "incident", "findings")


def assert_no_llm_input(func=None):
    """Assert that `eligible` is structurally closed to advisory input.

    Checks the live `inspect.signature`, not a comment:
      1. its parameters are exactly ELIGIBILITY_PARAMS, in order;
      2. none of them is variadic (*args / **kwargs) — so an extra argument
         cannot be smuggled in under any name;
      3. no parameter name reads as advisory/LLM/narrative.
    Raises AssertionError with the offending signature. Returns the signature.
    """
    func = eligible if func is None else func
    sig = inspect.signature(func)
    params = list(sig.parameters.values())
    names = tuple(p.name for p in params)
    assert names == ELIGIBILITY_PARAMS, (
        f"eligible() must take exactly {ELIGIBILITY_PARAMS}; got {names} — {sig}")
    for p in params:
        assert p.kind not in (inspect.Parameter.VAR_POSITIONAL,
                              inspect.Parameter.VAR_KEYWORD), (
            f"eligible() must declare no *args/**kwargs — {p.name} is {p.kind} — {sig}")
        assert not _ADVISORY_WORD_RE.search(p.name), (
            f"eligible() parameter {p.name!r} reads as an advisory input — {sig}")
    return sig
