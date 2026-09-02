#!/usr/bin/env python3
"""
precedent.py — deterministic precedent ranking (Stage E, interface only).

Scope note (E6): this module exists so the Stage E wall has a REAL signature to
close, not a hypothetical one. It carries the minimal deterministic ranking
interface the guard contract needs and nothing more. **E1 owns the real index
implementation** — the store query, the ATT&CK tag join, the disposition
surface. Do not grow this file under an E6 ticket.

Guardrail 1 restated for precedent recall: precedent is *recall*, never a
verdict and never an eligibility input. Two properties hold structurally here:

  * `rank()` takes exactly two positional-or-keyword parameters —
    `incident`, `candidates` — with no `*args` and no `**kwargs`. There is
    therefore no parameter, named or variadic, through which an advisory /
    model / LLM signal could enter the ranking. `assert_no_advisory_input()`
    checks that against the live `inspect.signature`, and
    `tests/test_stage_e_wall.py` runs it.

  * Data smuggling is closed the same way `runbooks._rule_facts` closes it:
    `_rule_facts()` projects each incident through `RULE_OWNED_PRECEDENT_KEYS`
    before any comparison, so Stage E advisory fields (`similarityNote`,
    `precedentOpinion`, `proposalDraft`, `llmSev`, …) are simply not present in
    the values the ranker sees. Mutating them cannot change an ordering.

The ranking itself is pure set overlap over rule-owned facts, ordered by
(-overlap, id) so the result is total and reproducible — no model, no network,
no randomness, no tie broken by anything but the incident id.

Usage:
  import precedent
  precedent.rank(incident, candidates)  # -> [{"id", "overlap", "because"}, ...]
"""

import inspect
import re

# Only these keys reach the comparison. Everything else — crucially every
# Stage E advisory field — is dropped before ranking.
RULE_OWNED_PRECEDENT_KEYS = frozenset({
    "id", "entity", "entityKind", "severity",
    "ruleIds", "attackTags", "assetCriticality",
})

# The dimensions overlap is counted over, in the order they are reported.
OVERLAP_DIMENSIONS = ("ruleIds", "entity", "attackTags", "assetCriticality")

RANK_PARAMS = ("incident", "candidates")

_ADVISORY_WORD_RE = re.compile(
    r"llm|advisory|narrative|hypoth|explan|model|prose|summary|rca|"
    r"similarity|precedent_opinion|opinion|proposal|draft",
    re.IGNORECASE)


def _facts(record):
    """Project one incident to its rule-owned facts. Advisory keys never survive."""
    if not isinstance(record, dict):
        return {}
    return {k: v for k, v in record.items() if k in RULE_OWNED_PRECEDENT_KEYS}


def _values(facts, dimension):
    """The comparable value set for one dimension. Absent -> empty set."""
    value = facts.get(dimension)
    if value is None:
        return frozenset()
    if isinstance(value, (list, tuple, set, frozenset)):
        return frozenset(str(v) for v in value if v is not None)
    return frozenset({str(value)})


def rank(incident, candidates):
    """Rank `candidates` by rule-owned overlap with `incident`.

    Returns a list of `{"id", "overlap", "because"}`, most overlap first, ties
    broken by id so the ordering is total and reproducible. Candidates with no
    overlap are omitted — an incident with no precedent gets the honest empty
    list, never a nearest-anything fallback.

    `because` names every dimension that matched and the values that matched,
    so a displayed precedent can always be traced back to the facts that
    produced it.
    """
    base = _facts(incident)
    out = []
    for cand in candidates or []:
        facts = _facts(cand)
        cid = facts.get("id")
        if not cid:
            continue
        overlap = 0
        because = []
        for dim in OVERLAP_DIMENSIONS:
            shared = _values(base, dim) & _values(facts, dim)
            if shared:
                overlap += len(shared)
                because.append(f"{dim}: " + ", ".join(sorted(shared)))
        if overlap:
            out.append({"id": str(cid), "overlap": overlap, "because": because})
    out.sort(key=lambda m: (-m["overlap"], m["id"]))
    return out


def assert_no_advisory_input(func=None):
    """Assert `rank` is structurally closed to advisory/model/LLM input.

    Checks the live `inspect.signature`, not a comment:
      1. its parameters are exactly RANK_PARAMS, in order;
      2. none is variadic (*args / **kwargs) — nothing can be smuggled in
         under any name;
      3. no parameter name reads as advisory / model / LLM / Stage E prose.
    Raises AssertionError naming the offending signature. Returns the signature.
    """
    func = rank if func is None else func
    sig = inspect.signature(func)
    params = list(sig.parameters.values())
    names = tuple(p.name for p in params)
    assert names == RANK_PARAMS, (
        f"rank() must take exactly {RANK_PARAMS}; got {names} — {sig}")
    for p in params:
        assert p.kind not in (inspect.Parameter.VAR_POSITIONAL,
                              inspect.Parameter.VAR_KEYWORD), (
            f"rank() must declare no *args/**kwargs — {p.name} is {p.kind} — {sig}")
        assert not _ADVISORY_WORD_RE.search(p.name), (
            f"rank() parameter {p.name!r} reads as an advisory input — {sig}")
    return sig
