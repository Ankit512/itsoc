#!/usr/bin/env python3
"""
precedent.py — the deterministic precedent index (Stage E, card E1).

What it is: "have we seen this before?", answered from stored incidents alone.
Given one incident and the incident store, it returns the prior incidents that
share rule-owned facts with it, ranked by how much they share, each carrying an
explanation built out of the shared facts themselves and — when the analyst
recorded one — the stored disposition of that prior incident.

What it is NOT, structurally rather than by promise (E6 wall, guardrail 1):

  * **Not a verdict and not an eligibility input.** `rank()` takes exactly two
    positional-or-keyword parameters — `incident`, `candidates` — with no
    `*args` and no `**kwargs`. There is no parameter, named or variadic,
    through which an advisory / model / LLM signal could enter the ranking.
    `assert_no_advisory_input()` checks that against the live
    `inspect.signature`, and `tests/test_stage_e_wall.py` runs it.

  * **Not reachable by data smuggling.** `facts()` projects every record
    through `RULE_OWNED_PRECEDENT_KEYS` before any comparison, exactly as
    `runbooks._rule_facts` does for eligibility. Stage E advisory fields
    (`similarityNote`, `precedentOpinion`, `proposalDraft`, `llmSev`, …) are
    simply not present in the values the ranker sees, so mutating them cannot
    change an ordering.

  * **Not a learned loop.** E0 disposition is DISPLAY_ONLY_KEYS, disjoint from
    the projection. Ranking cannot see a disposition, so a precedent's recorded
    outcome can never feed back into which precedents surface.
    `assert_no_disposition_input()` checks that disjointness.

  * **Not networked.** This module imports `inspect` and `re` and nothing else.
    The wall parses that from the AST, so the claim is checked, not asserted.

The ranking is pure set overlap over rule-owned facts, ordered by
(-overlap, -dimensionsMatched, id): total, reproducible, and broken by nothing
but the incident id. No model, no network, no randomness, no clock.

Scale: `Index` is a real inverted index over (dimension, value) tokens, so a
query scores only the candidates that share at least one fact and never walks
the store. `Index.cost()` reports that as exact integers, so "it does not scan"
is a deterministic assertion rather than a stopwatch reading.

Usage:
  import precedent
  idx = precedent.Index(stored_incidents)          # optional, reusable
  precedent.rank(incident, idx)                    # -> [{"id", "overlap", ...}]
  precedent.query(incident, idx, limit=10)         # + display + disposition
"""

import inspect
import re

# Only these keys reach the comparison. Everything else — crucially every
# Stage E advisory field and every E0 disposition field — is dropped before
# ranking. `techniques` and `criticality` are the store's own spellings of the
# ATT&CK and asset-criticality facts; `attackTags`/`assetCriticality` are the
# canonical dimension names, and both spellings feed the same dimension.
RULE_OWNED_PRECEDENT_KEYS = frozenset({
    "id", "entity", "entityKind", "entityValues", "severity",
    "ruleIds", "attackTags", "techniques", "assetCriticality", "criticality",
})

# Read for DISPLAY on a returned match, never by the ranker. Asserted disjoint
# from RULE_OWNED_PRECEDENT_KEYS by assert_no_disposition_input().
DISPLAY_ONLY_KEYS = ("title", "state", "createdAt", "runId", "severity",
                     "disposition", "dispositionReason", "dispositionAt")

# The dimensions overlap is counted over, in the order they are reported, and
# the record keys each one may be sourced from.
OVERLAP_DIMENSIONS = ("ruleIds", "entity", "attackTags", "assetCriticality")
DIMENSION_SOURCES = {
    "ruleIds": ("ruleIds",),
    "entity": ("entity", "entityValues"),
    "attackTags": ("attackTags", "techniques"),
    "assetCriticality": ("assetCriticality", "criticality"),
}
DIMENSION_LABELS = {
    "ruleIds": "same rule",
    "entity": "same entity",
    "attackTags": "same ATT&CK technique",
    "assetCriticality": "same asset criticality",
}

RANK_PARAMS = ("incident", "candidates")
DEFAULT_LIMIT = 10

_ADVISORY_WORD_RE = re.compile(
    r"llm|advisory|narrative|hypoth|explan|model|prose|summary|rca|"
    r"similarity|precedent_opinion|opinion|proposal|draft",
    re.IGNORECASE)


# ---------------------------------------------------------------------------
# projection
# ---------------------------------------------------------------------------

def facts(record):
    """Project one incident to its rule-owned facts. Advisory and disposition
    keys never survive — this is the only door into the ranker."""
    if not isinstance(record, dict):
        return {}
    return {k: v for k, v in record.items() if k in RULE_OWNED_PRECEDENT_KEYS}


_facts = facts        # E6 spelling, kept so nothing that imported it breaks.


def _atoms(value):
    """Comparable string atoms for one stored value. A technique dict
    contributes its id (`{"id": "T1110", ...}` -> "T1110"); a scalar
    contributes itself; None contributes nothing."""
    if value is None:
        return
    if isinstance(value, dict):
        ident = value.get("id")
        if ident is not None:
            yield str(ident)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            for atom in _atoms(item):
                yield atom
        return
    text = str(value).strip()
    if text:
        yield text


def _values(record_facts, dimension):
    """The comparable value set for one dimension, unioned over every store
    spelling that feeds it. Absent -> empty set (an honest no-overlap, never a
    wildcard match)."""
    out = set()
    for key in DIMENSION_SOURCES.get(dimension, (dimension,)):
        out.update(_atoms(record_facts.get(key)))
    return frozenset(out)


def tokens(record_facts):
    """Every (dimension, value) token a record carries. The index key space."""
    return {(dim, val) for dim in OVERLAP_DIMENSIONS
            for val in _values(record_facts, dim)}


# ---------------------------------------------------------------------------
# the index
# ---------------------------------------------------------------------------

class Index:
    """Inverted index over (dimension, value) tokens of stored incidents.

    Built once, queried many times. `candidates_for()` returns only the records
    that share at least one fact token with the query, so a query never walks
    the store and zero-overlap candidates are excluded by construction rather
    than by a post-filter.

    Pure data: the constructor projects every record through `facts()` on the
    way in, so the index physically cannot hold an advisory or disposition
    value in a ranking position. The original records are kept separately and
    are read only for display decoration in `query()`.
    """

    def __init__(self, candidates):
        self.records = []          # original dicts, positionally aligned
        self.facts = []            # rule-owned projections
        self.ids = []
        self.by_id = {}            # id -> original record, for display only
        self.postings = {}         # (dim, value) -> [positions], ascending
        for record in candidates or []:
            projected = facts(record)
            cid = projected.get("id")
            if cid is None or str(cid) == "":
                continue           # an id-less record is not addressable
            pos = len(self.facts)
            self.records.append(record if isinstance(record, dict) else {})
            self.facts.append(projected)
            self.ids.append(str(cid))
            self.by_id.setdefault(str(cid), record)
            for token in tokens(projected):
                self.postings.setdefault(token, []).append(pos)

    def __len__(self):
        return len(self.facts)

    def candidates_for(self, query_facts):
        """Ascending positions of every record sharing >=1 token. Deterministic."""
        hits = set()
        for token in tokens(query_facts):
            hits.update(self.postings.get(token, ()))
        return sorted(hits)

    def cost(self, incident):
        """Exact, clock-free query cost. `stored` is the whole index; `scored`
        is how many records the query actually compares. Asserting
        scored << stored is what proves the index is an index."""
        query_facts = facts(incident)
        query_tokens = tokens(query_facts)
        return {
            "stored": len(self.facts),
            "queryTokens": len(query_tokens),
            "postingsRead": sum(len(self.postings.get(t, ())) for t in query_tokens),
            "scored": len(self.candidates_for(query_facts)),
        }


# ---------------------------------------------------------------------------
# ranking
# ---------------------------------------------------------------------------

def explain(matched):
    """The human sentence for a match, derived ONLY from its matched facts.

    Pure function of `matched`: same input, same string, every time. A caller
    (or a test) can recompute it from the match's own `matched` map, which is
    what "the explanation is derivable from the facts" means operationally.
    """
    return "; ".join(because(matched))


def because(matched):
    """One clause per matched dimension, in OVERLAP_DIMENSIONS order."""
    out = []
    for dim in OVERLAP_DIMENSIONS:
        vals = matched.get(dim) or []
        if vals:
            out.append(f"{DIMENSION_LABELS[dim]}: " + ", ".join(vals))
    return out


def rank(incident, candidates):
    """Rank `candidates` by rule-owned overlap with `incident`.

    `candidates` is a list of stored incidents or a prebuilt `Index` over them.

    Returns a list of matches, each
    `{"id", "overlap", "dimensions", "matched", "because", "explanation"}`,
    most overlap first. Ties break on the number of distinct dimensions
    matched, then on id, so the ordering is total and reproducible.

    Two omissions are deliberate and are the honesty of this function:
      * the queried incident is never its own precedent — it is excluded by id;
      * a candidate with no overlap is omitted entirely. An incident with no
        precedent gets the empty list, never a nearest-anything fallback.

    No model, no network, no clock, no randomness, no disposition.
    """
    base = facts(incident)
    base_id = str(base.get("id") or "")
    base_values = {dim: _values(base, dim) for dim in OVERLAP_DIMENSIONS}
    index = candidates if isinstance(candidates, Index) else Index(candidates)

    out = []
    for pos in index.candidates_for(base):
        cid = index.ids[pos]
        if base_id and cid == base_id:
            continue
        cand = index.facts[pos]
        overlap = 0
        matched = {}
        for dim in OVERLAP_DIMENSIONS:
            shared = base_values[dim] & _values(cand, dim)
            if shared:
                overlap += len(shared)
                matched[dim] = sorted(shared)
        if not overlap:
            continue           # unreachable via the index; kept as the contract
        out.append({
            "id": cid,
            "overlap": overlap,
            "dimensions": [d for d in OVERLAP_DIMENSIONS if d in matched],
            "matched": matched,
            "because": because(matched),
            "explanation": explain(matched),
        })
    out.sort(key=lambda m: (-m["overlap"], -len(m["dimensions"]), m["id"]))
    return out


# ---------------------------------------------------------------------------
# the query surface — ranking plus display facts
# ---------------------------------------------------------------------------

def query(incident, candidates, limit=DEFAULT_LIMIT):
    """Ranked precedents for `incident`, decorated with display facts.

    Ranking happens FIRST and in full (`rank()` above); the display decoration
    below only reads keys off the already-ranked record. Disposition therefore
    cannot participate in the ordering even in principle — by the time it is
    read, the order is fixed.

    Every disposition field is reported exactly as stored, including its
    absence: `disposition: null` with `dispositionRecorded: false` reads as
    "this precedent was never dispositioned", never as a guess.
    """
    index = candidates if isinstance(candidates, Index) else Index(candidates)
    ranked = rank(incident, index)
    total = len(ranked)
    if limit is not None and limit >= 0:
        ranked = ranked[:limit]

    matches = []
    for match in ranked:
        record = index.by_id.get(match["id"], {})
        display = {k: record.get(k) for k in DISPLAY_ONLY_KEYS}
        display["dispositionRecorded"] = bool(record.get("disposition"))
        matches.append({**match, **display})

    return {
        "incidentId": str(facts(incident).get("id") or ""),
        "dimensions": list(OVERLAP_DIMENSIONS),
        "candidatesStored": len(index),
        "candidatesScored": index.cost(incident)["scored"],
        "matchCount": total,
        "precedents": matches,
        "note": ("Deterministic overlap of rule-owned facts over stored incidents. "
                 "Recall only — never a severity, a priority, or an eligibility input."),
    }


# ---------------------------------------------------------------------------
# structural assertions (run by tests/test_stage_e_wall.py)
# ---------------------------------------------------------------------------

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


def assert_no_disposition_input():
    """Assert the E0 disposition is display-only and cannot reach the ranker.

    Three properties, all structural:
      1. no display-only key is in the rule-owned projection;
      2. no dimension is sourced from a disposition key;
      3. `facts()` drops every disposition key off a real record.
    Returns the projected key set.
    """
    display = frozenset(DISPLAY_ONLY_KEYS)
    # `severity` is legitimately both: a rule-owned fact AND shown on a card.
    leaked_display = (display & RULE_OWNED_PRECEDENT_KEYS) - {"severity"}
    assert not leaked_display, (
        f"display-only keys leaked into the projection: {sorted(leaked_display)}")
    sourced = {k for keys in DIMENSION_SOURCES.values() for k in keys}
    bad = sorted(k for k in sourced if "disposition" in k.lower())
    assert not bad, f"a dimension is sourced from a disposition key: {bad}"
    probe = facts({"id": "x", "ruleIds": ["r"], "disposition": "confirmed",
                   "dispositionReason": "why", "dispositionAt": "2026-01-01",
                   "dispositionHistory": [{"action": "set"}]})
    leaked = sorted(k for k in probe if "disposition" in k.lower())
    assert not leaked, f"facts() carried a disposition key through: {leaked}"
    return frozenset(probe)
