"""Deterministic investigation engine (Stage-C C2).

EXTENDS `soc.derive_rca` — it does not reimplement it. `derive_rca` already gives
the deterministic Layer-1 facts (member timeline, unique rules, first/last seen)
and the Layer-2 runbook citation; this module adds four more deterministic layers
built straight from the run's own event records:

    timeline      full reconstruction from the events store, not just the sparse
                  finding-level entries derive_rca merges
    correlation   the incident entity mapped to the assets (hosts) it touched
    iocs          deterministic IOC extraction (IPs, accounts) over real records
    blastRadius   the set of assets and accounts in scope

Every fact this module emits carries a **resolvable record `{n}` citation** — the
`n` of a real row in the events store — so nothing here is a reconstruction that
cannot be traced back to a verbatim source line.

The one hard rule of this card is Decision **D2**: *deterministic case assembly
never waits on the LLM.* So `assemble()` takes no model callable and makes no
network call — it calls `derive_rca` with `hypothesis_fn=None` and returns the
whole deterministic case immediately. The advisory (model) layer is dispatched
SEPARATELY and shows an honest `pending` state until it fills or times out; it is
never allowed to block, delay, or fabricate the facts. Rules own severity; nothing
here reads back or changes a verdict.
"""

import concurrent.futures
import json
import re
import time

import explanation_guard
import log_analyzer as la
import redact
import soc

# The advisory chip label the console already uses for the model layer, kept
# identical so the split is invisible to the frontend contract.
ADVISORY_LABEL = "advisory · hypothesis · not a verdict"
ADVISORY_TIMEOUT = 45

_ADVISORY_AGENTS = {
    "narrative": "Summarize what happened and the likely sequence. Do not invent causality.",
    "attack": "Map only ATT&CK techniques supported by the cited records; explain the mapping.",
    "pivots": "Suggest concrete analyst pivots supported by the cited records, not remediation actions.",
}

_ADVISORY_SCHEMA = {
    "type": "object",
    "properties": {
        "sentences": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "records": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["text", "records"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["sentences"],
    "additionalProperties": False,
}

_ADVISORY_SYSTEM = (
    "You are one of three parallel SOC advisory agents. Rules own every verdict, "
    "severity, priority, correlation and eligibility; you may not change them. "
    "Use only the supplied deterministic case. Return JSON matching the schema. "
    "Each item must be exactly one factual sentence and must list every source "
    "record number that supports it. Omit a sentence when no record supports it."
)

# Username IOCs are pulled with the SAME patterns the redaction choke point uses,
# so what we surface as an account IOC is exactly what egress would mask — one
# source of truth, no drift.
_USER_PATTERNS = redact.USER_PATTERNS


def _events_by_n(state):
    """Index the events store by record number. Every citation this module emits
    is one of these keys, which is what makes the citations resolvable."""
    return {e["n"]: e for e in (state or {}).get("events", []) if e.get("n") is not None}


def _entity_events(entity, entity_kind, events):
    """The incident entity's real footprint in the events store.

    For an IP/entity the footprint is every record whose verbatim `raw` contains
    it; for a host it is every record on that host. Either way each event carries
    its own record `n`, so the footprint is fully cited and never fabricated."""
    if not entity:
        return []
    if entity_kind == "host":
        return [e for e in events if (e.get("host") or "") == entity]
    return [e for e in events if entity in (e.get("raw") or "")]


def _timeline(finding_events, entity_events):
    """Full timeline reconstruction: the union of the records the rules fired on
    and the entity's footprint, deduped by record `n` and ordered by (time, n).

    This is deliberately richer than derive_rca's finding-level timeline, which
    only carries the few entries a rule tagged — here every relevant source line
    is present, each addressable by its `n`."""
    by_n = {}
    for e in finding_events + entity_events:
        n = e.get("n")
        if n is None:
            continue
        by_n[n] = {
            "n": n,
            "ts": e.get("ts", ""),
            "level": e.get("level", ""),
            "host": e.get("host", ""),
            "msg": e.get("msg", ""),
            "raw": e.get("raw", ""),          # verbatim source line
            "isFinding": bool(e.get("isFinding")),
            "findingId": e.get("findingId"),
        }
    return [by_n[n] for n in sorted(by_n,
                                    key=lambda k: (by_n[k]["ts"] == "", by_n[k]["ts"], k))]


def _correlation(entity, entity_kind, entity_events):
    """Correlate the entity to the assets (hosts) it actually touched. Each asset
    lists the record `n`s that place the entity on it — the correlation is the
    evidence, not an assertion."""
    hosts = {}
    for e in entity_events:
        host = e.get("host") or ""
        if not host or host == entity:            # a host entity is not its own asset
            continue
        slot = hosts.setdefault(host, [])
        slot.append(e["n"])
    assets = []
    for host in sorted(hosts):
        records = sorted(hosts[host])
        assets.append({
            "name": host,
            "kind": "host",
            "role": "target",                     # the entity acted against this host
            "records": records,
            "firstRecord": records[0],
            "eventCount": len(records),
        })
    return {"entity": entity, "entityKind": entity_kind, "assets": assets}


def _iocs(events):
    """Deterministic IOC extraction over the real records: IPv4/IPv6 addresses and
    the account names the auth lines name. Pure regex over verbatim `raw` — no
    inference, no model. Each IOC lists every record `n` it was observed on."""
    found = {}                                     # (type, value) -> [n, ...]

    def note(kind, value, n):
        found.setdefault((kind, value), []).append(n)

    for e in events:
        n = e.get("n")
        raw = e.get("raw") or ""
        if n is None:
            continue
        for ip in redact.IPV4_RE.findall(raw):
            note("ipv4", ip, n)
        for ip in redact.IPV6_RE.findall(raw):
            note("ipv6", ip, n)
        for pat in _USER_PATTERNS:
            for m in pat.finditer(raw):
                note("account", m.group("u"), n)

    iocs = []
    for (kind, value), ns in found.items():
        records = sorted(set(ns))
        iocs.append({"type": kind, "value": value, "records": records,
                     "firstRecord": records[0], "count": len(records)})
    # Deterministic order: type, then first appearance, then value.
    iocs.sort(key=lambda i: (i["type"], i["firstRecord"], i["value"]))
    return iocs


def _blast_radius(entity, correlation, iocs):
    """The set of assets and accounts in scope for this incident, each traceable
    to the records that put them there. The source entity is named separately so
    the set never conflates the attacker with the victims."""
    assets = [a["name"] for a in correlation["assets"]]
    asset_records = sorted({n for a in correlation["assets"] for n in a["records"]})
    accounts = sorted({i["value"] for i in iocs if i["type"] == "account"})
    account_records = sorted({n for i in iocs if i["type"] == "account" for n in i["records"]})
    return {
        "sourceEntity": entity,
        "assets": assets,
        "accounts": accounts,
        "assetCount": len(assets),
        "accountCount": len(accounts),
        "records": sorted(set(asset_records) | set(account_records)),
    }


def resolve_record(state, n):
    """The events-store row a citation `{n}` points at, or None. Callers (and the
    test) use this to prove every emitted citation is resolvable."""
    return _events_by_n(state).get(n)


def _redacted_case(case, state):
    """The only model input: a redacted, bounded projection of deterministic data."""
    projection = {
        "incidentId": case.get("incidentId"),
        "facts": case.get("facts"),
        "runbook": case.get("runbook"),
        "investigation": case.get("investigation"),
    }
    hosts = {e.get("host") for e in (state or {}).get("events", []) if e.get("host")}
    scope = redact.Redactor(hosts=hosts)

    def walk(value):
        if isinstance(value, dict):
            return {key: walk(sub) for key, sub in value.items()}
        if isinstance(value, list):
            return [walk(sub) for sub in value]
        if isinstance(value, str):
            return scope.redact(value)
        return value

    # Redact values before serialization: applying the text sanitizer to encoded
    # JSON can remove escape characters and make the payload syntactically invalid.
    return walk(projection)


def _sentence_guard(sentence, records, redacted_case, state):
    """Require citations to exist, then ground prose in the cited record corpus."""
    by_n = _events_by_n(state)
    cited = [by_n.get(n) for n in records]
    if not records or any(row is None for row in cited):
        return {"ok": False, "reasons": ["one or more citations do not resolve"]}

    # Guard against the same redacted representation the model saw. Limiting the
    # evidence field to cited rows prevents an unrelated record from grounding a
    # claim. Deterministic incident facts remain available for incident-wide facts.
    redacted_rows = {e.get("n"): e for e in redacted_case["investigation"]["timeline"]}
    guard_input = {
        "facts": redacted_case.get("facts"),
        "runbook": redacted_case.get("runbook"),
        "evidence": [redacted_rows[n] for n in records if n in redacted_rows],
    }
    return explanation_guard.verify_explanation(guard_input, sentence)


def _run_advisory_agent(kind, instruction, case, state, chat_fn, timeout):
    redacted_case = _redacted_case(case, state)
    prompt = instruction + "\n\nDeterministic case:\n" + json.dumps(redacted_case, sort_keys=True)
    raw = chat_fn(la.LLM_BASE_URL, la.LLM_API_KEY, la.LLM_MODEL,
                  _ADVISORY_SYSTEM, prompt, timeout=timeout,
                  response_schema=_ADVISORY_SCHEMA)
    parsed = json.loads(la.strip_fences(raw))
    candidates = parsed.get("sentences", []) if isinstance(parsed, dict) else []
    factual = 0
    accepted = []
    rejected = []
    for item in candidates:
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            continue
        text = item["text"].strip()
        if not text:
            continue
        factual += 1
        records = item.get("records")
        if not isinstance(records, list) or any(type(n) is not int for n in records):
            verdict = {"ok": False, "reasons": ["citations are not integer record numbers"]}
            records = []
        else:
            records = sorted(set(records))
            verdict = _sentence_guard(text, records, redacted_case, state)
        if verdict["ok"]:
            accepted.append({"text": text, "records": records})
        else:
            rejected.append({"text": text, "records": records,
                             "reasons": verdict["reasons"]})

    cited = len(accepted)
    ratio = cited / factual if factual else 0.0
    rendered = " ".join(f'{s["text"]} ' + " ".join(f'{{{n}}}' for n in s["records"])
                        for s in accepted) or None
    return {
        "kind": kind,
        "label": f"ADVISORY · {kind}",
        "status": "complete" if rendered else "rejected",
        "text": rendered,
        "sentences": accepted,
        "rejected": rejected,
        "grounding": {"factual_sentences": factual,
                      "cited_and_resolvable": cited,
                      "ratio": round(ratio, 3)},
        "note": (None if rendered else
                 "ADVISORY · unverified — all model prose was withheld by the grounding guard"),
    }


def dispatch_advisory(iid, state=None, chat_fn=None, timeout=ADVISORY_TIMEOUT):
    """Run three advisory agents separately from deterministic case assembly.

    Bounded to three workers and a 45-second production deadline per worker.
    This function is called only by the separate advisory route; `assemble()`
    remains model-free and cannot wait on this executor.
    """
    state = state or {}
    case = assemble(iid, state)
    if case is None:
        return None
    chat_fn = chat_fn or la.chat_completion
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=3,
                                                       thread_name_prefix="itsoc-advisory")
    futures = {
        executor.submit(_run_advisory_agent, kind, instruction, case, state,
                        chat_fn, timeout): kind
        for kind, instruction in _ADVISORY_AGENTS.items()
    }
    done, unfinished = concurrent.futures.wait(futures, timeout=timeout)
    blocks = []
    for future, kind in futures.items():
        if future in unfinished:
            future.cancel()
            blocks.append({
                "kind": kind, "label": f"ADVISORY · {kind}", "status": "timed_out",
                "text": None, "sentences": [], "rejected": [],
                "grounding": {"factual_sentences": 0, "cited_and_resolvable": 0,
                              "ratio": 0.0},
                "note": "ADVISORY · timed out — retry",
            })
            continue
        try:
            blocks.append(future.result())
        except Exception as exc:
            blocks.append({
                "kind": kind, "label": f"ADVISORY · {kind}", "status": "timed_out",
                "text": None, "sentences": [], "rejected": [],
                "grounding": {"factual_sentences": 0, "cited_and_resolvable": 0,
                              "ratio": 0.0},
                "note": f"ADVISORY · timed out — retry ({type(exc).__name__})",
            })
    executor.shutdown(wait=False, cancel_futures=True)
    blocks.sort(key=lambda b: list(_ADVISORY_AGENTS).index(b["kind"]))
    factual = sum(b["grounding"]["factual_sentences"] for b in blocks)
    cited = sum(b["grounding"]["cited_and_resolvable"] for b in blocks)
    timed_out = any(b["status"] == "timed_out" for b in blocks)
    return {
        "incidentId": case["incidentId"],
        "label": "ADVISORY",
        "status": "timed_out" if timed_out else "complete",
        "blocks": blocks,
        "grounding": {"factual_sentences": factual, "cited_and_resolvable": cited,
                      "ratio": round(cited / factual, 3) if factual else 0.0},
        "note": ("ADVISORY · timed out — retry" if timed_out else
                 "ADVISORY · model prose; never a verdict or control signal"),
    }


def assemble(iid, state=None, now=None):
    """Assemble the full DETERMINISTIC investigation case for one incident.

    Extends soc.derive_rca (facts + runbook) with timeline reconstruction, entity
    /asset correlation, IOC extraction and a blast-radius set — every fact cited
    by a resolvable record `{n}`. Returns None for an unknown id.

    D2: this makes NO model call and NEVER blocks on the LLM. `hypothesis_fn` is
    pinned to None, and the advisory layer is returned as an honest `pending`
    seam for the separate advisory dispatch to fill (or honestly time out) — it
    can never delay, block, or fabricate anything below.
    """
    t0 = time.perf_counter()

    # Layer 1+2, deterministic, no model (hypothesis_fn defaults to None).
    base = soc.derive_rca(iid, state)
    if base is None:
        return None

    events = (state or {}).get("events", [])
    facts = base.get("facts", {})
    entity = facts.get("entity")
    entity_kind = facts.get("entityKind")
    member_ids = set(facts.get("findingIds", []))

    finding_events = [e for e in events if e.get("findingId") in member_ids]
    entity_events = _entity_events(entity, entity_kind, events)
    considered = finding_events + entity_events

    timeline = _timeline(finding_events, entity_events)
    correlation = _correlation(entity, entity_kind, entity_events)
    iocs = _iocs(considered)
    blast = _blast_radius(entity, correlation, iocs)

    # Honest gap: with no run loaded (or a different run) there are no event rows
    # to reconstruct from — say so rather than invent a timeline.
    note = None
    if not events:
        note = ("no run is loaded, so the events-store layers are empty — the "
                "facts above come from the incident's stored fields only")
    elif entity and not entity_events:
        note = ("the entity does not appear in the loaded run's events — its "
                "footprint could not be reconstructed from this run")

    investigation = {
        "entity": entity,
        "entityKind": entity_kind,
        "timeline": timeline,
        "correlation": correlation,
        "iocs": iocs,
        "blastRadius": blast,
        "recordsConsidered": sorted({e["n"] for e in considered if e.get("n") is not None}),
        "note": note,
    }

    # The advisory (model) layer — dispatched SEPARATELY, never here. It is an
    # honest pending seam: no text yet, and the deterministic case is complete
    # without it. The parallel advisory card fills this or times it out honestly.
    advisory = {
        "status": "pending",
        "label": ADVISORY_LABEL,
        "text": None,
        "note": ("advisory analysis is dispatched separately and never blocks the "
                 "deterministic case — it fills or honestly times out"),
    }

    assembled_ms = round((time.perf_counter() - t0) * 1000, 3)

    # Backward-compatible superset of the RCA contract: keep incidentId/facts/
    # runbook, keep `hypothesis` (now an honest pending mirror of `advisory` so
    # the existing panel renders the pending state without a frontend change),
    # and add the deterministic investigation + advisory seam.
    return {
        "incidentId": base["incidentId"],
        "facts": facts,
        "runbook": base.get("runbook"),
        "hypothesis": {
            "text": None,
            "label": (base.get("hypothesis") or {}).get("label", ADVISORY_LABEL),
            "note": ("advisory analysis pending — dispatched separately; the "
                     "deterministic case is complete and does not wait on the model"),
            "status": "pending",
        },
        "investigation": investigation,
        "advisory": advisory,
        "deterministic": True,
        "assembledInMs": assembled_ms,
    }
