#!/usr/bin/env python3
"""
soc.py — the SOC subsystems behind /api/incidents, /api/assets, /api/users,
/api/cases, /api/reports, /api/threat-intel and /api/metrics.

One honesty rule governs everything here (see docs/soc_subsystems.md, the
contract the frontend builds against): a value is either DERIVED from data
that actually exists — parsed events, rule findings, saved runs, files on
disk — or ENTERED by the analyst. Nothing is fabricated; where the honest
answer is "not enough data", the answer is null.

Severity stays owned by the detector's rules. An incident's severity is the
max of its members' rule severities — an aggregation for display, never a new
verdict. The LLM appears nowhere in this module.

Stores live in console/.soc/ (gitignored, like .runs/):
    incidents.json   derived incidents + analyst lifecycle fields
    cases.json       analyst-created cases (pure user-entered data)
    reports/         generated report artifacts (standalone HTML exports)

Stdlib only. anomaly_detector.py is never imported or modified.
"""

import hashlib
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "threat_intel"))

import explanation_guard  # noqa: E402
import export  # noqa: E402
import org_context  # noqa: E402
import redact  # noqa: E402
from rule_mitre_map import RULE_TECHNIQUES  # noqa: E402
from tactic_phase_map import phase_for_tactics  # noqa: E402

SOC_DIR = HERE / ".soc"                       # monkeypatched to a tmp dir in tests

# Analyst lifecycle — full CASE/incident machine:
#   NEW → TRIAGED → INVESTIGATING → ESCALATED → RESOLVED → CLOSED
# Aliases keep previously stored values and older API clients working.
# `acknowledged` is the old name for TRIAGED; `open` is the old case NEW.
INCIDENT_STATES = ("new", "triaged", "investigating", "escalated", "resolved", "closed")
INCIDENT_STATE_ALIASES = {"acknowledged": "triaged"}
INCIDENT_TERMINAL = ("resolved", "closed")
CASE_STATUSES = ("new", "triaged", "investigating", "escalated", "resolved", "closed")
CASE_STATUS_ALIASES = {"open": "new"}
CASE_ACTIVITY_KINDS = ("comment", "note", "attachment", "observable", "runbook", "state", "assignee", "system")
CASE_OBSERVABLE_TYPES = ("url", "ip", "hash", "domain", "email")
CASE_ATTACHMENT_KINDS = ("note", "json", "html", "image", "other")
CLUSTER_GAP_SECONDS = 30 * 60                 # the documented correlation window


def normalize_incident_state(value):
    s = str(value or "").strip().lower()
    return INCIDENT_STATE_ALIASES.get(s, s)


def normalize_case_status(value):
    s = str(value or "").strip().lower()
    return CASE_STATUS_ALIASES.get(s, s)

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value):
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    # Normalize to naive-UTC so mixed tz-aware/tz-naive store timestamps never
    # raise "can't compare offset-naive and offset-aware datetimes" when
    # subtracted/compared (metrics MTTD/MTTR + incident cluster math).
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# ---------------------------------------------------------------------------
# JSON stores
# ---------------------------------------------------------------------------

def _load(name):
    path = SOC_DIR / name
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save(name, data):
    SOC_DIR.mkdir(parents=True, exist_ok=True)
    (SOC_DIR / name).write_text(json.dumps(data, indent=1))


# ---------------------------------------------------------------------------
# Incidents — correlated clusters of real findings
# ---------------------------------------------------------------------------

SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _primary_entity(finding):
    """The entity a finding is about: first IP chip, else derived host, else
    its rule type. All three are values the parser actually observed."""
    for chip in finding.get("chips") or []:
        text = str(chip.get("text", ""))
        if redact.IPV4_RE.fullmatch(text):
            return text, "ip"
    if finding.get("hostDerived") and finding.get("host") not in (None, "", "—"):
        return finding["host"], "host"
    return finding.get("type") or "finding", "rule"


def derive_incidents(state):
    """Cluster the run's findings by shared entity + ≤30-minute chain gaps.

    Deterministic and documented in docs/soc_subsystems.md. An incident is
    only ever built from ≥1 real finding — there is no other source.
    Deduplicates literal duplicates and rolls single-finding low-value clusters
    into a consolidated rollup.
    """
    by_entity = {}
    seen_finding_ids = set()
    for f in state.get("findings", []):
        fid = f.get("id")
        if fid and fid in seen_finding_ids:
            continue
        if fid:
            seen_finding_ids.add(fid)
        entity, kind = _primary_entity(f)
        by_entity.setdefault((entity, kind), []).append(f)

    incidents = []
    seen_incident_ids = set()
    for (entity, kind), members in by_entity.items():
        stamped = sorted((f for f in members if _parse_ts(f.get("stamp"))),
                         key=lambda f: f["stamp"])
        unstamped = [f for f in members if not _parse_ts(f.get("stamp"))]

        clusters = []
        for f in stamped:
            if clusters and (_parse_ts(f["stamp"])
                             - _parse_ts(clusters[-1][-1]["stamp"])
                             ).total_seconds() <= CLUSTER_GAP_SECONDS:
                clusters[-1].append(f)
            else:
                clusters.append([f])
        if unstamped:                          # join the first cluster; flagged below
            if clusters:
                clusters[0].extend(unstamped)
            else:
                clusters.append(unstamped)

        # Roll up single-finding LOW/INFO clusters for this entity to prevent noise
        low_single_clusters = [
            c for c in clusters
            if len(c) == 1 and str(c[0].get("sev", "")).upper() in ("LOW", "INFO")
        ]
        if len(low_single_clusters) > 1:
            combined_low = [f for c in low_single_clusters for f in c]
            clusters = [
                c for c in clusters
                if not (len(c) == 1 and str(c[0].get("sev", "")).upper() in ("LOW", "INFO"))
            ]
            clusters.append(combined_low)

        for members in clusters:
            if not members:
                continue
            stamps = sorted(f["stamp"] for f in members if _parse_ts(f.get("stamp")))
            first = stamps[0] if stamps else None
            techniques, tactics = [], []
            for f in members:
                for t in f.get("mitre") or []:
                    if all(t["id"] != x["id"] for x in techniques):
                        techniques.append({"id": t["id"], "name": t["name"],
                                           "tactic": t["tactic"]})
                    if t["tactic"] not in tactics:
                        tactics.append(t["tactic"])
            sev = min((str(f.get("sev", "INFO")).upper() for f in members),
                      key=lambda s: SEV_RANK.get(s, 5))
            fids = sorted(str(f.get("id")) for f in members)
            fids_hash = hashlib.sha1(",".join(fids).encode()).hexdigest()[:8]
            raw_id = f"{state.get('runId', '')}|{entity}|{kind}|{first or 'no-stamp'}|{fids_hash}"
            inc_id = "inc-" + hashlib.sha1(raw_id.encode()).hexdigest()[:12]
            if inc_id in seen_incident_ids:
                continue
            seen_incident_ids.add(inc_id)

            is_rollup = len(members) > 1 and sev in ("LOW", "INFO") and len(stamps) > 1 and (
                (_parse_ts(stamps[-1]) - _parse_ts(stamps[0])).total_seconds() > CLUSTER_GAP_SECONDS
            )
            title = (
                f"{entity} — {len(members)} low-severity finding(s) (rollup)"
                if is_rollup
                else f"{entity} — {len(members)} correlated finding(s)"
            )

            pri_info = org_context.derive_incident_priority(
                {"entity": entity, "entityKind": kind, "severity": sev},
                members=members,
            )

            incidents.append({
                "id": inc_id,
                "runId": state.get("runId", ""),
                "entity": entity,
                "entityKind": kind,
                "title": title,
                "severity": sev,
                "priority": pri_info["priority"],
                "criticality": pri_info["criticality"],
                "priorityRationale": pri_info["rationale"],
                "findingIds": [f.get("id") for f in members],
                "findingCount": len(members),
                "techniques": techniques,
                "attackerStatus": phase_for_tactics(tactics),
                "createdAt": first,            # detection = earliest finding time
                "firstSeen": first,
                "lastSeen": stamps[-1] if stamps else None,
                "timeUncertain": bool(unstamped),
                "isRollup": bool(is_rollup),
            })
    return incidents


def sync_incidents(state):
    """Upsert derived incidents into the store, preserving analyst lifecycle.

    Deterministic ids make this idempotent: re-analyzing the same run updates
    the derived fields of an existing incident and never duplicates it or
    erases the analyst's state/acknowledgedAt/resolvedAt."""
    store = _load("incidents.json")
    for inc in derive_incidents(state):
        prev = store.get(inc["id"], {})
        inc["state"] = prev.get("state", "new")
        inc["acknowledgedAt"] = prev.get("acknowledgedAt")
        inc["resolvedAt"] = prev.get("resolvedAt")
        # C1-T1 (Cases->Incidents merge): case metadata absorbed onto a rule
        # incident is ANALYST data, not derived. derive_incidents() rebuilds the
        # dict from findings alone and knows nothing about it, so it MUST be
        # carried across every re-derivation here — otherwise the next analyze
        # silently drops it (the "silent killer" tripwire). See migrate_cases_
        # to_incidents(). Defaults keep pre-migration incidents unchanged.
        inc["origin"] = prev.get("origin", "rule")
        inc["cases"] = prev.get("cases", [])
        store[inc["id"]] = inc
    _save("incidents.json", store)
    return store


def list_incidents(state=None, state_filter=None):
    """All stored incidents, newest detection first. Syncs from the current
    run first when one is loaded, so the list always reflects real findings."""
    if state and not state.get("idle"):
        store = sync_incidents(state)
    else:
        store = _load("incidents.json")
    out = sorted(store.values(), key=lambda i: i.get("createdAt") or "", reverse=True)
    deduped = []
    seen = set()
    for inc in out:
        if inc.get("id") and inc["id"] not in seen:
            seen.add(inc["id"])
            deduped.append(inc)
    if state_filter:
        wanted = normalize_incident_state(state_filter)
        deduped = [i for i in deduped
                   if normalize_incident_state(i.get("state")) == wanted]
    return [_public_incident(i) for i in deduped]


def _public_incident(inc):
    """Project stored lifecycle aliases onto the current 6-state machine."""
    if not inc:
        return inc
    out = dict(inc)
    st = normalize_incident_state(out.get("state"))
    if st in INCIDENT_STATES:
        out["state"] = st
    return out


# ---------------------------------------------------------------------------
# Canonical demo-scenario alias (C2-T0)
# ---------------------------------------------------------------------------
# Incident ids are DERIVED from a content hash (see derive_incidents) that embeds
# the run id, so they are not human-chosen and drift with the run date. Yet the
# design kit, the C2 acceptance scenario and the C5 demo script all refer to the
# canonical brute-force scenario 203.0.113.44 -> server-01 by ONE fixed, memorable
# id: INC-4a7f. We do NOT fabricate an incident carrying that id — that would be a
# lie, and the incident must be REAL output of the real rules. Instead we make the
# real, rule-produced incident ADDRESSABLE by the alias: it resolves to whichever
# stored incident matches the scenario signature (attacker entity), and to None
# when that scenario has not been analyzed — an honest empty, never a minted
# record. No derived id changes: every incident keeps exactly the id
# derive_incidents computed, so id behaviour for all other incidents is untouched.
INCIDENT_ALIASES = {
    "INC-4a7f": {"entity": "203.0.113.44", "entityKind": "ip"},
}


def _resolve_alias_id(iid, store):
    """Map a canonical alias (e.g. INC-4a7f) to the REAL derived id of the stored
    incident that matches its scenario signature, or None if that scenario is not
    present. A non-alias id is returned unchanged — aliases are the only ids this
    touches, so ordinary incident lookup is byte-for-byte unaffected. When a
    scenario recurs across runs in one store the pick is deterministic: prefer the
    brute-force incident (technique T1110), then earliest-detected, then id order."""
    sig = INCIDENT_ALIASES.get(iid)
    if sig is None:
        return iid
    matches = [rid for rid, inc in store.items()
               if inc.get("entity") == sig["entity"]
               and inc.get("entityKind") == sig["entityKind"]]
    if not matches:
        return None

    def _rank(rid):
        inc = store[rid]
        has_bf = any(t.get("id") == "T1110" for t in inc.get("techniques") or [])
        return (0 if has_bf else 1, inc.get("createdAt") or "", rid)
    return sorted(matches, key=_rank)[0]


def get_incident(iid):
    """One incident by id. A canonical demo alias (INCIDENT_ALIASES, e.g.
    INC-4a7f) resolves to the real rule-produced incident for its scenario and is
    annotated with `alias`; an unknown id or an unmatched alias returns None."""
    store = _load("incidents.json")
    real_id = _resolve_alias_id(iid, store)
    if not real_id:
        return None
    inc = store.get(real_id)
    if inc is not None and real_id != iid:
        inc = {**inc, "alias": iid}
    return _public_incident(inc)


def set_incident_state(iid, new_state):
    """Analyst lifecycle transition. Timestamps record what actually happened:
    acknowledgedAt on the first move out of 'new' (including TRIAGED),
    resolvedAt on entering RESOLVED or CLOSED (cleared when reopened).
    Aliases: acknowledged → triaged. Returns the updated incident, or None
    for an unknown id; ValueError on a bad state."""
    new_state = normalize_incident_state(new_state)
    if new_state not in INCIDENT_STATES:
        raise ValueError(f"state must be one of {INCIDENT_STATES}")
    store = _load("incidents.json")
    real_id = _resolve_alias_id(iid, store)      # INC-4a7f -> real derived id
    inc = store.get(real_id) if real_id else None
    if not inc:
        return None
    if new_state != "new" and not inc.get("acknowledgedAt"):
        inc["acknowledgedAt"] = _now()
    if new_state in INCIDENT_TERMINAL and not inc.get("resolvedAt"):
        inc["resolvedAt"] = _now()
    if new_state not in INCIDENT_TERMINAL:
        inc["resolvedAt"] = None
    inc["state"] = new_state
    _save("incidents.json", store)
    return _public_incident(inc)


# ---------------------------------------------------------------------------
# Cross-run brute-force attempt series (RCA right-rail sparkline)
# ---------------------------------------------------------------------------
# A DERIVED display aggregation over the persistent run history — never a
# verdict. Attempts/run = the sum of `occurrences` over that run's findings
# that (a) are about this entity and (b) fired a brute-force / failed-auth
# rule. Only runs where the entity ACTUALLY has such a finding contribute a
# point — a run where the entity is absent is not a fabricated zero. Fewer
# than two real points → an honest "n/a — needs >=2 runs", never a trend.
# The caller (serve.py) supplies the real saved runs; this stays FS-agnostic.

_BRUTE_RE = re.compile(
    r"brute|failed|auth[_-]?fail|login[_-]?fail|password[_-]?spray|"
    r"credential|failed[_-]?login|ssh[_-]?fail",
    re.I)


def entity_attempt_series(runs, entity, limit=7):
    """Per-entity brute-force attempt series across saved runs.

    `runs` = [{"label", "date", "findings": [...]}, ...] oldest→newest (the
    real saved run history). Returns a display dict:
      available True  → {points, thisRun, avg, changePct, direction, forecast,
                         runs, caption}
      available False → {points, note} (honest n/a; <2 real points)
    Never fabricates a point, a zero, or a direction.
    """
    points = []
    for r in runs:
        total = 0
        hit = False
        for f in r.get("findings", []) or []:
            ent, _ = _primary_entity(f)
            if ent != entity:
                continue
            if not _BRUTE_RE.search(str(f.get("type", ""))):
                continue
            hit = True
            try:
                total += int(f.get("occurrences") or 0)
            except (TypeError, ValueError):
                pass
        if hit:
            points.append({"label": r.get("label", ""),
                           "date": r.get("date", ""),
                           "attempts": total})
    points = points[-limit:]
    if len(points) < 2:
        return {"available": False,
                "entity": entity,
                "points": points,
                "note": "n/a — needs ≥2 runs with brute-force activity "
                        "for this entity"}
    attempts = [p["attempts"] for p in points]
    this_run, prior, first = attempts[-1], attempts[-2], attempts[0]
    avg = round(sum(attempts) / len(attempts), 1)
    change_pct = None if prior == 0 else round((this_run - prior) / prior * 100)
    direction = "up" if this_run > first else "down" if this_run < first else "flat"
    forecast = {"up": "elevated", "down": "easing", "flat": "steady"}[direction]
    return {"available": True,
            "entity": entity,
            "points": points,
            "thisRun": this_run,
            "avg": avg,
            "changePct": change_pct,
            "direction": direction,
            "forecast": forecast,
            "runs": len(points),
            "caption": "derived from run history, not a verdict"}


# ---------------------------------------------------------------------------
# RCA — layered root-cause view of one incident (advisory on top, never below)
# ---------------------------------------------------------------------------
#
# Three layers, each degrading to an HONEST absence, never a fabricated fill:
#   1. deterministic cluster facts — always present, straight from the
#      incident record and its member findings (whose timelines are
#      rule_context.enrich/timeline_for output carried through the adapter);
#   2. a runbook citation — only when BM25 retrieval over
#      console/.soc/runbooks/*.md clears an explicit score+coverage bar;
#   3. an LLM hypothesis — only via a caller-injected callable, built solely
#      from layers 1–2, labeled advisory, and withheld when
#      explanation_guard.verify_explanation rejects it.
# Nothing here reads or writes severity; rules own the verdict.

RCA_HYPOTHESIS_LABEL = "advisory · hypothesis · not a verdict"

# Conservative "is this runbook actually about this incident" bar, applied to
# the BEST-scoring runbook only. Coverage = fraction of the incident's
# distinct RULE-ID tokens present in the doc (the applicability question —
# free-text tokens like IP digits deliberately don't count); score = plain
# BM25 (k1=1.5, b=0.75) over the full query. Both must clear. Deliberately
# strict — a wrong citation reads as authority, an honest "no runbook match"
# reads as exactly what it is. Tunable defaults, not validated constants.
RCA_MIN_COVERAGE = 0.5
RCA_MIN_SCORE = 1.0

_WORD_RE = re.compile(r"[a-z0-9]+")


def _rca_tokens(text):
    return _WORD_RE.findall(text.lower())


def _bm25_rank(query_tokens, docs, k1=1.5, b=0.75):
    """Plain BM25 over tokenized docs. Returns [(score, index)] best-first.

    Stdlib-only on purpose: the corpus is a handful of markdown files, and a
    dependency-free scorer keeps the honest-threshold logic auditable."""
    if not docs:
        return []
    n = len(docs)
    avgdl = sum(len(d) for d in docs) / n
    df = Counter()
    for d in docs:
        df.update(set(d))
    scores = []
    for i, d in enumerate(docs):
        tf = Counter(d)
        score = 0.0
        for term in query_tokens:
            if not tf[term]:
                continue
            idf = math.log((n - df[term] + 0.5) / (df[term] + 0.5) + 1)
            score += idf * (tf[term] * (k1 + 1)) / (
                tf[term] + k1 * (1 - b + b * len(d) / avgdl))
        scores.append((score, i))
    return sorted(scores, key=lambda pair: -pair[0])


def _cite_runbook(query_text, rule_tokens):
    """Best runbook for this incident, or an honest no-match.

    Returns {"matched": True, file, title, passage, score, coverage} only when
    the best doc clears BOTH thresholds; otherwise {"matched": False, "note"}.
    A citation is never forced — an empty runbooks dir (or a cluster whose
    rules aren't loaded) is a no-match, not an error, and the passage shown is
    the doc's own best paragraph, verbatim."""
    runbooks_dir = SOC_DIR / "runbooks"
    files = sorted(runbooks_dir.glob("*.md")) if runbooks_dir.is_dir() else []
    if not files:
        return {"matched": False,
                "note": "no runbook match — the runbook store is empty"}
    if not rule_tokens:
        return {"matched": False,
                "note": "no runbook match — this incident's rules are not "
                        "loaded, so applicability cannot be checked"}

    texts = []
    for path in files:
        try:
            texts.append(path.read_text(errors="replace"))
        except OSError:
            texts.append("")
    docs = [_rca_tokens(t) for t in texts]

    query = _rca_tokens(query_text)
    distinct = set(query)
    ranked = _bm25_rank(query, docs)
    if not ranked or not distinct:
        return {"matched": False, "note": "no runbook match"}

    score, best = ranked[0]
    coverage = len(rule_tokens & set(docs[best])) / len(rule_tokens)
    if score < RCA_MIN_SCORE or coverage < RCA_MIN_COVERAGE:
        return {"matched": False,
                "note": (f"no runbook match — best candidate "
                         f"{files[best].name} scored {score:.2f} "
                         f"(coverage {coverage:.0%}), below the citation bar")}

    text = texts[best]
    title = next((ln.lstrip("# ").strip() for ln in text.splitlines()
                  if ln.startswith("#")), files[best].name)
    # The cited passage is the doc's own best paragraph, chosen by term hits —
    # quoted verbatim so the analyst reads the runbook, not a paraphrase.
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    passage = max(paragraphs,
                  key=lambda p: len(distinct & set(_rca_tokens(p))))
    return {"matched": True, "file": files[best].name, "title": title,
            "passage": passage, "score": round(score, 2),
            "coverage": round(coverage, 2)}


def derive_rca(iid, state=None, hypothesis_fn=None):
    """Layered RCA for one incident; None for an unknown id.

    `hypothesis_fn`, when given, is a callable(prompt) -> advisory prose owned
    by the caller (serve.py injects the local model; tests inject stubs). This
    module never imports the LLM, and severity is never read back or changed.
    """
    inc = get_incident(iid)
    if not inc:
        return None

    # --- Layer 1: deterministic facts, always ------------------------------
    by_id = {}
    if state and not state.get("idle") and state.get("runId") == inc.get("runId"):
        by_id = {f.get("id"): f for f in state.get("findings", [])}
    members = [by_id[fid] for fid in inc.get("findingIds", []) if fid in by_id]

    timeline = []
    for m in members:
        for e in m.get("timeline", []):
            timeline.append({"t": e.get("t", ""), "label": e.get("label", ""),
                             "line": e.get("line"), "findingId": m.get("id"),
                             "rule": m.get("type")})
    timeline.sort(key=lambda e: (e["t"] == "", e["t"], e["line"] or 0))

    facts = {
        "incidentId": inc["id"],
        "entity": inc.get("entity"),
        "entityKind": inc.get("entityKind"),
        "findingIds": inc.get("findingIds", []),
        "membersLoaded": len(members),
        "rules": sorted({m.get("type") for m in members if m.get("type")}),
        "firstSeen": inc.get("firstSeen"),
        "lastSeen": inc.get("lastSeen"),
        "timeline": timeline,
        # Honest gap, not a reconstruction: member findings live in run state,
        # so an incident from another run keeps its ids but loses the timeline.
        "note": (None if len(members) == len(inc.get("findingIds", []))
                 else "some member findings are not in the loaded run — "
                      "their timeline entries are unavailable"),
    }

    # --- Layer 2: runbook citation, only over the bar ----------------------
    query = " ".join(facts["rules"] * 2                # rule ids weigh double
                     + [inc.get("entityKind") or ""]
                     + [m.get("title") or "" for m in members])
    rule_tokens = {tok for rule in facts["rules"] for tok in _rca_tokens(rule)}
    runbook = _cite_runbook(query, rule_tokens)

    # --- Layer 3: advisory hypothesis, guarded -----------------------------
    hypothesis = {"text": None, "label": RCA_HYPOTHESIS_LABEL,
                  "note": "model unavailable — deterministic facts only"}
    if hypothesis_fn is not None:
        prompt = json.dumps({
            "task": ("Write a 2-4 sentence root-cause hypothesis for this "
                     "incident. Use ONLY the facts and the cited runbook "
                     "passage below. Never name a host, IP, or username that "
                     "does not appear in them. Do not rate or change "
                     "severity. Plain text only."),
            "facts": facts,
            "runbook_passage": runbook.get("passage") if runbook["matched"] else None,
        }, indent=1)
        try:
            text = (hypothesis_fn(prompt) or "").strip()
        except Exception:
            text = ""
        if not text:
            hypothesis["note"] = "model returned no hypothesis"
        else:
            # Grounding corpus for the guard: the cluster's own deterministic
            # fields plus the cited passage (prose may echo what it was shown).
            # The rule id is asserted only for a single-rule cluster — with
            # mixed rules there is no one fault type the prose must match.
            rules = facts["rules"]
            pseudo = {
                "type": rules[0] if len(rules) == 1 else None,
                "summary": inc.get("title", ""),
                "entities": {"entity": inc.get("entity")},
                "rules": rules,
                "members": [{"title": m.get("title"), "type": m.get("type"),
                             "host": m.get("host"), "chips": m.get("chips")}
                            for m in members],
                "timeline": timeline,
                "runbook": runbook.get("passage") if runbook["matched"] else "",
                "span": [facts["firstSeen"], facts["lastSeen"]],
            }
            verdict = explanation_guard.verify_explanation(pseudo, text)
            if verdict["ok"]:
                hypothesis = {"text": text, "label": RCA_HYPOTHESIS_LABEL,
                              "note": None}
            else:
                hypothesis = {"text": None, "label": RCA_HYPOTHESIS_LABEL,
                              "note": "withheld — failed the explanation "
                                      "consistency guard",
                              "reasons": verdict["reasons"]}

    return {"incidentId": inc["id"], "facts": facts, "runbook": runbook,
            "hypothesis": hypothesis}



# ---------------------------------------------------------------------------
# Assets & users — observed entities only

# ---------------------------------------------------------------------------

def derive_assets(state):
    """Hosts seen in parsed events + IPs seen in findings. Nothing else exists."""
    assets = {}
    org_ctx = org_context.load_org_context()

    def touch(name, kind):
        key = (kind, name)
        if key not in assets:
            crit = org_ctx.get_criticality(name)
            assets[key] = {"id": f"asset-{kind}-{name}", "name": name, "kind": kind,
                           "events": 0, "findings": 0, "atRisk": False,
                           "criticality": crit,
                           "riskScore": 0, "maxSeverity": None,
                           "lastSeen": None}
        return assets[key]

    for e in state.get("events", []):
        if e.get("host"):
            a = touch(e["host"], "host")
            a["events"] += 1
            if e.get("ts") and (a["lastSeen"] or "") < e["ts"]:
                a["lastSeen"] = e["ts"]

    for f in state.get("findings", []):
        f_sev = str(f.get("sev") or "INFO").upper()
        weight = SEV_WEIGHT.get(f_sev, 1)

        if f.get("hostDerived") and f.get("host") not in (None, "", "—"):
            a = touch(f["host"], "host")
            a["findings"] += 1
            a["atRisk"] = True
            crit_mult = org_context.CRITICALITY_WEIGHTS.get(a.get("criticality", "standard"), 1.0)
            a["riskScore"] += round(weight * crit_mult, 1)
            if not a["maxSeverity"] or SEV_RANK.get(f_sev, 5) < SEV_RANK.get(a["maxSeverity"], 5):
                a["maxSeverity"] = f_sev

        for chip in f.get("chips") or []:
            text = str(chip.get("text", ""))
            if redact.IPV4_RE.fullmatch(text):
                a = touch(text, "ip")
                a["findings"] += 1
                a["atRisk"] = True
                crit_mult = org_context.CRITICALITY_WEIGHTS.get(a.get("criticality", "standard"), 1.0)
                a["riskScore"] += round(weight * crit_mult, 1)
                if not a["maxSeverity"] or SEV_RANK.get(f_sev, 5) < SEV_RANK.get(a["maxSeverity"], 5):
                    a["maxSeverity"] = f_sev
                if f.get("stamp") and (a["lastSeen"] or "") < f["stamp"]:
                    a["lastSeen"] = f["stamp"]

    return sorted(assets.values(),
                  key=lambda a: (-a["riskScore"], -a["findings"], -a["events"], a["name"]))


def derive_users(state):
    """Usernames actually present in event messages and finding titles,
    extracted with the SAME patterns the redaction pass masks (one vocabulary,
    two uses). No user directory is invented."""
    users = {}

    def found_in(text):
        for pat in redact.USER_PATTERNS:
            for m in pat.finditer(text or ""):
                yield m.group("u")

    for e in state.get("events", []):
        for name in found_in(e.get("msg")):
            u = users.setdefault(name, {"id": f"user-{name}", "name": name,
                                        "events": 0, "findings": 0, "atRisk": False,
                                        "riskScore": 0, "maxSeverity": None})
            u["events"] += 1

    for f in state.get("findings", []):
        f_sev = str(f.get("sev") or "INFO").upper()
        weight = SEV_WEIGHT.get(f_sev, 1)
        for name in set(found_in(f.get("title"))):
            u = users.setdefault(name, {"id": f"user-{name}", "name": name,
                                        "events": 0, "findings": 0, "atRisk": False,
                                        "riskScore": 0, "maxSeverity": None})
            u["findings"] += 1
            u["atRisk"] = True
            u["riskScore"] += weight
            if not u["maxSeverity"] or SEV_RANK.get(f_sev, 5) < SEV_RANK.get(u["maxSeverity"], 5):
                u["maxSeverity"] = f_sev

    return sorted(users.values(), key=lambda u: (-u["riskScore"], -u["findings"], -u["events"], u["name"]))



# ---------------------------------------------------------------------------
# Cases — analyst-entered, so storing them IS the honest source
# ---------------------------------------------------------------------------

def _case_links(src, existing=None):
    """Preserve findings/incidents and carry linked cases without inventing ids."""
    src = src or {}
    prev = existing or {}
    out = {}
    for key in ("findings", "incidents", "cases"):
        if key in src:
            raw = src.get(key) or []
        else:
            raw = prev.get(key) or []
        seen, ids = set(), []
        for item in raw:
            value = str(item or "").strip()
            if value and value not in seen:
                seen.add(value)
                ids.append(value)
        out[key] = ids
    return out


def _public_case(case):
    if not case:
        return case
    out = dict(case)
    st = normalize_case_status(out.get("status"))
    if st in CASE_STATUSES:
        out["status"] = st
    # These additive fields are deliberately populated for old saved cases too:
    # clients can use one stable case-file shape without inventing data.
    out["activity"] = list(out.get("activity") or [])
    out["observables"] = list(out.get("observables") or [])
    out["attachments"] = list(out.get("attachments") or [])
    out["links"] = _case_links(out.get("links"))
    return out


def _case_activity(case, kind, text, actor="analyst"):
    """Append one analyst/system action to a case's honest local timeline."""
    if kind not in CASE_ACTIVITY_KINDS:
        raise ValueError(f"activity kind must be one of {CASE_ACTIVITY_KINDS}")
    activity = list(case.get("activity") or [])
    activity.append({
        "at": _now(),
        "actor": str(actor or "analyst")[:100],
        "kind": kind,
        "text": str(text or "")[:10000],
    })
    case["activity"] = activity


def _save_case(store, case):
    case["updatedAt"] = _now()
    store[case["id"]] = case
    _save("cases.json", store)
    _try_absorb_cases()                        # keep incidents in sync (C1-T1)
    return _public_case(case)


def list_cases():
    store = _load("cases.json")
    return sorted((_public_case(c) for c in store.values()),
                  key=lambda c: c.get("createdAt") or "", reverse=True)


def get_case(cid):
    return _public_case(_load("cases.json").get(cid))


def create_case(payload):
    title = str(payload.get("title") or "").strip()
    if not title:
        raise ValueError("a case needs a title")
    store = _load("cases.json")
    cid = f"case-{max((int(k.split('-')[1]) for k in store), default=0) + 1}"
    case = {
        "id": cid,
        "title": title[:200],
        "notes": str(payload.get("notes") or "")[:10000],
        "assignee": str(payload.get("assignee") or "")[:100],
        "status": "new",
        "history": [{"status": "new", "at": _now()}],
        "activity": [],
        "observables": [],
        "attachments": [],
        "links": _case_links(payload.get("links")),
        "createdAt": _now(),
        "updatedAt": _now(),
    }
    category = str(payload.get("category") or "").strip()[:100]
    if category:
        case["category"] = category
    summary = payload.get("summary")
    if summary is not None:
        if not isinstance(summary, dict):
            raise ValueError("summary must be an object")
        case["summary"] = {
            key: str(summary.get(key) or "")[:2000]
            for key in ("what", "impact", "when")
            if summary.get(key) is not None
        }
    _case_activity(case, "system", "Case created", "system")
    _case_activity(case, "state", "Status changed to new", "system")
    if case["assignee"]:
        _case_activity(case, "assignee", f"Assignee changed to {case['assignee']}", "system")
    store[cid] = case
    _save("cases.json", store)
    _try_absorb_cases()                        # keep incidents in sync (C1-T1)
    return _public_case(case)


def patch_case(cid, payload):
    """Update analyst-entered case fields. None for an
    unknown id; ValueError for an invalid field value."""
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    if "status" in payload:
        status = normalize_case_status(payload["status"])
        if status not in CASE_STATUSES:
            raise ValueError(f"status must be one of {CASE_STATUSES}")
        if case.get("status") != status:
            hist = list(case.get("history") or [])
            hist.append({"status": status, "at": _now()})
            case["history"] = hist
            _case_activity(case, "state", f"Status changed to {status}",
                           payload.get("actor") or "analyst")
        case["status"] = status
    if "title" in payload:
        title = str(payload["title"] or "").strip()
        if not title:
            raise ValueError("a case needs a title")
        case["title"] = title[:200]
    if "notes" in payload:
        notes = str(payload["notes"] or "")[:10000]
        if case.get("notes") != notes:
            _case_activity(case, "note", "Case notes updated", payload.get("actor") or "analyst")
        case["notes"] = notes
    if "assignee" in payload:
        assignee = str(payload["assignee"] or "")[:100]
        if case.get("assignee") != assignee:
            _case_activity(case, "assignee",
                           f"Assignee changed to {assignee or 'unassigned'}",
                           payload.get("actor") or "analyst")
        case["assignee"] = assignee
    if "category" in payload:
        category = str(payload["category"] or "").strip()[:100]
        if category:
            case["category"] = category
        else:
            case.pop("category", None)
    if "summary" in payload:
        summary = payload["summary"]
        if summary is not None and not isinstance(summary, dict):
            raise ValueError("summary must be an object")
        cleaned = ({
            key: str(summary.get(key) or "")[:2000]
            for key in ("what", "impact", "when")
            if summary.get(key) is not None
        } if summary is not None else None)
        if cleaned:
            case["summary"] = cleaned
        else:
            case.pop("summary", None)
    if "links" in payload:
        case["links"] = _case_links(payload.get("links"), case.get("links"))
    return _save_case(store, case)


def build_case_summary(case):
    """Deterministic What/Impact/When from objects on the file. Advisory only."""
    case = case or {}
    observables = list(case.get("observables") or [])
    attachments = list(case.get("attachments") or [])
    what_parts = [str(case.get("title") or "").strip()]
    notes = str(case.get("notes") or "").strip()
    if notes:
        what_parts.append(notes)
    if observables:
        bits = []
        for item in observables[:8]:
            value = item.get("value") or ""
            if not value:
                continue
            bit = f"{item.get('type') or 'unknown'} {value}"
            if item.get("verdict"):
                bit += f" ({item['verdict']})"
            bits.append(bit)
        if bits:
            what_parts.append("Observables on the file: " + "; ".join(bits) + ".")
    what = " ".join(p for p in what_parts if p) or "No title or notes have been recorded."
    if attachments:
        names = ", ".join(str(a.get("name") or "unnamed") for a in attachments[:8])
        impact = f"Attachments recorded: {names}."
    else:
        impact = "No impact statement has been recorded on this case file."
    activity = list(case.get("activity") or [])
    when = ""
    if activity:
        when = str((activity[-1] or {}).get("at") or "")
    when = when or str(case.get("createdAt") or "") or "No timestamp is on this case file."
    return {"what": what[:2000], "impact": impact[:2000], "when": when[:2000]}


def regenerate_case_summary(cid, actor="analyst"):
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    case["summary"] = build_case_summary(case)
    _case_activity(case, "system",
                   "Case summary regenerated from case-file objects (advisory, not a verdict)",
                   actor or "analyst")
    return _save_case(store, case)


def add_case_link(cid, payload):
    """Link another existing case. Does not invent a related case."""
    other_id = str(payload.get("caseId") or payload.get("id") or "").strip()
    if not other_id:
        raise ValueError("a case link needs caseId")
    if other_id == cid:
        raise ValueError("a case cannot link to itself")
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    if other_id not in store:
        raise ValueError("no such case to link")
    links = _case_links(case.get("links"))
    if other_id not in links["cases"]:
        links["cases"].append(other_id)
    case["links"] = links
    other = store[other_id]
    other_links = _case_links(other.get("links"))
    if cid not in other_links["cases"]:
        other_links["cases"].append(cid)
        other["links"] = other_links
        store[other_id] = other
    _case_activity(case, "system", f"Linked case {other_id}",
                   payload.get("actor") or "analyst")
    return _save_case(store, case)


def add_case_comment(cid, payload):
    text = str(payload.get("text") or "").strip()
    if not text:
        raise ValueError("a comment needs text")
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    _case_activity(case, "comment", text, payload.get("actor") or "analyst")
    return _save_case(store, case)


def add_case_observable(cid, payload):
    observable_type = str(payload.get("type") or "").strip().lower()
    value = str(payload.get("value") or "").strip()
    if observable_type not in CASE_OBSERVABLE_TYPES:
        raise ValueError(f"observable type must be one of {CASE_OBSERVABLE_TYPES}")
    if not value:
        raise ValueError("an observable needs a value")
    verdict = payload.get("verdict")
    if verdict is not None and str(verdict).strip().upper() in SEV_RANK:
        raise ValueError("observable verdict must not be a rule severity")
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    observables = list(case.get("observables") or [])
    oid = f"observable-{len(observables) + 1}"
    item = {"id": oid, "type": observable_type, "value": value[:2000]}
    if verdict is not None and str(verdict).strip():
        item["verdict"] = str(verdict).strip()[:200]
    observables.append(item)
    case["observables"] = observables
    _case_activity(case, "observable", f"Observable added: {observable_type} {item['value']}",
                   payload.get("actor") or "analyst")
    return _save_case(store, case)


def add_case_attachment(cid, payload):
    name = str(payload.get("name") or "").strip()
    kind = str(payload.get("kind") or "other").strip().lower()
    if not name:
        raise ValueError("an attachment needs a name")
    if kind not in CASE_ATTACHMENT_KINDS:
        raise ValueError(f"attachment kind must be one of {CASE_ATTACHMENT_KINDS}")
    size = payload.get("size")
    if size is not None:
        try:
            size = int(size)
        except (TypeError, ValueError):
            raise ValueError("attachment size must be an integer") from None
        if size < 0:
            raise ValueError("attachment size must not be negative")
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    attachments = list(case.get("attachments") or [])
    item = {"id": f"attachment-{len(attachments) + 1}", "name": name[:500], "kind": kind}
    if size is not None:
        item["size"] = size
    attachments.append(item)
    case["attachments"] = attachments
    _case_activity(case, "attachment", f"Attachment metadata added: {item['name']}",
                   payload.get("actor") or "analyst")
    return _save_case(store, case)


def add_case_runbook(cid, runbook_id, state):
    """Record an eligible shipped runbook reference; never execute a command."""
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None, None
    scan = copilot_runbook_scan(state)
    row = next((item for item in scan.get("runbooks") or []
                if item.get("id") == runbook_id), None)
    if not row:
        return case, {"eligible": False, "reason": "runbook is not shipped"}
    if not row.get("eligible"):
        return case, {"eligible": False,
                      "reason": "; ".join(row.get("missing") or ["not eligible"])}
    _case_activity(case, "runbook",
                   f"Runbook added: {row.get('name') or runbook_id} ({runbook_id}); advisory only, not executed",
                   "analyst")
    case = _save_case(store, case)
    markdown = (
        f"# Advisory playbook: {row.get('name') or runbook_id}\n\n"
        f"Shipped runbook `{runbook_id}` is eligible for incident `{row.get('incidentId')}` on this run.\n\n"
        "This records an advisory case-file reference only. No containment, quarantine, connector, or command was executed."
    )
    return case, {"eligible": True, "markdown": markdown, "runbook": row}


# ---------------------------------------------------------------------------
# Cases -> Incidents additive migration (C1-T1) — OWNER-RATIFIED 2026-08-28
# ---------------------------------------------------------------------------
# Cases absorb into incidents ADDITIVELY. Nothing is derived, suppressed, or
# escalated here — this is display/linkage metadata only; rules still own every
# real verdict (guardrail 1). Two paths, both loss-free:
#
#   * A case LINKED to incident(s) is projected onto each linked incident as an
#     embedded record under incident["cases"], keyed by caseId so re-running is
#     idempotent. Many-to-many is handled explicitly: the WHOLE case travels to
#     every incident it names (never folded arbitrarily into one). The incident
#     keeps origin "rule".
#   * An INCIDENT-LESS case (no resolvable incident link) becomes a FIRST-CLASS
#     MANUAL incident: origin "manual", no findings, no rule verdict. The owner
#     ruled these are manual incidents, NOT a separate store. Honesty is the
#     point: a manual incident must NEVER be confusable with a rule-detected one
#     — it is badged, and a severity is shown ONLY if the analyst assigned one
#     (labelled analyst-assigned), never as a rule verdict.
#
# Case status is the analyst's lifecycle. Incidents keep their existing
# operational states; the analyst's real case status is preserved verbatim as
# caseStatus and never flattened away. The EXPLICIT, documented status map
# (case status -> incident operational state) — the 5-state target lifecycle
# (…-> pending-approval -> contained -> …) is NOT introduced as incident states
# here: those belong to the C3/C4 approval/containment flow (phase order), and
# an incident 'closed' state would require editing metrics(), which carries a
# foreign uncommitted change. Reported to god as a precedence note.
CASE_STATUS_TO_INCIDENT_STATE = {
    "new": "new",
    "open": "new",                 # alias of NEW
    "triaged": "triaged",
    "investigating": "investigating",
    "escalated": "escalated",
    "resolved": "resolved",
    "closed": "closed",
}
MANUAL_INCIDENT_BADGE = "MANUAL — analyst-created, no rule verdict"


def _embed_case(case):
    """The additive, loss-free projection of a case kept on an incident. Every
    case field is carried verbatim; the analyst's real case status stays as
    caseStatus. links.findings is preserved as linkedFindings — deliberately
    SEPARATE from the incident's derived findingIds (analyst-chosen vs derived,
    and findingIds is recomputed every sync)."""
    links = case.get("links") or {}
    return {
        "caseId": case.get("id"),
        "title": case.get("title", ""),
        "notes": case.get("notes", ""),
        "assignee": case.get("assignee", ""),
        "caseStatus": normalize_case_status(case.get("status") or "new"),
        "caseCreatedAt": case.get("createdAt"),
        "caseUpdatedAt": case.get("updatedAt"),
        "linkedFindings": [str(x) for x in (links.get("findings") or [])],
        "linkedIncidents": [str(x) for x in (links.get("incidents") or [])],
    }


def _manual_incident_from_case(case, prev=None):
    """A first-class MANUAL incident for an incident-less case. It carries the
    case lifecycle, notes and assignee, and is honestly marked so it can NEVER
    be mistaken for a rule-detected incident: no findings, no rule verdict, and
    a severity ONLY if the analyst assigned one. Any analyst lifecycle already
    recorded on a prior migration (prev) is preserved so re-running is safe."""
    prev = prev or {}
    cid = case.get("id") or "case"
    inc_id = "inc-manual-" + hashlib.sha1(str(cid).encode()).hexdigest()[:10]
    analyst_sev = case.get("severity")         # cases carry none today -> None
    mapped = CASE_STATUS_TO_INCIDENT_STATE.get(
        normalize_case_status(case.get("status") or "new"), "new")
    return {
        "id": inc_id,
        "runId": "",
        "entity": case.get("assignee") or "—",
        "entityKind": "manual",
        "title": case.get("title", "") or f"Manual case {cid}",
        "severity": None,                       # never a rule verdict
        "analystSeverity": analyst_sev,         # shown ONLY if set, labelled
        "origin": "manual",
        "manualBadge": MANUAL_INCIDENT_BADGE,
        "findingIds": [],
        "findingCount": 0,
        "techniques": [],
        "attackerStatus": "",
        "createdAt": case.get("createdAt"),
        "firstSeen": None,
        "lastSeen": None,
        "timeUncertain": False,
        "isRollup": False,
        # analyst lifecycle: seeded from the case status map, then preserved
        "state": prev.get("state", mapped),
        "acknowledgedAt": prev.get("acknowledgedAt"),
        "resolvedAt": prev.get("resolvedAt"),
        "cases": [_embed_case(case)],
    }


def migrate_cases_to_incidents(soc_dir=None):
    """ADDITIVE, idempotent one-way migration: project every case in cases.json
    into incidents.json. Never deletes an incident and never overwrites a
    derived field — only attaches case metadata and creates manual incidents.
    Returns an honest summary (counts + any incident links that did not
    resolve). Operates on soc_dir when given (a COPY, in tests)."""
    global SOC_DIR
    prev_dir = SOC_DIR
    if soc_dir is not None:
        SOC_DIR = Path(soc_dir)
    try:
        cases = _load("cases.json")
        incidents = _load("incidents.json")
        attached = 0
        manual = 0
        orphaned_links = []
        for case in cases.values():
            wanted = [str(x) for x in ((case.get("links") or {}).get("incidents") or [])]
            targets = [i for i in wanted if i in incidents]
            orphaned_links.extend([i for i in wanted if i not in incidents])
            if targets:
                embedded = _embed_case(case)
                for iid in targets:
                    inc = incidents[iid]
                    bucket = inc.setdefault("cases", [])
                    bucket[:] = [c for c in bucket if c.get("caseId") != case.get("id")]
                    bucket.append(embedded)
                    inc.setdefault("origin", "rule")
                    attached += 1
            else:
                # No resolvable incident link -> host it as a manual incident so
                # the case's title/notes/assignee/lifecycle are never dropped.
                man = _manual_incident_from_case(case, prev=incidents.get(
                    "inc-manual-" + hashlib.sha1(str(case.get("id") or "case").encode()).hexdigest()[:10]))
                incidents[man["id"]] = man
                manual += 1
        _save("incidents.json", incidents)
        return {
            "cases": len(cases),
            "attachedLinks": attached,
            "manualIncidents": manual,
            "orphanedIncidentLinks": sorted(set(orphaned_links)),
        }
    finally:
        SOC_DIR = prev_dir


def _try_absorb_cases():
    """Run the migration but never let a merge failure break a case write or the
    server boot — honest degradation, not a crash."""
    try:
        migrate_cases_to_incidents()
    except Exception as exc:                    # pragma: no cover - defensive
        print(f"  cases->incidents migration skipped: {exc}", flush=True)


# ---------------------------------------------------------------------------
# Reports — files that exist, plus a generate action
# ---------------------------------------------------------------------------

def _reports_dir():
    d = SOC_DIR / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_reports():
    out = []
    for path in sorted(_reports_dir().glob("*.html"),
                       key=lambda p: p.stat().st_mtime, reverse=True):
        st = path.stat()
        out.append({"name": path.name, "bytes": st.st_size,
                    "createdAt": datetime.fromtimestamp(
                        st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")})
    return out


def generate_report(state):
    """Render the current run through the existing standalone exporter."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_run = re.sub(r"[^A-Za-z0-9._-]", "_", state.get("runId") or "run")
    path = _reports_dir() / f"{safe_run}-{stamp}.html"
    path.write_text(export.build(state))
    st = path.stat()
    return {"name": path.name, "bytes": st.st_size,
            "createdAt": datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")}


# ---------------------------------------------------------------------------
# Threat intel — surface what threat_intel/ already holds
# ---------------------------------------------------------------------------

def threat_intel_summary():
    indicators = []
    bundle_path = ROOT / "threat_intel" / "demo_threat_intel.json"
    try:
        bundle = json.loads(bundle_path.read_text())
    except (OSError, json.JSONDecodeError):
        bundle = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            indicators.append({"id": obj.get("id"), "name": obj.get("name"),
                               "pattern": obj.get("pattern"),
                               "types": obj.get("indicator_types", []),
                               "validFrom": obj.get("valid_from")})
    return {
        "indicators": indicators,
        "indicatorSource": "threat_intel/demo_threat_intel.json (offline STIX bundle)",
        "ruleTechniques": {k: [dict(t) for t in v] for k, v in RULE_TECHNIQUES.items()},
        "attackCacheWarm": any((Path.home() / ".cache" / "mitre_attack").glob("*")
                               ) if (Path.home() / ".cache" / "mitre_attack").exists()
                             else False,
    }


# ---------------------------------------------------------------------------
# Metrics — real lifecycle math or null, never a made-up number
# ---------------------------------------------------------------------------

def _mean_seconds(pairs):
    """Mean duration over (start, end) iso pairs that BOTH exist. (value, basis)."""
    durations = []
    for start, end in pairs:
        a, b = _parse_ts(start), _parse_ts(end)
        if a and b and b >= a:
            durations.append((b - a).total_seconds())
    if not durations:
        return None, 0
    return round(sum(durations) / len(durations)), len(durations)


def metrics(state, run_labels=()):
    incidents = list(_load("incidents.json").values())
    mtta, mtta_basis = _mean_seconds(
        (i.get("createdAt"), i.get("acknowledgedAt")) for i in incidents)
    mttr, mttr_basis = _mean_seconds(
        (i.get("createdAt"), i.get("resolvedAt"))
        for i in incidents
        if normalize_incident_state(i.get("state")) in INCIDENT_TERMINAL)

    idle = not state or state.get("idle")
    return {
        "openIncidents": sum(
            1 for i in incidents
            if normalize_incident_state(i.get("state")) not in INCIDENT_TERMINAL),
        "mttaSeconds": mtta, "mttaBasis": mtta_basis,
        "mttrSeconds": mttr, "mttrBasis": mttr_basis,
        # HIGH+ risk only — counting all atRisk dilutes the signal when most
        # entities have at least one LOW finding (ITSOC_REDESIGN_SPEC §Phase 4).
        "assetsAtRisk": None if idle else sum(
            1 for a in derive_assets(state)
            if (a.get("maxSeverity") or "").upper() in ("CRITICAL", "HIGH")),
        "usersAtRisk": None if idle else sum(
            1 for u in derive_users(state)
            if (u.get("maxSeverity") or "").upper() in ("CRITICAL", "HIGH")),
        "dataSources": len({label for label in run_labels if label}),
    }


# ---------------------------------------------------------------------------
# AI copilot Showcase (design-v2 P3 / handoff §4)
#
# build_view is the copilot's SHOWCASE selector: given an analyst question, it
# chooses WHAT real data to surface (which view + which entity) and returns a
# structured directive the rail renders as is-* cards. It is a DISPLAY
# aggregation like everything else in this module — it NEVER creates or changes
# a verdict/severity. Every value in a view is real backend data: severities are
# the rule-owned levels already on the findings/incidents, titles are the
# detector/rule text (no model naming), and citedFindings is a real count. The
# selection is deterministic keyword intent — no LLM decides what is surfaced.
# Prose still comes from ask_analyst/askStream (advisory), guarded separately.
# ---------------------------------------------------------------------------

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _sev_rank(sev):
    return _SEV_ORDER.get(str(sev or "").upper(), 9)


def _finding_sev(f):
    return (f.get("sev") or f.get("ruleSev") or "").upper()


def _view_sev_filter(q):
    for s in ("critical", "high", "medium", "low"):
        if s in q:
            return s.upper()
    return None


def _view_entities(findings):
    """Real entity tokens observed in the run: finding hosts + line hits (IPs)."""
    ents = set()
    for f in findings:
        if f.get("host"):
            ents.add(f["host"])
        for ln in f.get("lines") or []:
            if ln.get("hit"):
                ents.add(ln["hit"])
    return ents


def _match_entity(q, findings):
    ql = (q or "").lower()
    matches = [e for e in _view_entities(findings) if e and e.lower() in ql]
    return max(matches, key=len) if matches else None


def _finding_item(f):
    return {
        "id": f.get("id"),
        "severity": _finding_sev(f),
        "rule": f.get("type", ""),
        "host": f.get("host", ""),
        "title": f.get("title", ""),
        "deeplink": f"/findings?sel={f.get('id')}",
    }


def _findings_view(findings, sevf, limit=5):
    fs = [f for f in findings if not sevf or _finding_sev(f) == sevf]
    fs = sorted(fs, key=lambda f: _sev_rank(_finding_sev(f)))
    title = f"Top {sevf.title() + ' ' if sevf else ''}findings"
    return {
        "type": "findings", "title": title, "filter": sevf or "all",
        "items": [_finding_item(f) for f in fs[:limit]],
        "deeplink": "/findings", "citedFindings": len(fs),
    }


def _incidents_view(state, sevf, limit=8):
    incs = list_incidents(state)
    if sevf:
        incs = [i for i in incs if str(i.get("severity", "")).upper() == sevf]
    incs = sorted(incs, key=lambda i: (_sev_rank(i.get("severity")), i.get("createdAt") or ""))
    items = [{
        "id": i.get("id"),
        "severity": str(i.get("severity", "")).upper(),
        "entity": i.get("entity", ""),
        "findingCount": i.get("findingCount", 0),
        "deeplink": f"/incidents?sel={i.get('id')}",
    } for i in incs[:limit]]
    title = f"{sevf.title() + ' ' if sevf else 'Top '}incidents"
    return {
        "type": "incidents", "title": title, "filter": sevf or "all",
        "items": items, "deeplink": "/incidents",
        "citedFindings": sum(int(i.get("findingCount", 0)) for i in incs),
    }


def _entity_view(entity, findings, limit=6):
    ef = [f for f in findings
          if f.get("host") == entity
          or any(ln.get("hit") == entity for ln in (f.get("lines") or []))]
    ef = sorted(ef, key=lambda f: _sev_rank(_finding_sev(f)))
    return {
        "type": "entity", "title": f"{entity} — {len(ef)} finding(s)", "filter": entity,
        "items": [_finding_item(f) for f in ef[:limit]],
        "deeplink": f"/findings?q={entity}", "citedFindings": len(ef),
    }


def _dashboard_view(state):
    findings = state.get("findings") or []
    sev = {b: sum(1 for f in findings if _finding_sev(f) == b)
           for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    m = metrics(state)
    kpis = [
        {"label": "Findings", "value": len(findings)},
        {"label": "Critical", "value": sev["CRITICAL"]},
        {"label": "High", "value": sev["HIGH"]},
        {"label": "Open incidents", "value": m["openIncidents"]},
        {"label": "Assets at risk", "value": m["assetsAtRisk"], "note": "per-run"},
        {"label": "Users at risk", "value": m["usersAtRisk"], "note": "per-run"},
    ]
    return {
        "type": "dashboard", "title": "Current run — dashboard summary", "filter": "current",
        "kpis": kpis, "deeplink": "/", "citedFindings": len(findings),
    }


def build_view(question, state):
    """Deterministic showcase selector. Returns a view directive dict, or None
    when the question is not a showcase request (prose-only). Never a verdict."""
    if not state or state.get("idle"):
        return None
    q = (question or "").lower().strip()
    if not q:
        return None
    findings = state.get("findings") or []

    entity = _match_entity(q, findings)
    if entity:
        return _entity_view(entity, findings)
    if any(w in q for w in ("dashboard", "summar", "overview", "posture", "big picture")):
        return _dashboard_view(state)
    if "incident" in q:
        return _incidents_view(state, _view_sev_filter(q))
    if any(w in q for w in ("finding", "alert", "detection", "top ")):
        return _findings_view(findings, _view_sev_filter(q))
    return None


# ===========================================================================
# Approvals — gated response with per-action step-up (Stage C, C3-T2 / D3)
# ===========================================================================
# The API-route LOGIC for the approvals flow. Each public function returns an
# HTTP-style (status_code, body) tuple so the flow — including the 409 path and
# the re-evaluation refusal — is fully demonstrable without an HTTP server; the
# eventual serve.py delegation is a thin parse-and-emit wrapper over these.
#
# Guardrails held here: rules own eligibility (runbooks.eligible), so the LLM
# can never open this gate; the connector is invoked ONLY inside approve, and
# ONLY after a successful step-up verification; every approve/reject/execute is
# written to the append-only hash-chained audit ledger; and the redacted command
# (never the raw one) is what lands in the stored record and the audit entry.
#
# State machine:  pending -> approved -> executed | failed
#                 pending -> rejected
# `failed` records the real reason and NEVER fake-contains.

APPROVAL_STATES = ("pending", "approved", "rejected", "executed", "failed")
APPROVALS_FILE = "approvals.json"


def _approval_id():
    import secrets
    return "appr-" + secrets.token_hex(6)


def _render_template_value(value, ctx):
    """Substitute {{incident.<field>}} placeholders in one string with rule-owned
    incident facts. Non-strings pass through untouched. Unknown placeholders are
    left verbatim (honest — we never invent a value for a field we do not have)."""
    if not isinstance(value, str):
        return value
    out = value
    for key, repl in ctx.items():
        out = out.replace("{{" + key + "}}", str(repl))
    return out


def _incident_context(incident, members):
    """The rule-owned facts a runbook step template may reference. Advisory
    fields are structurally absent — only detector/verdict output is here."""
    rules = sorted({str(m.get("type")) for m in members if m.get("type")})
    refs = []
    for m in members:
        for line in m.get("lines") or []:
            if isinstance(line, dict) and line.get("n") is not None:
                refs.append(int(line["n"]))
    refs = sorted(set(refs))
    return {
        "incident.entity": incident.get("entity") or "",
        "incident.id": incident.get("id") or "",
        "incident.rules": ",".join(rules),
        "incident.record_refs": ",".join(str(n) for n in refs),
        "incident.firstSeen": incident.get("firstSeen") or "",
        "incident.lastSeen": incident.get("lastSeen") or "",
    }, refs


def _render_params(template, incident, members):
    ctx, _refs = _incident_context(incident, members)
    return {k: _render_template_value(v, ctx) for k, v in (template or {}).items()}


def _incident_members(incident, state):
    """Member findings of an incident from the loaded run state (the same source
    derive_rca uses). eligible() reads type/host/lines/occurrences off these."""
    if not state or state.get("idle"):
        return []
    by_id = {f.get("id"): f for f in state.get("findings", [])}
    return [by_id[fid] for fid in (incident.get("findingIds") or []) if fid in by_id]


def _runbook_by_id(runbook_id):
    import runbooks
    return runbooks.load_runbooks().get(runbook_id)


def _action_step(runbook, step_index=None):
    """The connector-bearing step to gate. Defaults to the first 'action' step;
    an explicit index selects a specific step."""
    steps = runbook.get("steps") or []
    if step_index is not None:
        return steps[step_index] if 0 <= step_index < len(steps) else None
    for s in steps:
        if s.get("type") == "action":
            return s
    return steps[0] if steps else None


def _connector_config(name):
    """Connector transport config (host/user/port/key_path) from a config file
    only — never argv, never a log (guardrail 4). Honest empty when absent; the
    connector then falls back to its own defaults."""
    cfg = _load("connectors.json")
    return (cfg.get(name) or cfg.get(name.lower()) or {}) if isinstance(cfg, dict) else {}


def _eligibility(runbook, incident, members):
    import runbooks
    return runbooks.eligible(runbook, incident, members)


def create_approval(payload, state=None):
    """POST /api/approvals — create a PENDING approval for one runbook step.

    Rules own eligibility: an ineligible runbook is refused with 409 and the
    body's `missing` array is exactly `runbooks.eligible()['missing']`, so the
    API error cannot disagree with the engine. No connector runs and no audit
    entry is written here — creating a pending record is not a consequential act;
    only approve/reject/execute are.
    """
    payload = payload or {}
    incident_id = str(payload.get("incidentId") or payload.get("incident_id") or "").strip()
    runbook_id = str(payload.get("runbookId") or payload.get("runbook_id") or "").strip()
    step_index = payload.get("stepIndex")
    if not incident_id or not runbook_id:
        return 400, {"error": "incidentId and runbookId are required"}

    incident = get_incident(incident_id)
    if not incident:
        return 404, {"error": f"no such incident: {incident_id}"}
    runbook = _runbook_by_id(runbook_id)
    if not runbook:
        return 404, {"error": f"no such runbook: {runbook_id}"}

    members = _incident_members(incident, state)
    verdict = _eligibility(runbook, incident, members)
    if not verdict.get("eligible"):
        # 409 body populated DIRECTLY from the engine — not restated, not reworded.
        return 409, {"error": "runbook is not eligible for this incident",
                     "incidentId": incident_id, "runbookId": runbook_id,
                     "missing": verdict.get("missing", [])}

    step = _action_step(runbook, step_index)
    if not step:
        return 422, {"error": "runbook has no actionable step"}

    _ctx, refs = _incident_context(incident, members)
    rendered = _render_params(step.get("params_template"), incident, members)

    # The stored/displayed command is the REDACTED preview — raw params never
    # reach the record, a log, or the UI (they travel only over the connector
    # transport at execute time). This closes the redact gap in the connector path.
    import actions
    try:
        connector = actions.get_connector(step["connector"], _connector_config(step["connector"]))
        preview = connector.preview(rendered, {"entity": incident.get("entity"),
                                               "incident_id": incident_id})
        request_redacted = {"command": preview.get("command"),
                            "description": preview.get("description"),
                            "connector": preview.get("connector"),
                            "action": preview.get("action"),
                            "params": preview.get("params")}
    except Exception as exc:                       # honest: preview failure is visible
        request_redacted = {"error": f"preview failed: {type(exc).__name__}: {exc}"}

    now = _now()
    record = {
        "id": _approval_id(),
        "incidentId": incident_id,             # rule-owned
        "runbookId": runbook_id,               # rule-owned
        "connector": step["connector"],        # connector-owned
        "step": 0,
        "state": "pending",
        "eligibilityProof": verdict,           # rule-owned (verbatim from eligible())
        "evidenceRefs": [str(n) for n in refs],  # rule-owned
        "requestRedacted": request_redacted,   # connector-owned (redacted)
        "responseVerbatim": None,              # connector-owned (filled at execute)
        "actor": None,                         # analyst-supplied (verified at step-up)
        "failureReason": None,
        "createdAt": now,
        "updatedAt": now,
    }
    store = _load(APPROVALS_FILE)
    store[record["id"]] = record
    _save(APPROVALS_FILE, store)
    return 201, record


def get_approval(approval_id):
    return _load(APPROVALS_FILE).get(approval_id)


def list_approvals(state_filter=None):
    out = sorted(_load(APPROVALS_FILE).values(),
                 key=lambda a: a.get("createdAt") or "", reverse=True)
    if state_filter:
        out = [a for a in out if a.get("state") == state_filter]
    return out


# ---- append-only hash-chained audit ledger (C4-T2a / D4) -----------------
def audit_chain():
    """Return the audit ledger entries and the live verify_chain() verdict.
    Source of truth is console/.soc/audit/chain.jsonl. Missing ledger -> honest empty."""
    import audit
    verdict = audit.verify_chain()
    try:
        entries = audit.read_entries()
    except Exception:
        entries = []
        for line in audit.read_lines():
            try:
                import json
                entries.append(json.loads(line))
            except Exception:
                break
    return 200, {"entries": entries, "verification": verdict}


def audit_verify():
    """Return the live verify_chain() verdict over the audit ledger."""
    import audit
    verdict = audit.verify_chain()
    return 200, verdict



def _audit(actor, record, step, status, eligibility_proof=None,
           response_verbatim=None):
    """One append to the hash-chained ledger for a consequential act. The actor
    is the verified step-up username and nothing else about the credential."""
    import audit
    return audit.append(
        actor=actor,
        incident_id=record.get("incidentId", ""),
        runbook_id=record.get("runbookId", ""),
        step=step,
        status=status,
        eligibility_proof=eligibility_proof if eligibility_proof is not None
        else record.get("eligibilityProof"),
        evidence_refs=record.get("evidenceRefs"),
        request_redacted=record.get("requestRedacted"),
        response_verbatim=response_verbatim,
    )


def reject_approval(approval_id, passphrase, provider=None):
    """Reject a pending approval — requires a successful step-up verification.
    pending -> rejected. Writes one 'rejected' audit entry stamped with the
    verified username. No connector is ever touched on this path."""
    import auth
    provider = provider or auth.AUTH_PROVIDER
    ok, username = provider.verify_stepup_passphrase(passphrase)
    # The passphrase is not referenced again after this line — never stored,
    # never logged, never returned.
    if not ok:
        return 401, {"error": "step-up verification failed"}

    store = _load(APPROVALS_FILE)
    record = store.get(approval_id)
    if not record:
        return 404, {"error": f"no such approval: {approval_id}"}
    if record.get("state") != "pending":
        return 409, {"error": "approval is not pending", "state": record.get("state")}

    record["state"] = "rejected"
    record["actor"] = username
    record["updatedAt"] = _now()
    store[approval_id] = record
    _save(APPROVALS_FILE, store)
    _audit(username, record, step="reject", status="rejected")
    return 200, record


def approve_approval(approval_id, passphrase, state=None, connector_factory=None,
                     provider=None):
    """Approve a pending approval and fire its connector — the ONLY path on which
    a connector is ever invoked, and only AFTER a successful step-up.

    Order: step-up -> RE-EVALUATE eligibility -> approved (audit) -> execute
    (audit executed|failed). The re-evaluation (owner-ratified) re-runs
    runbooks.eligible() against the CURRENT incident/findings immediately before
    firing, so an approval cannot execute against evidence that no longer holds.
    A connector failure is recorded honestly as `failed` with the real reason and
    never fake-contains.
    """
    import auth
    provider = provider or auth.AUTH_PROVIDER
    ok, username = provider.verify_stepup_passphrase(passphrase)
    if not ok:
        # Refused before anything happens: no state change, no connector, no audit.
        return 401, {"error": "step-up verification failed"}

    store = _load(APPROVALS_FILE)
    record = store.get(approval_id)
    if not record:
        return 404, {"error": f"no such approval: {approval_id}"}
    if record.get("state") != "pending":
        return 409, {"error": "approval is not pending", "state": record.get("state")}

    incident = get_incident(record["incidentId"])
    runbook = _runbook_by_id(record["runbookId"])
    if not incident or not runbook:
        record["state"] = "failed"
        record["failureReason"] = "incident or runbook no longer exists"
        record["actor"] = username
        record["updatedAt"] = _now()
        store[approval_id] = record
        _save(APPROVALS_FILE, store)
        _audit(username, record, step="approve", status="failed")
        return 409, {"error": record["failureReason"]}

    members = _incident_members(incident, state)

    # --- RE-EVALUATION GUARANTEE: eligibility must STILL hold, right now -------
    verdict = _eligibility(runbook, incident, members)
    if not verdict.get("eligible"):
        record["state"] = "failed"
        record["eligibilityProof"] = verdict
        record["failureReason"] = "re-evaluation failed: the incident no longer meets the runbook's evidence requirements"
        record["actor"] = username
        record["responseVerbatim"] = None          # never fake-contain
        record["updatedAt"] = _now()
        store[approval_id] = record
        _save(APPROVALS_FILE, store)
        _audit(username, record, step="approve", status="failed",
               eligibility_proof=verdict)
        return 409, {"error": record["failureReason"], "missing": verdict.get("missing", [])}

    # --- eligible: transition to approved and record it -----------------------
    record["state"] = "approved"
    record["actor"] = username
    record["eligibilityProof"] = verdict
    record["updatedAt"] = _now()
    store[approval_id] = record
    _save(APPROVALS_FILE, store)
    _audit(username, record, step="approve", status="approved")

    # --- fire the connector (unredacted params over the transport only) -------
    step = _action_step(runbook)
    rendered = _render_params((step or {}).get("params_template"), incident, members)
    rendered.setdefault("approval_id", approval_id)
    if connector_factory is None:
        import actions
        def connector_factory(name):
            return actions.get_connector(name, _connector_config(name))

    try:
        connector = connector_factory(record["connector"])
        result = connector.execute(rendered, {"entity": incident.get("entity"),
                                             "approval_id": approval_id,
                                             "incident_id": record["incidentId"]})
    except Exception as exc:                        # honest: a raised connector is a failure
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "output": ""}

    if result.get("ok"):
        record["state"] = "executed"
        record["responseVerbatim"] = {"output": result.get("output", ""),
                                     "connector": result.get("connector"),
                                     "action": result.get("action")}
        record["updatedAt"] = _now()
        store[approval_id] = record
        _save(APPROVALS_FILE, store)
        _audit(username, record, step="execute", status="executed",
               response_verbatim=record["responseVerbatim"])
        return 200, record

    # connector failed — record the REAL reason, never a fabricated success.
    record["state"] = "failed"
    record["failureReason"] = result.get("error") or "connector reported failure"
    record["responseVerbatim"] = {"output": result.get("output", ""),
                                 "error": result.get("error")}
    record["updatedAt"] = _now()
    store[approval_id] = record
    _save(APPROVALS_FILE, store)
    _audit(username, record, step="execute", status="failed",
           response_verbatim=record["responseVerbatim"])
    return 200, record


# ===========================================================================
# Copilot runbook recommendation — advisory-typed, no executable handle (C3-T4)
# ===========================================================================
# Build doc C3 item 4: "AI copilot may *recommend* among eligible runbooks and
# draft justifications; recommendation payloads are advisory-typed and carry no
# executable handle." Enforced here:
#
#   * RULES OWN ELIGIBILITY. The candidate set is exactly what runbooks.eligible()
#     returns — computed with NO model input. The model may only rank and explain
#     WITHIN that set; any id it names that is not eligible is dropped, so it can
#     never widen the gate. (runbooks.eligible() is never modified — its signature
#     stays closed to any LLM parameter.)
#   * NO EXECUTABLE HANDLE. The payload carries no approval id, no connector name
#     or config, no rendered command, no params, and no token — nothing a caller
#     could replay as an approval. It names runbooks by their rule id only.
#   * ADVISORY-TYPED. type == "runbook_recommendation", advisory == True, and the
#     model's justifications sit under an advisory-labelled block, exactly as C2
#     treats advisory prose.
#   * D2. The eligible list is computed FIRST and returned regardless of the
#     model. The advisory portion runs under a hard timeout in a worker; if the
#     model raises or hangs, the eligible list still returns and the advisory is
#     honestly `timed_out`/`absent` — never fabricated, never silently dropped.

RECOMMENDATION_LABEL = "advisory · recommendation · not a verdict"
_RECO_TIMEOUT = 30

_RECO_SYSTEM = (
    "You are a SOC copilot. Rules own eligibility, severity, priority and every "
    "verdict; you may not change them. You are given the ONLY runbooks that are "
    "already eligible for this incident. Rank them and justify each, using ONLY "
    "the supplied rule facts. Never name a runbook that is not in the eligible "
    "list. Never emit a command, a connector, or any executable detail. Return "
    "JSON matching the schema."
)

_RECO_SCHEMA = {
    "type": "object",
    "properties": {
        "ranking": {"type": "array", "items": {"type": "string"}},
        "justifications": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "runbookId": {"type": "string"},
                    "text": {"type": "string"},
                },
                "required": ["runbookId", "text"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["ranking", "justifications"],
    "additionalProperties": False,
}


def eligible_runbooks(incident, state=None):
    """DETERMINISTIC candidate set: every runbook runbooks.eligible() says YES to
    for this incident, each with its rule-owned proof. No model, and deliberately
    NO connector/params/command — an eligible entry is a reference, not a handle."""
    import runbooks
    members = _incident_members(incident, state)
    out = []
    for rid, rb in sorted(runbooks.load_runbooks().items()):
        verdict = runbooks.eligible(rb, incident, members)
        if verdict.get("eligible"):
            out.append({
                "runbookId": rid,                 # rule id — a reference, not a handle
                "name": rb.get("name"),
                "severityFloor": rb.get("severity_floor"),
                # C4-F1: additive, rule-owned field for the Response panel's
                # trigger-rule chips — the runbook definition's trigger.rule_ids
                # VERBATIM (a copy, no derivation/filtering). Same class of fact
                # as severityFloor; carries no verdict semantics.
                "triggerRules": list(rb.get("trigger", {}).get("rule_ids") or []),
                "eligibilityProof": verdict,       # rule-owned, verbatim from eligible()
            })
    return out


def copilot_runbook_scan(state):
    """Shipped runbooks vs THIS run's derived incidents — display only.

    Rules own eligibility (`runbooks.eligible`). Nothing is executed, no
    connector is contacted, and an empty/ineligible set is honest rather
    than a fallback runbook. Used by the copilot Runbook tab so the analyst
    does not have to already be on /incidents?sel= to see why a book does
    or does not apply.
    """
    import runbooks
    books = runbooks.load_runbooks()
    idle = not state or state.get("idle") or state.get("unrecognized") or state.get("emptyInput")
    incidents = [] if idle else derive_incidents(state)
    rows = []
    for rid, rb in sorted(books.items()):
        row = {
            "id": rid,
            "name": rb.get("name") or rid,
            "severityFloor": rb.get("severity_floor"),
            "triggerRules": list((rb.get("trigger") or {}).get("rule_ids") or []),
            "eligible": False,
            "missing": ["no derived incident on this run"],
            "incidentId": None,
        }
        for inc in incidents:
            members = _incident_members(inc, state)
            v = runbooks.eligible(rb, inc, members)
            if v.get("eligible"):
                row["eligible"] = True
                row["missing"] = []
                row["incidentId"] = inc.get("id")
                break
            miss = list(v.get("missing") or [])
            if (row["missing"] == ["no derived incident on this run"]
                    or (miss and len(miss) < len(row["missing"]))):
                row["missing"] = miss
                row["incidentId"] = inc.get("id")
        rows.append(row)
    n_ok = sum(1 for r in rows if r["eligible"])
    return {
        "runbooks": rows,
        "incidentCount": len(incidents),
        "note": (
            f"{n_ok} of {len(rows)} shipped runbook(s) eligible on this run. "
            "Eligibility is rule-owned. Nothing is executed from here."
        ),
    }


def _call_reco_model(chat_fn, prompt, timeout):
    import log_analyzer as la
    return chat_fn(la.LLM_BASE_URL, la.LLM_API_KEY, la.LLM_MODEL,
                   _RECO_SYSTEM, prompt, timeout=timeout, response_schema=_RECO_SCHEMA)


def _recommendation_advisory(facts, eligible, chat_fn, timeout):
    """The ADVISORY half: a model ranking + justifications, bounded by a hard
    timeout and filtered to the eligible ids. Returns an honest status —
    complete | absent | timed_out — and never a fabricated recommendation."""
    import concurrent.futures

    eligible_ids = [e["runbookId"] for e in eligible]
    base = {"label": RECOMMENDATION_LABEL, "ranking": [], "justifications": []}
    if not eligible_ids:
        return {**base, "status": "absent",
                "note": "no eligible runbook — nothing for the model to rank"}
    if chat_fn is None:
        import log_analyzer as la
        chat_fn = la.chat_completion

    prompt = json.dumps({
        "task": "Rank the eligible runbooks best-first and justify each in one "
                "sentence, using only these rule facts.",
        "incident": facts,
        "eligible_runbooks": [{"runbookId": e["runbookId"], "name": e["name"],
                               "severityFloor": e["severityFloor"]} for e in eligible],
    }, sort_keys=True)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1,
                                                     thread_name_prefix="itsoc-reco")
    future = executor.submit(_call_reco_model, chat_fn, prompt, timeout)
    try:
        raw = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        executor.shutdown(wait=False, cancel_futures=True)
        return {**base, "status": "timed_out",
                "note": "ADVISORY · timed out — the eligible list above is complete without it"}
    except Exception as exc:                       # noqa: BLE001 — reported honestly
        executor.shutdown(wait=False, cancel_futures=True)
        return {**base, "status": "timed_out",
                "note": f"ADVISORY · model unavailable ({type(exc).__name__}) — "
                        "the eligible list above is complete without it"}
    executor.shutdown(wait=False, cancel_futures=True)

    import log_analyzer as la
    try:
        parsed = json.loads(la.strip_fences(raw))
    except Exception:
        return {**base, "status": "absent",
                "note": "model returned unparseable output — withheld"}
    if not isinstance(parsed, dict):
        return {**base, "status": "absent", "note": "model output was not an object — withheld"}

    # FILTER to the eligible set — the single most important line: a model id that
    # is not eligible is dropped, so the copilot can never widen the gate.
    seen = set()
    ranking = []
    for rid in parsed.get("ranking") or []:
        if rid in eligible_ids and rid not in seen:
            seen.add(rid)
            ranking.append(rid)
    justifications = []
    for j in parsed.get("justifications") or []:
        if (isinstance(j, dict) and j.get("runbookId") in eligible_ids
                and str(j.get("text", "")).strip()):
            justifications.append({"runbookId": j["runbookId"],
                                   "text": str(j["text"]).strip()})
    if not ranking and not justifications:
        return {**base, "status": "absent",
                "note": "model produced nothing grounded in the eligible set — withheld"}
    return {"label": RECOMMENDATION_LABEL, "status": "complete",
            "ranking": ranking, "justifications": justifications, "note": None}


def recommend_runbooks(incident, state=None, chat_fn=None, timeout=None):
    """Advisory-typed runbook recommendation for one incident.

    The `eligible` list is deterministic and rule-owned; `recommendation` is the
    advisory (model) ranking + justifications, filtered to the eligible set and
    honestly absent/timed-out when the model cannot answer. The payload carries
    NO executable handle — it can never be replayed as an approval.
    """
    timeout = _RECO_TIMEOUT if timeout is None else timeout  # resolved live, so a
    # test (or config) can shrink the model deadline without touching the default.
    members = _incident_members(incident, state)
    eligible = eligible_runbooks(incident, state)
    facts = {
        "incidentId": incident.get("id") if incident else None,
        "entityKind": incident.get("entityKind") if incident else None,
        "severity": incident.get("severity") if incident else None,
        "rules": sorted({str(m.get("type")) for m in members if m.get("type")}),
    }
    recommendation = _recommendation_advisory(facts, eligible, chat_fn, timeout)
    return {
        "type": "runbook_recommendation",       # advisory-typed marker
        "advisory": True,
        "incidentId": incident.get("id") if incident else None,
        "eligible": eligible,                    # deterministic, rule-owned
        "recommendation": recommendation,        # advisory (model), honest states
    }


def recommend_for_incident(incident_id, state=None, chat_fn=None, timeout=None):
    """(status, body) wrapper for the serve.py delegation — fetch the incident,
    404 if unknown, else the advisory-typed recommendation."""
    inc = get_incident(incident_id)
    if not inc:
        return 404, {"error": f"no such incident: {incident_id}"}
    return 200, recommend_runbooks(inc, state, chat_fn=chat_fn, timeout=timeout)
