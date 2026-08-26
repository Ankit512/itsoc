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
import redact  # noqa: E402
from rule_mitre_map import RULE_TECHNIQUES  # noqa: E402
from tactic_phase_map import phase_for_tactics  # noqa: E402

SOC_DIR = HERE / ".soc"                       # monkeypatched to a tmp dir in tests

INCIDENT_STATES = ("new", "acknowledged", "investigating", "resolved")
CASE_STATUSES = ("open", "investigating", "closed")
CLUSTER_GAP_SECONDS = 30 * 60                 # the documented correlation window

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


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

            incidents.append({
                "id": inc_id,
                "runId": state.get("runId", ""),
                "entity": entity,
                "entityKind": kind,
                "title": title,
                "severity": sev,
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
        deduped = [i for i in deduped if i.get("state") == state_filter]
    return deduped


def get_incident(iid):
    return _load("incidents.json").get(iid)


def set_incident_state(iid, new_state):
    """Analyst lifecycle transition. Timestamps record what actually happened:
    acknowledgedAt on the first move out of 'new', resolvedAt on entering
    'resolved' (cleared when a mistaken resolve is reopened). Returns the
    updated incident, or None for an unknown id; ValueError on a bad state."""
    if new_state not in INCIDENT_STATES:
        raise ValueError(f"state must be one of {INCIDENT_STATES}")
    store = _load("incidents.json")
    inc = store.get(iid)
    if not inc:
        return None
    if new_state != "new" and not inc.get("acknowledgedAt"):
        inc["acknowledgedAt"] = _now()
    if new_state == "resolved" and not inc.get("resolvedAt"):
        inc["resolvedAt"] = _now()
    if new_state != "resolved":
        inc["resolvedAt"] = None
    inc["state"] = new_state
    _save("incidents.json", store)
    return inc


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

    def touch(name, kind):
        key = (kind, name)
        if key not in assets:
            assets[key] = {"id": f"asset-{kind}-{name}", "name": name, "kind": kind,
                           "events": 0, "findings": 0, "atRisk": False,
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
            a["riskScore"] += weight
            if not a["maxSeverity"] or SEV_RANK.get(f_sev, 5) < SEV_RANK.get(a["maxSeverity"], 5):
                a["maxSeverity"] = f_sev

        for chip in f.get("chips") or []:
            text = str(chip.get("text", ""))
            if redact.IPV4_RE.fullmatch(text):
                a = touch(text, "ip")
                a["findings"] += 1
                a["atRisk"] = True
                a["riskScore"] += weight
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

def list_cases():
    store = _load("cases.json")
    return sorted(store.values(), key=lambda c: c.get("createdAt") or "", reverse=True)


def get_case(cid):
    return _load("cases.json").get(cid)


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
        "status": "open",
        "links": {
            "findings": [str(x) for x in (payload.get("links") or {}).get("findings", [])],
            "incidents": [str(x) for x in (payload.get("links") or {}).get("incidents", [])],
        },
        "createdAt": _now(),
        "updatedAt": _now(),
    }
    store[cid] = case
    _save("cases.json", store)
    return case


def patch_case(cid, payload):
    """Update any subset of title/notes/assignee/status/links. None for an
    unknown id; ValueError for an invalid field value."""
    store = _load("cases.json")
    case = store.get(cid)
    if not case:
        return None
    if "status" in payload:
        if payload["status"] not in CASE_STATUSES:
            raise ValueError(f"status must be one of {CASE_STATUSES}")
        case["status"] = payload["status"]
    if "title" in payload:
        title = str(payload["title"] or "").strip()
        if not title:
            raise ValueError("a case needs a title")
        case["title"] = title[:200]
    if "notes" in payload:
        case["notes"] = str(payload["notes"] or "")[:10000]
    if "assignee" in payload:
        case["assignee"] = str(payload["assignee"] or "")[:100]
    if "links" in payload:
        links = payload["links"] or {}
        case["links"] = {
            "findings": [str(x) for x in links.get("findings", [])],
            "incidents": [str(x) for x in links.get("incidents", [])],
        }
    case["updatedAt"] = _now()
    _save("cases.json", store)
    return case


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
    mttd, mttd_basis = _mean_seconds(
        (i.get("createdAt"), i.get("acknowledgedAt")) for i in incidents)
    mttr, mttr_basis = _mean_seconds(
        (i.get("createdAt"), i.get("resolvedAt"))
        for i in incidents if i.get("state") == "resolved")

    idle = not state or state.get("idle")
    return {
        "openIncidents": sum(1 for i in incidents if i.get("state") != "resolved"),
        "mttdSeconds": mttd, "mttdBasis": mttd_basis,
        "mttrSeconds": mttr, "mttrBasis": mttr_basis,
        # Per-run derivations have no honest value without a run.
        "assetsAtRisk": None if idle else sum(
            1 for a in derive_assets(state) if a["atRisk"]),
        "usersAtRisk": None if idle else sum(
            1 for u in derive_users(state) if u["atRisk"]),
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
