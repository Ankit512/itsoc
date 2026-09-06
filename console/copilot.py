#!/usr/bin/env python3
"""
copilot.py — deterministic investigation layer for the AI analyst rail.

HyperSOC-style: the copilot digs into run data the Overview collapses
(matching lines, raw evidence, grouped signatures) and talks from those
facts. The LLM, when reachable, explains the same facts — it never
searches, never invents alerts, and never changes a rule-owned severity.

Returns:
  suggested_questions(state) -> list[str]
  investigate(question, state) -> dict
    answer, citations[{n, raw, findingId}], followups, facts, source="rules"
"""

import json
import re

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
_STOP = {
    "the", "a", "an", "me", "show", "what", "are", "is", "of", "for", "this",
    "run", "please", "tell", "about", "how", "why", "can", "you", "walk",
    "through", "matching", "lines", "evidence", "alert", "alerts", "finding",
    "findings", "top", "recent", "today", "today's", "with", "from", "that",
    "have", "has", "was", "were", "and", "or", "to", "in", "on", "at", "it",
    "summarize", "summary", "explain", "look", "into", "any", "all",
}
_ATTACK_WORDS = (
    "attack", "threat", "apt", "malware", "ransomware", "compromise",
    "intrusion", "c2", "beacon", "exploit",
)
_MAX_CITATIONS = 12
_MAX_SUGGEST = 6
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FAIL_RE = re.compile(
    r"auth failed|failed password|failed login|authentication failure|"
    r"invalid user|login failed|failed for user",
    re.I,
)
_ADMIN_RE = re.compile(r"\b(admin|root|administrator)\b", re.I)


def _sev(f):
    return str(f.get("sev") or f.get("severity") or "").upper()


def _occ(f):
    try:
        n = int(f.get("occurrences") or 1)
    except (TypeError, ValueError):
        n = 1
    return n if n > 0 else 1


def _findings(state):
    return list(state.get("findings") or []) if state else []


def _events(state):
    return list(state.get("events") or []) if state else []


def _ranked(findings):
    return sorted(findings, key=lambda f: (_SEV_RANK.get(_sev(f), 9), -_occ(f)))


def suggested_questions(state, case=None):
    """Run-aware prompts. Never suggest a band/story the run does not have."""
    if case:
        qs = ["Summarize this case"]
        for observable in case.get("observables") or []:
            if observable.get("type") == "url" and observable.get("value"):
                qs.append(f"Analyze {observable['value']}")
        if case.get("attachments"):
            qs.append("Scan attachments")
            qs.append("Analyze email headers")
            qs.append("Analyze email body")
        links = case.get("links") or {}
        if links.get("cases") or links.get("findings") or links.get("incidents"):
            cid = case.get("id") or ""
            qs.append(f"Find cases related to {cid}" if cid else "Find related cases")
        # Preserve order while making a stable, object-scoped chip list.
        return list(dict.fromkeys(qs))
    if not state or state.get("idle"):
        return ["Analyze a log first, then I can walk the evidence with you."]
    if state.get("unrecognized") or state.get("emptyInput"):
        return ["Why is this run unrecognized — is it an all-clear?"]

    findings = _findings(state)
    if not findings:
        parsed = state.get("linesParsed") or 0
        if parsed:
            return [
                "0 findings with lines parsed — which rules ran, and what would have fired?",
                "Show me a sample of INFO lines the dashboard collapsed.",
            ]
        return ["Nothing was parsed. What does that mean for this file?"]

    qs = ["Explain the current dashboard and recommend the next best actions"]
    top = _ranked(findings)[0]
    title = (top.get("title") or top.get("type") or "the top finding").strip()
    if _occ(top) > 1:
        short = title.split(" ×")[0] if " ×" in title else title
        qs.append(f"Walk me through {short} with the matching source lines")
        qs.append(f"Show matching lines for {top.get('type') or short}")
    else:
        qs.append(f"Walk the evidence for {title}")

    crit = [f for f in findings if _sev(f) == "CRITICAL"]
    high = [f for f in findings if _sev(f) == "HIGH"]
    if not crit and high:
        qs.append("There are 0 critical findings — what's the highest-severity story?")
    elif crit:
        qs.append("Walk the critical finding with cited source lines")

    types = {str(f.get("type") or "") for f in findings}
    if any(t.startswith("windows_cbs") for t in types):
        qs.append("Are these CBS HRESULTs a security incident or servicing noise?")
    if any(t.startswith("auth_bruteforce") for t in types):
        qs.append("Walk the brute-force timeline with evidence line citations")
        qs.append("Show me failed administrator logins in this run")
        qs.append("Investigate this alert")
    if any(_occ(f) > 1 for f in findings):
        qs.append("What did Overview group, and which matching lines are hidden?")
    qs.insert(0, "Walk this run from every connected module")

    mitre = [f for f in findings if f.get("mitre")]
    if mitre:
        qs.append("What MITRE techniques are involved?")
    elif findings:
        qs.append("Why is ATT&CK empty on this run?")
    if high or crit:
        qs.append(f"Why was this classified as {_sev(top)}?")
    ip = _first_ip(findings, _events(state))
    if ip:
        qs.append(f"Show me hosts communicating with {ip}")

    # Dedupe while preserving order.
    out, seen = [], set()
    for q in qs:
        if q not in seen:
            seen.add(q)
            out.append(q)
        if len(out) >= _MAX_SUGGEST:
            break
    return out


def _needles(question, findings):
    q = (question or "").strip()
    needles = []
    quoted = re.findall(r'"([^"]{2,80})"|\'([^\']{2,80})\'', q)
    for a, b in quoted:
        needles.append((a or b).lower())
    ql = q.lower()
    for f in findings:
        typ = str(f.get("type") or "").lower()
        if typ and typ in ql:
            needles.append(typ)
        title = str(f.get("title") or "")
        for token in re.findall(r"[A-Z][A-Z0-9_]{4,}", title):
            if token.lower() in ql:
                needles.append(token.lower())
        sig = str((f.get("entities") or {}).get("signature") or "")
        if sig and sig.lower() in ql:
            needles.append(sig.lower())
    for tok in re.findall(r"[a-z0-9_]{4,}", ql):
        if tok not in _STOP:
            needles.append(tok)
    # Unique, longest first so "cbs_e_manifest_invalid_item" beats "cbs".
    uniq = []
    for n in sorted(set(needles), key=lambda s: (-len(s), s)):
        uniq.append(n)
    return uniq[:8]


def _search_events(events, needles, limit=_MAX_CITATIONS):
    if not needles:
        return []
    hits = []
    for e in events:
        blob = f"{e.get('raw') or ''} {e.get('msg') or ''}".lower()
        if any(n in blob for n in needles):
            hits.append(e)
            if len(hits) >= limit:
                break
    return hits


def _citations_from_events(events, finding_id=None):
    out = []
    for e in events:
        raw = str(e.get("raw") or e.get("msg") or "")
        out.append({
            "n": e.get("n"),
            "raw": raw[:240],
            "findingId": finding_id or e.get("findingId"),
        })
    return out


def _citations_from_finding(f):
    out = []
    for line in (f.get("lines") or [])[:_MAX_CITATIONS]:
        if not isinstance(line, dict):
            continue
        raw = f"{line.get('a') or ''}{line.get('hit') or ''}{line.get('b') or ''}"
        out.append({
            "n": line.get("n"),
            "raw": raw[:240],
            "findingId": f.get("id"),
        })
    if out:
        return out
    for t in (f.get("timeline") or [])[:_MAX_CITATIONS]:
        if not isinstance(t, dict):
            continue
        out.append({
            "n": t.get("line"),
            "raw": str(t.get("label") or t.get("message") or "")[:240],
            "findingId": f.get("id"),
        })
    return out


def _followups(findings, current=None):
    qs, seen = [], set()
    for f in _ranked(findings):
        if current is not None and f.get("id") == current.get("id"):
            continue
        title = (f.get("title") or f.get("type") or "").split(" ×")[0]
        if not title:
            continue
        q = (f"Show matching lines for {title}" if _occ(f) > 1
             else f"Walk the evidence for {title}")
        if q in seen:
            continue
        seen.add(q)
        qs.append(q)
        if len(qs) >= 3:
            break
    return qs


def _brief(findings, events):
    parts = []
    n_events = len(events)
    matching = sum(_occ(f) for f in findings)
    leftover = matching - len(findings)
    parts.append(
        f"{len(findings)} cards · {matching} matching lines · {n_events} events."
    )
    if leftover > 0:
        parts.append(f"{leftover} lines sit behind those cards, not on the dashboard.")
    for f in _ranked(findings)[:4]:
        parts.append(
            f"- [{_sev(f)}] {f.get('title')} ×{_occ(f)}"
        )
    if len(findings) > 4:
        parts.append(f"- …and {len(findings) - 4} more.")
    return "\n".join(parts)


def _hidden_lines(findings, events):
    """What Overview grouped vs the matching source lines it collapsed."""
    matching = sum(_occ(f) for f in findings)
    leftover = matching - len(findings)
    parts = [
        f"{len(findings)} grouped card(s) cover {matching} matching lines "
        f"({len(events)} parsed events)."
    ]
    cites = []
    top = _ranked(findings)[0] if findings else None
    if leftover > 0 and top:
        parts.append(f"{leftover} of those lines are hidden behind the cards. Cited below.")
        fid = top.get("id")
        mine = [e for e in events if e.get("findingId") == fid]
        ent = top.get("entities") or {}
        sig = str(ent.get("hresult_name") or ent.get("signature") or "")
        if not sig:
            tokens = re.findall(r"[A-Z][A-Z0-9_]{6,}", str(top.get("title") or ""))
            if tokens:
                sig = max(tokens, key=len)
        if sig:
            seen = {e.get("n") for e in mine}
            for e in _search_events(events, [sig.lower()]):
                if e.get("n") not in seen:
                    mine.append(e)
                    seen.add(e.get("n"))
        mine = mine[:_MAX_CITATIONS]
        cites = _citations_from_events(mine, fid) or _citations_from_finding(top)
        parts.append(
            f"Largest card: [{_sev(top)}] {top.get('title')} — "
            f"{_occ(top)} matching line(s), {len(cites)} cited here."
        )
    elif top:
        parts.append("Every finding is a single line — nothing extra is hidden.")
        cites = _citations_from_finding(top)
    else:
        parts.append("No grouped findings on this run.")
    return "\n".join(parts), cites


def _sample_non_finding(events):
    leftover = [e for e in events if not e.get("isFinding")]
    if not leftover:
        return (
            "Every parsed event sits on a finding card — there is no leftover "
            "INFO pool the dashboard collapsed."
        ), []
    sample = leftover[:_MAX_CITATIONS]
    answer = (
        f"{len(leftover)} parsed event(s) are not on a finding card "
        f"(usually source INFO/noise). {len(sample)} cited below, verbatim. "
        "That is not an all-clear on the cards that did fire."
    )
    return answer, _citations_from_events(sample)


_ANGLE_WORDS = (
    "every angle", "every connected", "all modules", "thorough",
    "full picture", "connected module", "walk this run from every",
    "investigate this run", "all angles", "every module",
)


def collect_angles(state, extras=None):
    """One compact view of every module on THIS run. Display facts, not verdicts."""
    extras = extras or {}
    idle = not state or state.get("idle")
    findings = _findings(state) if not idle else []
    events = _events(state) if not idle else []
    matching = sum(_occ(f) for f in findings)
    top = _ranked(findings)[:3]
    incidents = list(extras.get("incidents") or [])
    assets = list(extras.get("assets") or [])
    users = list(extras.get("users") or [])
    ti = extras.get("ti") if isinstance(extras.get("ti"), dict) else {}
    scan = extras.get("runbooks") if isinstance(extras.get("runbooks"), dict) else {}
    forecast = extras.get("forecast") if isinstance(extras.get("forecast"), dict) else {}
    books = list(scan.get("runbooks") or [])
    eligible = [b for b in books if b.get("eligible")]
    indicators = list(ti.get("indicators") or [])
    ioc_hits = []
    tokens = []
    for f in findings:
        for c in f.get("chips") or []:
            t = str(c.get("text") or "")
            if len(t) >= 7:
                tokens.append(t)
        title = str(f.get("title") or "")
        for tok in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", title):
            tokens.append(tok)
    for ind in indicators[:40]:
        blob = f"{ind.get('pattern') or ''} {ind.get('name') or ''}"
        for t in tokens:
            if t and t in blob:
                ioc_hits.append({"token": t, "indicator": ind.get("name") or ind.get("id")})
                break
    techniques = []
    seen = set()
    for f in findings:
        for t in f.get("mitre") or []:
            tid = t.get("id")
            if tid and tid not in seen:
                seen.add(tid)
                techniques.append({"id": tid, "name": t.get("name") or tid,
                                   "tactic": t.get("tactic") or ""})
    at_risk = [a for a in assets if (a.get("maxSeverity") or "").upper() in ("CRITICAL", "HIGH")]
    users_risk = [u for u in users if (u.get("maxSeverity") or "").upper() in ("CRITICAL", "HIGH")]
    phases = list((forecast or {}).get("phases") or [])
    watch = [p.get("name") for p in phases if p.get("watch")]
    return {
        "runId": None if idle else (state or {}).get("runId"),
        "idle": bool(idle),
        "detections": {
            "findings": len(findings),
            "matchingLines": matching,
            "events": len(events),
            "top": [{"id": f.get("id"), "sev": _sev(f), "title": f.get("title"),
                     "type": f.get("type")} for f in top],
        },
        "incidents": {
            "count": len(incidents),
            "top": [{"id": i.get("id"), "severity": i.get("severity"),
                     "entity": i.get("entity"), "title": i.get("title")}
                    for i in incidents[:4]],
        },
        "assets": {
            "count": len(assets),
            "atRiskHigh": len(at_risk),
            "names": [a.get("name") for a in assets[:6] if a.get("name")],
        },
        "users": {
            "count": len(users),
            "atRiskHigh": len(users_risk),
            "names": [u.get("name") for u in users[:6] if u.get("name")],
        },
        "mitre": {
            "techniques": techniques[:8],
            "watch": watch,
            "note": (forecast or {}).get("note"),
        },
        "intel": {
            "indicators": len(indicators),
            "source": ti.get("indicatorSource") or "n/a",
            "hits": ioc_hits[:6],
        },
        "runbooks": {
            "eligible": [{"id": b.get("id"), "name": b.get("name")} for b in eligible],
            "notEligible": max(0, len(books) - len(eligible)),
        },
        "sigma": {
            "hits": len(extras.get("sigmaHits") or (state or {}).get("sigmaHits") or []),
        },
        "triage": extras.get("triage") if isinstance(extras.get("triage"), dict) else {
            "advisory": True, "disagreements": 0, "count": 0,
        },
        "cases": {
            "count": len(extras.get("cases") or []),
        },
        "links": [
            {"label": "Findings", "href": "/alerts", "count": len(findings)},
            {"label": "Incidents", "href": "/incidents", "count": len(incidents)},
            {"label": "Assets", "href": "/assets", "count": len(assets)},
            {"label": "Intel", "href": "/intel", "count": len(indicators)},
            {"label": "Cases", "href": "/cases", "count": len(extras.get("cases") or [])},
        ],
    }


def render_angles(angles):
    """Plain-language brief across modules. Advisory only."""
    if not angles or angles.get("idle"):
        return "No run loaded. Analyze a log first — I only read modules for the current run."
    d = angles.get("detections") or {}
    inc = angles.get("incidents") or {}
    ast = angles.get("assets") or {}
    usr = angles.get("users") or {}
    mit = angles.get("mitre") or {}
    intel = angles.get("intel") or {}
    rb = angles.get("runbooks") or {}
    sig = angles.get("sigma") or {}
    tri = angles.get("triage") or {}
    cases = angles.get("cases") or {}
    lines = [
        f"This run ({angles.get('runId')}) from every connected module. "
        "Advisory — rules still own severity; I am not opening a case.",
        f"Detections: {d.get('findings', 0)} card(s), "
        f"{d.get('matchingLines', 0)} matching line(s), "
        f"{d.get('events', 0)} parsed event(s).",
    ]
    for t in d.get("top") or []:
        lines.append(f"- [{t.get('sev')}] {t.get('title')}")
    lines.append(
        f"Incidents: {inc.get('count', 0)} derived cluster(s) "
        "(same findings, grouped — not a new verdict)."
    )
    for i in inc.get("top") or []:
        lines.append(f"- {i.get('severity')} {i.get('entity') or i.get('id')}: {i.get('title') or ''}")
    names = ", ".join(ast.get("names") or []) or "n/a"
    lines.append(
        f"Assets: {ast.get('count', 0)} observed, "
        f"{ast.get('atRiskHigh', 0)} at HIGH/CRITICAL. Names: {names}."
    )
    unames = ", ".join(usr.get("names") or []) or "n/a"
    lines.append(
        f"Users: {usr.get('count', 0)} extracted from the log, "
        f"{usr.get('atRiskHigh', 0)} at HIGH/CRITICAL. Names: {unames}."
    )
    techs = mit.get("techniques") or []
    if techs:
        lines.append("MITRE: " + ", ".join(f"{t.get('id')} {t.get('name')}" for t in techs) + ".")
        if mit.get("watch"):
            lines.append(
                "Watch (not in this log): " + ", ".join(mit["watch"]) +
                " — a continuation picture, not a detection."
            )
    else:
        lines.append("MITRE: empty on this run — I will not invent an attack chain.")
    hits = intel.get("hits") or []
    lines.append(
        f"Intel: {intel.get('indicators', 0)} offline indicator(s); "
        f"{len(hits)} token hit(s) in this run."
        + ("" if not hits else " " + ", ".join(
            f"{h.get('token')}→{h.get('indicator')}" for h in hits[:4]))
    )
    elig = rb.get("eligible") or []
    if elig:
        lines.append("Runbooks eligible: " + ", ".join(
            b.get("name") or b.get("id") for b in elig) +
            " — not executed from chat.")
    else:
        lines.append(
            f"Runbooks: 0 eligible, {rb.get('notEligible', 0)} shipped book(s) did not match."
        )
    lines.append(
        f"Sigma: {sig.get('hits', 0)} gap-fill hit(s) on events the detector did not already flag."
    )
    disagrees = (tri.get("disagreements") if isinstance(tri, dict) else 0) or 0
    lines.append(
        f"AI triage: {disagrees} finding(s) where the advisory severity differs from the "
        "rule verdict — AI recommends, analyst decides, not a new verdict."
    )
    lines.append(
        f"Cases: {cases.get('count', 0)} analyst-owned (NEW→CLOSED). Chat does not open one."
    )
    lines.append("Open the same run in Findings, Incidents, Assets, or Intel — same data.")
    return "\n".join(lines)


def _blob(obj):
    if not isinstance(obj, dict):
        return str(obj or "")
    return " ".join([
        str(obj.get("raw") or ""),
        str(obj.get("msg") or ""),
        str(obj.get("title") or ""),
        str(obj.get("host") or ""),
    ])


def _users_in(text):
    out = []
    for m in re.finditer(
            r"(?:user '|for '|user=|invalid user )([^'\s,]+)", text or "", re.I):
        u = m.group(1).strip("'\"")
        if u and u.lower() not in ("from", "for"):
            out.append(u)
    return out


def _first_ip(findings, events):
    for f in findings:
        for c in f.get("chips") or []:
            m = _IPV4.search(str(c.get("text") or ""))
            if m:
                return m.group(0)
        m = _IPV4.search(str(f.get("title") or "") + " " + str(f.get("host") or ""))
        if m:
            return m.group(0)
        for line in f.get("lines") or []:
            m = _IPV4.search(f"{line.get('a') or ''}{line.get('hit') or ''}{line.get('b') or ''}")
            if m:
                return m.group(0)
    for e in events:
        m = _IPV4.search(_blob(e))
        if m:
            return m.group(0)
    return None


def _failed_login_hits(events, want_admin=False):
    hits = []
    for e in events:
        blob = _blob(e)
        if not _FAIL_RE.search(blob):
            continue
        if want_admin and not _ADMIN_RE.search(blob):
            continue
        hits.append(e)
        if len(hits) >= _MAX_CITATIONS:
            break
    return hits


def _mitre_answer(findings, extras=None):
    techs, seen = [], set()
    for f in findings:
        for t in f.get("mitre") or []:
            tid = t.get("id")
            if tid and tid not in seen:
                seen.add(tid)
                techs.append(t)
    if not techs:
        return (
            "No MITRE ATT&CK techniques are mapped on this run. "
            "That is honest empty — not a missed attack chain."
        ), []
    parts = ["MITRE techniques on this run (rule-mapped, not invented):"]
    for t in techs:
        parts.append(
            f"- {t.get('id')} {t.get('name') or ''} "
            f"({t.get('tactic') or 'n/a'})"
        )
    fc = (extras or {}).get("forecast") or {}
    watch = [p.get("name") for p in (fc.get("phases") or []) if p.get("watch")]
    if watch:
        parts.append(
            "Not in this log (watch, not a detection): " + ", ".join(watch) + "."
        )
    cites = _citations_from_finding(_ranked(findings)[0]) if findings else []
    return "\n".join(parts), cites


def _why_classified(f):
    """Rules own severity. Explain the existing verdict; never change it."""
    sev = _sev(f)
    why = f.get("ruleWhy") or f.get("rationale") or ""
    occ = _occ(f)
    parts = [
        f"[{sev}] {f.get('title')} — severity is rule-owned "
        f"(rule `{f.get('type')}`), not an AI rating."
    ]
    if occ > 1:
        parts.append(f"{occ} matching source lines were grouped into this one card.")
    if why:
        parts.append(f"Rule rationale: {why}")
    else:
        parts.append(
            "The detector/rules assigned this band from the matched pattern. "
            "I cannot raise or lower it."
        )
    return "\n".join(parts), _citations_from_finding(f)


def _hosts_for_ip(ip, events, findings):
    hosts, cites_src = [], []
    seen_h = set()
    for e in events:
        blob = _blob(e)
        if ip not in blob:
            continue
        h = e.get("host") or ""
        if h and h not in seen_h:
            seen_h.add(h)
            hosts.append(h)
        cites_src.append(e)
        if len(cites_src) >= _MAX_CITATIONS:
            break
    if not cites_src:
        for f in findings:
            blob = _blob(f) + " ".join(
                str(c.get("text") or "") for c in (f.get("chips") or []))
            if ip in blob:
                h = f.get("host") or ""
                if h and h not in seen_h:
                    seen_h.add(h)
                    hosts.append(h)
                cites_src.extend(
                    {"n": ln.get("n"), "raw": f"{ln.get('a') or ''}{ln.get('hit') or ''}{ln.get('b') or ''}",
                     "findingId": f.get("id")}
                    for ln in (f.get("lines") or [])[:4]
                )
    names = ", ".join(hosts) if hosts else "n/a (no hostname on those lines)"
    answer = (
        f"Hosts communicating with {ip} in this run: {names}. "
        f"{len(cites_src)} matching source line(s) cited. "
        "Same-run telemetry only — I am not scanning a live network."
    )
    return answer, _citations_from_events(cites_src[:_MAX_CITATIONS])


def _alert_report(f, events, extras=None):
    """Ajay's AI investigation pass — report only, no SOAR execution."""
    extras = extras or {}
    raw_bits = [_blob(f)]
    for ln in f.get("lines") or []:
        raw_bits.append(f"{ln.get('a') or ''}{ln.get('hit') or ''}{ln.get('b') or ''}")
    blob = " ".join(raw_bits)
    ips = list(dict.fromkeys(_IPV4.findall(blob)))
    users = list(dict.fromkeys(_users_in(blob)))
    host = f.get("host") or f.get("scope") or "n/a"
    fid = f.get("id")
    related = [e for e in events if e.get("findingId") == fid]
    if not related:
        needles = ips or users or ([host] if host not in ("n/a", "", "—") else [])
        related = _search_events(events, [str(n).lower() for n in needles]) if needles else []
    ti_hits = []
    for ind in ((extras.get("ti") or {}).get("indicators") or [])[:40]:
        pat = f"{ind.get('pattern') or ''} {ind.get('name') or ''}"
        for ip in ips:
            if ip and ip in pat:
                ti_hits.append(f"{ip} → {ind.get('name') or ind.get('id')}")
    mitre = f.get("mitre") or []
    parts = [
        f"Investigation report for [{_sev(f)}] {f.get('title')} "
        f"(advisory — I am not opening a case or executing a runbook).",
        f"User: {', '.join(users) if users else 'n/a'}",
        f"Endpoint/host: {host}",
        f"Source IP: {', '.join(ips) if ips else 'n/a'}",
        f"Related events in this run: {len(related)}",
        "MITRE: " + (
            ", ".join(f"{t.get('id')} {t.get('name')}" for t in mitre)
            if mitre else "none mapped"
        ),
        "IOC: " + (", ".join(ti_hits) if ti_hits else "no offline-indicator hit"),
    ]
    tl = f.get("timeline") or []
    if tl:
        parts.append("Timeline:")
        for row in tl[:8]:
            parts.append(f"- {row.get('t') or row.get('ts') or ''} {row.get('label') or row.get('message') or ''}")
    why = f.get("ruleWhy") or f.get("rationale")
    if why:
        parts.append(f"Why the rule fired: {why}")
    incidents = (extras.get("incidents") or [])
    mine = [i for i in incidents if fid in (i.get("findingIds") or [])]
    if mine:
        parts.append(
            "Derived incident: " +
            ", ".join(f"{i.get('id')} ({i.get('severity')} {i.get('entity')})" for i in mine[:3])
            + " — clustering only, not a new verdict."
        )
    cites = _citations_from_finding(f)
    if related:
        extra = _citations_from_events(related, fid)
        seen = {c.get("n") for c in cites}
        for c in extra:
            if c.get("n") not in seen:
                cites.append(c)
                seen.add(c.get("n"))
        cites = cites[:_MAX_CITATIONS]
    return "\n".join(parts), cites


def _case_description(case):
    """Render analyst-entered case-file facts without adding a verdict/story."""
    lines = []
    summary = case.get("summary") or {}
    for key, label in (("what", "What"), ("impact", "Impact"), ("when", "When")):
        if summary.get(key):
            lines.append(f"{label}: {summary[key]}")
    if case.get("notes"):
        lines.append(f"Notes: {case['notes']}")
    for observable in case.get("observables") or []:
        value = observable.get("value")
        if not value:
            continue
        detail = f"Observable ({observable.get('type') or 'unknown'}): {value}"
        if observable.get("verdict"):
            detail += f" — {observable['verdict']}"
        lines.append(detail)
    for attachment in case.get("attachments") or []:
        detail = f"Attachment ({attachment.get('kind') or 'other'}): {attachment.get('name') or 'unnamed'}"
        if attachment.get("size") is not None:
            detail += f" ({attachment['size']} bytes)"
        lines.append(detail)
    for item in case.get("activity") or []:
        text = item.get("text")
        if text:
            lines.append(f"Activity ({item.get('kind') or 'system'}): {text}")
    return "\n".join(lines) or "No analyst notes, observables, attachments, or activity have been recorded for this case."


def _screen_label(context):
    """The route label supplied by the client, never inferred from model text."""
    context = context if isinstance(context, dict) else {}
    screen = str(context.get("screen") or "").strip()
    route = str(context.get("route") or "").strip()
    route_label = {
        "/": "Overview", "/alerts": "Findings", "/incidents": "Incidents",
        "/cases": "Cases", "/reports": "Reports", "/sources": "Sources",
        "/integrations": "Integrations",
    }.get(route)
    return route_label or screen or "current workspace"


def _next_actions(findings, extras, screen):
    """Safe, evidence-first navigation recommendations.

    These are suggestions and deep links, never ticket mutations, severity
    changes, runbook execution, or automatic assignment.
    """
    extras = extras or {}
    actions = []
    top = _ranked(findings)[0] if findings else None
    incidents = list(extras.get("incidents") or [])
    cases = list(extras.get("cases") or [])
    runbooks = list((extras.get("runbooks") or {}).get("runbooks") or [])
    if top:
        actions.append({
            "label": "Review the strongest evidence",
            "detail": f"Open the rule-owned {_sev(top)} finding before deciding on containment.",
            "href": f"/alerts?sel={top.get('id')}",
            "kind": "evidence",
        })
        incident = next((i for i in incidents if top.get("id") in (i.get("findingIds") or [])), None)
        if incident:
            actions.append({
                "label": "Review the correlated incident",
                "detail": f"{incident.get('id')} groups existing findings; it is not a new verdict.",
                "href": f"/incidents?sel={incident.get('id')}",
                "kind": "incident",
            })
    eligible = [r for r in runbooks if r.get("eligible")]
    if eligible:
        actions.append({
            "label": "Review an eligible response runbook",
            "detail": f"{eligible[0].get('name') or eligible[0].get('id')} is eligible; review/approval remains human-controlled.",
            "href": "/incidents",
            "kind": "runbook",
        })
    ownerless = [c for c in cases if not str(c.get("assignee") or "").strip()]
    if ownerless:
        actions.append({
            "label": "Assign a responsible person",
            "detail": f"{len(ownerless)} case(s) have no recorded owner. Confirm accountability on the case file.",
            "href": f"/cases?sel={ownerless[0].get('id')}",
            "kind": "ownership",
        })
    elif cases:
        actions.append({
            "label": "Check ticket ownership",
            "detail": f"{len(cases)} case(s) exist; verify the recorded owner and status before escalating.",
            "href": "/cases",
            "kind": "ownership",
        })
    if screen != "Reports":
        actions.append({
            "label": "Open the evidence report",
            "detail": "Use reporting to preserve the current run's facts and analyst decisions.",
            "href": "/reports",
            "kind": "report",
        })
    return actions[:4]


def _workspace_brief(findings, events, extras, context, facts):
    """Explain a visible workspace using the current run, not canned copy."""
    screen = _screen_label(context)
    angles = collect_angles({"idle": False, "findings": findings, "events": events,
                             "runId": (context or {}).get("runId")}, extras)
    matching = sum(_occ(f) for f in findings)
    top = _ranked(findings)[0] if findings else None
    if screen == "Findings":
        surface = (
            f"Findings is the evidence workspace: {len(findings)} rule-owned card(s) represent "
            f"{matching} matching line(s). Select a row to inspect the rule rationale, timeline, and cited source lines."
        )
    elif screen == "Incidents":
        surface = (
            f"Incidents groups related findings into {len(extras.get('incidents') or [])} correlation cluster(s). "
            "It helps sequence review; it does not replace a finding's rule-owned severity."
        )
    elif screen == "Cases":
        surface = (
            f"Cases is the analyst-owned work queue with {len(extras.get('cases') or [])} stored ticket(s). "
            "Use its responsible-person field and workflow templates to make ownership explicit."
        )
    elif screen == "Reports":
        surface = (
            "Reports turns the current run's evidence, analyst notes, and approved response history into a reviewable record. "
            "It does not create findings or actions."
        )
    elif screen == "Sources":
        surface = (
            "Sources is the ingestion control point. Its live collectors show real transport status; a connected Splunk poll only analyses events returned by that configured source."
        )
    else:
        surface = (
            f"Overview is a current-run briefing: {len(findings)} rule-owned finding card(s), {matching} matching line(s), "
            f"and {len(events)} parsed event(s). The cards summarize evidence rather than inventing a narrative."
        )
    lines = [
        f"What the dashboard says — {screen}",
        surface,
    ]
    if top:
        lines.append(
            f"Priority evidence: [{_sev(top)}] {top.get('title')} on {top.get('host') or 'an unrecorded host'} "
            f"({ _occ(top) } matching line(s), rule `{top.get('type')}`)."
        )
    inc_count = len(extras.get("incidents") or [])
    asset_count = len(extras.get("assets") or [])
    user_count = len(extras.get("users") or [])
    lines.append(
        f"Connected context: {inc_count} incident cluster(s), {asset_count} observed asset(s), and {user_count} observed user(s). "
        "These are linked views over the same run, not independent detections."
    )
    actions = _next_actions(findings, extras, screen)
    lines.append("Next best actions:")
    lines.extend(f"- {item['label']}: {item['detail']}" for item in actions)
    ownerless = [c for c in (extras.get("cases") or []) if not str(c.get("assignee") or "").strip()]
    lines.append(
        "Ticket routing: " + (
            f"{len(ownerless)} case(s) are unassigned; Copilot recommends review but never assigns people automatically."
            if ownerless else
            "review the recorded owner and status on the case board; Copilot never changes ticket responsibility itself."
        )
    )
    lines.append(
        "Reporting: open Reports to capture the current evidence and analyst decisions. Any forecast is a watchlist, not a detection."
    )
    cites = _citations_from_finding(top) if top else []
    return "\n".join(lines), cites, actions, angles


def _workspace_followups(findings, extras):
    """Questions that route back into specific investigation intents."""
    top = _ranked(findings)[0] if findings else None
    out = []
    if top:
        out.append(f"Investigate {top.get('id') or top.get('title')}")
        out.append(f"Why was this alert classified as {_sev(top)} risk?")
    if any(not str(c.get("assignee") or "").strip() for c in (extras.get("cases") or [])):
        out.append("Which tickets need a responsible person?")
    return out[:3]


def investigate(question, state, extras=None, case=None, context=None):
    """Deterministic investigation. Never a new verdict."""
    empty = {
        "answer": "",
        "citations": [],
        "followups": [],
        "facts": {},
        "actions": [],
        "source": "rules",
    }
    q = str(question or "").strip()
    ql = q.lower()
    if case and "quarantine" in ql:
        scan = (extras or {}).get("runbooks") or {}
        eligible = [r for r in scan.get("runbooks") or [] if r.get("eligible")]
        if eligible:
            names = ", ".join(str(r.get("id")) for r in eligible)
            empty["answer"] = (
                f"Quarantine is never executed from Copilot. Eligible shipped runbook(s) on this run: {names}; "
                "add one to the case through the advisory Run endpoint if appropriate."
            )
        else:
            empty["answer"] = "Quarantine is not eligible for this case/run. Copilot did not execute anything."
        empty["source"] = "case"
        empty["followups"] = suggested_questions(state, case=case)
        return empty
    if case and (not q or "summarize this case" in ql or "summary" in ql):
        empty["answer"] = f"Title: {case.get('title') or 'Untitled case'}\nDescription:\n{_case_description(case)}"
        empty["source"] = "case"
        empty["followups"] = suggested_questions(state, case=case)
        empty["facts"] = {
            "observables": len(case.get("observables") or []),
            "attachments": len(case.get("attachments") or []),
            "activity": len(case.get("activity") or []),
        }
        return empty
    if case and (("scan" in ql and "attach" in ql) or "analyze email" in ql or "analyze body" in ql or "analyze headers" in ql):
        import soc as _soc
        attachments = list(case.get("attachments") or [])
        if not attachments:
            empty["answer"] = "No attachments are recorded on this case file."
        else:
            want_headers = "header" in ql
            want_body = "body" in ql or "html" in ql
            lines = ["Attachments on the case file (stored bytes, not a malware verdict):"]
            for item in attachments:
                extra = f" {item['size']} bytes" if item.get("size") is not None else ""
                digest = (item.get("sha256") or "")[:12]
                stored = "stored" if item.get("stored") else "bytes missing"
                sha = f" sha256={digest}…" if digest else ""
                lines.append(f"- {item.get('name') or 'unnamed'} [{item.get('kind') or 'other'}]{extra}{sha} ({stored})")
                inspected = _soc.inspect_attachment(case.get("id"), item.get("id"))
                if not inspected:
                    continue
                if (want_headers or "scan" in ql) and inspected.get("headers"):
                    lines.append("  Headers:\n" + inspected["headers"][:1500])
                if (want_body or "scan" in ql) and inspected.get("bodyPreview"):
                    lines.append("  Body preview: " + inspected["bodyPreview"][:800])
            lines.append(inspected.get("note") if inspected else "Read from stored bytes when present.")
            empty["answer"] = "\n".join(lines)
        empty["source"] = "case"
        empty["followups"] = suggested_questions(state, case=case)
        return empty
    if case and ("analyze" in ql):
        observables = list(case.get("observables") or [])
        hit = None
        for item in observables:
            value = str(item.get("value") or "")
            if value and value.lower() in ql:
                hit = item
                break
        if hit is None and observables:
            hit = observables[0]
        if not hit:
            empty["answer"] = "No observables are on this case file to analyze."
        else:
            verdict = hit.get("verdict")
            empty["answer"] = (
                f"Observable on the case file: {hit.get('type')} {hit.get('value')}."
                + (f" Recorded note: {verdict}." if verdict else
                   " No enrichment is recorded on this object — Copilot did not look it up remotely.")
            )
        empty["source"] = "case"
        empty["followups"] = suggested_questions(state, case=case)
        return empty
    if case and ("related" in ql):
        links = case.get("links") or {}
        cases = list(links.get("cases") or [])
        findings = list(links.get("findings") or [])
        incidents = list(links.get("incidents") or [])
        parts = []
        if cases:
            parts.append("Linked cases: " + ", ".join(cases) + ".")
        else:
            parts.append("No other cases are linked.")
        if findings:
            parts.append("Linked findings: " + ", ".join(findings) + ".")
        if incidents:
            parts.append("Linked incidents: " + ", ".join(incidents) + ".")
        empty["answer"] = " ".join(parts)
        empty["source"] = "case"
        empty["followups"] = suggested_questions(state, case=case)
        return empty
    if case:
        empty["answer"] = (
            "I can only talk about objects on this case file (title, notes, "
            "observables, attachments, activity, links). Ask to summarize, "
            "analyze an observable, scan attachments, or find related cases."
        )
        empty["source"] = "case"
        empty["followups"] = suggested_questions(state, case=case)
        return empty
    if not state or state.get("idle"):
        empty["answer"] = (
            "No run is loaded. Analyze a log first — I only investigate "
            "findings and source lines that exist for the current run."
        )
        return empty
    if state.get("unrecognized") or state.get("emptyInput"):
        empty["answer"] = (
            "This run was not recognized / nothing was parsed. That is NOT "
            "an all-clear. I have no source lines to dig."
        )
        return empty

    findings = _findings(state)
    events = _events(state)
    angles = collect_angles(state, extras)
    facts = {
        "findings": len(findings),
        "events": len(events),
        "matchingLines": sum(_occ(f) for f in findings),
        "modules": {
            "incidents": (angles.get("incidents") or {}).get("count"),
            "assets": (angles.get("assets") or {}).get("count"),
            "users": (angles.get("users") or {}).get("count"),
            "intelHits": len((angles.get("intel") or {}).get("hits") or []),
        },
    }

    # CB-1: the learned second opinion is a GROUNDED CONTEXT SOURCE, answered
    # deterministically from the STORED advisory block. Routed ahead of the
    # workspace/angle branches so a model question is never absorbed by a
    # generic one, and answered here rather than by the LLM so no number is
    # ever paraphrased on the way out.
    learned = learned_question(ql, context)
    if learned:
        kind, incident_id = learned
        return learned_answer(kind, incident_id, extras or {},
                              run_id=state.get("runId"))

    wants_workspace = (
        ("explain" in ql and any(w in ql for w in ("screen", "page", "dashboard", "card", "workspace")))
        or any(w in ql for w in ("what should i do next", "next best", "next step", "best suggestion"))
    )
    if wants_workspace:
        answer, cites, actions, workspace = _workspace_brief(findings, events, extras or {}, context or {}, facts)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _workspace_followups(findings, extras or {}),
            "facts": {**facts, "workspace": workspace},
            "actions": actions,
            "source": "rules",
        }

    wants_ownership = any(w in ql for w in ("ticket", "case", "assignee", "responsible person", "responsible analyst")) \
        and any(w in ql for w in ("assign", "owner", "responsible", "need", "unassigned", "route"))
    if wants_ownership:
        cases = list((extras or {}).get("cases") or [])
        ownerless = [c for c in cases if not str(c.get("assignee") or "").strip()]
        actions = _next_actions(findings, extras or {}, _screen_label(context))
        if ownerless:
            names = ", ".join(str(c.get("id") or c.get("title") or "untitled case") for c in ownerless[:6])
            answer = (
                f"Ticket routing: {len(ownerless)} of {len(cases)} case(s) have no responsible person recorded. "
                f"Review these first: {names}. Copilot can recommend the evidence and workflow, but a human must choose and save the owner."
            )
        elif cases:
            answer = (
                f"Ticket routing: all {len(cases)} stored case(s) have a recorded responsible person. "
                "Review status and evidence before changing ownership; Copilot did not modify any ticket."
            )
        else:
            answer = "Ticket routing: no analyst-created cases exist for this run. Copilot did not create or assign a ticket."
        return {
            "answer": answer,
            "citations": _citations_from_finding(_ranked(findings)[0]) if findings else [],
            "followups": _workspace_followups(findings, extras or {}),
            "facts": facts,
            "actions": actions,
            "source": "rules",
        }

    if not q:
        empty["answer"] = "Ask about a finding, a HRESULT, a host, or a matching line."
        empty["facts"] = facts
        empty["followups"] = suggested_questions(state)
        return empty

    if any(w in ql for w in _ANGLE_WORDS):
        top = _ranked(findings)[0] if findings else None
        return {
            "answer": render_angles(angles),
            "citations": _citations_from_finding(top) if top else [],
            "followups": _followups(findings, top),
            "facts": facts,
            "angles": angles,
            "source": "rules",
        }

    # Ajay chat examples — same-run telemetry, never a new verdict.
    if ("mitre" in ql or "att&ck" in ql or "attck" in ql
            or ("technique" in ql and "involved" in ql)):
        answer, cites = _mitre_answer(findings, extras)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings),
            "facts": facts,
            "source": "rules",
        }

    if any(w in ql for w in (
        "failed login", "failed administrator", "failed admin",
        "auth failed", "failed password", "administrator login",
    )):
        want_admin = "admin" in ql or "root" in ql
        hits = _failed_login_hits(events, want_admin=want_admin)
        if not hits:
            hits = _failed_login_hits(events, want_admin=False)
            note = (
                "No administrator-principal failures in this file. "
                if want_admin else ""
            )
        else:
            note = ""
        if "24" in ql or "hour" in ql:
            note += (
                "This file is the time window I have — I am not querying a 24h data lake. "
            )
        if not hits:
            answer = (
                note +
                "No failed-login lines in this run's parsed events. "
                "That is not an all-clear on other findings."
            )
            cites = []
        else:
            answer = (
                note +
                f"{len(hits)} failed-login line(s) in this run"
                + (" (admin/root principals)." if want_admin else ".")
                + " Cited verbatim below."
            )
            cites = _citations_from_events(hits)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings),
            "facts": facts,
            "source": "rules",
        }

    ip_q = _IPV4.search(q)
    if ip_q and any(w in ql for w in ("host", "communicat", "talk", "connect")):
        answer, cites = _hosts_for_ip(ip_q.group(0), events, findings)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings),
            "facts": facts,
            "source": "rules",
        }

    if (("classif" in ql or "why was this" in ql or "why is this" in ql)
            and any(w in ql for w in ("high", "critical", "risk", "severity"))):
        top = _ranked(findings)[0] if findings else None
        if not top:
            answer, cites = "No findings to explain.", []
        else:
            answer, cites = _why_classified(top)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings, top),
            "facts": facts,
            "source": "rules",
        }

    if ql.startswith("investigate") or "investigate this alert" in ql \
            or "investigate this case" in ql:
        target = None
        for f in findings:
            if str(f.get("id") or "") and str(f.get("id")) in q:
                target = f
                break
        if target is None:
            target = _ranked(findings)[0] if findings else None
        if not target:
            return {
                "answer": "No finding on this run to investigate.",
                "citations": [],
                "followups": suggested_questions(state),
                "facts": facts,
                "source": "rules",
            }
        answer, cites = _alert_report(target, events, extras)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings, target),
            "facts": facts,
            "source": "rules",
        }

    # --- honest empty bands / not-an-attack -------------------------------
    crit = [f for f in findings if _sev(f) == "CRITICAL"]
    if any(w in ql for w in ("critical", "crit")) and not crit:
        top = _ranked(findings)[0] if findings else None
        answer = (
            f"0 CRITICAL findings on this run. The rules did not assign critical."
        )
        if top:
            answer += (
                f" Highest severity is {_sev(top)}: {top.get('title')} "
                f"(×{_occ(top)} matching lines, rule {top.get('type')})."
            )
        cbs = any(str(f.get("type") or "").startswith("windows_cbs") for f in findings)
        if cbs:
            answer += (
                " CBS Fail/HRESULT is source-reported Info on the line; "
                "rules grouped it operationally — that is not a missed CRITICAL."
            )
        return {
            "answer": answer,
            "citations": _citations_from_finding(top) if top else [],
            "followups": _followups(findings, top),
            "facts": facts,
            "source": "rules",
        }

    types = {str(f.get("type") or "") for f in findings}
    wants_attack = any(w in ql for w in _ATTACK_WORDS)
    cbs_run = any(t.startswith("windows_cbs") for t in types)
    mitre_n = sum(1 for f in findings if f.get("mitre"))
    if wants_attack and cbs_run and mitre_n == 0:
        top = next((f for f in _ranked(findings)
                    if str(f.get("type") or "").startswith("windows_cbs")), None)
        answer = (
            "These are Windows CBS/CSI servicing HRESULTs, not an ATT&CK-mapped "
            "intrusion. Source level on the lines is Info; the rules grouped "
            f"Fail/HRESULT into {sum(1 for t in types if t.startswith('windows_cbs'))} "
            "operational finding(s). No mapped tactic, so Overview ATT&CK is empty "
            "on purpose — not a missed attack pattern."
        )
        return {
            "answer": answer,
            "citations": _citations_from_finding(top) if top else [],
            "followups": _followups(findings, top),
            "facts": facts,
            "source": "rules",
        }

    wants_hidden = any(w in ql for w in (
        "hidden", "collapsed", "what did overview", "overview group",
        "grouped card", "which matching lines are hidden",
    ))
    wants_info_pool = any(w in ql for w in (
        "info line", "sample of info", "leftover", "not a finding",
        "dashboard collapsed",
    ))
    if wants_hidden:
        answer, cites = _hidden_lines(findings, events)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings),
            "facts": facts,
            "source": "rules",
        }
    if wants_info_pool:
        answer, cites = _sample_non_finding(events)
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings),
            "facts": facts,
            "source": "rules",
        }

    if any(w in ql for w in ("summar", "what happened", "brief", "overview",
                             "posture", "big picture", "dashboard")):
        answer = _brief(findings, events)
        cites = []
        if findings:
            matching = facts.get("matchingLines") or 0
            if matching > len(findings):
                answer_h, cites = _hidden_lines(findings, events)
                answer = answer + "\n" + answer_h
            else:
                cites = _citations_from_finding(_ranked(findings)[0])
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings),
            "facts": facts,
            "source": "rules",
        }

    needles = _needles(q, findings)
    matched_finding = None
    for f in _ranked(findings):
        blob = " ".join([
            str(f.get("type") or ""),
            str(f.get("title") or ""),
            str((f.get("entities") or {}).get("hresult_name") or ""),
            str((f.get("entities") or {}).get("signature") or ""),
        ]).lower()
        if needles and any(n in blob for n in needles):
            matched_finding = f
            break

    hits = _search_events(events, needles) if needles else []
    facts["needles"] = needles
    facts["eventHits"] = len(hits)

    if matched_finding:
        cites = _citations_from_finding(matched_finding)
        fid = matched_finding.get("id")
        if hits:
            # Prefer lines tagged on this finding, then other needle hits
            # (matching lines Overview never put on the card).
            tagged = [e for e in hits if e.get("findingId") == fid]
            rest = [e for e in hits if e.get("findingId") != fid]
            extra = _citations_from_events((tagged + rest)[:_MAX_CITATIONS], fid)
            seen = {c.get("n") for c in cites}
            for c in extra:
                if c.get("n") not in seen:
                    cites.append(c)
                    seen.add(c.get("n"))
            cites = cites[:_MAX_CITATIONS]
        elif not cites:
            cites = _citations_from_events(hits, fid)
        occ = _occ(matched_finding)
        shown = len(cites)
        answer = (
            f"[{_sev(matched_finding)}] {matched_finding.get('title')} — "
            f"{occ} matching line(s) in one Overview card. {shown} cited below."
        )
        if occ > shown:
            answer += f" {occ - shown} more in the log."
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings, matched_finding),
            "facts": facts,
            "source": "rules",
        }

    if hits:
        cites = _citations_from_events(hits)
        answer = (
            f"I searched {len(events)} parsed event(s) (the lines Overview does "
            f"not list as cards) for {needles!r} and found {len(hits)} hit(s). "
            "Cited raw lines below. Severity stays whatever the rules already assigned."
        )
        return {
            "answer": answer,
            "citations": cites,
            "followups": _followups(findings),
            "facts": facts,
            "source": "rules",
        }

    if findings:
        answer = (
            f"I searched {len(events)} event(s) and {len(findings)} finding(s) "
            f"for {needles or ql!r} and found no matching source lines. "
            "That is not an all-clear on other findings — ask about a card on this run."
        )
        return {
            "answer": answer,
            "citations": [],
            "followups": suggested_questions(state),
            "facts": facts,
            "source": "rules",
        }

    empty["answer"] = "No findings and no event hits for that question."
    empty["facts"] = facts
    return empty


def prompt_facts(inv):
    """Compact block to splice into the LLM user prompt — hidden-line evidence."""
    if not inv:
        return ""
    lines = ["Investigation facts (deterministic, from the source log — not Overview cards):"]
    if inv.get("answer"):
        lines.append(inv["answer"])
    for c in inv.get("citations") or []:
        n = c.get("n")
        raw = (c.get("raw") or "").replace("\n", " ")
        cite = f"{{{n}}}" if n not in (None, "") else "{n/a}"
        lines.append(f"  {cite} {raw[:200]}")
    ang = inv.get("angles")
    if ang and not ang.get("idle"):
        lines.append("Connected modules (same run — display facts, not verdicts):")
        lines.append(render_angles(ang))
    lines.append(
        "Use these facts. Do not invent additional alerts or change severity. "
        "Cite {n} when you quote a line."
    )
    return "\n".join(lines)


# Kill-chain phases — same grouping as tactic_phase_map.py. Display only;
# never a new verdict. Later unobserved phases are a watch list, not detections.
_PHASES = (
    "Planning / Probing",
    "Breaking In",
    "Spreading Inside",
    "Damaging / Stealing",
)
_TACTIC_PHASE = {
    "Reconnaissance": "Planning / Probing",
    "Resource Development": "Planning / Probing",
    "Initial Access": "Breaking In",
    "Execution": "Breaking In",
    "Persistence": "Spreading Inside",
    "Privilege Escalation": "Spreading Inside",
    "Defense Evasion": "Spreading Inside",
    "Credential Access": "Spreading Inside",
    "Discovery": "Spreading Inside",
    "Lateral Movement": "Spreading Inside",
    "Collection": "Spreading Inside",
    "Command and Control": "Damaging / Stealing",
    "Exfiltration": "Damaging / Stealing",
    "Impact": "Damaging / Stealing",
}


def forecast_view(state, history=None):
    """This-run kill chain + saved-run volume. Never invents an attack."""
    idle = not state or state.get("idle")
    findings = _findings(state) if not idle else []
    techniques, seen = [], set()
    for f in findings:
        for t in f.get("mitre") or []:
            tid = t.get("id")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            techniques.append({
                "id": tid,
                "name": t.get("name") or tid,
                "tactic": t.get("tactic") or "",
            })
    observed = set()
    for t in techniques:
        ph = _TACTIC_PHASE.get(t["tactic"])
        if ph:
            observed.add(ph)
    deepest = None
    for p in _PHASES:
        if p in observed:
            deepest = p
    phases = []
    for p in _PHASES:
        later = deepest is not None and _PHASES.index(p) > _PHASES.index(deepest)
        phases.append({
            "name": p,
            "observed": p in observed,
            "watch": later and p not in observed,
            "tactics": sorted({t["tactic"] for t in techniques
                               if _TACTIC_PHASE.get(t["tactic"]) == p}),
        })
    hist = []
    for r in (history or [])[:12]:
        if not isinstance(r, dict) or r.get("unreadable"):
            continue
        try:
            n = int(r.get("findingCount") if r.get("findingCount") is not None
                    else r.get("findings") or 0)
        except (TypeError, ValueError):
            n = 0
        hist.append({
            "runId": r.get("runId") or r.get("label") or r.get("file") or "run",
            "findingCount": n,
        })
    hist.reverse()  # oldest first for a left-to-right sparkline
    matching = sum(_occ(f) for f in findings)
    top = _ranked(findings)[0] if findings else None
    if idle:
        note = "No run loaded — nothing to forecast."
    elif not findings:
        note = "No findings on this run. I will not invent a next attack."
    elif not observed:
        note = (
            "No ATT&CK mapping on this run. I will not draw a next-attack "
            "picture — volume below is operational, not an intrusion forecast."
        )
    else:
        watch = [p["name"] for p in phases if p["watch"]]
        note = (
            f"Observed up to {deepest}. "
            + (
                "Later phases were not in this log — shown as watch, not detections."
                if watch else
                "Deepest kill-chain phase in this log is the last one; nothing later to watch."
            )
        )
    return {
        "thisRun": {
            "runId": (state or {}).get("runId"),
            "findings": len(findings),
            "matchingLines": matching,
            "topTitle": (top.get("title") if top else None),
            "topSev": (_sev(top) if top else None),
        },
        "techniques": techniques,
        "phases": phases,
        "history": hist,
        "note": note,
        "source": "rules",
    }


def draft_playbook(state, scan=None):
    """Advisory playbook for THIS run. Not executable; not a new verdict."""
    run_id = str((state or {}).get("runId") or "run")
    empty = {
        "advisory": True,
        "executable": False,
        "source": "rules",
        "title": f"Playbook · {run_id}",
        "filename": f"playbook-{run_id}.md",
        "markdown": "",
        "note": "",
    }
    if not state or state.get("idle"):
        empty["markdown"] = "# Playbook\n\nNo run loaded. Analyze a log first.\n"
        empty["note"] = "No run loaded."
        return empty
    if state.get("unrecognized") or state.get("emptyInput"):
        empty["markdown"] = (
            f"# Playbook · {run_id}\n\n"
            "This run was not recognized / nothing was parsed. "
            "That is NOT an all-clear. No playbook steps to generate.\n"
        )
        empty["note"] = "Unrecognized run — no playbook steps."
        return empty

    fc = forecast_view(state)
    findings = _findings(state)
    top = _ranked(findings)[0] if findings else None
    lines = [
        f"# Playbook · {run_id}",
        "",
        "> ADVISORY DRAFT. Rules own severity. This document does not execute "
        "anything and does not change a verdict.",
        "",
        "## What this file showed",
        fc["note"],
        f"- {fc['thisRun']['findings']} finding(s), "
        f"{fc['thisRun']['matchingLines']} matching line(s).",
    ]
    if top:
        lines.append(
            f"- Highest: [{_sev(top)}] {top.get('title')} "
            f"(rule `{top.get('type')}`)."
        )
    if fc["techniques"]:
        lines.append("- Mapped techniques: " + ", ".join(
            f"{t['id']} {t['name']}" for t in fc["techniques"][:8]))
    else:
        lines.append("- No ATT&CK mapping — do not treat this as an intrusion playbook.")
    lines += ["", "## What to do next (human)"]
    lines.append("1. Open the highest finding and read the cited source lines.")
    if top and _occ(top) > 1:
        lines.append(
            f"2. The top card collapses {_occ(top)} matching lines — "
            "confirm they share one signature, not mixed events."
        )
        n = 3
    else:
        n = 2
    watch = [p["name"] for p in fc["phases"] if p.get("watch")]
    if watch:
        lines.append(
            f"{n}. This log did **not** show: {', '.join(watch)}. "
            "If an attack continued it would typically look like activity in "
            "those phases. That is a watch list, not a detection in this file."
        )
        n += 1
    else:
        lines.append(
            f"{n}. No later kill-chain phase to watch from this file's mappings."
        )
        n += 1
    lines += ["", "## Shipped runbooks (eligibility only)"]
    books = (scan or {}).get("runbooks") or []
    if not books:
        lines.append("No shipped runbook definitions on this scan.")
    for rb in books:
        flag = "ELIGIBLE" if rb.get("eligible") else "not eligible"
        miss = (rb.get("missing") or ["n/a"])[0]
        lines.append(f"- **{rb.get('name') or rb.get('id')}** — {flag}.")
        if not rb.get("eligible"):
            lines.append(f"  - Why: {miss}")
        else:
            lines.append(
                "  - If you approve, use the shipped book on Approvals. "
                "This draft does not fire it."
            )
    lines += [
        "",
        "## Inert YAML (not loaded, not executable)",
        "",
        "```yaml",
        f"id: draft-{run_id}",
        f"name: Generated playbook for {run_id}",
        "origin: generated",
        "advisory: true",
        "executable: false",
        "note: Copy is inert. Promoting it to console/runbooks/ is a human action.",
        "```",
        "",
    ]
    empty["markdown"] = "\n".join(lines) + "\n"
    empty["note"] = "Advisory draft — not executed."
    return empty


# ---------------------------------------------------------------------------
# CB-1 — the learned second opinion as a GROUNDED CONTEXT SOURCE
# ---------------------------------------------------------------------------
# The learned triage model (E7a/E7b, benchmarked in E8) is ADVISORY FOREVER.
# This section lets the copilot TALK about it. It does not let the model do
# anything: nothing below writes `sev`, `ruleSev`, incident severity, priority,
# runbook eligibility or any execution state, and nothing below is reachable
# from a predicate that does.
#
# THE FIELD RULE, as enforced here rather than merely asserted.
# The only model-emitted structure this section reads is the `aiTriage` block
# that console/soc.py:_public_incident() attaches to an incident projection.
# `aiTriage` is in console/runbooks.py ADVISORY_KEYS *and* matches
# _ADVISORY_WORD_RE's `ai<Something>` class clause (card CB-0), so the
# rule-owned projection drops the whole subtree before any eligibility
# predicate can see it. `_assert_fenced()` below re-derives that from
# runbooks' own guard at read time, so a future refactor that un-fences the
# container breaks this read loudly instead of quietly widening the surface.
#
# NEVER RECOMPUTE. Severity, label, confidence and agreement are all read
# STRAIGHT OUT of the stored advisory block. Agreement in particular is never
# re-derived by comparing severities here: a display-time derivation is a
# second computation of a stored fact, and two computations drift.
#
# UNTRUSTED INPUT. Model output is log-adjacent data (guardrail 5). Every
# model-emitted string is rendered through `quote_model_value()` as a quoted,
# single-line, length-bounded DATA value — never as an instruction.

LEARNED_SOURCE = "learned"
LEARNED_LABEL = "ADVISORY · learned second opinion · not a verdict"

# The advisory container this section is allowed to read, and the leaf keys it
# reads out of it. The container is what the guard fences; the leaves travel
# inside it and cannot escape it.
LEARNED_CONTAINER = "aiTriage"
LEARNED_LEAVES = ("aiSeverity", "aiLabel", "confidence", "agrees", "status",
                  "ruleSeverity", "modelAvailable", "unavailableReason")

# Incident ids are `inc-<hash>`; the canonical demo aliases are `INC-4a7f`
# style. Matched case-insensitively and resolved case-insensitively, so a
# question typed in either case reaches the same real incident.
_INCIDENT_ID_RE = re.compile(r"\binc-[A-Za-z0-9_-]{2,}\b", re.I)

# Instruction-shaped content in a model-emitted value. Matching does NOT drop
# the value — it is still shown verbatim, because silently swallowing what the
# model emitted would be its own dishonesty. It marks the value as refused as
# an instruction, so the surface says out loud that it was read as data.
_INSTRUCTION_RE = re.compile(
    r"ignore\s+(?:all\s+|any\s+|the\s+)?previous|"
    r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)|"
    r"new\s+instructions?\b|system\s+prompt|"
    r"\byou\s+(?:must|should\s+now|will\s+now)\b|"
    r"\bapprove\b|\bexecute\b|\bquarantine\b|\boverride\b|"
    r"\bescalate\b|\bsuppress\b|\bset\s+sev\b|\bmark\s+as\b",
    re.I)

_MODEL_VALUE_LIMIT = 240


def _assert_fenced(field):
    """Refuse to read a field the advisory guard does not fence.

    Imported lazily: console/runbooks.py owns the fence, and nothing on the
    verdict path may pull the copilot in through an import cycle.
    """
    import runbooks
    if field in runbooks.ADVISORY_KEYS:
        return field
    if runbooks._ADVISORY_WORD_RE.search(field):
        return field
    raise ValueError(
        f"CB-1 refuses to read {field!r}: the advisory guard in "
        "console/runbooks.py does not fence it. Report the field; do not "
        "widen the guard to make the read legal.")


def quote_model_value(value, limit=_MODEL_VALUE_LIMIT):
    """Render one model-emitted value as DATA. Returns (quoted, neutralised).

    Flattened to a single line (so it cannot forge a new paragraph or a fake
    system turn), length-bounded, and wrapped in quotes. `neutralised` is True
    when the value reads as an instruction — it is still quoted verbatim, and
    the caller says plainly that it was refused as an instruction.
    """
    if value is None:
        return "not recorded", False
    text = str(value)
    text = "".join(" " if ch < " " or ch == "\x7f" else ch for ch in text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    neutralised = bool(_INSTRUCTION_RE.search(text))
    return '"' + text.replace('"', '\\"') + '"', neutralised


def advisory_block(incident):
    """The stored advisory block for one incident, or None. Reads, never derives."""
    _assert_fenced(LEARNED_CONTAINER)
    block = (incident or {}).get(LEARNED_CONTAINER)
    return block if isinstance(block, dict) else None


def _incidents_with_opinion(extras, run_id=None):
    """Current-run incident projections that carry a stored advisory block."""
    rows = list((extras or {}).get("incidentsAdvisory") or [])
    out = []
    for inc in rows:
        if not isinstance(inc, dict) or not inc.get("id"):
            continue
        if run_id and inc.get("runId") and inc.get("runId") != run_id:
            continue
        out.append(inc)
    return out


def _sidecar(extras):
    """The provenance sidecar as recorded. Never generated, never filled in."""
    triage = (extras or {}).get("triage") or {}
    prov = triage.get("modelProvenance")
    return prov if isinstance(prov, dict) else {}


# ---------------------------------------------------------------------------
# the citation guard
# ---------------------------------------------------------------------------

def guard_claims(claims, incident_ids, sidecar_fields):
    """Every rendered claim must cite something that RESOLVES. No exceptions.

    A citation is either a real incident id from this run, or `sidecar:<field>`
    naming a key that is actually present in the provenance sidecar. A claim
    with no citation, or with a citation that does not resolve, is REJECTED and
    never rendered — the reason is kept so the surface can show what it refused.
    """
    known = set(incident_ids or ())
    fields = set(sidecar_fields or ())
    accepted, rejected = [], []
    for claim in claims or ():
        text = str((claim or {}).get("text") or "").strip()
        if not text:
            continue
        cites = [str(c) for c in ((claim or {}).get("cites") or [])]
        reasons = []
        if not cites:
            reasons.append("no citation — a factual claim must cite an "
                           "incident id or a sidecar field")
        for ref in cites:
            if ref.startswith("sidecar:"):
                if ref.split(":", 1)[1] not in fields:
                    reasons.append(f"{ref} is not a field recorded in the "
                                   "provenance sidecar")
            elif ref not in known:
                reasons.append(f"{ref} does not resolve to an incident on "
                               "this run")
        if reasons:
            rejected.append({"text": text, "cites": cites, "reasons": reasons})
        else:
            accepted.append({"text": text, "cites": cites})
    return accepted, rejected


def render_claims(claims, incident_ids, sidecar_fields):
    """Guard, then render. Returns (answer_text, guard_report)."""
    accepted, rejected = guard_claims(claims, incident_ids, sidecar_fields)
    lines = [f"{c['text']} [{', '.join(c['cites'])}]" for c in accepted]
    report = {
        "claims": len(accepted) + len(rejected),
        "accepted": len(accepted),
        "rejected": rejected,
        "note": ("Every rendered sentence cites a real incident id or a real "
                 "provenance-sidecar field. Uncited claims are refused, not "
                 "softened."),
    }
    return "\n".join(lines), report


def _learned_result(answer, guard, facts, followups, extras_view=None):
    """Build a learned-source investigation result with standard fields.

    Returns a dict with answer, citations, followups, facts, actions, source,
    label, advisory flag, and citation guard. If extras_view is provided, it
    is attached as the 'learned' key for structured panel rendering.
    """
    out = {
        "answer": answer,
        "citations": [],
        "followups": followups,
        "facts": facts,
        "actions": [],
        "source": LEARNED_SOURCE,
        "label": LEARNED_LABEL,
        "advisory": True,
        "citationGuard": guard,
    }
    if extras_view is not None:
        out["learned"] = extras_view
    return out


_LEARNED_FOOTER = (
    "ADVISORY. The rules own the verdict; the learned model never changes, "
    "escalates or suppresses it, and nothing here approves anything."
)


# ---------------------------------------------------------------------------
# behaviour 1 — per-incident learned opinion
# ---------------------------------------------------------------------------

def learned_opinion(incident_id, extras, run_id=None):
    """State the learned opinion for ONE incident, citing the stored values."""
    rows = _incidents_with_opinion(extras, run_id)
    ids = [i["id"] for i in rows]
    sidecar = _sidecar(extras)
    wanted = str(incident_id or "").strip().lower()
    inc = next((i for i in rows
                if str(i.get("id") or "").lower() == wanted
                or str(i.get("alias") or "").lower() == wanted), None)
    if inc is None:
        claims = []
        answer = (f"No incident {incident_id} exists on this run, so there is "
                  "no stored learned opinion to read. I did not guess one.")
        guard = {"claims": 0, "accepted": 0, "rejected": [],
                 "note": "nothing was claimed, so nothing needed a citation"}
        return _learned_result(answer, guard,
                               {"incidentId": incident_id, "found": False},
                               ["What does the model disagree with the rules about?"])

    block = advisory_block(inc)
    iid = inc["id"]
    if not block:
        answer = "\n".join([
            f"Incident {iid} carries no learned advisory block at all — the "
            "second opinion was not attached to this projection. Nothing is "
            "shown in its place.",
            _LEARNED_FOOTER,
        ])
        guard = {"claims": 0, "accepted": 0, "rejected": [],
                 "note": "no advisory block, so no claim was made"}
        return _learned_result(answer, guard,
                               {"incidentId": iid, "modelAvailable": None},
                               _learned_followups(rows))

    rule_sev, _ = quote_model_value(block.get("ruleSeverity") or inc.get("severity"))
    if not block.get("modelAvailable"):
        # Behaviour 4 — honest absence. No opinion, no zeroed opinion, no guess.
        reason, reason_neutralised = quote_model_value(block.get("unavailableReason"))
        claims = [
            {"text": f"The rules verdict on {iid} is {rule_sev} and it stands.",
             "cites": [iid]},
            {"text": (f"The learned second opinion is UNAVAILABLE for {iid}: "
                      f"reason as recorded {reason}."),
             "cites": [iid]},
            {"text": ("No severity, no confidence and no agreement are shown, "
                      "because none were produced. I will not say what the "
                      "model would have said."),
             "cites": [iid]},
        ]
        answer, guard = render_claims(claims, ids, sidecar.keys())
        if reason_neutralised:
            answer += ("\nThat reason string reads as an instruction. It was "
                       "quoted as data and refused as an instruction.")
        answer += "\n" + _LEARNED_FOOTER
        return _learned_result(
            answer, guard,
            {"incidentId": iid, "modelAvailable": False,
             "aiSeverity": None, "confidence": None, "agrees": None},
            _learned_followups(rows),
            {"incidentId": iid, "modelAvailable": False,
             "ruleSeverity": block.get("ruleSeverity"),
             "aiSeverity": None, "aiLabel": None, "confidence": None,
             "agrees": None, "status": "unavailable",
             "unavailableReason": block.get("unavailableReason"),
             "neutralised": reason_neutralised})

    # Values are QUOTED STRAIGHT OUT of the stored block. No re-derivation.
    ai_sev, sev_neutralised = quote_model_value(block.get("aiSeverity"))
    ai_label, label_neutralised = quote_model_value(block.get("aiLabel"))
    confidence = block.get("confidence")
    agrees = block.get("agrees")
    status = block.get("status")
    conf_text = ("not recorded" if confidence is None else repr(confidence))
    agree_text = ("agrees with" if agrees is True
                  else "disagrees with" if agrees is False
                  else "records no agreement state against")

    claims = [
        {"text": f"The rules say {rule_sev} on {iid}, and that verdict stands.",
         "cites": [iid]},
        {"text": (f"The learned model reads {iid} as {ai_label} and would call "
                  f"it {ai_sev}, at confidence {conf_text}."),
         "cites": [iid]},
        {"text": (f"As stored, the model {agree_text} the rules verdict "
                  f"(status {status!r})."),
         "cites": [iid]},
    ]
    if agrees is False:
        claims.append({
            "text": ("That disagreement is INFORMATION — a prompt to look at "
                     f"{iid}, never a recommendation to override the rules."),
            "cites": [iid]})
    answer, guard = render_claims(claims, ids, sidecar.keys())
    if sev_neutralised or label_neutralised:
        answer += ("\nOne or more of those model-emitted values reads as an "
                   "instruction. They are quoted above as data and were "
                   "refused as instructions.")
    answer += "\n" + _LEARNED_FOOTER
    return _learned_result(
        answer, guard,
        {"incidentId": iid, "modelAvailable": True,
         "aiSeverity": block.get("aiSeverity"), "aiLabel": block.get("aiLabel"),
         "confidence": confidence, "agrees": agrees, "status": status},
        _learned_followups(rows),
        {"incidentId": iid, "modelAvailable": True,
         "ruleSeverity": block.get("ruleSeverity"),
         "aiSeverity": block.get("aiSeverity"), "aiLabel": block.get("aiLabel"),
         "confidence": confidence, "agrees": agrees, "status": status,
         "unavailableReason": None,
         "neutralised": bool(sev_neutralised or label_neutralised)})


def _learned_followups(rows):
    """Generate suggested follow-up questions for learned-model answers.

    Returns a list of up to _MAX_SUGGEST follow-up questions, including
    standard queries about disagreements and provenance, plus a specific
    incident query if any disagreeing incident exists in rows.
    """
    qs = ["What does the model disagree with the rules about?",
          "How was this model trained?"]
    for inc in rows:
        block = advisory_block(inc)
        if block and block.get("agrees") is False:
            qs.append(f"What does the model say about {inc['id']}?")
            break
    return qs[:_MAX_SUGGEST]


# ---------------------------------------------------------------------------
# behaviour 2 — cross-incident disagreement list
# ---------------------------------------------------------------------------

def learned_disagreements(extras, run_id=None):
    """READ-ONLY list of incidents where the stored opinion disagrees."""
    rows = _incidents_with_opinion(extras, run_id)
    ids = [i["id"] for i in rows]
    sidecar = _sidecar(extras)
    scored, unavailable, disagreeing = 0, 0, []
    for inc in rows:
        block = advisory_block(inc)
        if not block:
            continue
        if not block.get("modelAvailable"):
            unavailable += 1
            continue
        scored += 1
        if block.get("agrees") is False:
            disagreeing.append((inc, block))

    if rows and unavailable and not scored:
        # Behaviour 4 across the list: the model answered for nothing.
        first = advisory_block(rows[0]) or {}
        reason, neutralised = quote_model_value(first.get("unavailableReason"))
        claims = [{
            "text": (f"The learned model is UNAVAILABLE on this run, so there "
                     f"is no disagreement list to give: {unavailable} of "
                     f"{len(rows)} incident(s) carry no opinion. Reason as "
                     f"recorded {reason}."),
            "cites": [rows[0]["id"]]}]
        answer, guard = render_claims(claims, ids, sidecar.keys())
        if neutralised:
            answer += ("\nThat reason string reads as an instruction. It was "
                       "quoted as data and refused as an instruction.")
        answer += ("\nI am not showing an empty agreement list as if the model "
                   "had agreed with everything.\n" + _LEARNED_FOOTER)
        return _learned_result(answer, guard,
                               {"scored": 0, "unavailable": unavailable,
                                "disagreements": None},
                               ["How was this model trained?"],
                               {"kind": "disagreements", "modelAvailable": False,
                                "scored": 0, "unavailable": unavailable,
                                "items": []})

    if not rows:
        answer = ("No incidents exist on this run, so the learned model has "
                  "nothing to agree or disagree with.\n" + _LEARNED_FOOTER)
        guard = {"claims": 0, "accepted": 0, "rejected": [],
                 "note": "nothing was claimed, so nothing needed a citation"}
        return _learned_result(answer, guard, {"scored": 0, "disagreements": 0},
                               ["How was this model trained?"],
                               {"kind": "disagreements", "modelAvailable": None,
                                "scored": 0, "unavailable": 0, "items": []})

    claims = []
    items = []
    if not disagreeing:
        claims.append({
            "text": (f"The learned model disagrees with the rules on none of "
                     f"the {scored} scored incident(s) on this run."),
            "cites": [rows[0]["id"]]})
    else:
        claims.append({
            "text": (f"The learned model disagrees with the rules on "
                     f"{len(disagreeing)} of {scored} scored incident(s) on "
                     "this run. These are the false-positive candidates worth "
                     "a look — nothing here changes a verdict."),
            "cites": [d[0]["id"] for d in disagreeing]})
        for inc, block in disagreeing:
            iid = inc["id"]
            rule_sev, _ = quote_model_value(block.get("ruleSeverity")
                                            or inc.get("severity"))
            ai_sev, sev_n = quote_model_value(block.get("aiSeverity"))
            ai_label, label_n = quote_model_value(block.get("aiLabel"))
            conf = block.get("confidence")
            claims.append({
                "text": (f"{iid}: rules {rule_sev}; model {ai_label} at "
                         f"{ai_sev}, confidence "
                         f"{'not recorded' if conf is None else repr(conf)}."),
                "cites": [iid]})
            items.append({
                "incidentId": iid,
                "title": inc.get("title"),
                "ruleSeverity": block.get("ruleSeverity") or inc.get("severity"),
                "aiSeverity": block.get("aiSeverity"),
                "aiLabel": block.get("aiLabel"),
                "confidence": conf,
                "agrees": block.get("agrees"),
                "status": block.get("status"),
                "neutralised": bool(sev_n or label_n),
                "deeplink": f"/incidents?sel={iid}",
            })
    if unavailable:
        claims.append({
            "text": (f"{unavailable} further incident(s) carry no learned "
                     "opinion at all and are excluded rather than counted as "
                     "agreement."),
            "cites": [rows[0]["id"]]})
    answer, guard = render_claims(claims, ids, sidecar.keys())
    if any(i["neutralised"] for i in items):
        answer += ("\nOne or more model-emitted values above reads as an "
                   "instruction. They are quoted as data and were refused as "
                   "instructions.")
    answer += "\n" + _LEARNED_FOOTER
    return _learned_result(
        answer, guard,
        {"scored": scored, "unavailable": unavailable,
         "disagreements": len(disagreeing)},
        _learned_followups(rows),
        {"kind": "disagreements", "modelAvailable": True, "scored": scored,
         "unavailable": unavailable, "items": items})


# ---------------------------------------------------------------------------
# behaviour 3 — provenance on ask, VERBATIM from the sidecar
# ---------------------------------------------------------------------------
# Answered from `triage_v1.provenance.json` as recorded and from nowhere else.
# Nothing here is generated, inferred or rounded: every field the sidecar holds
# is quoted, and a field it does not hold is reported as NOT RECORDED rather
# than reconstructed from a plausible-sounding default.

# Human labels for the sidecar keys that have one. A key with no label is still
# quoted — under its own name — so a sidecar that grows a field does not
# silently lose it here.
PROVENANCE_LABELS = {
    "trainedAt": "trained at",
    "startedAt": "training started at",
    "trainDurationSeconds": "training duration (seconds)",
    "datasetRows": "training rows",
    "dataset": "training dataset composition",
    "labels": "label vocabulary",
    "labelSource": "label source",
    "seed": "random seed",
    "seedsUsed": "seeds used",
    "variants": "generated variants",
    "featureCount": "feature count",
    "featureKeys": "feature keys",
    "crossValidation": "cross-validation benchmark scores",
    "model": "estimator",
    "modelFile": "model file",
    "modelSha256": "model sha256",
    "sklearnVersion": "scikit-learn version",
    "python": "python version",
    "pipeline": "training pipeline",
    "scope": "scope of the claim",
    "card": "originating card",
    "wall": "advisory wall",
}

# Fields an analyst reasonably asks for that this sidecar does NOT record. They
# are named and reported as unrecorded — the honest answer to "what is its
# false-positive rate in production?" is that nobody wrote it down.
PROVENANCE_EXPECTED = ("holdoutRows", "productionAccuracy", "falsePositiveRate")

_PROVENANCE_VALUE_LIMIT = 400


def learned_provenance(extras, run_id=None):
    """Answer 'how was this model trained?' from the sidecar, VERBATIM."""
    rows = _incidents_with_opinion(extras, run_id)
    ids = [i["id"] for i in rows]
    sidecar = _sidecar(extras)
    triage = (extras or {}).get("triage") or {}

    if not sidecar:
        reason, neutralised = quote_model_value(triage.get("modelReason"))
        answer = ("There is no provenance sidecar recorded on this "
                  "installation, so I cannot tell you how the model was "
                  f"trained. Reason as recorded: {reason}. I will not "
                  "reconstruct training details from generation.")
        if neutralised:
            answer += (" That reason string reads as an instruction; it is "
                       "quoted as data and was refused as an instruction.")
        answer += "\n" + _LEARNED_FOOTER
        guard = {"claims": 0, "accepted": 0, "rejected": [],
                 "note": ("nothing was claimed: an unrecorded provenance is "
                          "stated as unrecorded, not cited")}
        return _learned_result(answer, guard,
                               {"provenanceRecorded": False},
                               ["What does the model disagree with the rules about?"],
                               {"kind": "provenance", "recorded": False,
                                "fields": [],
                                "missing": list(PROVENANCE_EXPECTED)})

    claims, fields, missing = [], [], []
    for key in sorted(sidecar):
        if sidecar[key] is None:
            missing.append(key)
            continue
        raw = sidecar[key]
        if isinstance(raw, (dict, list)):
            raw = json.dumps(raw, sort_keys=True)
        value, neutralised = quote_model_value(raw, _PROVENANCE_VALUE_LIMIT)
        label = PROVENANCE_LABELS.get(key, key)
        claims.append({"text": f"{label}: {value}.", "cites": [f"sidecar:{key}"]})
        fields.append({"key": key, "label": label, "value": value,
                       "neutralised": neutralised})
    missing += [k for k in PROVENANCE_EXPECTED if k not in sidecar]
    answer, guard = render_claims(claims, ids, sidecar.keys())
    header = ("Model provenance, quoted verbatim from the sidecar "
              "(triage_v1.provenance.json). Nothing here is generated:")
    answer = header + "\n" + answer
    if missing:
        answer += ("\nNot recorded in the sidecar, so not stated: "
                   + ", ".join(missing) + ".")
    if any(f["neutralised"] for f in fields):
        answer += ("\nOne or more sidecar values reads as an instruction. They "
                   "are quoted as data and were refused as instructions.")
    answer += "\n" + _LEARNED_FOOTER
    return _learned_result(
        answer, guard,
        {"provenanceRecorded": True, "fields": len(fields),
         "missing": len(missing)},
        ["What does the model disagree with the rules about?"],
        {"kind": "provenance", "recorded": True, "fields": fields,
         "missing": missing})


# ---------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------
# Deliberately narrow. A bare "model" or "ai" would hijack unrelated questions
# (the analyst LLM, an ATT&CK question, a "model" in prose), so the router only
# fires on a phrase that names the LEARNED second opinion.
_LEARNED_WORDS = ("learned model", "learned second opinion", "second opinion",
                  "triage model", "aitriage", "the model", "this model",
                  "ml model", "learned classifier", "model's")
_PROVENANCE_WORDS = ("trained", "training", "provenance", "training data",
                     "training set", "seed", "benchmark", "how was this model")
_DISAGREE_WORDS = ("disagree", "disagreement", "false positive candidate",
                   "false-positive candidate", "differ from the rules")


def learned_question(ql, context=None):
    """Which learned-model behaviour this question asks for, or None.

    Deterministic and word-based, in the same idiom as the rest of this module.
    """
    ql = str(ql or "").lower()
    mentions_model = any(w in ql for w in _LEARNED_WORDS)
    if mentions_model and any(w in ql for w in _PROVENANCE_WORDS):
        return ("provenance", None)
    if any(w in ql for w in _DISAGREE_WORDS) and mentions_model:
        return ("disagreements", None)
    if not mentions_model:
        return None
    hit = _INCIDENT_ID_RE.search(str(ql))
    if hit:
        return ("opinion", hit.group(0))
    selected = str((context or {}).get("selectedIncidentId") or "").strip()
    if selected:
        return ("opinion", selected)
    return ("disagreements", None)


def learned_answer(kind, incident_id, extras, run_id=None):
    """Dispatch to the appropriate learned-model answer function.

    Routes to learned_provenance for "provenance", learned_opinion for
    "opinion", or learned_disagreements otherwise, based on the kind
    parameter returned by learned_question.
    """
    if kind == "provenance":
        return learned_provenance(extras, run_id)
    if kind == "opinion":
        return learned_opinion(incident_id, extras, run_id)
    return learned_disagreements(extras, run_id)
