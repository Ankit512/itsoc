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


def suggested_questions(state):
    """Run-aware prompts. Never suggest a band/story the run does not have."""
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

    qs = []
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
        "links": [
            {"label": "Findings", "href": "/alerts", "count": len(findings)},
            {"label": "Incidents", "href": "/incidents", "count": len(incidents)},
            {"label": "Assets", "href": "/assets", "count": len(assets)},
            {"label": "Intel", "href": "/intel", "count": len(indicators)},
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


def investigate(question, state, extras=None):
    """Deterministic investigation. Never a new verdict."""
    empty = {
        "answer": "",
        "citations": [],
        "followups": [],
        "facts": {},
        "source": "rules",
    }
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
    q = str(question or "").strip()
    ql = q.lower()
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
