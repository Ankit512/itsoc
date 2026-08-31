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
_MAX_SUGGEST = 5


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
    if any(_occ(f) > 1 for f in findings):
        qs.append("What did Overview group, and which matching lines are hidden?")

    mitre = [f for f in findings if f.get("mitre")]
    if not mitre and findings:
        qs.append("Why is ATT&CK empty on this run?")

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
        f"This run has {len(findings)} grouped finding(s) covering "
        f"{matching} matching line(s) across {n_events} parsed event(s). "
        "Overview shows the cards; the matching lines sit in the source log."
    )
    if leftover > 0:
        parts.append(
            f"{leftover} matching line(s) are collapsed behind those cards — "
            "not missing, just not one-row dashboard tiles."
        )
    for f in _ranked(findings)[:6]:
        parts.append(
            f"- [{_sev(f)}] {f.get('type')}: {f.get('title')} "
            f"(×{_occ(f)}; host {f.get('host') or f.get('scope') or 'n/a'})"
        )
    if len(findings) > 6:
        parts.append(f"- …and {len(findings) - 6} more grouped finding(s).")
    parts.append(
        "Severity is rule-owned. I can pull the hidden matching lines for any card."
    )
    return "\n".join(parts)


def _hidden_lines(findings, events):
    """What Overview grouped vs the matching source lines it collapsed."""
    matching = sum(_occ(f) for f in findings)
    leftover = matching - len(findings)
    parts = [
        f"Overview shows {len(findings)} grouped card(s) covering "
        f"{matching} matching source line(s) across {len(events)} parsed event(s)."
    ]
    cites = []
    top = _ranked(findings)[0] if findings else None
    if leftover > 0 and top:
        parts.append(
            f"{leftover} matching line(s) are not one-row cards — they sit in "
            "the source log. Cited below from the parsed event store (verbatim)."
        )
        fid = top.get("id")
        mine = [e for e in events if e.get("findingId") == fid]
        sig = str((top.get("entities") or {}).get("hresult_name")
                  or (top.get("entities") or {}).get("signature")
                  or "")
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


def investigate(question, state):
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
    facts = {
        "findings": len(findings),
        "events": len(events),
        "matchingLines": sum(_occ(f) for f in findings),
    }

    if not q:
        empty["answer"] = "Ask about a finding, a HRESULT, a host, or a matching line."
        empty["facts"] = facts
        empty["followups"] = suggested_questions(state)
        return empty

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
            f"[{_sev(matched_finding)}] {matched_finding.get('type')}: "
            f"{matched_finding.get('title')} — {occ} matching source line(s). "
            f"Overview collapses those into one card; here are "
            f"{shown} cited line(s) from the log (verbatim)."
        )
        if occ > shown:
            answer += f" {occ - shown} further matching line(s) are not listed here."
        rationale = matched_finding.get("ruleWhy") or matched_finding.get("rationale") or ""
        if rationale:
            answer += f"\nRule rationale: {rationale}"
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
    lines.append(
        "Use these facts. Do not invent additional alerts or change severity. "
        "Cite {n} when you quote a line."
    )
    return "\n".join(lines)
