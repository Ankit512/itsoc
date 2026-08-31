#!/usr/bin/env python3
"""
sigma_match.py — sibling Sigma matcher (JSON subset). Stdlib only.

Matches canonical records `{n, ts, level, host, msg, raw}` (plus extra
fields collectors attach) against bundled rules in console/sigma/*.json.

This is a detection sibling, like rules_syslog.detect_extra — it never
imports or edits anomaly_detector.py. Severity on a Sigma hit is the
rule's own `level` field (rule-owned), never an LLM rating.

Hits are gap-fill by default: events the frozen detector already flagged
are not re-emitted as Sigma findings, so Overview counts are not doubled.
Webhook ingest matches every accepted event because those never went
through the detector.

Unrecognized / empty input stays empty — no fabricated hits.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES_DIR = HERE / "sigma"

_LEVEL = {
    "informational": "INFO", "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM", "med": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL", "crit": "CRITICAL",
}

# Field aliases so Sigma keys resolve on both detector records and collector JSON.
_FIELD_ALIASES = {
    "msg": ("msg", "message", "Message"),
    "message": ("msg", "message", "Message"),
    "raw": ("raw",),
    "host": ("host", "hostname", "ComputerName", "DeviceName"),
    "level": ("level", "severity", "Severity"),
    "eventid": ("event_id", "EventID", "EventId", "eventId"),
    "action": ("action", "Action", "ActionType"),
    "user": ("user", "username", "UserName", "TargetUserName"),
    "src_ip": ("src_ip", "src", "source_ip", "SourceIp"),
    "dst_ip": ("dst_ip", "dst", "dest_ip", "DestinationIp"),
}


def _load_rules(directory=None):
    d = Path(directory) if directory else RULES_DIR
    rules = []
    if not d.is_dir():
        return rules
    for path in sorted(d.glob("*.json")):
        try:
            rule = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(rule, dict) or not rule.get("id"):
            continue
        rule["_path"] = str(path)
        rules.append(rule)
    return rules


def list_rules(directory=None):
    """Public catalog — no match results, just what is shipped."""
    out = []
    for r in _load_rules(directory):
        out.append({
            "id": r.get("id"),
            "title": r.get("title") or r.get("id"),
            "level": _LEVEL.get(str(r.get("level") or "").lower(), "INFO"),
            "status": r.get("status") or "",
            "logsource": r.get("logsource") or {},
            "file": Path(r.get("_path") or "").name,
        })
    return out


def _field_values(rec, name):
    keys = _FIELD_ALIASES.get(name.lower(), (name, name.lower(), name.upper()))
    vals = []
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            vals.append(rec[k])
    return vals


def _blob(rec):
    parts = [str(rec.get("msg") or ""), str(rec.get("raw") or ""),
             str(rec.get("action") or ""), str(rec.get("event_id") or "")]
    return " ".join(parts)


def _match_token(actual, expected, modifier):
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if modifier == "re":
        try:
            return re.search(e, a, re.I) is not None
        except re.error:
            return False
    a_l, e_l = a.lower(), e.lower()
    if modifier == "startswith":
        return a_l.startswith(e_l)
    if modifier == "endswith":
        return a_l.endswith(e_l)
    if modifier in ("contains", "", None):
        return e_l in a_l
    return a_l == e_l


def _match_selection(rec, selection):
    """AND across keys; a list value is OR (Sigma default)."""
    if not isinstance(selection, dict) or not selection:
        return False
    for key, expected in selection.items():
        if "|" in str(key):
            field, modifier = str(key).split("|", 1)
        else:
            field, modifier = str(key), "contains" if isinstance(expected, list) else ""
        values = _field_values(rec, field)
        # Only search the concatenated text for fields that actually live in
        # the line (msg/raw/event id). A missing `action` must NOT match the
        # word "block" inside an HDFS block-id line.
        if not values and field.lower() in (
            "msg", "message", "raw", "eventid", "event_id",
        ):
            values = [_blob(rec)]
        if not values:
            return False
        want = expected if isinstance(expected, list) else [expected]
        if not any(_match_token(v, exp, modifier) for v in values for exp in want):
            return False
    return True


def _eval_condition(rec, detection, condition):
    """Tiny condition language: `selection`, `A and not B`, `A or B`."""
    condition = (condition or "selection").strip()
    selections = {k: v for k, v in detection.items() if k != "condition"}
    # Tokenize identifiers vs operators.
    tokens = re.findall(r"and|or|not|[A-Za-z][\w*]*", condition)
    if not tokens:
        return _match_selection(rec, selections.get("selection") or {})

    def ident(name):
        if name.endswith("*"):
            prefix = name[:-1]
            return any(_match_selection(rec, sel)
                       for k, sel in selections.items() if k.startswith(prefix))
        sel = selections.get(name)
        if sel is None:
            return False
        return _match_selection(rec, sel)

    # Recursive-descent for `not`, `and`, `or` (or binds looser).
    i = [0]

    def peek():
        return tokens[i[0]] if i[0] < len(tokens) else None

    def take():
        t = peek()
        i[0] += 1
        return t

    def parse_not():
        if peek() == "not":
            take()
            return not parse_not()
        name = take()
        return ident(name) if name else False

    def parse_and():
        val = parse_not()
        while peek() == "and":
            take()
            val = val and parse_not()
        return val

    def parse_or():
        val = parse_and()
        while peek() == "or":
            take()
            val = val or parse_and()
        return val

    try:
        return parse_or()
    except (IndexError, TypeError):
        return False


def match_record(rec, rules=None):
    """Return the list of rules that fire on one record."""
    hits = []
    for rule in (rules if rules is not None else _load_rules()):
        detection = rule.get("detection") or {}
        if _eval_condition(rec, detection, detection.get("condition")):
            hits.append(rule)
    return hits


def match_records(records, rules=None, gap_fill=False):
    """Group hits by rule id. `gap_fill` skips records already on a finding."""
    rules = rules if rules is not None else _load_rules()
    grouped = {}
    for rec in records or []:
        if gap_fill and rec.get("isFinding"):
            continue
        for rule in match_record(rec, rules):
            rid = rule.get("id")
            bucket = grouped.setdefault(rid, {"rule": rule, "records": []})
            bucket["records"].append(rec)
    return grouped


def _sev_for(rule):
    return _LEVEL.get(str(rule.get("level") or "").lower(), "INFO")


def as_anomalies(grouped):
    """Detector-shaped extras (same keys detect_extra emits)."""
    anomalies = []
    for rid, bucket in grouped.items():
        rule = bucket["rule"]
        recs = bucket["records"]
        if not recs:
            continue
        evidence = recs[0].get("raw") or recs[0].get("msg") or ""
        hosts = sorted({str(r.get("host") or "") for r in recs if r.get("host")})
        anomalies.append({
            "type": f"sigma_{rid}".replace("-", "_"),
            "severity": _sev_for(rule).lower(),
            "summary": rule.get("title") or rid,
            "evidence": evidence,
            "rationale": (
                f"Sigma rule {rid} matched {len(recs)} event(s). "
                "Severity is the Sigma rule level — not an AI rating."
            ),
            "entities": {"host": hosts[0]} if hosts else {},
            "occurrences": len(recs),
            "predicate": f"sigma:{rid}",
            "timeline": [
                {"ts": str(r.get("ts") or ""), "event": str(r.get("msg") or "")[:160],
                 "line": r.get("n")}
                for r in recs[:12]
            ],
        })
    return anomalies


def as_findings(grouped, start_index=0):
    """Console finding dicts (adapter shape). Rule-owned sev; never LLM."""
    findings = []
    i = start_index
    for rid, bucket in grouped.items():
        rule = bucket["rule"]
        recs = bucket["records"]
        if not recs:
            continue
        sev = _sev_for(rule)
        host = next((str(r.get("host") or "") for r in recs if r.get("host")), "")
        lines = []
        for r in recs[:12]:
            raw = str(r.get("raw") or r.get("msg") or "")
            lines.append({"n": r.get("n") or "", "a": raw, "hit": "", "b": "", "crit": sev == "CRITICAL"})
        last = recs[-1]
        ts = str(last.get("ts") or "")
        findings.append({
            "id": f"sigma-{i}",
            "sev": sev,
            "ruleSev": sev,
            "llmSev": None,
            "delta": None,
            "prov": "RULE-CAUGHT",
            "type": f"sigma_{rid}".replace("-", "_"),
            "host": host or "—",
            "hostDerived": bool(host),
            "time": ts[11:19] if len(ts) >= 19 else "",
            "stamp": ts,
            "title": rule.get("title") or rid,
            "ruleWhy": (
                f"Sigma rule {rid} matched {len(recs)} event(s) the frozen "
                "detector did not already flag. Severity is the Sigma rule "
                "level, not an AI rating."
            ),
            "explanation": "",
            "predicate": f"sigma:{rid}",
            "ruleRef": Path(rule.get("_path") or "").name or f"sigma:{rid}",
            "occurrences": len(recs),
            "mitre": [],
            "chips": [{"text": "sigma"}, {"text": rid}],
            "lines": lines,
            "linesNote": "verbatim source lines the Sigma rule matched",
            "timeline": [
                {"t": str(r.get("ts") or "")[11:19],
                 "label": str(r.get("msg") or "")[:120],
                 "line": r.get("n")}
                for r in recs[:12]
            ],
        })
        i += 1
    return findings


def findings_from_events(events, gap_fill=True):
    grouped = match_records(events, gap_fill=gap_fill)
    return as_findings(grouped)


def hits_summary(events, gap_fill=True):
    grouped = match_records(events, gap_fill=gap_fill)
    return [
        {
            "id": bucket["rule"].get("id"),
            "title": bucket["rule"].get("title"),
            "level": _sev_for(bucket["rule"]),
            "count": len(bucket["records"]),
            "advisory": False,
            "note": "Sigma rule-owned match — not an AI verdict.",
        }
        for bucket in grouped.values()
    ]
