#!/usr/bin/env python3
"""
adapter.py — turn an analyzer report.json into the console's state shape.

The console renders state, not reports. Everything it shows must trace to
something the analyzer actually produced; where a field has no source, the
adapter says so rather than inventing a plausible value.

Two things the report cannot carry on its own:

  - Evidence TEXT. The report records line *numbers* (timeline) and one evidence
    string, but not the log lines themselves. They are read back from
    `source_file` through normalize.py — the project's own parser — so the
    console shows the real line, and the host column is the host that parser
    found on that line rather than a guess.

  - Match offsets. Nothing records where inside a line a rule matched, so the
    highlight is placed on the most specific entity present (dest_ip:port, then
    ip). That is an approximation and is the only inferred thing here.

Stdlib only. Read-only: reads a report, a log, optionally a threat-intel report.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "threat_intel"))

import normalize  # noqa: E402
import log_analyzer  # noqa: E402  # universal multi-format loader (JSON/CSV/XML/text/…)
from rule_mitre_map import techniques_for_rule  # noqa: E402

# Fallback mappings for newer deterministic rules that may not yet exist in
# threat_intel/rule_mitre_map.py. These are derived ATT&CK annotations only;
# they never change severity or prove malicious intent.
FALLBACK_MITRE = {
    "zookeeper_quorum_instability": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "zookeeper_connection_broken": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "zookeeper_sendworker_exit": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "zookeeper_sendworker_interrupt": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "zookeeper_sendworker_interrupted": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "threat_ransomware": [{"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}],
    "threat_active_compromise": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}],
    "threat_c2_indicator": [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}],
    "threat_malware_indicator": [{"id": "T1204.002", "name": "Malicious File", "tactic": "Execution"}],
    "threat_persistence": [{"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence"}],
    "threat_privilege_escalation": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],
    "threat_lateral_movement": [{"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"}],
    "threat_port_scan": [{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"}],
    "threat_credential_attack": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "threat_data_exfiltration": [{"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}],
    "threat_rogue_wireless": [{"id": "T1557.002", "name": "ARP Cache Poisoning", "tactic": "Credential Access"}],
    "suspicious_outbound": [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}],
    "ioc_observed": [],

    # Core deterministic detections not present in older rule_mitre_map.py versions.
    "auth_bruteforce": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "auth_bruteforce_success": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "possible_break_in": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "suspicious_outbound": [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}],
    "insecure_service_exposure": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "vulnerability_nmap_nse": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "url_security_header": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "url_tls": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "url_server_disclosure": [{"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"}],
    "url_information_disclosure": [{"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"}],
    "critical_service_event": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "disk_pressure": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "error_rate_spike": [{"id": "T1499.002", "name": "Service Exhaustion", "tactic": "Impact"}],
    "windows_audit_log_cleared": [{"id": "T1070.001", "name": "Clear Windows Event Logs", "tactic": "Defense Evasion"}],
    "windows_service_installed": [{"id": "T1543.003", "name": "Windows Service", "tactic": "Persistence"}],
    "windows_user_created": [{"id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence"}],
    "windows_user_deleted": [{"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"}],
    "windows_privileged_group_change": [{"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"}],
    "windows_account_lockout": [{"id": "T1531", "name": "Account Access Removal", "tactic": "Impact"}],
    "windows_suspicious_process": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
}

def _mitre_for_rule(rule_id):
    """Return ATT&CK annotations from the canonical map, then safe fallbacks.

    Fallbacks cover deterministic rules added after older rule_mitre_map.py
    versions. Unknown rules remain unmapped rather than receiving a guessed
    ATT&CK technique. MITRE is display/enrichment metadata only.
    """
    rid = str(rule_id or "")
    mapped = techniques_for_rule(rid) or []
    if mapped:
        return mapped
    return FALLBACK_MITRE.get(rid, [])

SEV_COLOR = {
    "CRITICAL": "#e2807f", "HIGH": "#d8a35e", "MEDIUM": "#dcb64a",
    "LOW": "#9397ab", "INFO": "#75798c",
}
LINE_RANGE_RE = re.compile(r"lines (\d+)-(\d+)")

# DISPLAY GROUPING ONLY — how a plain (non-finding) event's log LEVEL maps to a
# dashboard bucket, so the full event list can be segmented by criticality.
# This is presentation, never a verdict: rules own real severity, findings keep
# their rule-assigned bucket, and nothing here can inflate or suppress either.
# An unrecognized level goes to UNKNOWN — honesty over guessing, always.
LEVEL_BUCKET = {
    "CRIT": "CRITICAL", "CRITICAL": "CRITICAL", "FATAL": "CRITICAL",
    "ALERT": "CRITICAL", "EMERG": "CRITICAL",
    "ERROR": "HIGH", "ERR": "HIGH",
    "WARN": "MEDIUM", "WARNING": "MEDIUM",
    "INFO": "INFO", "NOTICE": "INFO",
    "DEBUG": "LOW", "TRACE": "LOW",
}
BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")

# rule_id -> the detector function that owns it, for the "rule predicate" panel.
RULE_REF = {
    "auth_bruteforce": "anomaly_detector.py · detect_auth_bruteforce()",
    "auth_bruteforce_success": "anomaly_detector.py · detect_auth_bruteforce()",
    "suspicious_outbound": "anomaly_detector.py · detect_suspicious_ports()",
    "critical_service_event": "anomaly_detector.py · detect_critical_and_resource()",
    "disk_pressure": "anomaly_detector.py · detect_critical_and_resource()",
    "error_rate_spike": "anomaly_detector.py · detect_error_bursts()",
    "possible_break_in": "rules_syslog.py · detect_break_in_attempts()",
}


def _bridge_record(r):
    """Coerce ONE load_log_file record into the console envelope shape the
    dashboard expects: {n, ts, level, host, msg, raw}.

    load_log_file records vary by format. Syslog records (normalize.load, run
    first inside load_log_file) already carry every field, so this is a no-op
    for them — syslog stays bit-for-bit as before. Universal records instead
    carry {line, timestamp, msg, raw, …} and may lack n / ts / level / host;
    fill only what is missing, never overwriting a value the parser set.
    """
    out = dict(r)
    out["n"] = r.get("n") if r.get("n") is not None else r.get("line")
    ts = r.get("ts")
    if ts is None:
        ts = log_analyzer._coerce_timestamp(r.get("timestamp"))
    out["ts"] = ts
    if not out.get("level"):
        out["level"] = r.get("severity") or ""
    if not out.get("host"):
        out["host"] = ""
    if not out.get("msg"):
        out["msg"] = r.get("message") or ""
    return out


def load_console_records(source_file):
    """(records, stats) for the console: parse the source log through the
    universal loader (so non-syslog formats hydrate too) and bridge every
    record into the console envelope shape. Shared by hydration and live-tail."""
    path = Path(source_file)
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        return [], {}
    records, stats = log_analyzer.load_log_file(path)
    return [_bridge_record(r) for r in records], stats


def _load_records(source_file):
    """Index the source log by line number, using the project's universal
    loader (load_log_file) so JSON/CSV/XML/access-log/text files hydrate too —
    not only syslog, which normalize.load alone could parse."""
    path = Path(source_file)
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        return {}, False
    records, _stats = load_console_records(source_file)
    return {r["n"]: r for r in records}, True


def _line_numbers(finding):
    nums = {e["line"] for e in finding.get("timeline", []) if e.get("line")}
    m = LINE_RANGE_RE.search(finding.get("evidence") or "")
    if m:
        nums |= {int(m.group(1)), int(m.group(2))}
    return sorted(nums)


def _highlight(raw, entities):
    """Split a line into (before, hit, after). No offsets are recorded anywhere,
    so the most specific entity present is used; no match means no highlight."""
    marks = []
    if entities.get("dest_ip") and entities.get("port"):
        marks.append(f"{entities['dest_ip']}:{entities['port']}")
    marks += [str(entities[k]) for k in ("ip", "dest_ip") if entities.get(k)]
    for mark in marks:
        i = raw.find(mark)
        if i >= 0:
            return raw[:i], mark, raw[i + len(mark):]
    return raw, "", ""


def _evidence_lines(finding, by_line, have_log):
    """Real log lines for the evidence pane, hydrated by line number."""
    entities = finding.get("entities") or {}
    is_crit = str(finding.get("severity", "")).upper() == "CRITICAL"
    out = []
    for n in _line_numbers(finding):
        record = by_line.get(n)
        if not record:
            continue
        a, hit, b = _highlight(record["raw"], entities)
        out.append({"n": n, "a": a, "hit": hit, "b": b, "crit": is_crit})

    if out:
        return out, None
    # No log available (or no line numbers): show the evidence string verbatim,
    # and say why it is not a line-numbered excerpt.
    ev = finding.get("evidence") or ""
    note = ("source log not readable — showing the recorded evidence string"
            if not have_log else "this rule records a summary, not a line excerpt")
    return ([{"n": "", "a": ev, "hit": "", "b": "", "crit": is_crit}] if ev else []), note


def _target_host(finding, lines, by_line):
    """The host the finding is ABOUT, taken from the parsed log line.

    Auth rules key on the source IP and carry no host, so the design's "host"
    column would otherwise show the attacker's address. Deriving it from the
    hydrated line gives the machine that was attacked; when nothing can be
    derived the caller labels the value as a source IP instead of pretending.
    """
    for line in lines:
        record = by_line.get(line.get("n"))
        if record and record.get("host"):
            return record["host"], True
    entities = finding.get("entities") or {}
    if entities.get("host"):
        return entities["host"], True
    for key in ("ip", "dest_ip"):
        if entities.get(key):
            return entities[key], False
    return "—", False


def _threat_chips(finding, threat_report):
    """Optional: MITRE / threat-intel context, matched by IP. Omitted if absent."""
    if not threat_report:
        return []
    entities = finding.get("entities") or {}
    ips = {str(entities[k]) for k in ("ip", "dest_ip") if entities.get(k)}
    chips = []
    for match in threat_report.get("findings", []):
        if match.get("observed_value") not in ips:
            continue
        for technique in match.get("mitre_techniques", []):
            chips.append({"text": f"{technique['technique_id']} · {technique['name']}"})
        if not match.get("mitre_techniques"):
            chips.append({"text": match.get("threat_intel_name", "threat-intel match")})
    return chips


def _events(by_line, findings, report_findings):
    """EVERY parsed record as a dashboard event, plus counts per bucket.

    Sourced from the same records the evidence pane already hydrates, so each
    event's `raw` is the verbatim source line and each parsed line appears
    exactly once — the full log, not just the findings. A line a finding sits
    on inherits that finding's rule-assigned bucket (first finding wins when
    several share a line); every other line is grouped by its own log level
    through LEVEL_BUCKET. Grouping only — severity stays owned by the rules.
    """
    finding_line = {}                   # line n -> id of the first finding on it
    for f_report, f_adapted in zip(report_findings, findings):
        for n in _line_numbers(f_report):
            finding_line.setdefault(n, f_adapted["id"])
    sev_by_id = {f["id"]: f["sev"] for f in findings}

    events = []
    counts = {b: 0 for b in BUCKETS}
    for n in sorted(by_line):
        r = by_line[n]
        fid = finding_line.get(n)
        if fid is not None:
            sev = sev_by_id[fid]
            bucket = sev if sev in BUCKETS else "UNKNOWN"
        else:
            bucket = LEVEL_BUCKET.get(str(r.get("level") or "").upper(), "UNKNOWN")
        counts[bucket] += 1
        events.append({
            "n": n,
            "ts": r["ts"].isoformat() if r.get("ts") else "",
            "level": r.get("level") or "",
            "host": r.get("host") or "",
            "msg": r.get("msg") or "",
            "raw": r["raw"],            # verbatim source line — never fabricated
            "bucket": bucket,
            "isFinding": fid is not None,
            "findingId": fid,
        })
    return events, counts


def _mitre_frequency(findings):
    """Ranked ATT&CK technique frequency across findings.

    Counts findings per technique (via each finding's rule_mitre_map-derived
    "mitre" list), descending, ties broken by technique id for determinism.
    Unmapped rules contribute nothing; no findings -> [].
    """
    agg = {}
    for f in findings:
        for t in f.get("mitre") or []:
            entry = agg.setdefault(t["id"], {"id": t["id"], "name": t["name"],
                                             "tactic": t["tactic"], "count": 0})
            entry["count"] += 1
    return sorted(agg.values(), key=lambda e: (-e["count"], e["id"]))


def _entry_time(entry):
    """Clock-time label for one timeline entry, whichever shape it's in.

    rule_context.py's rebuilt entries carry "t" already (e.g. "14:02:31").
    Entries this module never rebuilds — a rule id rule_context.py has no
    case for, like rules_syslog.py's web_* findings — keep their original
    {line, ts, event} shape from anomaly_detector.py/rules_syslog.py, which
    has no "t" key at all. Derive it from the ISO "ts" instead of assuming
    one shape everywhere.
    """
    t = entry.get("t")
    if t:
        return t
    ts = entry.get("ts") or ""
    return ts[11:19] if len(ts) >= 19 else ""


def _entry_label(entry):
    """Human label for one timeline entry, whichever shape it's in (see
    _entry_time): rebuilt entries use "label", original ones use "event"."""
    return entry.get("label") or entry.get("event") or ""


def adapt(report, threat_report=None):
    by_line, have_log = _load_records(report.get("source_file", ""))
    compare = report.get("compare")
    compare_run = compare is not None


    findings = []
    for f in report.get("findings", []):
        source = f.get("source", "llm")
        is_detector = source == "detector"
        sev = str(f.get("severity", "info")).upper()
        timeline = f.get("timeline", [])
        lines, lines_note = _evidence_lines(f, by_line, have_log)
        host, host_derived = _target_host(f, lines, by_line)
        entities = f.get("entities") or {}

        chips = _threat_chips(f, threat_report)
        if not is_detector and source != "analyzer":
            chips.append({"text": "no rule fired"})
        for key in ("ip", "dest_ip"):
            if entities.get(key):
                chips.append({"text": str(entities[key])})

        findings.append({
            "id": f"{source}-{len(findings)}",
            "sev": sev,
            "sevColor": SEV_COLOR.get(sev, "#9397ab"),
            "ruleSev": sev if is_detector else "— below threshold",
            "llmSev": f.get("llm_alone_severity"),
            "llmWhy": f.get("llm_alone_why"),
            "delta": f.get("llm_alone_delta"),
            "prov": {"detector": "RULE-CAUGHT", "analyzer": "ANALYZER"}.get(source, "LLM-SURFACED"),
            "type": f.get("rule_id") or f.get("category") or "finding",
            "host": host,
            "hostDerived": host_derived,
            "time": _entry_time(timeline[-1]) if timeline else "",
            "stamp": (timeline[-1].get("ts") or "") if timeline else "",
            "title": f.get("summary", ""),
            "ruleWhy": f.get("rationale", ""),
            "explanation": f.get("recommended_action", ""),
            "predicate": f.get("predicate", ""),
            "ruleRef": RULE_REF.get(f.get("rule_id"), ""),
            "occurrences": f.get("occurrences", 1),
            # CBS/CSI channel (or similar) when the log has no hostname — display
            # only, never a fabricated machine name (hostDerived stays false).
            "scope": str(entities.get("channel") or ""),
            # Derived ATT&CK annotation from threat_intel/rule_mitre_map.py.
            # Read-only context: it never alters severity, verdict, or order,
            # and an unmapped rule gets [] — the console then shows nothing.
            "mitre": _mitre_for_rule(f.get("rule_id")),
            "chips": chips,
            "lines": lines,
            "linesNote": lines_note,
            # `line` is carried through deliberately: on-demand explanation needs to
            # find the chunk a finding came from, and dropping it silently broke that.
            "timeline": [{"t": _entry_time(e), "label": _entry_label(e),
                          "line": e.get("line"),
                          "dot": SEV_COLOR.get(sev, "#9397ab")} for e in timeline],
        })

    stamps = [f["stamp"] for f in findings if f["stamp"]]
    window = (f"{min(stamps)[11:16]}–{max(stamps)[11:16]} UTC" if stamps else "")
    hosts = sorted({f["host"] for f in findings if f["hostDerived"]})
    degraded = bool(compare) and compare.get("chunks_usable", 0) < compare.get("chunks_total", 0)
    analyzer_errors = [f for f in report.get("findings", []) if f.get("source") == "analyzer"]

    # The full event list for the dashboard. When the source log is not
    # readable there is nothing honest to show, so events stays empty rather
    # than reconstructed; the existing unrecognized/emptyInput flags are
    # untouched and still drive the honest banner.
    # Honest-empty contract: when the analyzer's own run parsed nothing
    # (unrecognized format or empty input, i.e. lines_parsed == 0), emit no
    # events — even though the universal loader can coerce arbitrary readable
    # text into "records", showing them would contradict the
    # unrecognized/emptyInput banner. When lines were parsed, every record is
    # surfaced exactly as before.
    if report.get("lines_parsed") == 0:
        events, severity_counts = [], {b: 0 for b in BUCKETS}
    else:
        events, severity_counts = _events(by_line, findings, report.get("findings", []))

    source_name = Path(report.get("source_file", "run")).stem
    return {
        "live": True,
        "runId": f"{source_name}-{report.get('generated_at', '')[:10]}",
        "runWindow": window,
        "runHosts": ", ".join(hosts) if hosts else "—",
        "runParsed": _parsed_label(report),
        "generatedAt": report.get("generated_at", ""),

        # Integrity, not provenance: every value here is recomputable from the
        # files on disk. Nothing signs this run and the UI must not imply it does.
        "manifest": {
            "input_sha256": report.get("input_sha256"),
            "detector_sha256": report.get("detector_sha256"),
            "model": report.get("model"),
            "temperature": report.get("temperature"),
            "ruleset": report.get("ruleset"),
            "endpoint": report.get("endpoint"),
        },

        # Three different empty outcomes, and the console must never conflate them:
        #   parsed > 0, no findings  -> all clear (a real success)
        #   parsed == 0, lines seen  -> unrecognized format (nothing was analyzed)
        #   parsed == 0, no lines    -> empty input
        # Reporting the second as "all clear" would be a false success on an audit
        # surface: zero findings because nothing was read is not zero findings.
        "linesParsed": report.get("lines_parsed", 0),
        "linesUnparsed": report.get("lines_unparsed", 0),
        "unrecognized": (report.get("lines_parsed", 0) == 0
                         and report.get("lines_unparsed", 0) > 0),
        "emptyInput": (report.get("lines_parsed", 0) == 0
                       and report.get("lines_unparsed", 0) == 0),

        "compareRun": compare_run,
        "underratedCount": (compare or {}).get("underrated_count"),
        "chunksUsable": (compare or {}).get("chunks_usable"),
        "chunksTotal": (compare or {}).get("chunks_total"),
        "degraded": degraded,
        "analyzerErrors": len(analyzer_errors),
        # Model findings only — an analyzer_error is a failure, not a contribution.
        "modelFindings": len([f for f in report.get("findings", [])
                              if f.get("source") == "llm"]),
        "findings": findings,

        # Dashboard data (additive — nothing above is removed or renamed).
        # events: every parsed line, verbatim, grouped for display only.
        # severityCounts: events per bucket; sums to linesParsed when the
        # source log is readable. mitreFrequency: ranked ATT&CK technique
        # counts across findings; unmapped rules contribute nothing.
        "events": events,
        "severityCounts": severity_counts,
        "mitreFrequency": _mitre_frequency(findings),
    }


def _parsed_label(report):
    parsed = report.get("lines_parsed")
    if parsed is None:
        return f"{report.get('total_chunks_analyzed', '?')} chunk(s) analyzed"
    unparsed = report.get("lines_unparsed", 0)
    label = f"{parsed:,} lines parsed"
    return label + (f" · {unparsed:,} unparsed" if unparsed else " · 0 unparsed")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Adapt an analyzer report.json into console state")
    ap.add_argument("report")
    ap.add_argument("--threat-intel", default=None,
                    help="Optional threat_detector.py report.json, for MITRE chips")
    ap.add_argument("-o", "--output", default=None, help="Write state JSON here (default: stdout)")
    args = ap.parse_args()

    report = json.loads(Path(args.report).read_text())
    threat = json.loads(Path(args.threat_intel).read_text()) if args.threat_intel else None
    state = adapt(report, threat)
    text = json.dumps(state, indent=2)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output} ({len(state['findings'])} finding(s))")
    else:
        print(text)


if __name__ == "__main__":
    main()
