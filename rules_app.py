#!/usr/bin/env python3
"""
rules_app.py — app/vendor-level deterministic sibling rules for the formats the
classic syslog family does not own (Windows event exports, vendor CSV/JSON/XML
SIEM exports, application logs such as ZooKeeper, generic text).

Ported from the multi-format working tree and adapted to this repo's contract:

  * SIBLING module. anomaly_detector.py is never imported or modified; these
    rules ADD findings with their own new types — they never set, change,
    suppress, or escalate a verdict the frozen detector produced.
  * Deterministic only. Every severity here comes from an explicit rule table
    (event-id, threshold, or pattern) — never from a model, never guessed
    beyond the written pattern.
  * `raw`/evidence carry real source text verbatim; occurrence counts and line
    ranges are computed, never invented.
  * The Windows auth canonicalization translates 4625/4624 events into the
    SAME canonical vocabulary rules_syslog.py feeds the frozen detector, so
    brute-force/compromise correlation on Windows exports is owned by the
    frozen detector — not re-implemented here.

Wired in log_analyzer.run() for non-rfc3164 formats only: the frozen detector
plus rules_syslog remain the sole rule surface for classic syslog (and for
tests/eval), so integrating this module cannot move an eval verdict.

Excluded from the port on purpose: every nmap/NSE active-scanning rule and its
finding types — this project is read-only by principle (ITSOC_V2_SPEC §2).
"""

import re

import rules_syslog  # canonical auth vocabulary templates (CANON_FAIL/CANON_OK)

# ---------------------------------------------------------------------------
# Record field access (Windows/SIEM exports are key=value or column dicts)
# ---------------------------------------------------------------------------

def _field(record, *names, default=None):
    """Case-insensitive field lookup for Windows/SIEM exports."""
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    wanted = {n.lower() for n in names}
    for key, value in record.items():
        if str(key).lower() in wanted and value not in (None, ""):
            return value
    return default


def _event_id(record):
    value = _field(record, "event_id", "EventCode", "EventID", "EventId", "Id")
    if value is None:
        return None
    m = re.search(r"\d+", str(value))
    return m.group(0) if m else str(value).strip()


def _record_ip(record):
    return _field(
        record,
        "src_ip", "SourceNetworkAddress", "IpAddress", "SourceIp",
        "SourceIP", "ClientAddress", "ClientIP", "source_ip",
    )


def _record_user(record):
    return _field(
        record,
        "TargetUserName", "TargetUsername", "UserName", "Username",
        "AccountName", "SubjectUserName", "user", "User",
        default="unknown",
    )


def _line(record):
    return _field(record, "n", "line", "LineNumber", default=0)


def _raw(record):
    return str(record.get("raw") or record.get("original_msg") or record.get("msg") or "")


def _entity_host(record):
    return _field(record, "host", "ComputerName", "Hostname", "Computer", default="unknown")


def _record_text(record):
    return str(record.get("msg") or record.get("message") or record.get("raw") or "")


def _all_text(record):
    vals = []
    for k in ("raw", "msg", "message", "Message", "event", "Event", "action",
              "Action", "reason", "Reason", "description", "Description"):
        v = record.get(k)
        if v not in (None, ""):
            vals.append(str(v))
    return " ".join(vals)


def _anomaly(severity, atype, summary, record, rationale, entities=None,
             recommended_action=""):
    return {
        "severity": severity,
        "type": atype,
        "summary": summary,
        "evidence": _raw(record),
        "rationale": rationale,
        "entities": entities or {},
        "recommended_action": recommended_action,
    }


def _timeline_entry(record, label):
    """Console-shape timeline entry ({t, ts, label, line}) from any record.

    Same shape rule_context._event produces, so the adapter renders these
    without a special case. `ts` may be a datetime (universal records are
    _adapt-ed) or a source string; `t` is the clock part when derivable.
    """
    ts = record.get("ts") or record.get("timestamp")
    if hasattr(ts, "isoformat"):
        iso = ts.isoformat()
        t = ts.strftime("%H:%M:%S")
    else:
        iso = str(ts) if ts else None
        t = iso[11:19] if iso and len(iso) >= 19 else ""
    return {"t": t, "ts": iso, "label": label, "line": _line(record) or None}


# ---------------------------------------------------------------------------
# Windows auth canonicalization — the frozen detector owns the verdict
# ---------------------------------------------------------------------------

WINDOWS_FAIL_IDS = {"4625"}
WINDOWS_SUCCESS_IDS = {"4624"}
WINDOWS_USER_CREATED_IDS = {"4720"}
WINDOWS_USER_DELETED_IDS = {"4726"}
WINDOWS_GROUP_ADD_IDS = {"4732", "4728", "4756"}
WINDOWS_LOCKOUT_IDS = {"4740"}
WINDOWS_AUDIT_CLEARED_IDS = {"1102", "104"}
WINDOWS_SERVICE_INSTALL_IDS = {"7045"}
WINDOWS_PROCESS_CREATE_IDS = {"4688"}

_LOCAL_IPS = {"-", "::1", "127.0.0.1", "0.0.0.0"}


def canonicalize_windows_auth(records):
    """Translate Windows 4625/4624 logon events into the canonical auth
    vocabulary the frozen detector's brute-force/compromise rules understand.

    Same contract as rules_syslog.canonicalize: msg is rewritten in a safe
    copy, `raw` is never touched, original_msg/auth_source/auth_ip are set.
    Non-Windows records pass through untouched. Returns (records, counts).
    """
    out = []
    counts = {"auth_fail": 0, "auth_ok": 0}
    for r in records:
        eid = _event_id(r)
        kind = source = None
        if eid in WINDOWS_FAIL_IDS:
            kind, source, canon = "auth_fail", "windows_4625", rules_syslog.CANON_FAIL
        elif eid in WINDOWS_SUCCESS_IDS:
            kind, source, canon = "auth_ok", "windows_4624", rules_syslog.CANON_OK
        if kind:
            ip = _record_ip(r)
            if ip and str(ip).strip() not in _LOCAL_IPS:
                copy = dict(r)
                msg = _record_text(r)
                copy["msg"] = canon.format(user=_record_user(r), ip=ip)
                copy["original_msg"] = msg
                copy["auth_source"] = source
                copy["auth_ip"] = str(ip)
                counts[kind] += 1
                out.append(copy)
                continue
        out.append(r)
    return out, counts


# ---------------------------------------------------------------------------
# Windows Event-ID rules (high-signal events v1 has no rule for)
# ---------------------------------------------------------------------------

def detect_windows_extra(records):
    """Windows Event-ID rules not covered by anomaly_detector.py.

    Intentionally high-signal events rather than one finding per routine
    4624/4672 event. Authentication correlation stays delegated to the frozen
    detector via canonicalize_windows_auth.
    """
    anomalies = []
    for r in records:
        eid = _event_id(r)
        if not eid:
            continue

        host = _entity_host(r)
        user = _record_user(r)
        subject = _field(r, "SubjectUserName", "SubjectUser", default="")
        process = _field(r, "NewProcessName", "ProcessName", "Image", default="")
        service = _field(r, "ServiceName", "ServiceFileName", default="")

        if eid in WINDOWS_AUDIT_CLEARED_IDS:
            anomalies.append(_anomaly(
                "critical", "windows_audit_log_cleared",
                f"Windows audit log was cleared on {host}",
                r,
                "Security/audit history was explicitly cleared. This can remove evidence "
                "of prior activity and should be treated as a potential defense-evasion event.",
                {"host": host, "event_id": eid},
                "Identify the actor and source, preserve remaining logs, and investigate "
                "activity immediately before the clear."))

        elif eid in WINDOWS_SERVICE_INSTALL_IDS:
            anomalies.append(_anomaly(
                "high", "windows_service_installed",
                f"New Windows service installed on {host}: {service or 'service name unavailable'}",
                r,
                "A newly installed service can be legitimate software deployment, persistence, "
                "or remote administration. Validate the service binary, account, and installer source.",
                {"host": host, "event_id": eid, "service": service},
                "Validate the service owner, binary path, signer, parent process, and change ticket."))

        elif eid in WINDOWS_USER_CREATED_IDS:
            anomalies.append(_anomaly(
                "high", "windows_user_created",
                f"Windows user account created on {host}: {user}",
                r,
                "Unexpected account creation can provide persistence or unauthorized access.",
                {"host": host, "event_id": eid, "user": user, "subject_user": subject},
                "Confirm the account creation request and disable/remove it if unauthorized."))

        elif eid in WINDOWS_USER_DELETED_IDS:
            anomalies.append(_anomaly(
                "medium", "windows_user_deleted",
                f"Windows user account deleted on {host}: {user}",
                r,
                "Account deletion may be administrative, but can also remove an "
                "attacker-controlled account or evidence.",
                {"host": host, "event_id": eid, "user": user, "subject_user": subject},
                "Validate the change request and review the deleted account's recent activity."))

        elif eid in WINDOWS_GROUP_ADD_IDS:
            group = _field(r, "TargetUserName", "MemberName", "GroupName",
                           "TargetGroupName", default="group/member unavailable")
            anomalies.append(_anomaly(
                "high", "windows_privileged_group_change",
                f"Windows group membership changed on {host}: {group}",
                r,
                "Security-sensitive group membership changes can grant additional "
                "privileges or persistence.",
                {"host": host, "event_id": eid, "group_or_member": group,
                 "subject_user": subject},
                "Confirm the administrator/change ticket and verify the resulting privileges."))

        elif eid in WINDOWS_LOCKOUT_IDS:
            anomalies.append(_anomaly(
                "medium", "windows_account_lockout",
                f"Windows account lockout on {host}: {user}",
                r,
                "Account lockouts can indicate password guessing, stale credentials, "
                "or an operational issue.",
                {"host": host, "event_id": eid, "user": user,
                 "src_ip": _record_ip(r) or ""},
                "Correlate with nearby failed logons and identify the source "
                "generating the failures."))

        elif eid in WINDOWS_PROCESS_CREATE_IDS:
            text = " ".join(str(_field(r, k, default="")) for k in (
                "NewProcessName", "CommandLine", "ParentProcessName")).lower()
            suspicious = any(x in text for x in (
                r"\powershell.exe", r"\pwsh.exe", r"\cmd.exe",
                r"\wscript.exe", r"\cscript.exe", r"\mshta.exe",
                r"\rundll32.exe", r"\regsvr32.exe", r"\certutil.exe",
                r"\bitsadmin.exe"))
            if suspicious:
                anomalies.append(_anomaly(
                    "medium", "windows_suspicious_process",
                    f"Suspicious Windows process execution on {host}: "
                    f"{process or 'process unavailable'}",
                    r,
                    "The process name is commonly associated with scripting, LOLBins, or "
                    "command execution. Context is required; this rule is not proof of compromise.",
                    {"host": host, "event_id": eid, "process": process,
                     "command_line": _field(r, "CommandLine", default="")},
                    "Review command line, parent process, user, signer, and surrounding events."))

    return anomalies


# ---------------------------------------------------------------------------
# Cross-platform / network / security-device deterministic rules
# ---------------------------------------------------------------------------
# These rules deliberately operate on both structured fields and raw vendor
# text. They are high-signal security/availability conditions, not a claim
# that every possible OEM event has been enumerated.

DEVICE_PATTERNS = {
    "firewall": re.compile(r"\b(firewall|fortigate|fortinet|checkpoint|check point|palo alto|pan-os|sophos|asa|firepower|srx|sonicwall)\b", re.I),
    "router": re.compile(r"\b(router|routing|bgp|ospf|eigrp|cisco ios|juniper junos|arista)\b", re.I),
    "switch": re.compile(r"\b(switch|switching|spanning-tree|stp|rstp|mstp|port-security|etherchannel|lacp)\b", re.I),
    "wireless_ap": re.compile(r"\b(wireless|wifi|wi-fi|access point|\bap\b|aruba|ruckus|cisco wlc|controller)\b", re.I),
    "storage": re.compile(r"\b(storage|san|nas|netapp|synology|qnap|pure storage|emc|dell emc|isilon|powerstore|unity|raid|iscsi|fibre channel|fc port)\b", re.I),
    "siem": re.compile(r"\b(siem|log360|splunk|qradar|arcsight|sentinel|elastic|elk|wazuh|security information and event management)\b", re.I),
    "dlp": re.compile(r"\b(dlp|data loss prevention|information protection|endpoint dlp|forcepoint|symantec dlp|broadcom dlp|digital guardian)\b", re.I),
    "linux": re.compile(r"\b(sshd|sudo|pam_unix|systemd|journal|linux|ubuntu|debian|redhat|rhel|centos|rocky|almalinux|kernel|auditd)\b", re.I),
    "windows": re.compile(r"\b(windows|eventcode|eventid|winlog|powershell|microsoft-windows)\b", re.I),
}

# Generic severity vocabulary. Vendor-native severity is respected where
# possible; these patterns cover appliances that emit only textual messages.
CRITICAL_PATTERNS = [
    re.compile(r"\b(audit|security|event)\s+log\s+(cleared|deleted|purged|erased)\b", re.I),
    re.compile(r"\b(configuration|config)\s+(factory[- ]reset|reset|wiped|lost|corrupt)\b", re.I),
    re.compile(r"\b(ha|cluster)\s+(split[- ]brain|split brain|both nodes down|critical failover)\b", re.I),
    re.compile(r"\b(storage|san|nas)\s+(pool|array|volume)\s+(offline|failed|unavailable|corrupt)\b", re.I),
    re.compile(r"\b(raid)\s+(array|volume)\s+(failed|offline|degraded beyond|critical)\b", re.I),
    re.compile(r"\b(data|dlp)\s+(exfiltration|leak|loss)\s+(detected|confirmed|blocked)\b", re.I),
    re.compile(r"\b(critical|fatal)\s+(security|system|hardware|storage|cluster|service)\b", re.I),
    re.compile(r"\b(rootkit|ransomware|malware|trojan|active compromise|confirmed breach)\b", re.I),
    re.compile(r"\b(unauthorized|unknown)\s+(admin|administrator|root)\s+(login|access)\b", re.I),
]
HIGH_PATTERNS = [
    re.compile(r"\b(failed|denied|blocked|dropped)\s+(admin|administrator|root|privileged)\s+(login|authentication|access)\b", re.I),
    re.compile(r"\b(configuration|config)\s+(changed|modified|updated|committed)\b", re.I),
    re.compile(r"\b(policy|rule|acl|firewall rule)\s+(disabled|deleted|removed|changed|modified)\b", re.I),
    re.compile(r"\b(interface|port|link|uplink)\s+(down|disabled|err[- ]disabled)\b", re.I),
    re.compile(r"\b(bgp|ospf|routing)\s+(neighbor|peer|adjacency)\s+(down|reset|lost|flap)\b", re.I),
    re.compile(r"\b(stp|spanning[- ]tree)\s+(topology|root)\s+(change|changed|elected|guard)\b", re.I),
    re.compile(r"\b(arp|mac)\s+(spoof|flap|flood|attack)\b", re.I),
    re.compile(r"\b(vpn|ipsec|tunnel)\s+(failed|down|terminated|invalid)\b", re.I),
    re.compile(r"\b(wireless|wifi|wlan)\s+(rogue|evil twin|intrusion|attack|unauthorized)\b", re.I),
    re.compile(r"\b(storage|san|nas)\s+(replication|backup|snapshot)\s+(failed|failed to|error|stopped)\b", re.I),
    re.compile(r"\b(iscsi|fibre channel|fc)\s+(session|path|link)\s+(down|failed|lost)\b", re.I),
    re.compile(r"\b(dlp)\b.*\b(blocked|prevented|quarantined|policy violation)\b", re.I),
    re.compile(r"\b(siem)\b.*\b(collector|ingestion|indexer|pipeline)\b.*\b(down|failed|stopped|error)\b", re.I),
    re.compile(r"\b(command|powershell|script|process)\b.*\b(unauthorized|blocked|suspicious|malicious)\b", re.I),
]
MEDIUM_PATTERNS = [
    re.compile(r"\b(authentication|login|login attempt)\b.*\b(failed|failure|denied)\b", re.I),
    re.compile(r"\b(account|user)\b.*\b(locked|lockout|disabled)\b", re.I),
    re.compile(r"\b(interface|port|link)\b.*\b(flapp|flap|recovered|recovery|down|up)\b", re.I),
    re.compile(r"\b(packet|traffic|connection|session)\b.*\b(drop|dropped|denied|timeout|reject)\b", re.I),
    re.compile(r"\b(cpu|memory|ram|utilization)\b.*\b(8[5-9]|9[0-9]|100)\s*%", re.I),
    re.compile(r"\b(disk|filesystem|volume|storage)\b.*\b(8[0-9]|9[0-9]|100)\s*%", re.I),
    re.compile(r"\b(backup|snapshot|replication)\b.*\b(warn|warning|delayed|retry|missed)\b", re.I),
    re.compile(r"\b(dns|ntp|dhcp)\b.*\b(fail|failed|timeout|unreachable|unsynchronized)\b", re.I),
    re.compile(r"\b(wireless|wifi|wlan)\b.*\b(deauth|disassoc|roaming|authentication failure)\b", re.I),
    re.compile(r"\b(siem|collector|agent|forwarder)\b.*\b(queue|buffer|backlog|delay|dropped)\b", re.I),
    re.compile(r"\b(dlp)\b.*\b(warning|monitor|audit|violation)\b", re.I),
]
LOW_PATTERNS = [
    re.compile(r"\b(retry|retries|temporary failure|transient|reconnect|reconnected)\b", re.I),
    re.compile(r"\b(threshold|utilization)\b.*\b(7[0-9]|8[0-4])\s*%", re.I),
    re.compile(r"\b(license|certificate)\b.*\b(expir|renew|warning)\b", re.I),
    re.compile(r"\b(time|clock|ntp)\b.*\b(drift|offset)\b", re.I),
    re.compile(r"\b(interface|port|link)\b.*\b(up|restored|recovered)\b", re.I),
]

# Structured-field severity mapping used by many firewall/SIEM/JSON/CSV exports.
# NOTE: INFO/NOTICE deliberately do NOT map to a severity — a record whose only
# signal is a default/informational level must not become an alert (the
# universal parser defaults level to INFO, and honesty forbids alerting on a
# default). Textual patterns can still match such a record's message.
SEVERITY_MAP = {
    "EMERGENCY": "critical", "EMERG": "critical", "ALERT": "critical",
    "CRITICAL": "critical", "CRIT": "critical", "FATAL": "critical",
    "HIGH": "high", "ERROR": "high", "ERR": "high",
    "MEDIUM": "medium", "WARNING": "medium", "WARN": "medium",
    "LOW": "low",
}

_ALL_WINDOWS_IDS = (WINDOWS_AUDIT_CLEARED_IDS | WINDOWS_SERVICE_INSTALL_IDS |
                    WINDOWS_USER_CREATED_IDS | WINDOWS_USER_DELETED_IDS |
                    WINDOWS_GROUP_ADD_IDS | WINDOWS_LOCKOUT_IDS |
                    WINDOWS_PROCESS_CREATE_IDS |
                    WINDOWS_FAIL_IDS | WINDOWS_SUCCESS_IDS)


def _vendor(record):
    return str(_field(record, "vendor", "Vendor", "device_vendor",
                      "Manufacturer", "Product", "product", default=""))


def _device_type(record, text):
    explicit = str(_field(record, "device_type", "DeviceType", "type", "Type",
                          default="")).lower()
    for typ in DEVICE_PATTERNS:
        if typ in explicit:
            return typ
    for typ, rx in DEVICE_PATTERNS.items():
        if rx.search(text) or rx.search(_vendor(record)):
            return typ
    return "unknown"


def _structured_severity(record):
    raw = _field(record, "severity", "Severity", "level", "Level", "priority",
                 "Priority", "severity_level", default="")
    return SEVERITY_MAP.get(str(raw).strip().upper())


def _severity_from_text(text):
    for sev, patterns in (("critical", CRITICAL_PATTERNS), ("high", HIGH_PATTERNS),
                          ("medium", MEDIUM_PATTERNS), ("low", LOW_PATTERNS)):
        if any(rx.search(text) for rx in patterns):
            return sev
    return None


def detect_infrastructure_alerts(records):
    """High-signal security/availability/operational alerts across
    heterogeneous devices (firewall/router/switch/storage/SIEM/DLP...)."""
    anomalies = []
    for r in records:
        text = _all_text(r)
        if not text.strip():
            continue
        eid = _event_id(r)
        host = _entity_host(r)
        dtype = _device_type(r, text)
        sev = _structured_severity(r) or _severity_from_text(text)
        # Routine INFO/DEBUG stays silent unless a deterministic pattern matches.
        if not sev:
            continue
        # Dedicated Windows Event-ID rules own their events.
        if eid in _ALL_WINDOWS_IDS:
            continue
        # Ordinary success/up/recovery lines are not alerts.
        if sev == "low" and not any(x in text.lower() for x in (
                "warning", "threshold", "expir", "drift", "retry",
                "certificate", "license")):
            continue
        action = {
            "critical": "Immediately validate the event, preserve evidence, identify the actor/source and assess service or security impact.",
            "high": "Validate the event against an approved change/security action and investigate the source, affected asset and surrounding events.",
            "medium": "Correlate with nearby events and confirm whether this is expected operational activity or a security/availability issue.",
            "low": "Review during routine monitoring and confirm that the condition is expected or below the operational threshold.",
        }[sev]
        summary = f"{dtype.replace('_', ' ').title()} {sev} alert on {host}"
        if eid:
            summary += f" (EventID {eid})"
        anomalies.append(_anomaly(
            sev, f"infra_{dtype}_{sev}", summary, r,
            f"Deterministic cross-platform rule matched a {sev.upper()} condition "
            f"in {dtype.replace('_', ' ')} telemetry.",
            {"host": host, "device_type": dtype, "event_id": eid or "",
             "vendor": _vendor(r)},
            action))
    return anomalies


# ---------------------------------------------------------------------------
# Threat / IOC detection across heterogeneous telemetry
# ---------------------------------------------------------------------------

THREAT_PATTERNS = [
    ("critical", "threat_ransomware", re.compile(r"\b(ransomware|crypto\w*locker|files encrypted|mass encryption|ransom note)\b", re.I)),
    ("critical", "threat_active_compromise", re.compile(r"\b(active compromise|confirmed breach|account takeover|credential theft confirmed)\b", re.I)),
    ("high", "threat_c2_indicator", re.compile(r"\b(command[- ]and[- ]control|c2|beacon(?:ing)?|reverse shell|meterpreter|cobalt strike|powershell.*download|download.*powershell)\b", re.I)),
    ("high", "threat_malware_indicator", re.compile(r"\b(malware|trojan|backdoor|rootkit|keylogger|botnet|malicious payload|malicious executable)\b", re.I)),
    ("high", "threat_persistence", re.compile(r"\b(persistence|scheduled task created|run key|startup folder|new service.*persistence|cron.*persistence)\b", re.I)),
    ("high", "threat_privilege_escalation", re.compile(r"\b(privilege escalation|elevated privileges|added to administrators|sudoers modified|setuid)\b", re.I)),
    ("high", "threat_lateral_movement", re.compile(r"\b(lateral movement|pass[- ]the[- ]hash|remote service|psexec|wmic.*remote|winrm.*remote|remote desktop.*suspicious)\b", re.I)),
    ("medium", "threat_port_scan", re.compile(r"\b(port scan|network scan|host discovery|masscan|nmap scan|scan detected)\b", re.I)),
    ("medium", "threat_credential_attack", re.compile(r"\b(password spray|credential stuffing|brute[- ]force|multiple authentication failures|login failures from multiple)\b", re.I)),
    ("medium", "threat_rogue_wireless", re.compile(r"\b(rogue ap|evil twin|unauthorized access point|wireless intrusion)\b", re.I)),
    ("medium", "threat_data_exfiltration", re.compile(r"\b(data exfiltration|large outbound transfer|sensitive data.*external|dlp.*exfiltration)\b", re.I)),
]

IOC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|ru|cn|top|xyz|info|biz|io|cc)\b", re.I)
IOC_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.I)


def detect_threats(records):
    """Deterministic threat-vocabulary patterns in security telemetry text."""
    out = []
    for r in records:
        text = " ".join(str(r.get(k, "")) for k in
                        ("raw", "msg", "original_msg", "message") if r.get(k))
        if not text.strip():
            continue
        for sev, atype, rx in THREAT_PATTERNS:
            if not rx.search(text):
                continue
            ips = sorted(set(IOC_IP_RE.findall(text)))
            domains = sorted(set(IOC_DOMAIN_RE.findall(text)))
            hashes = sorted(set(IOC_HASH_RE.findall(text)))
            host = _entity_host(r)
            out.append(_anomaly(
                sev, atype,
                f"{atype.replace('_', ' ').title()} detected on {host}",
                r,
                f"Deterministic threat pattern matched security telemetry: {rx.pattern}",
                {"host": host, "ioc_ips": ips, "ioc_domains": domains,
                 "ioc_hashes": hashes},
                "Preserve evidence, identify the source and affected asset, correlate "
                "adjacent events, and contain according to the incident playbook."))
            break
    return out


def detect_iocs(records):
    """Surface explicit IP/domain/hash indicators WITHOUT declaring them malicious."""
    out = []
    for r in records:
        text = " ".join(str(r.get(k, "")) for k in
                        ("raw", "msg", "original_msg", "message") if r.get(k))
        ips = sorted(set(IOC_IP_RE.findall(text)))
        domains = sorted(set(IOC_DOMAIN_RE.findall(text)))
        hashes = sorted(set(IOC_HASH_RE.findall(text)))
        if not (ips or domains or hashes):
            continue
        # Presence of an IP alone is NOT an indicator; require security context.
        if not re.search(r"\b(c2|malware|trojan|ransomware|blocked|denied|indicator|ioc|threat|exploit|attack)\b", text, re.I):
            continue
        out.append(_anomaly(
            "medium", "ioc_observed",
            f"Potential IOC observed on {_entity_host(r)}", r,
            "An IP, domain or file hash was observed in security-relevant context. "
            "Presence alone does not prove maliciousness.",
            {"host": _entity_host(r), "ioc_ips": ips, "ioc_domains": domains,
             "ioc_hashes": hashes},
            "Validate the indicator against approved threat-intelligence sources "
            "and correlate it with the originating asset."))
    return out


# ---------------------------------------------------------------------------
# ZooKeeper application rules (WARN/INFO lifecycle patterns, threshold-scored)
# ---------------------------------------------------------------------------

def _zk_severity(count, thresholds):
    for minimum, severity in thresholds:
        if count >= minimum:
            return severity.lower()
    return "info"


_ZK_RULES = (
    {
        "type": "zookeeper_connection_broken",
        "pattern": re.compile(r"\bConnection broken for id\b", re.I),
        "summary": "ZooKeeper quorum connection repeatedly broke between peer nodes",
        "rationale": "Repeated quorum connection breaks can indicate unstable peer communication, network loss, or a failing ZooKeeper peer.",
        "action": "Check ZooKeeper peer connectivity on the quorum port, packet loss/latency, firewall rules, node health, and ZooKeeper server logs on both peers.",
        "thresholds": ((20, "HIGH"), (5, "MEDIUM"), (1, "LOW")),
    },
    {
        "type": "zookeeper_sendworker_exit",
        "pattern": re.compile(r"\bSend worker leaving thread\b", re.I),
        "summary": "ZooKeeper SendWorker thread repeatedly exited",
        "rationale": "Repeated SendWorker exits are consistent with churn in the quorum communication layer and should be correlated with peer connection failures.",
        "action": "Correlate SendWorker exits with Connection broken and Interrupting SendWorker events; verify peer reachability and ZooKeeper JVM/node health.",
        "thresholds": ((30, "HIGH"), (10, "MEDIUM"), (1, "LOW")),
    },
    {
        "type": "zookeeper_sendworker_interrupted",
        "pattern": re.compile(r"\bInterrupted while waiting for message on queue\b", re.I),
        "summary": "ZooKeeper SendWorker was repeatedly interrupted while waiting for quorum messages",
        "rationale": "Frequent queue interruptions can accompany quorum connection churn and thread shutdown/restart activity.",
        "action": "Review quorum connection stability, JVM/thread health, and the surrounding ZooKeeper WARN/ERROR sequence.",
        "thresholds": ((50, "MEDIUM"), (10, "LOW"), (1, "INFO")),
    },
    {
        "type": "zookeeper_sendworker_interrupt",
        "pattern": re.compile(r"\bInterrupting SendWorker\b", re.I),
        "summary": "ZooKeeper RecvWorker repeatedly interrupted a SendWorker",
        "rationale": "This is a quorum communication lifecycle event. High recurrence together with broken connections indicates instability rather than a normal isolated shutdown.",
        "action": "Correlate with Connection broken and SendWorker exit events and inspect network and peer health.",
        "thresholds": ((30, "MEDIUM"), (10, "LOW"), (1, "INFO")),
    },
    {
        "type": "zookeeper_peer_connection_request",
        "pattern": re.compile(r"\bReceived connection request\s+/\S+", re.I),
        "summary": "ZooKeeper received a quorum peer connection request",
        "rationale": "Peer connection requests are normally informational, but a high rate alongside connection failures can indicate reconnect churn.",
        "action": "Review the rate of peer reconnects and correlate the source peer with Connection broken events.",
        "thresholds": ((50, "LOW"), (10, "INFO"), (1, "INFO")),
    },
    {
        "type": "zookeeper_session_expired",
        "pattern": re.compile(r"\bExpiring session\b.*\btimeout of\b.*\bexceeded\b", re.I),
        "summary": "ZooKeeper session expired because its timeout was exceeded",
        "rationale": "An expired session means the client did not maintain its ZooKeeper session within the negotiated timeout.",
        "action": "Identify the client, check client-to-ZooKeeper connectivity and latency, and correlate with server load and quorum instability.",
        "thresholds": ((10, "HIGH"), (3, "MEDIUM"), (1, "LOW")),
    },
    {
        "type": "zookeeper_socket_closed",
        "pattern": re.compile(r"\bClosed socket connection for client\b", re.I),
        "summary": "ZooKeeper closed a client socket connection",
        "rationale": "A single socket close is common lifecycle activity; repeated closes should be correlated with session expiration or connection churn.",
        "action": "Correlate the client address with session expiration, reconnects, and application health before treating it as an incident.",
        "thresholds": ((30, "LOW"), (1, "INFO")),
    },
    {
        "type": "zookeeper_leader_election",
        "pattern": re.compile(r"\bFastLeaderElection\b.*\b(LOOKING|leader)\b", re.I),
        "summary": "ZooKeeper leader-election activity was recorded",
        "rationale": "Leader-election activity can be normal during startup, but repeated elections during an established cluster can indicate quorum instability.",
        "action": "Correlate election events with quorum connection failures, node restarts, latency, and cluster membership.",
        "thresholds": ((5, "HIGH"), (2, "MEDIUM"), (1, "LOW")),
    },
)

_ZK_MARKER_RE = re.compile(
    r"(?:QuorumCnxManager|ZooKeeperServer|FastLeaderElection|NIOServerCnxn)", re.I)


def _zookeeper_extra_anomalies(records):
    """Application-specific ZooKeeper conditions missed by generic rules.

    Operates on the already-normalized record stream, so it works with plain
    ZooKeeper logs as well as logs coming through the universal parser. The
    ruleset only activates when the input actually looks like ZooKeeper.
    """
    if not records:
        return []

    matched = {rule["type"]: [] for rule in _ZK_RULES}
    for rec in records:
        text = _record_text(rec)
        if not text:
            continue
        for rule in _ZK_RULES:
            if rule["pattern"].search(text):
                matched[rule["type"]].append(rec)

    zk_total = sum(len(v) for v in matched.values())
    zk_marker = any(_ZK_MARKER_RE.search(_record_text(r)) for r in records[:1000])
    if not zk_marker and zk_total == 0:
        return []

    findings = []
    for rule in _ZK_RULES:
        hits = matched[rule["type"]]
        if not hits:
            continue

        count = len(hits)
        sev = _zk_severity(count, rule["thresholds"])

        # Compact evidence timeline: first 8 samples plus an honest "N more"
        # marker, so a 2,000-line file does not create a huge report.
        timeline = [_timeline_entry(r, _record_text(r)[:300]) for r in hits[:8]]
        if count > 8:
            timeline.append(_timeline_entry(
                hits[-1], f"... {count - 8} additional matching event(s)"))

        first = _record_text(hits[0])[:500]
        last = _record_text(hits[-1])[:500]
        line_numbers = [_line(r) for r in hits if _line(r)]
        entities = {}

        ips = []
        for h in hits:
            ips.extend(re.findall(r"/((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?",
                                  _record_text(h)))
        if ips:
            entities["ips"] = list(dict.fromkeys(ips))[:20]

        summary = rule["summary"]
        if count > 1:
            summary += f" ({count} occurrences)"

        findings.append({
            "severity": sev,
            "type": rule["type"],
            "summary": summary,
            "evidence": (
                f"{first}"
                + (f" | last matching event: {last}" if last != first else "")
                + (f" | source lines: {min(line_numbers)}-{max(line_numbers)}"
                   if line_numbers else "")),
            "rationale": rule["rationale"],
            "entities": entities,
            "occurrences": count,
            "timeline": timeline,
            "predicate": f"ZooKeeper pattern '{rule['type']}' matched {count} record(s)",
            "recommended_action": rule["action"],
            "source": "zookeeper_rules",
        })

    # Correlation alert: the combination is more useful than any single WARN.
    broken = len(matched["zookeeper_connection_broken"])
    exits = len(matched["zookeeper_sendworker_exit"])
    interrupted = len(matched["zookeeper_sendworker_interrupt"])
    queue_wait = len(matched["zookeeper_sendworker_interrupted"])
    if broken and (exits or interrupted or queue_wait):
        total = broken + exits + interrupted + queue_wait
        if broken >= 20 and (exits + interrupted + queue_wait) >= 20:
            sev = "critical"
        elif broken >= 5 and (exits + interrupted + queue_wait) >= 5:
            sev = "high"
        else:
            sev = "medium"
        findings.append({
            "severity": sev,
            "type": "zookeeper_quorum_instability",
            "summary": (
                "ZooKeeper quorum communication instability detected: "
                f"{broken} connection-break event(s), {exits} SendWorker exit(s), "
                f"{interrupted} SendWorker interrupt(s), and {queue_wait} "
                "queue interruption(s)"),
            "evidence": (
                "Multiple ZooKeeper quorum failure lifecycle patterns occurred in the "
                "same log. This is a correlation alert, not a claim of malicious activity."),
            "rationale": "The combination of repeated broken peer connections and worker "
                         "interruption/exit activity is a stronger availability signal "
                         "than any single WARN event.",
            "entities": {},
            "occurrences": total,
            "timeline": [],
            "predicate": "Correlated ZooKeeper quorum communication instability",
            "recommended_action": (
                "Check all ZooKeeper peers on the quorum ports, packet loss/latency, "
                "firewall/load-balancer behavior, JVM saturation, disk I/O, and "
                "cluster health."),
            "source": "zookeeper_rules",
        })

    return findings


# ---------------------------------------------------------------------------
# Universal application/OS high-signal detection
# ---------------------------------------------------------------------------
# These rules complement, rather than replace, anomaly_detector/rules_syslog.
# They intentionally collapse repeated occurrences into semantic findings while
# preserving the occurrence count and source-line evidence.

_GENERIC_RULES = (
    ("generic_fatal_error", re.compile(r"\b(?:FATAL|CRITICAL|PANIC)\b", re.I), "critical", "Critical/fatal condition reported by the application or OS", "Investigate the surrounding events, process/service state, and recent configuration or deployment changes."),
    ("generic_out_of_memory", re.compile(r"(?:out of memory|oom-killer|oom kill|cannot allocate memory|java\.lang\.OutOfMemoryError|memory allocation failed)", re.I), "critical", "Out-of-memory condition detected", "Check memory pressure, OOM-killer events, process limits, JVM/container limits, and recent workload changes."),
    ("generic_disk_full", re.compile(r"(?:no space left on device|disk (?:is )?full|filesystem.*(?:full|100%|9[5-9]%))", re.I), "high", "Disk/filesystem capacity exhaustion detected", "Check filesystem utilization, inode usage, application logs, and safe cleanup/retention."),
    ("generic_service_failed", re.compile(r"(?:failed to start|start request repeated too quickly|service.*failed|unit .* failed|failed with result|Main process exited.*failure)", re.I), "high", "Service startup or runtime failure detected", "Check service status, dependencies, recent configuration changes, and the service journal/log."),
    ("generic_kernel_fault", re.compile(r"(?:kernel panic|segfault|general protection fault|BUG: unable to handle kernel|Oops:|call trace:)", re.I), "critical", "Kernel-level fault detected", "Investigate kernel/module changes, hardware health, crash dumps, and the affected host."),
    ("generic_connection_refused", re.compile(r"(?:connection refused|connect\(\).*refused|connection reset by peer|connection timed out|connect timeout)", re.I), "medium", "Network connection failure detected", "Check endpoint reachability, listening ports, firewall rules, routing, service health, and packet loss/latency."),
    ("generic_tls_failure", re.compile(r"(?:SSL(?:_ERROR)?|TLS).*(?:handshake|certificate|verify|alert|failed|error)|certificate.*(?:expired|invalid|verify failed)", re.I), "high", "TLS/SSL or certificate failure detected", "Verify certificate validity/chain, system time, trust stores, protocol/cipher compatibility, and the peer configuration."),
    ("generic_auth_failure", re.compile(r"(?:authentication failure|auth(?:entication)? failed|failed password|invalid password|login failed|user authentication failed)", re.I), "medium", "Authentication failure detected", "Correlate source, account, time, and recurrence; investigate brute-force or misconfiguration when repeated."),
    ("generic_permission_denied", re.compile(r"(?:permission denied|access denied|operation not permitted|unauthorized)", re.I), "medium", "Permission or authorization failure detected", "Verify the account, requested resource, ACL/role policy, and whether the access was expected."),
    ("generic_file_integrity", re.compile(r"(?:integrity check failed|checksum mismatch|hash mismatch|modified unexpectedly|tamper(?:ed|ing) detected)", re.I), "high", "File/integrity validation failure detected", "Validate the affected file/object against a trusted baseline and review the initiating process and account."),
    ("generic_security_block", re.compile(r"(?:blocked|denied|dropped).*(?:connection|packet|request|traffic)|(?:firewall|ids|ips).*(?:block|deny|drop)", re.I), "medium", "Security/network control blocked or denied activity", "Identify source, destination, rule/policy, and recurrence; determine whether the blocked activity was malicious or expected."),
    ("generic_http_server_error", re.compile(r"(?:HTTP/[12](?:\.\d)?\s+5\d\d|\b(?:status|response)\s+5\d\d\b|\b5\d\d\s+(?:GET|POST|PUT|DELETE))", re.I), "medium", "HTTP server-side error detected", "Correlate the endpoint, application error, upstream dependency, and request volume."),
    ("generic_database_failure", re.compile(r"(?:database|db|sql).*(?:connection failed|connection refused|deadlock|too many connections|query failed|timeout|unavailable)", re.I), "high", "Database availability or query failure detected", "Check database health, connection pool limits, locks/deadlocks, latency, and application dependency status."),
)

_PROMOTE = {"info": "low", "low": "medium", "medium": "high",
            "high": "critical", "critical": "critical"}


def _generic_extra_anomalies(records):
    if not records:
        return []
    hits = {rid: [] for rid, *_ in _GENERIC_RULES}
    for rec in records:
        text = _record_text(rec)
        if not text:
            continue
        for rid, pattern, *_ in _GENERIC_RULES:
            if pattern.search(text):
                hits[rid].append(rec)
    findings = []
    for rid, pattern, base_sev, summary, action in _GENERIC_RULES:
        rows = hits[rid]
        if not rows:
            continue
        # Repeated medium/high-signal failures are promoted one level.
        sev = _PROMOTE[base_sev] if len(rows) >= 10 else base_sev
        lines = [_line(r) for r in rows if _line(r)]
        sample = _record_text(rows[0])[:500]
        findings.append({
            "severity": sev,
            "type": rid,
            "summary": f"{summary} ({len(rows)} occurrences)",
            "evidence": sample + (f" | source lines: {min(lines)}-{max(lines)}"
                                  if lines else ""),
            "rationale": f"Deterministic high-signal pattern matched {len(rows)} "
                         "log record(s). Severity is rule-derived and recurrence-aware.",
            "entities": {},
            "occurrences": len(rows),
            "timeline": [_timeline_entry(r, _record_text(r)[:300]) for r in rows[:8]],
            "predicate": f"Generic high-signal pattern '{rid}' matched {len(rows)} record(s)",
            "recommended_action": action,
            "source": "generic_rules",
        })
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def detect_app_extra(records):
    """All app/vendor-level sibling findings for one record stream.

    Purely additive: returns NEW findings with their own types. Never reads,
    filters, or rewrites what the frozen detector found.
    """
    anomalies = []
    anomalies.extend(detect_windows_extra(records))
    anomalies.extend(detect_infrastructure_alerts(records))
    anomalies.extend(detect_threats(records))
    anomalies.extend(detect_iocs(records))
    anomalies.extend(_zookeeper_extra_anomalies(records))
    anomalies.extend(_generic_extra_anomalies(records))
    return anomalies
