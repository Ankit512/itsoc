#!/usr/bin/env python3
"""
rules_syslog.py — deterministic vocabulary/rule adapter for syslog and Windows text.

Compatibility contract with log_analyzer(2).py:
  * canonicalize(records) -> (records, counts)
  * dedupe_auth_attempts(records) -> (records, dropped)
  * detect_extra(records) -> list[anomaly]
  * canonical Windows 4625/4624 messages into anomaly_detector.py's auth vocabulary
  * preserve raw/original vendor text for evidence
"""
import re
from collections import defaultdict

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP, re.I
)
INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from " + IP, re.I)
PAM_FAILURE = re.compile(
    r"authentication failure;.*?rhost=" + IP + r"(?:\s+user=(?P<user>\S+))?", re.I
)
ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from "
    + IP, re.I
)
BREAK_IN = re.compile(r"POSSIBLE BREAK-IN ATTEMPT", re.I)
BRACKETED_IP = re.compile(r"\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]")

# Windows Event Log authentication vocabulary.
WINDOWS_FAIL_IDS = {"4625"}
WINDOWS_SUCCESS_IDS = {"4624"}
WINDOWS_USER_CREATED_IDS = {"4720"}
WINDOWS_USER_DELETED_IDS = {"4726"}
WINDOWS_GROUP_ADD_IDS = {"4732", "4728", "4756"}
WINDOWS_LOCKOUT_IDS = {"4740"}
WINDOWS_AUDIT_CLEARED_IDS = {"1102", "104"}
WINDOWS_SERVICE_INSTALL_IDS = {"7045"}
WINDOWS_PROCESS_CREATE_IDS = {"4688"}
WINDOWS_SPECIAL_PRIV_IDS = {"4672"}

CANON_FAIL = "auth failed for user '{user}' from {ip}"
CANON_OK = "auth success for user '{user}' from {ip}"


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


def _is_windows_event(record, event_id=None):
    return event_id is not None or any(
        k in record for k in (
            "EventCode", "EventID", "EventId", "LogName", "ProviderName",
            "ComputerName", "TargetUserName", "SubjectUserName"
        )
    )


def canonical_form(msg, record=None):
    """
    Translate real Linux/Windows authentication messages into v1 vocabulary.

    Returns (canonical_msg, kind, source, ip).
    """
    record = record or {}

    m = FAILED_PASSWORD.search(msg)
    if m:
        return (
            CANON_FAIL.format(user=m.group("user"), ip=m.group("ip")),
            "auth_fail", "failed_password", m.group("ip")
        )

    m = INVALID_USER.search(msg)
    if m:
        return (
            CANON_FAIL.format(user=m.group("user"), ip=m.group("ip")),
            "auth_fail", "invalid_user", m.group("ip")
        )

    m = PAM_FAILURE.search(msg)
    if m:
        return (
            CANON_FAIL.format(user=m.group("user") or "unknown", ip=m.group("ip")),
            "auth_fail", "pam_failure", m.group("ip")
        )

    m = ACCEPTED_PASSWORD.search(msg)
    if m:
        return (
            CANON_OK.format(user=m.group("user"), ip=m.group("ip")),
            "auth_ok", "accepted_password", m.group("ip")
        )

    event_id = _event_id(record)
    if event_id in WINDOWS_FAIL_IDS:
        ip = _record_ip(record)
        user = _record_user(record)
        if ip and str(ip).strip() not in {"-", "::1", "127.0.0.1", "0.0.0.0"}:
            return (
                CANON_FAIL.format(user=user, ip=ip),
                "auth_fail", "windows_4625", str(ip)
            )

    if event_id in WINDOWS_SUCCESS_IDS:
        ip = _record_ip(record)
        user = _field(
            record, "TargetUserName", "TargetUsername", "UserName",
            "Username", "AccountName", "SubjectUserName", default="unknown"
        )
        if ip and str(ip).strip() not in {"-", "::1", "127.0.0.1", "0.0.0.0"}:
            return (
                CANON_OK.format(user=user, ip=ip),
                "auth_ok", "windows_4624", str(ip)
            )

    return msg, None, None, None


def canonicalize(records):
    """Rewrite msg in safe copies. raw is never changed."""
    out = []
    counts = {
        "auth_fail": 0, "auth_ok": 0, "untouched": 0,
        "windows_auth_fail": 0, "windows_auth_ok": 0,
    }
    for r in records:
        msg = str(r.get("msg") or r.get("message") or r.get("raw") or "")
        canon, kind, source, ip = canonical_form(msg, r)
        copy = dict(r)
        if kind:
            copy["msg"] = canon
            copy["original_msg"] = msg
            copy["auth_source"] = source
            copy["auth_ip"] = ip
            counts[kind] += 1
            if source.startswith("windows_"):
                counts[f"{kind.replace('auth_', 'windows_auth_')}"] += 1
        else:
            counts["untouched"] += 1
        out.append(copy)
    return out, counts


COMPANION_SOURCES = ("invalid_user", "pam_failure")


def dedupe_auth_attempts(records):
    """
    Collapse sshd Invalid-user/PAM companion lines when a Failed-password anchor
    exists for the same (IP,pid). Windows events are left untouched.
    """
    anchored = {
        (r.get("auth_ip"), r.get("pid"))
        for r in records
        if r.get("auth_source") == "failed_password"
    }
    kept, dropped = [], 0
    for r in records:
        if (
            r.get("auth_source") in COMPANION_SOURCES
            and (r.get("auth_ip"), r.get("pid")) in anchored
        ):
            dropped += 1
            continue
        kept.append(r)
    return kept, dropped


def _line(record):
    return _field(record, "n", "line", "LineNumber", default=0)


def _raw(record):
    return str(record.get("raw") or record.get("original_msg") or record.get("msg") or "")


def _entity_host(record):
    return _field(record, "host", "ComputerName", "Hostname", "Computer", default="unknown")


def _anomaly(
    severity, atype, summary, record, rationale, entities=None, recommended_action=""
):
    return {
        "severity": severity,
        "type": atype,
        "summary": summary,
        "evidence": _raw(record),
        "rationale": rationale,
        "entities": entities or {},
        "recommended_action": recommended_action,
    }


def detect_windows_extra(records):
    """
    Windows Event-ID rules not covered by anomaly_detector.py.

    These are intentionally high-signal events rather than one finding per routine
    4624/4672 event.  Authentication correlation remains delegated to the v1
    detector after canonicalization.
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
                "Identify the actor and source, preserve remaining logs, and investigate activity immediately before the clear."
            ))

        elif eid in WINDOWS_SERVICE_INSTALL_IDS:
            anomalies.append(_anomaly(
                "high", "windows_service_installed",
                f"New Windows service installed on {host}: {service or 'service name unavailable'}",
                r,
                "A newly installed service can be legitimate software deployment, persistence, "
                "or remote administration. Validate the service binary, account, and installer source.",
                {"host": host, "event_id": eid, "service": service},
                "Validate the service owner, binary path, signer, parent process, and change ticket."
            ))

        elif eid in WINDOWS_USER_CREATED_IDS:
            anomalies.append(_anomaly(
                "high", "windows_user_created",
                f"Windows user account created on {host}: {user}",
                r,
                "Unexpected account creation can provide persistence or unauthorized access.",
                {"host": host, "event_id": eid, "user": user, "subject_user": subject},
                "Confirm the account creation request and disable/remove it if unauthorized."
            ))

        elif eid in WINDOWS_USER_DELETED_IDS:
            anomalies.append(_anomaly(
                "medium", "windows_user_deleted",
                f"Windows user account deleted on {host}: {user}",
                r,
                "Account deletion may be administrative, but can also remove an attacker-controlled account or evidence.",
                {"host": host, "event_id": eid, "user": user, "subject_user": subject},
                "Validate the change request and review the deleted account's recent activity."
            ))

        elif eid in WINDOWS_GROUP_ADD_IDS:
            group = _field(
                r, "TargetUserName", "MemberName", "GroupName",
                "TargetGroupName", default="group/member unavailable"
            )
            anomalies.append(_anomaly(
                "high", "windows_privileged_group_change",
                f"Windows group membership changed on {host}: {group}",
                r,
                "Security-sensitive group membership changes can grant additional privileges or persistence.",
                {"host": host, "event_id": eid, "group_or_member": group, "subject_user": subject},
                "Confirm the administrator/change ticket and verify the resulting privileges."
            ))

        elif eid in WINDOWS_LOCKOUT_IDS:
            anomalies.append(_anomaly(
                "medium", "windows_account_lockout",
                f"Windows account lockout on {host}: {user}",
                r,
                "Account lockouts can indicate password guessing, stale credentials, or an operational issue.",
                {"host": host, "event_id": eid, "user": user, "src_ip": _record_ip(r) or ""},
                "Correlate with nearby failed logons and identify the source generating the failures."
            ))

        elif eid in WINDOWS_PROCESS_CREATE_IDS:
            text = " ".join(str(_field(r, k, default="")) for k in (
                "NewProcessName", "CommandLine", "ParentProcessName"
            )).lower()
            suspicious = any(x in text for x in (
                r"\powershell.exe", r"\pwsh.exe", r"\cmd.exe",
                r"\wscript.exe", r"\cscript.exe", r"\mshta.exe",
                r"\rundll32.exe", r"\regsvr32.exe", r"\certutil.exe",
                r"\bitsadmin.exe",
            ))
            if suspicious:
                anomalies.append(_anomaly(
                    "medium", "windows_suspicious_process",
                    f"Suspicious Windows process execution on {host}: "
                    f"{process or 'process unavailable'}",
                    r,
                    "The process name is commonly associated with scripting, LOLBins, or "
                    "command execution. Context is required; this rule is not proof of compromise.",
                    {
                        "host": host, "event_id": eid, "process": process,
                        "command_line": _field(r, "CommandLine", default=""),
                    },
                    "Review command line, parent process, user, signer, and surrounding events."
                ))

    return anomalies


CBS_HRESULT_RE = re.compile(
    r"HRESULT\s*=\s*(0x[0-9a-fA-F]+)(?:\s*-\s*([A-Z][A-Z0-9_]+))?",
    re.I,
)
CBS_FAIL_RE = re.compile(
    r"\b(failed|failure|error|corrupt|exception|unable to)\b",
    re.I,
)
CBS_STORE_HRESULT_RE = re.compile(r"^(?:CBS_E_|CSI_E_|SPAPI_E_)", re.I)
CBS_VOLUME_HIGH = 10


def _is_windows_cbs(record):
    ch = str(_field(record, "channel", "cbs_channel", default="") or "").upper()
    return ch in {"CBS", "CSI", "DISM"}


def _cbs_head(text):
    head = CBS_HRESULT_RE.sub("", text)
    head = re.sub(r"[A-Za-z]:\\[^\s,\]]+", "<path>", head)
    head = re.sub(r"\s+", " ", head).strip(" :-[]")
    return head[:96] or "servicing message"


def detect_windows_cbs(records):
    """Group CBS/CSI/DISM Fail/HRESULT/Warning bursts.

    Record.level stays source-reported (Info stays Info). Severity here is
    operational, from HRESULT/fail grouping — not an Event-Log ERROR rewrite
    and not a claim of compromise. One finding per (channel, signature).
    """
    groups = defaultdict(list)
    for r in records:
        if not _is_windows_cbs(r):
            continue
        text = str(r.get("msg") or r.get("message") or "") or _raw(r)
        source = str(r.get("level") or "").upper()
        hm = CBS_HRESULT_RE.search(text)
        is_fail = bool(hm) or bool(CBS_FAIL_RE.search(text))
        is_warn_text = bool(re.search(r"\bwarning\b", text, re.I))
        source_alert = source in {
            "WARN", "WARNING", "ERROR", "ERR", "CRIT", "CRITICAL",
        }
        if not (is_fail or is_warn_text or source_alert):
            continue
        channel = str(_field(r, "channel", "cbs_channel", default="CBS") or "CBS").upper()
        if hm:
            code, name = hm.group(1), (hm.group(2) or "")
            kind = "hresult"
            sig = (name or code).upper()
            extra = {"hresult": code, "hresult_name": name or code}
        elif (is_warn_text or source in {"WARN", "WARNING"}) and not is_fail:
            kind = "warning"
            sig = _cbs_head(text)
            extra = {}
        else:
            kind = "failure"
            sig = _cbs_head(text)
            extra = {}
        groups[(kind, channel, sig)].append((r, extra, source))

    rank = {
        "CRIT": 4, "CRITICAL": 4,
        "ERROR": 3, "ERR": 3,
        "WARN": 2, "WARNING": 2,
        "INFO": 0, "INFORMATION": 0, "DEBUG": 0, "VERBOSE": 0,
    }
    anomalies = []
    for (kind, channel, sig), hits in sorted(
        groups.items(), key=lambda kv: (-len(kv[1]), kv[0])
    ):
        recs = [h[0] for h in hits]
        extras = hits[0][1]
        worst = max(rank.get(h[2], 0) for h in hits)
        n = len(recs)
        first, last = _line(recs[0]), _line(recs[-1])
        if worst >= 4:
            sev = "critical"
        elif worst >= 3:
            sev = "high"
        elif kind == "hresult":
            name = str(extras.get("hresult_name") or sig)
            if CBS_STORE_HRESULT_RE.match(name) and n >= CBS_VOLUME_HIGH:
                sev = "high"
            else:
                sev = "medium"
        elif kind == "warning":
            sev = "medium" if worst >= 2 else "low"
        else:
            sev = "medium"

        atype = {
            "hresult": "windows_cbs_hresult",
            "warning": "windows_cbs_warning",
            "failure": "windows_cbs_failure",
        }[kind]
        if kind == "hresult":
            label = extras.get("hresult_name") or extras.get("hresult") or sig
            summary = f"{channel} HRESULT {label} ×{n}"
        elif kind == "warning":
            summary = f"{channel} warning: {sig} ×{n}"
        else:
            summary = f"{channel} servicing failure: {sig} ×{n}"

        entities = {
            "channel": channel,
            "occurrences": n,
            "signature": sig,
        }
        entities.update(extras)
        anomalies.append({
            "severity": sev,
            "type": atype,
            "summary": summary,
            "evidence": _raw(recs[0]),
            "rationale": (
                f"Grouped {n} CBS/CSI/DISM line(s) (lines {first}-{last}) sharing "
                f"signature {sig!r}. Source-reported level is preserved on each "
                "record; this severity is operational (servicing Fail/HRESULT), "
                "not a Windows Event-Log ERROR and not a compromise verdict."
            ),
            "entities": entities,
            "recommended_action": (
                "Review the Windows component store (CBS.log / DISM), the named "
                "HRESULT, and whether a pending reboot or corrupt package is "
                "blocking servicing."
            ),
            "occurrences": n,
            "timeline": [
                {"line": _line(r), "message": _raw(r)[:300]} for r in recs[:50]
            ],
        })
    return anomalies


def detect_break_in_attempts(records):
    """Aggregate sshd reverse-DNS mismatch warnings by source IP."""
    by_ip = defaultdict(list)
    for r in records:
        text = str(r.get("original_msg") or r.get("msg") or "")
        raw = _raw(r)
        if not BREAK_IN.search(text) and not BREAK_IN.search(raw):
            continue
        m = BRACKETED_IP.search(raw)
        ip = m.group("ip") if m else _record_ip(r)
        if ip:
            by_ip[str(ip)].append(r)

    anomalies = []
    for ip, hits in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
        first, last = _line(hits[0]), _line(hits[-1])
        anomalies.append({
            "severity": "medium",
            "type": "possible_break_in",
            "summary": f"{len(hits)}x reverse-DNS mismatch flagged as POSSIBLE BREAK-IN from {ip}",
            "evidence": _raw(hits[0]),
            "rationale": (
                "sshd could not reverse-resolve the client address consistently. "
                "This can be caused by DNS configuration, but repeated occurrences "
                f"from one source ({len(hits)} here, lines {first}-{last}) are worth investigation."
            ),
            "entities": {"ip": ip, "occurrences": len(hits)},
        })
    return anomalies



# ---------------------------------------------------------------------------
# Cross-platform / network / security-device deterministic rules
# ---------------------------------------------------------------------------
# These rules deliberately operate on both structured fields and raw vendor text.
# They are high-signal security/availability conditions, not a claim that every
# possible OEM event has been enumerated.

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

# Generic severity vocabulary. Vendor-native severity is respected where possible,
# but these patterns cover appliances that emit only textual messages.
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
SEVERITY_MAP = {
    "EMERGENCY": "critical", "EMERG": "critical", "ALERT": "critical", "CRITICAL": "critical", "CRIT": "critical", "FATAL": "critical",
    "HIGH": "high", "ERROR": "high", "ERR": "high",
    "MEDIUM": "medium", "WARNING": "medium", "WARN": "medium",
    "LOW": "low", "NOTICE": "low", "INFO": "low", "INFORMATION": "low",
}


def _all_text(record):
    vals = []
    for k in ("raw", "msg", "message", "Message", "event", "Event", "action", "Action", "reason", "Reason", "description", "Description"):
        v = record.get(k)
        if v not in (None, ""):
            vals.append(str(v))
    return " ".join(vals)


def _vendor(record):
    return str(_field(record, "vendor", "Vendor", "device_vendor", "Manufacturer", "Product", "product", default=""))


def _device_type(record, text):
    explicit = str(_field(record, "device_type", "DeviceType", "type", "Type", default="")).lower()
    for typ in DEVICE_PATTERNS:
        if typ in explicit:
            return typ
    # Vendor is the same for every iteration — computed once, not 9 times.
    vendor = _vendor(record)
    # Union gate over the same 9 patterns: when nothing matches at all (the
    # common case), skip the per-type loop entirely. First-matching-TYPE
    # semantics below are untouched for records that pass the gate.
    if not (_DEVICE_ANY.search(text) or _DEVICE_ANY.search(vendor)):
        return "unknown"
    for typ, rx in DEVICE_PATTERNS.items():
        if rx.search(text) or rx.search(vendor):
            return typ
    return "unknown"


def _structured_severity(record):
    raw = _field(record, "severity", "Severity", "level", "Level", "priority", "Priority", "severity_level", default="")
    return SEVERITY_MAP.get(str(raw).strip().upper())


def _severity_from_text(text):
    # One mechanically derived union regex per family instead of up to 40
    # individual searches. A union of the SAME patterns matches exactly the
    # texts any member matches, and family order is preserved — so the result
    # is identical by construction (proven per-text by the parity test).
    for sev, union in _SEVERITY_UNIONS:
        if union.search(text):
            return sev
    return None


def _normalized_alert_id(record, severity, device_type):
    eid = _event_id(record)
    return eid or f"text-{device_type}-{severity}"


# Prefixes of the canonical auth vocabulary. A record whose message is already
# canonical is the dedicated auth rules' input even when no translation was
# needed (canonical-format logs arrive pre-translated, so no auth_source stamp).
_CANON_AUTH_PREFIXES = (CANON_FAIL.split("{")[0], CANON_OK.split("{")[0])

# The auth-failure vocabulary, mirroring normalize.AUTH_FAILURE_HINT. Needed
# here as well because an auth failure the canonicalizer cannot attribute (e.g.
# a pam_unix line whose rhost is a hostname, not an IP) carries no auth_source
# stamp yet is still the dedicated auth rules' input domain.
_AUTH_FAILURE_TEXT = re.compile(
    r"(failed password|authentication failure|invalid user|failed none|failed publickey|"
    r"break-in|failed to authenticate)", re.I)


def _is_dedicated_auth_input(record, text):
    """True when this record belongs to the dedicated auth/break-in rules.

    Auth events are the input to detect_auth_bruteforce / the compromise rule /
    detect_break_in_attempts — normalize deliberately levels auth failures WARN
    (not ERROR) for exactly this reason (see normalize.LEVEL_HINTS). Counting
    them here as generic infrastructure alerts reports one attack twice under
    two finding types; an auth burst below the rules' thresholds is honestly
    NO finding, not a rebadged medium alert."""
    if record.get("auth_source"):
        return True
    msg = str(record.get("msg") or record.get("message") or "")
    if any(prefix in msg for prefix in _CANON_AUTH_PREFIXES):
        return True
    return bool(BREAK_IN.search(text) or _AUTH_FAILURE_TEXT.search(text))


def detect_infrastructure_alerts(records):
    """Catch high-signal security, availability and operational alerts across heterogeneous devices."""
    anomalies = []
    for r in records:
        # CBS/CSI/DISM Fail/HRESULT is owned by detect_windows_cbs.
        if _is_windows_cbs(r):
            continue
        # BGL RAS FATAL/ERROR is owned by the frozen detector's CRIT/ERROR
        # rules (critical_service_event / error_rate_spike). Re-emitting as
        # infra_*_critical would double-count the same source-reported line.
        if str(r.get("format") or "").lower() == "bgl":
            continue
        text = _all_text(r)
        if not text.strip():
            continue
        eid = _event_id(r)
        sev = _structured_severity(r) or _severity_from_text(text)
        # Ignore routine INFO/DEBUG unless a deterministic security/availability pattern matches.
        if not sev:
            continue
        # Avoid duplicating dedicated Windows Event-ID rules.
        if eid in (WINDOWS_AUDIT_CLEARED_IDS | WINDOWS_SERVICE_INSTALL_IDS | WINDOWS_USER_CREATED_IDS | WINDOWS_USER_DELETED_IDS | WINDOWS_GROUP_ADD_IDS | WINDOWS_LOCKOUT_IDS | WINDOWS_PROCESS_CREATE_IDS):
            continue
        # Avoid duplicating the dedicated auth/break-in rules (same principle
        # as the Windows Event-ID guard above): those rules own auth events.
        if _is_dedicated_auth_input(r, text):
            continue
        # Avoid turning ordinary success/up/recovery lines into alerts.
        if sev == "low" and not any(x in text.lower() for x in ("warning", "threshold", "expir", "drift", "retry", "certificate", "license")):
            continue
        # Only records that will actually emit pay for device/host resolution —
        # both are pure lookups used solely in the emitted anomaly below, so
        # computing them after the guards cannot change which records emit.
        host = _entity_host(r)
        dtype = _device_type(r, text)
        action = {
            "critical": "Immediately validate the event, preserve evidence, identify the actor/source and assess service or security impact.",
            "high": "Validate the event against an approved change/security action and investigate the source, affected asset and surrounding events.",
            "medium": "Correlate with nearby events and confirm whether this is expected operational activity or a security/availability issue.",
            "low": "Review during routine monitoring and confirm that the condition is expected or below the operational threshold.",
        }[sev]
        summary = f"{dtype.replace('_', ' ').title()} {sev} alert on {host}"
        if eid:
            summary += f" (EventID {eid})"
        # Prefer concise vendor message as evidence while retaining full raw line in record.
        anomalies.append(_anomaly(
            sev,
            f"infra_{dtype}_{sev}",
            summary,
            r,
            f"Deterministic cross-platform rule matched a {sev.upper()} condition in {dtype.replace('_', ' ')} telemetry.",
            {"host": host, "device_type": dtype, "event_id": eid or "", "vendor": _vendor(r)},
            action,
        ))
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

# The "security-relevant context" vocabulary detect_iocs requires before an
# IP/domain/hash counts as an indicator candidate. Module-level so the gate
# reorder below uses the identical pattern the inline search used.
IOC_CONTEXT_RE = re.compile(
    r"\b(c2|malware|trojan|ransomware|blocked|denied|indicator|ioc|threat|exploit|attack)\b",
    re.I)


# ---------------------------------------------------------------------------
# Mechanically derived union gates (latency only — matching is unchanged)
# ---------------------------------------------------------------------------
# A union of the SAME compiled patterns matches a text if and only if some
# member matches it, so using the union as a boolean gate (or, for the
# severity families, as the family's boolean itself) cannot change what any
# rule matches. Derived from the tables above — never hand-written — and the
# parity test asserts gate(text) == any(member(text)) over the whole corpus.

def _union(patterns):
    return re.compile("|".join(f"(?:{p.pattern})" for p in patterns), re.I)


_DEVICE_ANY = _union(DEVICE_PATTERNS.values())
_SEVERITY_UNIONS = (
    ("critical", _union(CRITICAL_PATTERNS)),
    ("high", _union(HIGH_PATTERNS)),
    ("medium", _union(MEDIUM_PATTERNS)),
    ("low", _union(LOW_PATTERNS)),
)
_THREAT_ANY = _union([rx for _, _, rx in THREAT_PATTERNS])


def _threat_text(record):
    """The text composition detect_threats/detect_iocs sweep — built once per
    record by detect_extra and shared, instead of twice per record."""
    return " ".join(str(record.get(k, ""))
                    for k in ("raw", "msg", "original_msg", "message")
                    if record.get(k))


def detect_threats(records, _texts=None):
    out = []
    for i, r in enumerate(records):
        text = _texts[i] if _texts is not None else _threat_text(r)
        if not text.strip():
            continue
        # Union gate over the same 11 patterns; only matching records pay for
        # the ordered per-pattern loop (which decides type/severity).
        if not _THREAT_ANY.search(text):
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
                {"host": host, "ioc_ips": ips, "ioc_domains": domains, "ioc_hashes": hashes},
                "Preserve evidence, identify the source and affected asset, correlate adjacent events, and contain according to the incident runbook."
            ))
            break
    return out


def detect_iocs(records, _texts=None):
    """Surface explicit IP/domain/hash indicators without declaring them malicious."""
    out = []
    for i, r in enumerate(records):
        text = _texts[i] if _texts is not None else _threat_text(r)
        # A finding requires BOTH an indicator and security context; checking
        # the single cheap context regex first skips the three findall sweeps
        # on ordinary lines. Pure conjunction — the emitted set is unchanged.
        if not IOC_CONTEXT_RE.search(text):
            continue
        ips = sorted(set(IOC_IP_RE.findall(text)))
        domains = sorted(set(IOC_DOMAIN_RE.findall(text)))
        hashes = sorted(set(IOC_HASH_RE.findall(text)))
        if not (ips or domains or hashes):
            continue
        out.append(_anomaly(
            "medium", "ioc_observed", f"Potential IOC observed on {_entity_host(r)}", r,
            "An IP, domain or file hash was observed in security-relevant context. Presence alone does not prove maliciousness.",
            {"host": _entity_host(r), "ioc_ips": ips, "ioc_domains": domains, "ioc_hashes": hashes},
            "Validate the indicator against approved threat-intelligence sources and correlate it with the originating asset."
        ))
    return out


def detect_extra(records):
    """Backward-compatible entry point for every supported input format."""
    anomalies = []
    anomalies.extend(detect_break_in_attempts(records))
    anomalies.extend(detect_windows_extra(records))
    anomalies.extend(detect_windows_cbs(records))
    anomalies.extend(detect_infrastructure_alerts(records))
    # The threat and IOC sweeps read the same text composition — build it once.
    texts = [_threat_text(r) for r in records]
    anomalies.extend(detect_threats(records, _texts=texts))
    anomalies.extend(detect_iocs(records, _texts=texts))
    return anomalies
