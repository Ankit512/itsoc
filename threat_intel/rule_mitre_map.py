#!/usr/bin/env python3
"""
rule_mitre_map.py — the explicit rule_id -> MITRE ATT&CK technique table.

This file is the SOURCE OF TRUTH for which detector rule maps to which ATT&CK
technique. It lives in threat_intel/ deliberately: the detector never knows
about ATT&CK, and the console never hardcodes a mapping — both sides come here.

The mapping is a derived, read-only annotation. It never changes, suppresses,
escalates, or reorders a finding's severity or verdict — rules own severity.

Entries carry the technique name and tactic INLINE so resolution is fully
offline: no ATT&CK bundle download, no warm cache required. When the cache in
~/.cache/mitre_attack/ happens to be warm, test_threat_intel.py cross-checks
these entries against the official STIX data as a bonus.

A rule with no entry here gets NO tag. That is a statement, not an omission:
ops signals (disk pressure, error bursts, service crashes) are not attacker
behaviours, and guessing a technique would put invented evidence on an audit
surface. The same goes for possible_break_in: sshd's reverse-DNS warning fires
on probing whose method the rule does not verify, so no technique is claimed.
"""

# rule_id (the detector anomaly "type", carried as the report's rule_id)
#   -> list of {"id", "name", "tactic"}; [] / absent -> no tag, never guessed.
RULE_TECHNIQUES = {
    # >=5 failed logins from one source IP: password guessing, by definition.
    "auth_bruteforce": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    # The guessing worked: brute force plus use of the now-valid account.
    "auth_bruteforce_success": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    ],
    # Outbound to a known C2/backdoor port (4444, 31337, ...) — exactly T1571.
    "suspicious_outbound": [
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    ],
    # --- rules_app.py Windows Event-ID rules (multi-format ingestion) -------
    # Each event id IS the technique's canonical telemetry, so the mapping is
    # definitional, not guessed.
    "windows_audit_log_cleared": [
        {"id": "T1070.001", "name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    ],
    "windows_service_installed": [
        {"id": "T1543.003", "name": "Windows Service", "tactic": "Persistence"},
    ],
    "windows_user_created": [
        {"id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence"},
    ],
    "windows_user_deleted": [
        {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
    ],
    "windows_privileged_group_change": [
        {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"},
    ],
    "windows_account_lockout": [
        {"id": "T1531", "name": "Account Access Removal", "tactic": "Impact"},
    ],
    "windows_suspicious_process": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    # --- rules_app.py threat-vocabulary rules -------------------------------
    # The rule's pattern names the technique explicitly (the log SAID
    # "ransomware"/"lateral movement"/...), so the annotation restates the
    # matched vocabulary rather than inferring behaviour.
    "threat_ransomware": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    ],
    "threat_active_compromise": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    ],
    "threat_c2_indicator": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "threat_malware_indicator": [
        {"id": "T1204.002", "name": "Malicious File", "tactic": "Execution"},
    ],
    "threat_persistence": [
        {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence"},
    ],
    "threat_privilege_escalation": [
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    ],
    "threat_lateral_movement": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    ],
    "threat_port_scan": [
        {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
    ],
    "threat_credential_attack": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "threat_data_exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    # Deliberately unmapped — not attacker techniques, or method unverified:
    #   critical_service_event, disk_pressure, error_rate_spike, possible_break_in
    #   ioc_observed (an indicator candidate is not yet a technique)
    #   threat_rogue_wireless (a rogue AP's method is unverified; the upstream
    #     tree's T1557.002 "ARP Cache Poisoning" claim was wrong and is not kept)
    #   infra_* (availability/operational signals, not attacker behaviours)
    #   zookeeper_* / generic_* (ops signals; claiming ATT&CK "Service
    #     Exhaustion" for WARN lifecycle churn would be invented attribution)
}


def techniques_for_rule(rule_id):
    """Resolve a finding's rule_id to its ATT&CK techniques. Unknown -> []."""
    return [dict(t) for t in RULE_TECHNIQUES.get(rule_id or "", [])]
