# MITRE ATT&CK rule mapping used by the SOC.
# MITRE mappings are derived annotations only; they do not determine severity/verdict.
#
# Upstream source: MITRE ATT&CK Enterprise STIX 2.1 (https://github.com/mitre/cti/enterprise-attack).
# Note: Overall bundle version is not recorded in the local cache fixture; individual pattern
# object versions are referenced (e.g. T1499.002 v2.0 'Service Exhaustion Flood',
# T1046 v3.2 'Network Service Discovery', T1136.001 v2.6 'Local Account').

import copy

RULE_TECHNIQUES = {
    'auth_bruteforce': [{'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'}],
    'auth_bruteforce_success': [{'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'}],
    'critical_service_event': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}],
    'disk_pressure': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}],
    'error_rate_spike': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}],
    'insecure_service_exposure': [{'id': 'T1190',
                                   'name': 'Exploit Public-Facing Application',
                                   'tactic': 'Initial Access'}],
    'possible_break_in': [{'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'suspicious_outbound': [{'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'}],
    'threat_active_compromise': [{'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Initial Access'}],
    'threat_c2_indicator': [{'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'}],
    'threat_credential_attack': [{'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'}],
    'threat_data_exfiltration': [{'id': 'T1041', 'name': 'Exfiltration Over C2 Channel', 'tactic': 'Exfiltration'}],
    'threat_lateral_movement': [{'id': 'T1021', 'name': 'Remote Services', 'tactic': 'Lateral Movement'}],
    'threat_malware_indicator': [{'id': 'T1204.002', 'name': 'Malicious File', 'tactic': 'Execution'}],
    'threat_persistence': [{'id': 'T1053', 'name': 'Scheduled Task/Job', 'tactic': 'Persistence'}],
    'threat_port_scan': [{'id': 'T1046', 'name': 'Network Service Discovery', 'tactic': 'Discovery'}],
    'threat_privilege_escalation': [{'id': 'T1548',
                                     'name': 'Abuse Elevation Control Mechanism',
                                     'tactic': 'Privilege Escalation'}],
    'threat_ransomware': [{'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'}],
    'threat_rogue_wireless': [{'id': 'T1557.002', 'name': 'ARP Cache Poisoning', 'tactic': 'Credential Access'}],
    'url_information_disclosure': [{'id': 'T1082', 'name': 'System Information Discovery', 'tactic': 'Discovery'}],
    'url_security_header': [{'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'url_server_disclosure': [{'id': 'T1082', 'name': 'System Information Discovery', 'tactic': 'Discovery'}],
    'url_tls': [{'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'vulnerability_nmap_nse': [{'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'}],
    'windows_account_lockout': [{'id': 'T1531', 'name': 'Account Access Removal', 'tactic': 'Impact'}],
    'windows_audit_log_cleared': [{'id': 'T1070.001', 'name': 'Clear Windows Event Logs', 'tactic': 'Defense Evasion'}],
    'windows_privileged_group_change': [{'id': 'T1098', 'name': 'Account Manipulation', 'tactic': 'Persistence'}],
    'windows_service_installed': [{'id': 'T1543.003', 'name': 'Windows Service', 'tactic': 'Persistence'}],
    'windows_suspicious_process': [{'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}],
    'windows_user_created': [{'id': 'T1136.001', 'name': 'Local Account', 'tactic': 'Persistence'}],
    'windows_user_deleted': [{'id': 'T1070', 'name': 'Indicator Removal', 'tactic': 'Defense Evasion'}],
    'zookeeper_connection_broken': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}],
    'zookeeper_quorum_instability': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}],
    'zookeeper_sendworker_exit': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}],
    'zookeeper_sendworker_interrupt': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}],
    'zookeeper_sendworker_interrupted': [{'id': 'T1499.002', 'name': 'Service Exhaustion Flood', 'tactic': 'Impact'}]
}

def techniques_for_rule(rule_id):
    """Return ATT&CK technique annotations for a deterministic rule ID.
    Returns defensive deep copies so callers cannot mutate the table."""
    val = RULE_TECHNIQUES.get(str(rule_id or ""))
    return copy.deepcopy(val) if val is not None else []

# Backwards-compatible aliases used by older SOC components.
RULE_MITRE_MAP = RULE_TECHNIQUES
TECHNIQUE_MAP = RULE_TECHNIQUES
