# SOC MITRE + UDP Collector Final Merge

This bundle merges the updated MITRE adapter with the enhanced analyzer and universal UDP syslog collector.

## MITRE fix
`console/adapter.py` adds safe fallback ATT&CK mappings for deterministic rules that are not yet present in `threat_intel/rule_mitre_map.py`. MITRE is derived metadata only and does not change severity.

## Test
Use:
`python3 console/adapter.py zookeeper_integrated.json -o state.json`

The test report should contain a non-empty `mitreFrequency`, including Impact / T1499.002 for the ZooKeeper findings.

## Analyzer
The analyzer/support files are included at the project root. The analyzer imports `normalize.py`, `rule_context.py`, `rules_syslog.py`, and `anomaly_detector.py` from the same directory.

## UDP collector
`console/syslog_collector.py` supports concurrent UDP listeners on 513, 514, and 1514 when the OS permissions allow binding those ports.

## Dashboard server
The supplied `console/serve.py` is the existing SOC server with the collector integration. It also imports other existing SOC console modules (`export.py`, `redact.py`, `soc.py`, etc.); those modules are intentionally not fabricated in this bundle because they were not available as current source files in the working set.
