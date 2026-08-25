#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${1:-/home/ajukumar/log-anomaly-detector}"
cd "$APP_DIR"
for f in log_analyzer.py rules_syslog.py anomaly_detector.py normalize.py rule_context.py console/serve.py; do
  [ -f "$f" ] && cp "$f" "$f.backup.$(date +%Y%m%d%H%M%S)" || true
done
cp "$(dirname "$0")/log_analyzer.py" ./log_analyzer.py
cp "$(dirname "$0")/rules_syslog.py" ./rules_syslog.py
cp "$(dirname "$0")/anomaly_detector.py" ./anomaly_detector.py
cp "$(dirname "$0")/normalize.py" ./normalize.py
cp "$(dirname "$0")/rule_context.py" ./rule_context.py
if [ -d console ]; then cp "$(dirname "$0")/serve.py" console/serve.py; fi
python3 -m py_compile log_analyzer.py rules_syslog.py anomaly_detector.py normalize.py rule_context.py
printf '\nFixed SOC analyzer installed and syntax-checked.\n'
