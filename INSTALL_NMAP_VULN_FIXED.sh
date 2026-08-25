#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-/home/ajukumar/log-anomaly-detector}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DEST"
[ -f "$DEST/log_analyzer.py" ] && cp "$DEST/log_analyzer.py" "$DEST/log_analyzer.py.backup-nmap"
cp "$SCRIPT_DIR/log_analyzer_NMAP_vuln_fixed.py" "$DEST/log_analyzer.py"
python3 -m py_compile "$DEST/log_analyzer.py"
echo "Installed fixed log_analyzer.py into $DEST"
echo "Run: python3 $DEST/log_analyzer.py --input /path/to/log --output report --rules-only --nmap-target AUTHORIZED_TARGET"
