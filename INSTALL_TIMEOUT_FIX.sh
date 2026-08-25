#!/usr/bin/env bash
set -euo pipefail
DEST="${1:-/home/ajukumar/log-anomaly-detector}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$DEST"
if [ -f "$DEST/log_analyzer.py" ]; then
  cp "$DEST/log_analyzer.py" "$DEST/log_analyzer.py.backup-timeout"
fi
cp "$HERE/log_analyzer.py" "$DEST/log_analyzer.py"
python3 -m py_compile "$DEST/log_analyzer.py"
echo "Installed timeout/performance-fixed log_analyzer.py into $DEST"
