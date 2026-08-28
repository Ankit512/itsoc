#!/usr/bin/env python3
"""
jsonlog.py — sibling parser for JSON-line (JSONL/Newline-delimited JSON) logs.

Feeds the SAME canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

JSON-line format is one JSON object per line, common in cloud/container logs:

    {"timestamp":"2026-03-15T14:02:04Z","level":"error","message":"disk usage at 92%","host":"web-01"}

Field mapping is flexible — the parser recognizes common field name variants:
  - timestamp: timestamp, time, ts, @timestamp, datetime, date
  - level:     level, severity, loglevel, log_level, log.level, priority
  - message:   message, msg, log, text, body, content
  - host:      host, hostname, host_name, source, node, server

Severity is ONLY read from the log's own level field, mapped through a fixed
vocabulary. Anything unrecognized → "INFO" (never guessed from content).

`raw` always carries the actual source line, verbatim. Files that do not match
this format are NOT parsed here. No third-party dependencies.
anomaly_detector.py is never imported or modified.
"""

import json
from datetime import datetime, timezone

# Field name variants, checked in priority order
_TS_FIELDS = ("timestamp", "time", "ts", "@timestamp", "datetime", "date",
              "Timestamp", "Time", "DateTime")
_LEVEL_FIELDS = ("level", "severity", "loglevel", "log_level", "priority",
                 "Level", "Severity", "LogLevel")
_MSG_FIELDS = ("message", "msg", "log", "text", "body", "content",
               "Message", "Msg", "Log", "Text")
_HOST_FIELDS = ("host", "hostname", "host_name", "source", "node", "server",
                "Host", "Hostname", "Source", "Node", "Server")

# Severity normalization vocabulary (case-insensitive)
_LEVEL_MAP = {
    "emerg": "ERROR", "emergency": "ERROR", "panic": "ERROR",
    "alert": "ERROR", "fatal": "ERROR", "critical": "ERROR", "crit": "ERROR",
    "error": "ERROR", "err": "ERROR",
    "warn": "WARN", "warning": "WARN",
    "notice": "INFO", "info": "INFO", "information": "INFO",
    "debug": "DEBUG", "trace": "DEBUG", "verbose": "DEBUG",
}


def _pick(obj, fields, default=None):
    """Return the first matching field value from a dict, or default."""
    for f in fields:
        if f in obj:
            return obj[f]
    return default


def _parse_timestamp(val):
    """Best-effort parse of a timestamp value into a datetime."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    s = str(val).strip()
    if not s:
        return None
    # ISO 8601 variants
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        pass
    # Common syslog-style: "Mar 15 14:02:04"
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _normalize_level(val):
    """Map a level string to the project's standard vocabulary."""
    if val is None:
        return "INFO"
    key = str(val).strip().lower()
    return _LEVEL_MAP.get(key, "INFO")


def sniff(path, probe_lines=50):
    """Return 'jsonlog' if the file is newline-delimited JSON, else None."""
    matches = 0
    seen = 0
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                raw = line.rstrip("\n").strip()
                if not raw:
                    continue
                seen += 1
                if raw.startswith("{") and raw.endswith("}"):
                    try:
                        obj = json.loads(raw)
                        # Must be a dict with at least a message-like field
                        if isinstance(obj, dict) and _pick(obj, _MSG_FIELDS) is not None:
                            matches += 1
                    except json.JSONDecodeError:
                        pass
                if seen >= probe_lines:
                    break
    except (OSError, IOError):
        return None

    if not seen:
        return None
    if matches / seen >= 0.6:
        return "jsonlog"
    return None


def parse(path):
    """Parse a JSON-line file into canonical records.

    Returns (records, stats) where stats has keys:
      format, parsed, unparsed, total
    """
    records = []
    unparsed_lines = []
    total = 0

    with open(path, "r", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            total += 1

            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                unparsed_lines.append((n, raw))
                continue

            if not isinstance(obj, dict):
                unparsed_lines.append((n, raw))
                continue

            msg = _pick(obj, _MSG_FIELDS)
            if msg is None:
                # Fall back to stringifying the whole object
                msg = json.dumps(obj, ensure_ascii=False, default=str)

            ts = _parse_timestamp(_pick(obj, _TS_FIELDS))
            level = _normalize_level(_pick(obj, _LEVEL_FIELDS))
            host = _pick(obj, _HOST_FIELDS)
            if host is not None:
                host = str(host)

            records.append({
                "n": n,
                "ts": ts,
                "level": level,
                "host": host,
                "msg": str(msg),
                "raw": raw,
            })

    return records, {
        "format": "jsonlog",
        "parsed": len(records),
        "unparsed": len(unparsed_lines),
        "total": total,
    }
