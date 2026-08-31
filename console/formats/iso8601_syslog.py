#!/usr/bin/env python3
"""
iso8601_syslog.py — sibling parser for journald / rsyslog ISO-8601 syslog.

Feeds the SAME canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

Modern Debian/Ubuntu auth.log (and `journalctl -o short-iso-precise`) looks like:

    2026-05-05T21:35:23.101666-03:00 Debian sshd-session[9136]: Failed password for ...

That is NOT RFC 3164 (no "Mon DD") and NOT RFC 5424 (no <PRI>1 prefix). Native
sniff used to call it unknown; the universal fallback then fed detect() records
that lacked a `ts` key (KeyError). This module is the envelope — it does not
rewrite wording, invent findings, or touch the frozen detector.

The second token is a hostname, never a canonical level (INFO/WARN/ERROR/...).
Canonical `TS LEVEL HOST MSG` lines are therefore not stolen.

`raw` is the source line, verbatim. No third-party dependencies.
"""

import re
from datetime import datetime

# ISO-8601 stamp (optional fraction, Z or ±HH:MM) then host then the rest.
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)
PROC_RE = re.compile(r"^(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_LEVELS = {"INFO", "WARN", "WARNING", "ERROR", "CRIT", "CRITICAL", "DEBUG"}


def _parse_ts(raw):
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def sniff(path, probe_lines=50):
    """Return 'iso8601_syslog' on a clear majority, else None."""
    matched = seen = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            seen += 1
            m = LINE_RE.match(raw)
            if m and m.group("host") not in _LEVELS:
                matched += 1
            if seen >= probe_lines:
                break
    if matched and matched >= max(1, (seen * 2) // 3):
        return "iso8601_syslog"
    return None


def load(path, level_fn):
    """Parse ISO-8601 syslog lines. Returns (records, unparsed, total)."""
    records, unparsed = [], []
    total = 0
    with open(path, "r", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            total += 1
            m = LINE_RE.match(raw)
            if not m or m.group("host") in _LEVELS:
                unparsed.append((n, raw))
                continue
            rest = m.group("rest")
            pm = PROC_RE.match(rest)
            if pm:
                proc, pid, msg = pm.group("proc"), pm.group("pid"), pm.group("msg")
            else:
                proc, pid, msg = None, None, rest
            records.append({
                "n": n,
                "ts": _parse_ts(m.group("ts")),
                "level": level_fn(msg),
                "host": m.group("host"),
                "msg": msg,
                "raw": raw,
                "proc": proc,
                "pid": pid,
            })
    return records, unparsed, total
