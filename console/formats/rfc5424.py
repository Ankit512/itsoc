#!/usr/bin/env python3
"""
rfc5424.py — sibling parser for RFC 5424 structured syslog.

Feeds the SAME canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

RFC 5424 format:
    <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG

Example:
    <34>1 2026-03-15T14:02:04.000003+01:00 web-01 sshd 22987 - - Failed password for admin from 10.0.0.5

Structured data elements [SD-ID param="value"] are stripped from msg but the
full line is preserved verbatim in raw.

Severity is derived from the PRI field exactly as RFC 5424 §6.2.1 specifies:
    severity = PRI % 8 → {0: EMERG, 1: ALERT, 2: CRIT, 3: ERROR, 4: WARNING,
                           5: NOTICE, 6: INFO, 7: DEBUG}
This is a deterministic fact carried by the line itself — no guessing.

`raw` always carries the actual source line, verbatim. Files that do not match
this format are NOT parsed here; normalize.py's sniff falls through to other
formats. No third-party dependencies. anomaly_detector.py is never imported
or modified.
"""

import re
from datetime import datetime, timezone

# RFC 5424 PRI-VERSION header: <PRI>VERSION
# PRI = facility * 8 + severity (0–191)
# VERSION is always 1 for RFC 5424
_RFC5424_RE = re.compile(
    r"<(?P<pri>\d{1,3})>(?P<ver>\d) "
    r"(?P<ts>\S+) "               # TIMESTAMP (ISO 8601 or -)
    r"(?P<host>\S+) "             # HOSTNAME (or -)
    r"(?P<app>\S+) "              # APP-NAME (or -)
    r"(?P<procid>\S+) "           # PROCID (or -)
    r"(?P<msgid>\S+) "            # MSGID (or -)
    r"(?P<rest>.*)"               # SD + MSG
)

# Structured data: [exampleSDID@32473 key="val" key2="val2"]
_SD_RE = re.compile(r"\[([^\]]+)\]\s*")

# RFC 5424 severity levels (PRI % 8)
_SEV_MAP = {
    0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# Map RFC levels to the project's standard level vocabulary
_LEVEL_MAP = {
    "EMERG": "ERROR", "ALERT": "ERROR", "CRIT": "ERROR", "ERROR": "ERROR",
    "WARNING": "WARN", "NOTICE": "INFO", "INFO": "INFO", "DEBUG": "DEBUG",
}


def _parse_timestamp(ts_str):
    """Parse an RFC 5424 ISO 8601 timestamp, returning a datetime or None."""
    if ts_str == "-":
        return None
    try:
        # Python's fromisoformat handles most RFC 5424 timestamps
        # but we need to handle the Z suffix
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def _extract_msg(rest):
    """Strip structured data elements and return the message body."""
    # Remove all [SD] blocks from the rest
    msg = _SD_RE.sub("", rest).strip()
    if msg.startswith("- "):
        msg = msg[2:]
    elif msg == "-":
        msg = ""
    return msg


def sniff(path, probe_lines=50):
    """Return 'rfc5424' if the file looks like RFC 5424 syslog, else None."""
    matches = 0
    seen = 0
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                raw = line.rstrip("\n")
                if not raw.strip():
                    continue
                seen += 1
                if _RFC5424_RE.match(raw):
                    matches += 1
                if seen >= probe_lines:
                    break
    except (OSError, IOError):
        return None

    if not seen:
        return None
    # Require a clear majority to avoid stealing other formats
    if matches / seen >= 0.6:
        return "rfc5424"
    return None


def parse(path):
    """Parse an RFC 5424 file into canonical records.

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

            m = _RFC5424_RE.match(raw)
            if not m:
                unparsed_lines.append((n, raw))
                continue

            pri = int(m.group("pri"))
            severity = pri % 8
            rfc_level = _SEV_MAP.get(severity, "INFO")
            level = _LEVEL_MAP.get(rfc_level, "INFO")

            ts = _parse_timestamp(m.group("ts"))
            host = m.group("host") if m.group("host") != "-" else None
            app = m.group("app") if m.group("app") != "-" else None
            procid = m.group("procid") if m.group("procid") != "-" else None

            msg = _extract_msg(m.group("rest"))
            # Prefix with app[pid] like RFC 3164 format for rule compatibility
            if app and procid:
                msg = f"{app}[{procid}]: {msg}"
            elif app:
                msg = f"{app}: {msg}"

            records.append({
                "n": n,
                "ts": ts,
                "level": level,
                "host": host,
                "msg": msg,
                "raw": raw,
            })

    return records, {
        "format": "rfc5424",
        "parsed": len(records),
        "unparsed": len(unparsed_lines),
        "total": total,
    }
