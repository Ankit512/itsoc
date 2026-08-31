#!/usr/bin/env python3
"""
auth_csv.py — sibling parser for authentication CSV exports.

Feeds the SAME canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

Typical lab/SIEM export (header required; content-sniffed, never by file name):

    timestamp,ip_address,username,status,source
    2026-07-17T06:05:00Z,203.0.113.50,admin@example.com,failure,web

ENVELOPE ONLY. This module maps columns onto the record dict. It never rewrites
the row into fake syslog wording, never invents a finding, and never guesses a
syslog level from status=failure. Status/username/ip stay on the record so
rules_syslog.canonicalize can translate them into the frozen detector's
auth vocabulary — the same split as Windows 4625/4624.

`raw` is the source row, verbatim. No third-party dependencies.
anomaly_detector.py is never imported or modified.

Log360 CSV (Message/Time/Device/…) is a different sibling and is sniffed first.
"""

import csv
from datetime import datetime, timezone

# Header aliases, matched case-insensitively. All four families required.
TS_COLUMNS = ("timestamp", "time", "ts", "datetime", "date", "@timestamp")
IP_COLUMNS = ("ip_address", "ip", "src_ip", "source_ip", "client_ip", "sourceip")
USER_COLUMNS = ("username", "user", "account", "accountname", "targetusername")
STATUS_COLUMNS = ("status", "result", "outcome", "auth_status")
# Optional: auth surface (vpn/web) or a hostname column.
HOST_COLUMNS = ("host", "hostname", "device", "source")

# Log360's required pair — refuse to steal that export even if a Time column
# happens to sit next to something named Source.
LOG360_MARKERS = {"message", "logtype", "common severity"}

UNKNOWN_LEVEL = "UNKNOWN"


class _LineTrackingReader:
    """Pair each csv.reader row with the verbatim source text it came from."""

    def __init__(self, f):
        self.f = f
        self.lineno = 0
        self.buffer = []

    def __iter__(self):
        return self

    def __next__(self):
        line = next(self.f)
        self.lineno += 1
        self.buffer.append(line)
        return line

    def take(self):
        raw = "".join(self.buffer).rstrip("\n")
        start = self.lineno - (len(self.buffer) - 1)
        self.buffer = []
        return raw, start


def _norm_header(name):
    return (name or "").strip().lower().replace(" ", "").replace("-", "_")


def _header_names(line):
    try:
        cols = next(csv.reader([line]))
    except (csv.Error, StopIteration):
        return []
    return [_norm_header(c) for c in cols if c is not None]


def _has_any(names, aliases):
    return any(a.replace(" ", "").replace("-", "_") in names for a in aliases)


def header_matches(line):
    """True when the header is an auth CSV, not Log360, not a random table."""
    names = set(_header_names(line))
    if not names:
        return False
    if names & {_norm_header(m) for m in LOG360_MARKERS}:
        return False
    return (
        _has_any(names, TS_COLUMNS)
        and _has_any(names, IP_COLUMNS)
        and _has_any(names, USER_COLUMNS)
        and _has_any(names, STATUS_COLUMNS)
    )


def sniff(path, probe_lines=50):
    """Return 'auth_csv' when the first non-blank line is an auth CSV header."""
    del probe_lines  # header-only sniff, like log360_csv
    with open(path, "r", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            return "auth_csv" if header_matches(raw) else None
    return None


def _cell(row, index, aliases):
    for alias in aliases:
        key = _norm_header(alias)
        i = index.get(key)
        if i is not None and i < len(row):
            return (row[i] or "").strip()
    return ""


def _parse_ts(value):
    value = (value or "").strip()
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00").replace(",", "."))
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def load(path):
    """Parse an auth CSV. Returns (records, unparsed, total).

    The header is envelope, not an event: total counts data rows only.
    """
    records, unparsed = [], []
    total = 0
    with open(path, "r", errors="replace", newline="") as f:
        tracker = _LineTrackingReader(f)
        reader = csv.reader(tracker)
        try:
            header = next(reader)
        except StopIteration:
            return [], [], 0
        tracker.take()
        index = {_norm_header(name): i for i, name in enumerate(header)}

        for row in reader:
            raw, n = tracker.take()
            if not raw.strip():
                continue
            total += 1
            ts_s = _cell(row, index, TS_COLUMNS)
            ip = _cell(row, index, IP_COLUMNS)
            user = _cell(row, index, USER_COLUMNS)
            status = _cell(row, index, STATUS_COLUMNS)
            if not (ts_s and ip and user and status):
                unparsed.append((n, raw))
                continue
            host = _cell(row, index, HOST_COLUMNS) or ip
            records.append({
                "n": n,
                "ts": _parse_ts(ts_s),
                "level": UNKNOWN_LEVEL,   # no level column — never guess from status
                "host": host,
                "msg": raw,               # original row wording — vocabulary is not this module
                "raw": raw,
                "timestamp": ts_s,
                "ip_address": ip,
                "username": user,
                "status": status,
                "source": _cell(row, index, ("source",)),
            })
    return records, unparsed, total
