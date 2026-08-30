#!/usr/bin/env python3
"""
loghub.py — sibling parsers for Loghub/LogPAI application and supercomputer logs.

Feeds the SAME canonical record anomaly_detector.py consumes:

    {n, ts, level, host, msg, raw}

ENVELOPE ONLY. This module decides timestamp/level/host/message boundaries; it
never rewrites message wording and never touches rules, severities, or
correlation. Severity is SOURCE-REPORTED from the line's own level token
(Apache [error], log4j INFO/WARN/ERROR/FATAL, BGL RAS KERNEL FATAL, …).
It is never guessed from free-text "failed" / "error" in the message.

Covered grammars (2k Loghub samples, also the full Zenodo sets):

  apache      [Sun Dec 04 04:47:44 2005] [error] message
  log4j       Hadoop / ZooKeeper / Spark / HDFS / OpenStack Java-style
  bgl         Blue Gene/L RAS: ... RAS KERNEL FATAL message
  thunderbird supercomputer syslog with a BGL-like prefix, then rfc3164 rest
  proxifier   [10.30 16:49:06] chrome.exe - host:port error : reason

`raw` is always the verbatim source line. Files that are not clearly one of
these grammars are NOT parsed here. anomaly_detector.py is never imported
or modified.
"""

import re
from datetime import datetime, timezone

_LEVEL = r"TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|SEVERE"
_LEVEL_MAP = {
    "TRACE": "DEBUG", "DEBUG": "DEBUG",
    "INFO": "INFO", "INFORMATION": "INFO", "NOTICE": "INFO",
    "WARN": "WARN", "WARNING": "WARN",
    "ERROR": "ERROR", "ERR": "ERROR", "SEVERE": "ERROR",
    "FATAL": "CRIT", "CRITICAL": "CRIT", "CRIT": "CRIT",
    "EMERG": "CRIT", "EMERGENCY": "CRIT", "ALERT": "CRIT",
}
_APACHE_LEVEL_MAP = {
    "EMERG": "CRIT", "ALERT": "CRIT", "CRIT": "CRIT",
    "ERROR": "ERROR", "WARN": "WARN",
    "NOTICE": "INFO", "INFO": "INFO", "DEBUG": "DEBUG",
}

# Hadoop: 2015-10-18 18:01:47,978 INFO [main] logger: message
HADOOP_RE = re.compile(
    rf"^(?P<ts>\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}),(?P<ms>\d{{3}})\s+"
    rf"(?P<level>{_LEVEL})\s+"
    rf"(?:\[(?P<thread>[^\]]*)\]\s+)?(?P<msg>.*)$"
)
# ZooKeeper: 2015-07-29 17:41:44,747 - INFO  [thread] - message
ZK_RE = re.compile(
    rf"^(?P<ts>\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}),(?P<ms>\d{{3}})\s+-\s+"
    rf"(?P<level>{_LEVEL})\s+(?P<msg>.*)$",
    re.I,
)
# Spark: 17/06/09 20:10:40 INFO executor.Class: message
SPARK_RE = re.compile(
    rf"^(?P<ts>\d{{2}}/\d{{2}}/\d{{2}} \d{{2}}:\d{{2}}:\d{{2}})\s+"
    rf"(?P<level>{_LEVEL})\s+(?P<msg>.*)$"
)
# HDFS: 081109 203615 148 INFO dfs.DataNode$PacketResponder: message
HDFS_RE = re.compile(
    rf"^(?P<ymd>\d{{6}})\s+(?P<hms>\d{{6}})\s+(?P<tid>\d+)\s+"
    rf"(?P<level>{_LEVEL})\s+(?P<msg>.*)$"
)
# OpenStack: nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO logger msg
OPENSTACK_RE = re.compile(
    rf"^(?P<logfile>\S+)\s+"
    rf"(?P<ts>\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}})\.(?P<ms>\d{{3}})\s+"
    rf"(?P<pid>\d+)\s+(?P<level>{_LEVEL})\s+(?P<msg>.*)$"
)
# Apache error_log
APACHE_RE = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]\s+"
    r"\[(?P<level>emerg|alert|crit|error|warn|notice|info|debug)\]\s+"
    r"(?P<msg>.*)$",
    re.I,
)
# BGL RAS
BGL_RE = re.compile(
    rf"^(?P<label>\S+)\s+(?P<epoch>\d+)\s+(?P<date>\d{{4}}\.\d{{2}}\.\d{{2}})\s+"
    rf"(?P<host>\S+)\s+(?P<ts>\d{{4}}-\d{{2}}-\d{{2}}-\d{{2}}\.\d{{2}}\.\d{{2}}\.\d+)\s+"
    rf"(?P<host2>\S+)\s+(?P<facility>\S+)\s+(?P<component>\S+)\s+"
    rf"(?P<level>{_LEVEL})\s+(?P<msg>.*)$"
)
# Thunderbird: BGL-like prefix then rfc3164 stamp
THUNDERBIRD_RE = re.compile(
    r"^(?P<label>\S+)\s+(?P<epoch>\d+)\s+(?P<date>\d{4}\.\d{2}\.\d{2})\s+"
    r"(?P<node>\S+)\s+(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$"
)
# Proxifier: [10.30 16:49:06] chrome.exe - host:port error : reason
PROXIFIER_RE = re.compile(
    r"^\[(?P<ts>\d{1,2}\.\d{2} \d{2}:\d{2}:\d{2})\]\s+"
    r"(?P<proc>.+?)\s+-\s+(?P<msg>.*)$"
)
_PROXIFIER_ERROR = re.compile(r"\berror\s*:", re.I)

_LOG4J_RES = (ZK_RE, HADOOP_RE, SPARK_RE, HDFS_RE, OPENSTACK_RE)


def _map_level(raw):
    return _LEVEL_MAP.get(str(raw).strip().upper(), "INFO")


def _dt_iso_ms(ts, ms):
    try:
        base = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        return base.replace(microsecond=int(ms) * 1000, tzinfo=timezone.utc)
    except ValueError:
        return None


def _dt_spark(ts):
    try:
        return datetime.strptime(ts, "%y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _dt_hdfs(ymd, hms):
    try:
        yy, mm, dd = int(ymd[0:2]), int(ymd[2:4]), int(ymd[4:6])
        year = 2000 + yy if yy < 70 else 1900 + yy
        hh, mi, ss = int(hms[0:2]), int(hms[2:4]), int(hms[4:6])
        return datetime(year, mm, dd, hh, mi, ss, tzinfo=timezone.utc)
    except ValueError:
        return None


def _dt_apache(ts):
    ts = re.sub(r"\s+", " ", ts.strip())
    try:
        return datetime.strptime(ts, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _dt_bgl(ts):
    # 2005-06-03-15.42.50.675872
    head, _, frac = ts.partition(".")
    try:
        base = datetime.strptime(head, "%Y-%m-%d-%H.%M.%S")
        micro = int((frac + "000000")[:6])
        return base.replace(microsecond=micro, tzinfo=timezone.utc)
    except ValueError:
        return None


def _dt_proxifier(ts, year):
    # 10.30 16:49:06  -> month.day HH:MM:SS
    try:
        md, time_s = ts.split()
        mon_s, day_s = md.split(".")
        hh, mm, ss = (int(x) for x in time_s.split(":"))
        return datetime(int(year), int(mon_s), int(day_s), hh, mm, ss,
                        tzinfo=timezone.utc)
    except ValueError:
        return None


def _dt_tb(year, mon, day, time_s):
    months = {m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
    month = months.get(mon)
    if not month:
        return None
    try:
        hh, mm, ss = (int(x) for x in time_s.split(":"))
        return datetime(int(year), month, int(day), hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None


def _match_log4j(raw):
    for rx in _LOG4J_RES:
        m = rx.match(raw)
        if m:
            return rx, m
    return None, None


def sniff(path, probe_lines=50):
    """Return apache|log4j|bgl|thunderbird|proxifier if CONTENT matches, else None."""
    counts = {"apache": 0, "log4j": 0, "bgl": 0, "thunderbird": 0, "proxifier": 0}
    seen = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            seen += 1
            if APACHE_RE.match(raw):
                counts["apache"] += 1
            elif _match_log4j(raw)[0] is not None:
                counts["log4j"] += 1
            elif BGL_RE.match(raw):
                counts["bgl"] += 1
            elif THUNDERBIRD_RE.match(raw):
                counts["thunderbird"] += 1
            elif PROXIFIER_RE.match(raw):
                counts["proxifier"] += 1
            if seen >= probe_lines:
                break
    if not seen:
        return None
    best = max(counts, key=counts.get)
    if counts[best] and counts[best] >= max(1, (seen * 2) // 3):
        return best
    return None


def looks_like_log4j_line(line):
    """True for a Hadoop/ZK-style `YYYY-MM-DD HH:MM:SS,mmm LEVEL` line.

    Used to keep csv.Sniffer from claiming millisecond log4j timestamps.
    """
    return ZK_RE.match(line) is not None or HADOOP_RE.match(line) is not None


def _record(n, ts, level, host, msg, raw, **extra):
    rec = {
        "n": n,
        "ts": ts,
        "level": level,
        "host": host,
        "msg": msg,
        "raw": raw,
    }
    rec.update(extra)
    return rec


def _parse_log4j_line(n, raw):
    rx, m = _match_log4j(raw)
    if not m:
        return None
    level = _map_level(m.group("level"))
    msg = m.group("msg")
    if rx is ZK_RE:
        ts = _dt_iso_ms(m.group("ts"), m.group("ms"))
        return _record(n, ts, level, None, msg, raw)
    if rx is HADOOP_RE:
        ts = _dt_iso_ms(m.group("ts"), m.group("ms"))
        thread = m.group("thread") or ""
        return _record(n, ts, level, None, msg, raw, proc=thread or None)
    if rx is SPARK_RE:
        return _record(n, _dt_spark(m.group("ts")), level, None, msg, raw)
    if rx is HDFS_RE:
        ts = _dt_hdfs(m.group("ymd"), m.group("hms"))
        return _record(n, ts, level, None, msg, raw, pid=m.group("tid"))
    if rx is OPENSTACK_RE:
        ts = _dt_iso_ms(m.group("ts"), m.group("ms"))
        return _record(n, ts, level, None, msg, raw, pid=m.group("pid"),
                       proc=m.group("logfile"))
    return None


def load(path, fmt=None, base_year=None, level_fn=None):
    """Parse a sniffed loghub format into canonical records.

    Returns (records, unparsed, total). Unmatched non-blank lines are counted
    as unparsed — never silently dropped. `level_fn` is used only for
    thunderbird (syslog rest has no source level field), same contract as
    normalize.synthesize_level.
    """
    records, unparsed = [], []
    total = 0
    year = base_year or 2005
    prev_month = None
    months = {m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

    with open(path, "r", errors="replace") as f:
        for n, line in enumerate(f, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            total += 1
            rec = None
            if fmt == "apache":
                m = APACHE_RE.match(raw)
                if m:
                    rec = _record(
                        n, _dt_apache(m.group("ts")),
                        _APACHE_LEVEL_MAP.get(m.group("level").upper(), "INFO"),
                        None, m.group("msg"), raw,
                    )
            elif fmt == "log4j":
                rec = _parse_log4j_line(n, raw)
            elif fmt == "bgl":
                m = BGL_RE.match(raw)
                if m:
                    rec = _record(
                        n, _dt_bgl(m.group("ts")),
                        _map_level(m.group("level")),
                        m.group("host"), m.group("msg"), raw,
                        proc=m.group("component"),
                        format="bgl",
                    )
            elif fmt == "proxifier":
                m = PROXIFIER_RE.match(raw)
                if m:
                    msg = m.group("msg")
                    level = "ERROR" if _PROXIFIER_ERROR.search(msg) else "INFO"
                    rec = _record(
                        n, _dt_proxifier(m.group("ts"), year),
                        level, None, msg, raw, proc=m.group("proc"),
                    )
            elif fmt == "thunderbird":
                m = THUNDERBIRD_RE.match(raw)
                if m:
                    month = months.get(m.group("mon"))
                    if prev_month is not None and month and month < prev_month - 6:
                        year += 1
                    if month:
                        prev_month = month
                    date_year = int(m.group("date").split(".")[0])
                    ts = _dt_tb(date_year or year, m.group("mon"),
                                m.group("day"), m.group("time"))
                    msg = m.group("msg")
                    level = level_fn(msg) if level_fn else "INFO"
                    rec = _record(n, ts, level, m.group("host"), msg, raw)
            if rec is None:
                unparsed.append((n, raw))
            else:
                records.append(rec)
    return records, unparsed, total
