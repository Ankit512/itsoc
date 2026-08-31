#!/usr/bin/env python3
"""
collectors.py — sibling parsers for EDR / firewall / cloud JSON events.

Each parser feeds the SAME canonical record the detector consumes:

    {n, ts, level, host, msg, raw}

plus extra fields (action, src_ip, event_id, …) that Sigma and the store
can use. `raw` is always the real JSON (or source text), verbatim.

Severity/level is SOURCE-REPORTED from the event's own level field.
Unrecognized level → "INFO". Never guessed from message text.
anomaly_detector.py is never imported or modified.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

_TS_FIELDS = (
    "timestamp", "time", "ts", "@timestamp", "datetime", "eventTime",
    "ProcessStartTime", "CreationTimeStamp", "event_time", "TimeGenerated",
    "time_created",
)
_LEVEL_FIELDS = (
    "level", "severity", "Severity", "SeverityName", "severity_name",
    "priority", "LogLevel",
)
_HOST_FIELDS = (
    "host", "hostname", "ComputerName", "device", "DeviceName",
    "aid_computer", "computer_name", "resourceName", "instanceId",
)
_MSG_FIELDS = (
    "message", "msg", "DetectName", "ThreatName", "ActionType",
    "event_simpleName", "eventName", "operationName", "description",
    "Summary",
)
_ACTION_FIELDS = ("action", "Action", "ActionType", "outcome", "event_outcome")
_USER_FIELDS = (
    "user", "UserName", "TargetUserName", "account", "userName",
    "userIdentity.userName",
)
_SRC_IP = ("src_ip", "src", "source_ip", "SourceIp", "LocalIP", "sourceIPAddress",
           "ClientIP", "srcaddr")
_DST_IP = ("dst_ip", "dst", "dest_ip", "DestinationIp", "RemoteIP", "dstaddr")
_EVENT_ID = ("event_id", "EventID", "EventId", "eventId", "eid")

_LEVEL_MAP = {
    "emerg": "ERROR", "emergency": "ERROR", "panic": "ERROR",
    "alert": "ERROR", "fatal": "ERROR",
    "critical": "CRITICAL", "crit": "CRITICAL",
    "high": "HIGH",
    "error": "ERROR", "err": "ERROR",
    "medium": "MEDIUM", "med": "MEDIUM",
    "warn": "WARN", "warning": "WARN",
    "low": "LOW",
    "notice": "INFO", "info": "INFO", "information": "INFO", "informational": "INFO",
    "debug": "DEBUG", "trace": "DEBUG",
}


def _pick(obj, fields, default=None):
    for f in fields:
        if "." in f:
            cur = obj
            ok = True
            for part in f.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    ok = False
                    break
                cur = cur[part]
            if ok and cur not in (None, ""):
                return cur
        elif f in obj and obj[f] not in (None, ""):
            return obj[f]
    return default


def _parse_timestamp(val):
    if val is None:
        return None
    if isinstance(val, (int, float)):
        try:
            # CrowdStrike-style milliseconds
            if val > 1e12:
                val = val / 1000.0
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    s = str(val).strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _normalize_level(val):
    if val is None:
        return "INFO"
    if isinstance(val, (int, float)):
        # Numeric vendor scales: 1-4 or 0-100. Map conservatively.
        n = int(val)
        if n >= 4 or n >= 80:
            return "CRITICAL"
        if n == 3 or n >= 50:
            return "HIGH"
        if n == 2 or n >= 30:
            return "MEDIUM"
        return "INFO"
    return _LEVEL_MAP.get(str(val).strip().lower(), "INFO")


def _raw(obj, raw):
    if raw is not None:
        return str(raw)
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(obj)


def _record(obj, n=1, raw=None, extra=None):
    ts = _parse_timestamp(_pick(obj, _TS_FIELDS))
    msg = _pick(obj, _MSG_FIELDS)
    if msg is None:
        msg = json.dumps(obj, ensure_ascii=False, default=str)
    host = _pick(obj, _HOST_FIELDS)
    rec = {
        "n": n,
        "ts": ts.isoformat(timespec="seconds") if ts else "",
        "level": _normalize_level(_pick(obj, _LEVEL_FIELDS)),
        "host": str(host) if host is not None else "",
        "msg": str(msg),
        "raw": _raw(obj, raw),
        "action": str(_pick(obj, _ACTION_FIELDS) or ""),
        "user": str(_pick(obj, _USER_FIELDS) or ""),
        "src_ip": str(_pick(obj, _SRC_IP) or ""),
        "dst_ip": str(_pick(obj, _DST_IP) or ""),
        "event_id": str(_pick(obj, _EVENT_ID) or ""),
    }
    if extra:
        rec.update(extra)
    return rec


def sniff_kind(obj):
    """Best-effort source kind from keys actually present. Never guesses content."""
    if not isinstance(obj, dict):
        return "webhook"
    keys = set(obj)
    if keys & {"DetectName", "ThreatName", "event_simpleName", "aid", "DeviceId"}:
        return "edr"
    if keys & {"eventName", "eventSource", "awsRegion", "userIdentity"} \
            or "protoPayload" in obj or "operationName" in obj:
        return "cloud"
    if keys & {"srcaddr", "dstaddr", "pkts", "bytes"} \
            or (keys & {"action", "src", "dst", "sport", "dport"}) \
            or (keys & {"source_ip", "dest_ip"}):
        return "firewall"
    return "webhook"


def parse_edr(obj, n=1, raw=None):
    extra = {
        "category": "edr",
        "detect_name": str(_pick(obj, ("DetectName", "ThreatName", "threat_name")) or ""),
    }
    rec = _record(obj, n=n, raw=raw, extra=extra)
    rec["source_type"] = "edr"
    return rec


def parse_firewall(obj, n=1, raw=None):
    rec = _record(obj, n=n, raw=raw, extra={"category": "firewall"})
    rec["source_type"] = "firewall"
    # Common firewall action vocabulary stays source-reported.
    if not rec.get("action"):
        rec["action"] = str(_pick(obj, ("eventtype", "fw_action")) or "")
    return rec


def parse_cloud(obj, n=1, raw=None):
    # CloudTrail nests identity; flatten a username if present.
    ident = obj.get("userIdentity") if isinstance(obj.get("userIdentity"), dict) else {}
    extra = {
        "category": "cloud",
        "event_name": str(obj.get("eventName") or obj.get("operationName") or ""),
        "event_source": str(obj.get("eventSource") or ""),
        "aws_region": str(obj.get("awsRegion") or ""),
    }
    rec = _record(obj, n=n, raw=raw, extra=extra)
    if ident.get("userName") and not rec.get("user"):
        rec["user"] = str(ident["userName"])
    rec["source_type"] = "cloud"
    return rec


def parse_auto(obj, n=1, raw=None, source=None):
    kind = (source or sniff_kind(obj) or "webhook").lower()
    if kind == "edr":
        return parse_edr(obj, n=n, raw=raw)
    if kind == "firewall":
        return parse_firewall(obj, n=n, raw=raw)
    if kind == "cloud":
        return parse_cloud(obj, n=n, raw=raw)
    rec = _record(obj, n=n, raw=raw, extra={"category": "webhook"})
    rec["source_type"] = "webhook"
    return rec
