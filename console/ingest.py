#!/usr/bin/env python3
"""
ingest.py — webhook + EDR/firewall/cloud collector intake.

POST body (JSON object):
    { "source": "edr"|"firewall"|"cloud"|"webhook", "events": [ {...}, ... ] }
    { "source": "edr", "event": { ... } }
    { ...single event..., "source": "firewall" }   # also accepted

Each event is parsed by the matching sibling into `{n, ts, level, host, msg, raw}`
and stored verbatim through store.insert_event. `severity` on the stored row is
the SOURCE-REPORTED level — never a guessed verdict, never an AI rating.

Sigma then matches the accepted records (rule-owned hits, returned as
`sigmaHits`). Nothing here writes a finding `sev` and anomaly_detector.py
is never imported.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "formats"))

import collectors  # noqa: E402
import sigma_match  # noqa: E402
import store  # noqa: E402

KNOWN_SOURCES = ("edr", "firewall", "cloud", "webhook")


def _events_from_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    if "events" in payload:
        events = payload.get("events")
        if isinstance(events, dict):
            return [events]
        if isinstance(events, list):
            return events
        raise ValueError("events must be an object or an array")
    if "event" in payload and isinstance(payload.get("event"), dict):
        return [payload["event"]]
    # The rest of the object (minus envelope keys) is the event itself.
    event = {k: v for k, v in payload.items() if k not in ("source", "events", "event")}
    if not event:
        raise ValueError("no event payload")
    return [event]


def ingest_payload(payload):
    """Parse, store, Sigma-match. Never fabricates raw; never sets a verdict."""
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    source = str(payload.get("source") or "webhook").strip().lower()
    if source not in KNOWN_SOURCES:
        raise ValueError(f"source must be one of {KNOWN_SOURCES}")

    raw_events = _events_from_payload(payload)
    accepted = 0
    stored = 0
    duplicates = 0
    unparsed = 0
    records = []

    store.init_db()
    for i, item in enumerate(raw_events, start=1):
        accepted += 1
        rec = None
        raw_text = None
        if isinstance(item, str):
            raw_text = item
            try:
                obj = json.loads(item)
            except json.JSONDecodeError:
                # Honest: a non-JSON string is stored as a raw webhook line.
                obj = {"message": item, "raw": item}
        elif isinstance(item, dict):
            obj = item
            raw_text = None
        else:
            unparsed += 1
            continue
        try:
            rec = collectors.parse_auto(obj, n=i, raw=raw_text, source=source)
        except Exception:
            unparsed += 1
            continue
        if not rec or not rec.get("raw"):
            unparsed += 1
            continue
        records.append(rec)
        row = {
            "ts": rec.get("ts") or "",
            "source": source,
            "source_type": rec.get("source_type") or source,
            "category": rec.get("category") or source,
            "host": rec.get("host") or "",
            "src_ip": rec.get("src_ip") or "",
            "dst_ip": rec.get("dst_ip") or "",
            "user": rec.get("user") or "",
            "event_id": rec.get("event_id") or "",
            "severity": rec.get("level") or "",   # source-reported
            "action": rec.get("action") or "",
            "message": rec.get("msg") or "",
            "raw": rec.get("raw"),
        }
        try:
            if store.insert_event(row):
                stored += 1
            else:
                duplicates += 1
        except Exception:
            unparsed += 1

    grouped = sigma_match.match_records(records, gap_fill=False)
    sigma_hits = sigma_match.hits_summary(records, gap_fill=False)
    return {
        "source": source,
        "accepted": accepted,
        "stored": stored,
        "duplicates": duplicates,
        "unparsed": unparsed,
        "sigmaHits": sigma_hits,
        "sigmaFindings": sigma_match.as_findings(grouped),
        "note": (
            "Stored severity is source-reported. Sigma hits are rule-owned. "
            "Neither is an AI verdict; the frozen detector is unchanged."
        ),
    }


def status():
    """How many collector-sourced rows are in the store, by source_type."""
    store.init_db()
    out = {"sources": {}, "total": 0}
    try:
        page = store.query("events", limit=1, offset=0)
        out["total"] = int(page.get("total") or 0)
    except Exception:
        out["total"] = 0
    for kind in KNOWN_SOURCES + ("syslog",):
        try:
            p = store.query("events", filters={"source_type": kind}, limit=1, offset=0)
            out["sources"][kind] = int(p.get("total") or 0)
        except Exception:
            out["sources"][kind] = 0
    return out
