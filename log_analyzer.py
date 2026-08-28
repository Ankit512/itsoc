#!/usr/bin/env python3
"""
log_analyzer.py — Phase 1: AI-powered log analysis (read-only, no auto-actions)

What it does:
  1. Reads a log file (plain text — syslog, app logs, firewall logs, etc.)
  2. Splits it into manageable chunks
  3. Sends each chunk to an LLM with a strict "analyst" prompt
  4. Collects structured findings (severity, category, explanation, recommended action)
  5. Writes a JSON report + a human-readable Markdown summary

This is intentionally READ-ONLY. It does not query live systems, take action,
or auto-remediate anything. That comes in later phases.

Endpoint-agnostic: speaks the OpenAI-compatible Chat Completions API, so the same
code drives local Ollama (the zero-config default) or any hosted provider.
With the default local endpoint, log contents never leave the machine — point
LLM_BASE_URL at a hosted API and they will.

Usage:
  ollama serve                      # if not already running
  ollama pull qwen3:8b              # the default model — a standard tag, no create step
  python log_analyzer.py --input /path/to/logfile.log --output report

  # llama3.1:8b remains available as the fallback model:
  #   ollama pull llama3.1:8b && export LLM_MODEL=llama3.1:8b

  # or against a hosted OpenAI-compatible endpoint:
  export LLM_BASE_URL=https://api.example.com/v1
  export LLM_API_KEY=sk-...
  export LLM_MODEL=some-model
  python log_analyzer.py --input /path/to/logfile.log --output report

Requirements:
  Python 3 stdlib only. Ollama running on localhost:11434 (default config).
"""

import argparse
import hashlib
import json
import os
import re
import sys
import subprocess
import concurrent.futures
import time
import xml.etree.ElementTree as ET
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Deterministic pre-pass. Imported in-process (not shelled out) so anomalies stay
# as dicts. anomaly_detector.py is the validated original and is never modified;
# normalize.py handles the envelope and rules_syslog.py the vocabulary, so v1's
# correlation can run over formats its own regexes were never written for.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize  # noqa: E402
import rule_context  # noqa: E402
import rules_syslog  # noqa: E402
from anomaly_detector import detect, to_llm_context  # noqa: E402


LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama")
# qwen3:8b is a standard pullable tag (ollama pull qwen3:8b — no create step).
# Under json_schema enforcement it measured 5/5 schema-valid at the default
# token cap; llama3.1:8b stays the documented fallback (its grammar-constrained
# replies can hit the 384-token cap): export LLM_MODEL=llama3.1:8b
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3:8b")

# Thinking suppression for reasoning models (e.g. qwen3): sent as
# OpenAI-compatible `reasoning_effort` on every chat request. "none" disables
# qwen3's thinking on Ollama's /v1 endpoint (verified live; non-thinking models
# like llama3.1 simply ignore the field there), so the default model answers
# without paying reasoning latency. Set LLM_REASONING_EFFORT="" (empty) to omit
# the field entirely — e.g. for a hosted endpoint that rejects it.
LLM_REASONING_EFFORT = os.getenv("LLM_REASONING_EFFORT", "none")

# Schema-constrained decoding: ask the endpoint to constrain generation to the
# reply schema (OpenAI-compatible response_format type "json_schema" — Ollama
# honors it on /v1), so only schema-valid tokens can be emitted. Default ON;
# set LLM_STRUCTURED_OUTPUT=0 to use the json_object+validate path only.
# Endpoints that reject the schema fall back to that path automatically —
# loudly, and recorded in run metadata.
LLM_STRUCTURED_OUTPUT = os.getenv("LLM_STRUCTURED_OUTPUT", "1").lower() not in ("0", "false", "off")

# Set once, on the first schema-bearing request an endpoint rejects. Sticky for
# the rest of the process so every later call goes straight to the fallback path
# instead of paying a doomed request per chunk. Never cleared silently — the
# reason lands in run metadata via structured_output_status().
_STRUCTURED_FALLBACK = {"reason": None}


def structured_output_status():
    """The honest, machine-readable state of schema-constrained decoding.

    "on" | "off" | "fallback:<reason>" — written into run metadata so a report
    always says which decoding path produced it. An unsupported schema is never
    silently ignored: rejection flips this to "fallback:..." for the whole run.
    """
    if not LLM_STRUCTURED_OUTPUT:
        return "off"
    if _STRUCTURED_FALLBACK["reason"]:
        return f"fallback:{_STRUCTURED_FALLBACK['reason']}"
    return "on"

# 0 keeps reports reproducible: the same log yields the same findings.
try:
    LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0"))
except ValueError:
    print(f"ERROR: LLM_TEMPERATURE must be a number, got {os.getenv('LLM_TEMPERATURE')!r}")
    sys.exit(1)

RULESET_VERSION = "v3-universal-soc-high-coverage"

# Gap-fill = asking the model about chunks NO rule fired on, to catch sub-threshold
# things like "disk at 78%". It is the only reason to send a chunk containing no
# finding, and on a large log it is also the entire cost: 2,000 lines is 80 chunks,
# nearly all empty. So it runs automatically only on inputs small enough to be
# cheap, and is opt-in beyond that via --deep-scan.
GAP_FILL_MAX_CHUNKS = 4

# Keep LLM explanations bounded. The deterministic rules are authoritative and
# must not wait indefinitely for prose. These are environment-configurable.
LLM_TIMEOUT = int(os.getenv("SOC_LLM_TIMEOUT", "90"))
LLM_RETRIES = int(os.getenv("SOC_LLM_RETRIES", "0"))
LLM_WORKERS = max(1, int(os.getenv("SOC_LLM_WORKERS", "3")))
MAX_COMPLETION_TOKENS = int(os.getenv("SOC_MAX_COMPLETION_TOKENS", "384"))

# Explanations are generated eagerly for only the most severe findings; the rest are
# produced on demand when a reviewer opens them. Wall time for a run is then bounded
# by this number, not by the size of the log — a 2,000-line file with 18 findings
# costs the same first-paint as a 19-line one. Rules still cover every line.
EAGER_EXPLANATIONS = 3

# A chunk we already read can still come back with a finding unexplained: the model
# skips a rule id, or writes one explanation for two same-type findings and names only
# one host. Those used to render "n/a" forever. We re-ask for each such finding
# individually — the chunk is already selected, so this is prose we meant to have.
# Bounded, because in --deep-scan every chunk is selected and the tail is not worth
# minutes of wall time; whatever is left over is still explained on demand.
SECOND_PASS_MAX = 6

# Ollama unloads an idle model after ~5 minutes by default, so the first call of a
# run pays ~9s of load time. Pinning it at preflight removes that from the run.
OLLAMA_KEEP_ALIVE = "30m"

# Machine-readable progress for console/serve.py. Off by default so CLI output stays
# prose; serve.py sets LOG_ANALYZER_PROGRESS=1 and parses these lines.
_PROGRESS = os.getenv("LOG_ANALYZER_PROGRESS") == "1"
RULE_WARNING_SECONDS = int(os.getenv("SOC_RULE_WARNING_SECONDS", "30"))
ANALYSIS_HARD_TIMEOUT = int(os.getenv("SOC_ANALYSIS_HARD_TIMEOUT", "0"))  # 0 = disabled


def progress(**fields):
    if _PROGRESS:
        print("PROGRESS " + json.dumps(fields), flush=True)


FINDING_LINES_RE = re.compile(r"lines (\d+)-(\d+)")


def finding_line_numbers(anomaly):
    """Every source line this finding points at, from its timeline and evidence."""
    lines = {e["line"] for e in anomaly.get("timeline", []) if e.get("line")}
    m = FINDING_LINES_RE.search(anomaly.get("evidence") or "")
    if m:
        lines |= {int(m.group(1)), int(m.group(2))}
    return lines


def chunks_with_findings(anomalies, lines_per_chunk, chunk_count):
    """Indices of chunks that actually contain a detector finding.

    This is the whole performance story. The detector reads every line for free;
    the model is only needed to explain what the detector found. Sending it the
    other 70% of a large log costs minutes and buys nothing, because a finding it
    produced there would have no rule behind it anyway.
    """
    wanted = set()
    for a in anomalies:
        for line in finding_line_numbers(a):
            idx = (line - 1) // lines_per_chunk
            if 0 <= idx < chunk_count:
                wanted.add(idx)
    return wanted


def should_run_model(stats):
    """Run the LLM pass only when the parser actually structured something.

    When 0 lines parse, no rule has evaluated anything, so there is nothing for the
    model to explain and nothing to check its output against. Running it anyway
    produces unvalidated guesses over text we cannot read — measured on a macOS
    unified log, that was 21 spurious LOW findings about routine OS events, which
    then read on the console as coverage the run never had.

    Rules-first is the thesis: no structure, no analysis. Say so instead.
    """
    return stats.get("parsed", 0) > 0


def file_sha256(path):
    """Integrity hash for the run manifest.

    Recomputable by anyone holding the file. This is an INTEGRITY check, not a
    signature — nothing here attests to who produced the run, and the UI must
    never present it as if it did.
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


SYSTEM_PROMPT = """You are a SOC/NOC log analyst. You are given a chunk of raw log lines,
preceded by a list of anomalies already pre-flagged by deterministic rule-based detectors.

THE PRE-FLAGGED ANOMALIES ARE AUTHORITATIVE:
- Their severities are decided by validated rules. NEVER change, re-rate, or second-guess them.
- NEVER re-report a pre-flagged anomaly as one of your own findings. It is already in the report.
- Instead, EXPLAIN each pre-flagged anomaly in plain language for a human analyst: what it means,
  why it matters, and what to check. Put these in the "explanations" array, keyed by its rule id.

YOUR FINDINGS ARE FOR ADDITIONAL ISSUES ONLY:
- Report only genuine issues that are NOT already covered by a pre-flagged anomaly.
- Ignore routine/benign log lines — do not report normal operation as a finding.
- Be conservative: if you are not confident something is a real issue, do not report it,
  or mark it "low" and say why you're uncertain.
- Never invent details not present in the logs. If a line is ambiguous, say so.
- If everything notable is already pre-flagged, return an empty "findings" array. That is a
  correct and expected answer — do not invent findings to fill it.

Respond ONLY with valid JSON (no markdown fences, no preamble), matching this schema:

{
  "explanations": [
    {
      "rule_id": "the type of the pre-flagged anomaly you are explaining, e.g. auth_bruteforce_success",
      "explanation": "2-3 sentences a human analyst can act on: what happened, why it matters, what to check"
    }
  ],
  "findings": [
    {
      "severity": "info|low|medium|high|critical",
      "category": "string, e.g. authentication, network, disk, application_error, security, performance",
      "summary": "one-sentence description of what happened",
      "evidence": "the specific log line(s) or pattern that triggered this finding (short excerpt)",
      "recommended_action": "what a human analyst should check or do next",
      "confidence": "low|medium|high",
      "rule_id": null,
      "source": "llm"
    }
  ],
  "chunk_summary": "1-2 sentence overview of what this chunk of logs generally shows"
}
"""

# The machine-readable twin of the shape SYSTEM_PROMPT asks for, used for
# schema-constrained decoding (response_format type "json_schema"). Derived
# from THIS app's contract: validate_response() accepts a dict with a
# "findings" list whose items are dicts carrying a non-empty string "summary" —
# so that is exactly what the schema requires, and no more. Everything else is
# permitted-but-optional, matching the validator: over-constraining here would
# make the constrained path stricter than the validated path and reject replies
# the app would have accepted.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "explanations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": ["string", "null"]},
                    "explanation": {"type": "string"},
                },
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string"},
                    "category": {"type": "string"},
                    "summary": {"type": "string", "minLength": 1},
                    "evidence": {"type": "string"},
                    "recommended_action": {"type": "string"},
                    "confidence": {"type": "string"},
                    "rule_id": {"type": ["string", "null"]},
                    "source": {"type": "string"},
                },
                "required": ["summary"],
            },
        },
        "chunk_summary": {"type": "string"},
    },
    "required": ["findings"],
}

RETRY_NUDGE = (
    "\n\nYour previous reply was not valid JSON. Reply with the JSON object only — "
    "no prose, no markdown fences."
)

SCHEMA_NUDGE = (
    "\n\nYour previous reply was valid JSON but had the WRONG SHAPE. It must be a JSON "
    'object whose top-level keys are exactly "explanations" (array), "findings" (array) '
    'and "chunk_summary" (string). Do not invent other top-level keys such as "log" or '
    '"events". Put every issue you found inside the "findings" array.'
)



# ---------------------------------------------------------------------------
# Input handling / universal multi-format parser
# ---------------------------------------------------------------------------

WINDOWS_EVENT_START_RE = re.compile(
    r"^\s*(\d{1,2}/\d{1,2}/\d{4}\s+"
    r"\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\s*(?:AM|PM)?)\s*$",
    re.I,
)
KEY_VALUE_RE = re.compile(r"^\s*([^=\s][^=]*?)\s*=\s*(.*)$")
ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
SYSLOG_TS_RE = re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")


def detect_encoding(path: Path):
    """Detect common Windows/Linux text encodings from a small prefix."""
    with path.open("rb") as f:
        sample = f.read(65536)
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return "utf-16"
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    # UTF-16 without BOM is common in exported Windows text. Only select it
    # when NULs strongly indicate UTF-16; otherwise use UTF-8/cp1252.
    if b"\x00" in sample:
        even_nuls = sample[0::2].count(0)
        odd_nuls = sample[1::2].count(0)
        if max(even_nuls, odd_nuls) > max(20, len(sample) // 20):
            return "utf-16-le" if odd_nuls > even_nuls else "utf-16-be"
    try:
        sample.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        try:
            sample.decode("cp1252")
            return "cp1252"
        except UnicodeDecodeError:
            return "latin-1"


def iter_text_lines(path: Path, encoding=None):
    """Stream text lines. Never calls readlines() or loads the complete file."""
    encoding = encoding or detect_encoding(path)
    with path.open("r", encoding=encoding, errors="replace", newline=None) as f:
        for line in f:
            yield line.rstrip("\r\n")


def _parse_timestamp(msg):
    patterns = [
        r"\b\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\s*(?:AM|PM)\b",
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b",
        # Apache/nginx common-log time, e.g. "10/Oct/2000:13:55:36 -0700".
        r"\b\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}\b",
        r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",
        # Epoch millis then epoch seconds (leading 1 keeps this to ~2001-2286
        # so ordinary large integers are not mistaken for a timestamp).
        r"\b1\d{12}\b",
        r"\b1\d{9}\b",
    ]
    for pattern in patterns:
        m = re.search(pattern, msg)
        if m:
            return m.group(0)
    return None


def _coerce_timestamp(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value
    text = str(value).strip()
    from datetime import datetime, timezone
    # Epoch seconds / milliseconds. Epoch is an absolute instant (UTC), so this
    # honours the real time rather than guessing a year or a local zone.
    if text.isdigit():
        try:
            iv = int(text)
            if len(text) >= 13:      # milliseconds
                iv = iv / 1000.0
            return datetime.fromtimestamp(iv, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    for fmt in (
        "%m/%d/%Y %I:%M:%S.%f %p",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        # Apache/nginx common-log time; %z honours the embedded offset instead
        # of forcing UTC.
        "%d/%b/%Y:%H:%M:%S %z",
    ):
        try:
            return datetime.strptime(text.replace("Z", "+00:00"), fmt)
        except ValueError:
            continue
    return None


def _coerce_value(value):
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "none"}:
        return None
    return value


def _normalize_record(record, line_no=None, raw=None):
    """Create the common schema without throwing away vendor-specific fields."""
    r = dict(record or {})
    message = (
        r.get("msg") or r.get("message") or r.get("Message") or
        r.get("event") or r.get("Event") or r.get("log") or ""
    )
    if not message:
        # Keep a compact textual representation for structured records.
        message = json.dumps(r, ensure_ascii=False, default=str)

    timestamp = (
        r.get("timestamp") or r.get("@timestamp") or r.get("Timestamp") or
        r.get("time") or r.get("TimeCreated") or _parse_timestamp(str(message))
    )
    r["msg"] = str(message)
    r["message"] = str(message)
    r["timestamp"] = timestamp
    # Canonical time/line aliases required by anomaly_detector.py.
    r["ts"] = _coerce_timestamp(timestamp)

    # Canonical severity schema required by anomaly_detector.py.
    # Older/vendor-specific parsers may provide severity as `severity`,
    # `Severity`, `level`, `Level`, or `priority`.  The detector accesses
    # r["level"] directly, so every normalized record MUST contain it.
    level = (
        r.get("level") or r.get("Level") or r.get("severity") or
        r.get("Severity") or r.get("priority") or r.get("Priority")
    )
    if level is None or str(level).strip() == "":
        level = "INFO"

    level_text = str(level).strip().upper()
    level_aliases = {
        "EMERGENCY": "CRIT", "EMERG": "CRIT",
        "ALERT": "CRIT", "CRITICAL": "CRIT", "CRIT": "CRIT",
        "FATAL": "CRIT",
        "ERROR": "ERROR", "ERR": "ERROR",
        "WARNING": "WARN", "WARN": "WARN",
        "NOTICE": "INFO", "INFORMATION": "INFO", "INFO": "INFO",
        "DEBUG": "DEBUG", "TRACE": "DEBUG",
    }
    r["level"] = level_aliases.get(level_text, level_text)

    # Keep a conventional severity field as well.  This preserves vendor
    # values while giving downstream rules one predictable field.
    r.setdefault("severity", r["level"])

    if raw is not None:
        r["raw"] = raw
    else:
        r.setdefault("raw", str(message))
    if line_no is not None:
        r["line"] = line_no
        r["n"] = line_no
    else:
        r.setdefault("n", r.get("line"))
    return r


def _looks_like_windows_export(lines):
    sample = []
    for line in lines:
        if line.strip():
            sample.append(line)
        if len(sample) >= 80:
            break
    text = "\n".join(sample)
    return bool(
        re.search(r"(?im)^\s*LogName\s*=\s*Security\s*$", text) or
        re.search(r"(?im)^\s*EventCode\s*=\s*\d+\s*$", text) or
        any(WINDOWS_EVENT_START_RE.match(x) for x in sample)
    )


def parse_windows_text(path: Path, encoding=None):
    """Parse common Windows Event Log text exports.

    Typical input:
      08/18/2026 07:18:34.068 PM
      LogName=Security
      EventCode=4672
      ComputerName=DC01
      ...
    A timestamp starts a new event; key=value lines belong to that event.
    Multiline Message= values are preserved.
    """
    encoding = encoding or detect_encoding(path)
    records = []
    current = None
    current_lines = []
    event_start_line = None
    total_lines = 0

    def flush():
        nonlocal current, current_lines, event_start_line
        if not current:
            return
        raw = "\n".join(current_lines)
        record = dict(current)
        # Useful aliases for the existing detector/rules.
        if "EventCode" in record:
            record.setdefault("event_id", record["EventCode"])
        if "EventID" in record:
            record.setdefault("event_id", record["EventID"])
        if "ComputerName" in record:
            record.setdefault("host", record["ComputerName"])
        if "Hostname" in record:
            record.setdefault("host", record["Hostname"])
        if "IpAddress" in record:
            record.setdefault("src_ip", record["IpAddress"])
        if "SourceNetworkAddress" in record:
            record.setdefault("src_ip", record["SourceNetworkAddress"])
        record = _normalize_record(record, event_start_line, raw)
        records.append(record)
        current = None
        current_lines = []
        event_start_line = None

    for line_no, line in enumerate(iter_text_lines(path, encoding), start=1):
        total_lines = line_no
        stripped = line.strip()
        if not stripped:
            # Keep blank lines inside an event, but do not create events from them.
            if current is not None:
                current_lines.append(line)
            continue

        ts_match = WINDOWS_EVENT_START_RE.match(line)
        if ts_match:
            if current is not None:
                flush()
            current = {"timestamp": ts_match.group(1)}
            current_lines = [line]
            event_start_line = line_no
            continue

        # Some exports start with a header and then EventCode without a timestamp.
        kv = KEY_VALUE_RE.match(line)
        if kv:
            key, value = kv.group(1).strip(), _coerce_value(kv.group(2))
            if current is None:
                current = {}
                current_lines = []
                event_start_line = line_no
            current[key] = value
            current_lines.append(line)
        else:
            # A line before the first event is retained as an event rather than
            # being discarded. This is important for vendor text exports.
            if current is None:
                current = {}
                current_lines = []
                event_start_line = line_no
            current_lines.append(line)
            # Preserve multiline message content.
            if "Message" in current and current["Message"]:
                current["Message"] = str(current["Message"]) + "\n" + line

    flush()
    return records, {
        "format": "windows_event_text",
        "parsed": len(records),
        "total_lines": total_lines,
        "unparsed": max(0, total_lines - len(records)),
        "unparsed_examples": [],
        "encoding": encoding,
    }


def parse_text_stream(path: Path, encoding=None):
    """Generic streaming parser for syslog, Linux, network, firewall, backup and app logs."""
    encoding = encoding or detect_encoding(path)
    records = []
    total_lines = 0
    for line_no, raw in enumerate(iter_text_lines(path, encoding), start=1):
        total_lines = line_no
        msg = raw.strip()
        if not msg:
            continue
        record = {
            "msg": msg,
            "message": msg,
            "raw": raw,
            "line": line_no,
            "timestamp": _parse_timestamp(msg),
        }
        # Lightweight common field extraction; vendor-specific data remains in raw.
        ip_match = re.search(r"\b(?:src|source|src_ip|sourceip)[=: ]+([0-9a-fA-F:.]+)", msg, re.I)
        dst_match = re.search(r"\b(?:dst|destination|dst_ip|destinationip)[=: ]+([0-9a-fA-F:.]+)", msg, re.I)
        if ip_match:
            record["src_ip"] = ip_match.group(1)
        if dst_match:
            record["dst_ip"] = dst_match.group(1)
        records.append(record)

    return records, {
        "format": "generic_text",
        "parsed": len(records),
        "total_lines": total_lines,
        "unparsed": max(0, total_lines - len(records)),
        "unparsed_examples": [],
        "encoding": encoding,
    }


def parse_json_file(path: Path, encoding=None):
    """Parse JSON objects/arrays. JSONL/NDJSON is streamed separately."""
    encoding = encoding or detect_encoding(path)
    with path.open("r", encoding=encoding, errors="replace") as f:
        data = json.load(f)

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        # Common SIEM exports wrap events in one of these keys.
        for key in ("events", "results", "records", "logs", "items", "data"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        else:
            items = [data]
    else:
        items = [{"message": str(data)}]

    records = []
    for i, obj in enumerate(items, start=1):
        if isinstance(obj, dict):
            records.append(_normalize_record(obj, i, json.dumps(obj, ensure_ascii=False, default=str)))
        else:
            records.append(_normalize_record({"message": str(obj)}, i, str(obj)))

    return records, {
        "format": "json",
        "parsed": len(records),
        "total_lines": 0,
        "unparsed": 0,
        "unparsed_examples": [],
        "encoding": encoding,
    }


def parse_jsonl_file(path: Path, encoding=None):
    encoding = encoding or detect_encoding(path)
    records = []
    total_lines = 0
    bad = 0
    examples = []
    for line_no, line in enumerate(iter_text_lines(path, encoding), start=1):
        total_lines = line_no
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(_normalize_record(obj, line_no, line))
            else:
                records.append(_normalize_record({"message": str(obj)}, line_no, line))
        except json.JSONDecodeError:
            bad += 1
            if len(examples) < 5:
                examples.append(line)
    return records, {
        "format": "jsonl",
        "parsed": len(records),
        "total_lines": total_lines,
        "unparsed": bad,
        "unparsed_examples": examples,
        "encoding": encoding,
    }


def parse_csv_file(path: Path, encoding=None):
    import csv
    encoding = encoding or detect_encoding(path)
    records = []
    total_lines = 0
    with path.open("r", encoding=encoding, errors="replace", newline="") as f:
        sample = f.read(8192)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        for row_no, row in enumerate(reader, start=2):
            total_lines = row_no
            clean = {str(k).strip(): v for k, v in row.items() if k is not None}
            raw = json.dumps(clean, ensure_ascii=False, default=str)
            records.append(_normalize_record(clean, row_no, raw))
    return records, {
        "format": "csv",
        "parsed": len(records),
        "total_lines": total_lines,
        "unparsed": 0,
        "unparsed_examples": [],
        "encoding": encoding,
    }


def _xml_local_name(tag):
    return str(tag).split("}", 1)[-1].lower()


def parse_xml_file(path: Path, encoding=None):
    """Streaming XML parser for Windows exports and vendor XML/SIEM exports."""
    import xml.etree.ElementTree as ET

    encoding = encoding or detect_encoding(path)
    records = []
    event_names = {
        "event", "logentry", "record", "entry", "eventdata",
        "log", "message", "result"
    }

    # Prefer elements with event-like names and at least one child/attribute.
    # iterparse releases elements immediately after processing.
    for _, elem in ET.iterparse(str(path), events=("end",)):
        name = _xml_local_name(elem.tag)
        if name not in event_names:
            continue

        children = list(elem)
        attrs = dict(elem.attrib)
        values = dict(attrs)

        for child in children:
            cname = _xml_local_name(child.tag)
            text = "".join(child.itertext()).strip()
            if text:
                values[cname] = text

        text_self = (elem.text or "").strip()
        if text_self and not values:
            values["message"] = text_self

        if values:
            raw = ET.tostring(elem, encoding="unicode")
            records.append(_normalize_record(values, len(records) + 1, raw))

        elem.clear()

    # If no event-like nodes were found, make a final generic XML record from
    # the root rather than declaring the file unsupported.
    if not records:
        try:
            root = ET.parse(str(path)).getroot()
            raw = ET.tostring(root, encoding="unicode")
            records.append(_normalize_record(
                {"message": "".join(root.itertext()).strip()},
                1, raw
            ))
        except Exception:
            raise

    total_lines = 0
    with path.open("r", encoding=encoding, errors="replace") as f:
        for total_lines, _ in enumerate(f, start=1):
            pass

    return records, {
        "format": "xml",
        "parsed": len(records),
        "total_lines": total_lines,
        "unparsed": 0,
        "unparsed_examples": [],
        "encoding": encoding,
    }


def parse_html_file(path: Path, encoding=None):
    from html.parser import HTMLParser

    encoding = encoding or detect_encoding(path)

    class Collector(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.rows = []
            self.current = []
        def handle_data(self, data):
            data = data.strip()
            if data:
                self.current.append(data)
        def handle_endtag(self, tag):
            if tag.lower() in {"tr", "p", "div", "li"} and self.current:
                self.rows.append(" ".join(self.current))
                self.current = []

    parser = Collector()
    with path.open("r", encoding=encoding, errors="replace") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), ""):
            parser.feed(chunk)
    parser.close()

    records = [
        _normalize_record({"message": row}, i, row)
        for i, row in enumerate(parser.rows, start=1)
        if row.strip()
    ]
    return records, {
        "format": "html",
        "parsed": len(records),
        "total_lines": 0,
        "unparsed": 0,
        "unparsed_examples": [],
        "encoding": encoding,
    }


def _content_sample(path: Path):
    with path.open("rb") as f:
        return f.read(16384)


def detect_input_format(path: Path):
    ext = path.suffix.lower()
    sample = _content_sample(path)
    encoding = detect_encoding(path)
    text = sample.decode(encoding, errors="replace").lstrip()

    if ext in {".evtx"}:
        return "evtx", encoding
    if text.startswith("<") or ext in {".xml"}:
        return "xml", encoding
    if "<html" in text[:1000].lower() or ext in {".html", ".htm"}:
        return "html", encoding
    if ext in {".jsonl", ".ndjson"}:
        return "jsonl", encoding
    if ext == ".json":
        return "json", encoding
    if ext == ".csv":
        return "csv", encoding
    if _looks_like_windows_export(text.splitlines()):
        return "windows_event_text", encoding

    # Content-based JSON detection even when the extension is .txt/.log.
    if text.startswith("{") or text.startswith("["):
        try:
            json.loads(text)
            return "json", encoding
        except Exception:
            pass
        if "\n" in text:
            first = next((x for x in text.splitlines() if x.strip()), "")
            try:
                json.loads(first)
                return "jsonl", encoding
            except Exception:
                pass

    # CSV detection for extension-less vendor exports.
    if ext not in {".log", ".txt", ".raw", ".out", ".md", ".markdown"}:
        return "text", encoding
    first_lines = [x for x in text.splitlines() if x.strip()][:5]
    if first_lines and any("," in x for x in first_lines):
        import csv
        try:
            csv.Sniffer().sniff("\n".join(first_lines), delimiters=",;\t|")
            return "csv", encoding
        except csv.Error:
            pass

    return "text", encoding


def try_evtx(path: Path):
    try:
        from Evtx.Evtx import Evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        return None

    records = []
    with Evtx(str(path)) as log:
        for i, record in enumerate(log.records(), start=1):
            raw_xml = record.xml()
            try:
                root = ET.fromstring(raw_xml)
                values = {}
                for elem in root.iter():
                    name = _xml_local_name(elem.tag)
                    if elem.text and elem.text.strip():
                        values[name] = elem.text.strip()
                records.append(_normalize_record(values, i, raw_xml))
            except Exception:
                records.append(_normalize_record({"message": raw_xml}, i, raw_xml))
    return records, {
        "format": "evtx",
        "parsed": len(records),
        "total_lines": len(records),
        "unparsed": 0,
        "unparsed_examples": [],
        "encoding": "binary",
    }


def load_log_file(path: Path):
    """Canonical ingestion entry point for Windows/Linux/network/firewall/SIEM/backup logs.

    The project normalizer remains the first deterministic parser. If it recognizes
    nothing, this function NEVER converts a readable file into 'unsupported format';
    it invokes the content-aware universal parser.
    """
    try:
        native_records, native_stats = normalize.load(path)
        parsed = native_stats.get("parsed", 0)
        total = native_stats.get("total_lines", 0) or 0
        # Accept the native (syslog) parse ONLY when it covers a high fraction of
        # the non-blank lines. A weak partial match — e.g. a JSON/CSV/access log
        # where a handful of lines happen to look syslog-ish — falls through to
        # the universal parser instead of leaving most lines unparsed. Pure
        # syslog covers ~all lines, so its behaviour is unchanged.
        native_fraction = (parsed / total) if total > 0 else 0.0
        if parsed > 0 and native_fraction >= 0.6:
            native_stats.setdefault("encoding", "native")
            return native_records, native_stats
        if parsed > 0:
            print(
                f"WARNING: native parser recognized only {parsed}/{total} lines "
                f"({native_fraction:.0%}) in {path.name}; using universal "
                "multi-format ingestion."
            )
        else:
            print(
                f"WARNING: native parser recognized 0 records in {path.name}; "
                "using universal multi-format ingestion."
            )
    except Exception as exc:
        print(f"WARNING: native parser failed for {path.name}: {exc}")
        print("         Using universal multi-format ingestion.")

    fmt, encoding = detect_input_format(path)

    try:
        if fmt == "evtx":
            result = try_evtx(path)
            if result is None:
                print("WARNING: python-evtx is not installed; treating EVTX as unsupported binary.")
                raise ValueError("Install python-evtx to parse .evtx files")
            return result
        if fmt == "xml":
            return parse_xml_file(path, encoding)
        if fmt == "windows_event_text":
            return parse_windows_text(path, encoding)
        if fmt == "json":
            return parse_json_file(path, encoding)
        if fmt == "jsonl":
            return parse_jsonl_file(path, encoding)
        if fmt == "csv":
            return parse_csv_file(path, encoding)
        if fmt == "html":
            return parse_html_file(path, encoding)
        return parse_text_stream(path, encoding)
    except Exception as exc:
        # Last-resort text ingestion: readable text must remain analyzable.
        print(f"WARNING: {fmt} parser failed for {path.name}: {exc}")
        print("         Falling back to streaming text ingestion.")
        return parse_text_stream(path, encoding)


def chunk_log_file(path: Path, lines_per_chunk: int = 25):
    """Stream physical lines into LLM-sized chunks without readlines()."""
    chunk = []
    start_line = 1
    for line_no, line in enumerate(iter_text_lines(path), start=1):
        chunk.append(line)
        if len(chunk) >= lines_per_chunk:
            yield start_line, chunk
            start_line = line_no + 1
            chunk = []
    if chunk:
        yield start_line, chunk


def dedupe_anomalies(anomalies):
    """Collapse anomalies identical on (type, summary) into one, keeping an occurrence count.

    The detector legitimately fires once per matching line, so two identical CRIT lines
    produce two byte-identical bullets. Deduping here (not in the detector) keeps the
    validated detector untouched.
    """
    seen = {}
    order = []
    for a in anomalies:
        key = (a.get("type"), a.get("summary"))
        if key in seen:
            seen[key]["occurrences"] += 1
        else:
            copy = dict(a)
            copy["occurrences"] = 1
            seen[key] = copy
            order.append(key)
    return [seen[k] for k in order]


def build_user_prompt(log_text, ctx, suffix=""):
    """Build the user message. THE single place the prompt is assembled.

    Both the first attempt and the retry go through here, so pre-flagged context can
    never be dropped on a retry.
    """
    return f"{ctx}\n\nAnalyze this log chunk:\n\n{log_text}{suffix}"


def _use_schema(response_schema):
    """Should THIS call constrain decoding? Only when a caller passed a schema,
    the flag is on, and the endpoint hasn't already rejected one this run."""
    return (response_schema is not None and LLM_STRUCTURED_OUTPUT
            and not _STRUCTURED_FALLBACK["reason"])


def _schema_response_format(response_schema):
    return {"type": "json_schema",
            "json_schema": {"name": "log_analysis_reply", "schema": response_schema}}


def _record_schema_fallback(error):
    """An endpoint rejecting the schema is a fact about the run — record it for
    metadata and say so on the console. Never a silent downgrade."""
    reason = f"endpoint rejected json_schema (HTTP {error.code})"
    _STRUCTURED_FALLBACK["reason"] = reason
    print(f"  structured output unavailable: {reason}; "
          "falling back to json_object+validate (recorded in run metadata)")


def _chat_request(base_url, api_key, model, system, user, response_format, stream=False):
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": LLM_TEMPERATURE,
        "max_tokens": MAX_COMPLETION_TOKENS,
    }
    if LLM_REASONING_EFFORT:
        body["reasoning_effort"] = LLM_REASONING_EFFORT
    if response_format is not None:
        body["response_format"] = response_format
    if stream:
        body["stream"] = True
        # Streaming callers send prose (see chat_completion_stream) — a token
        # cap sized for one JSON reply would truncate it mid-sentence.
        del body["max_tokens"]
    return urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )


def chat_completion(base_url, api_key, model, system, user, timeout=LLM_TIMEOUT,
                    response_schema=None):
    """POST one prompt to an OpenAI-compatible /chat/completions and return the reply text.

    With `response_schema`, decoding is schema-constrained (response_format type
    "json_schema" — Ollama honors this on its /v1 endpoint) so only schema-valid
    tokens can be emitted. If the endpoint rejects the schema-bearing request,
    the call retries once as plain json_object and the downgrade is recorded via
    _record_schema_fallback — the caller still validates every reply, so the
    json_object+validate path stays the safety net either way.
    """
    use_schema = _use_schema(response_schema)
    response_format = (_schema_response_format(response_schema) if use_schema
                       else {"type": "json_object"})
    req = _chat_request(base_url, api_key, model, system, user, response_format)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if not use_schema:
            raise
        # Retry WITHOUT the schema before concluding anything: if this also
        # fails, the endpoint is broken (not schema-averse) and the original
        # error surfaces through the existing api_error path.
        retry = _chat_request(base_url, api_key, model, system, user,
                              {"type": "json_object"})
        with urllib.request.urlopen(retry, timeout=timeout) as resp:
            body = json.loads(resp.read())
        _record_schema_fallback(e)
    return body["choices"][0]["message"]["content"]


def chat_completion_stream(base_url, api_key, model, system, user, timeout=LLM_TIMEOUT):
    """Yield reply-text chunks from an OpenAI-compatible /chat/completions with
    stream:true (Ollama supports this on its /v1 endpoint).

    Prose, not JSON: streaming a `{"answer": ...}` wrapper would leak braces
    into the reader token-by-token, so the caller passes a prose system prompt.
    Each SSE `data:` line carries a delta; `[DONE]` ends the stream. The reply
    is still the model's real output — this only changes WHEN it arrives, never
    what it says, and it never touches severities or verdicts."""
    req = _chat_request(base_url, api_key, model, system, user, None, stream=True)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
                delta = obj["choices"][0]["delta"].get("content")
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
            if delta:
                yield delta


def strip_fences(text):
    """Defensive cleanup in case the model wraps in fences despite instructions."""
    return text.replace("```json", "").replace("```", "").strip()


def validate_response(obj):
    """Does the reply have the SHAPE the system prompt asked for?

    response_format=json_object guarantees only that the reply *parses*. Small models
    routinely return well-formed JSON of the wrong shape (e.g. {"log": [...]}), which
    a parseability-only check accepts and .get("findings", []) then silently reads as
    "no findings" — a false all-clear on a log full of real events.

    Drift also happens one level down: a correct "findings" list whose items use the
    model's own keys ("finding"/"description" instead of "summary"). Those render as
    empty placeholders and slip past restatement dedupe, so items are checked too.
    An empty findings list stays valid — "nothing beyond the pre-flagged anomalies"
    is a legitimate answer.
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        return False
    return all(_valid_finding(f) for f in obj["findings"])


def _valid_finding(f):
    return isinstance(f, dict) and isinstance(f.get("summary"), str) and bool(f["summary"].strip())


def describe_schema_failure(obj):
    """Say which layer drifted, so the report's evidence is actually diagnostic."""
    if not isinstance(obj, dict):
        return f"reply was a JSON {type(obj).__name__}, not an object"
    if not isinstance(obj.get("findings"), list):
        return f"no 'findings' array; top-level keys: {list(obj.keys())}"
    bad = [sorted(f.keys()) if isinstance(f, dict) else type(f).__name__
           for f in obj["findings"] if not _valid_finding(f)]
    return f"{len(bad)} findings[] item(s) lack a usable 'summary'; item keys: {bad[:2]}"


def analyze_chunk(base_url, api_key, model, chunk_lines, chunk_index, ctx):
    """Send one chunk to the model and parse the structured response.

    Retries once with a stricter nudge if the first reply is not valid JSON.
    """
    log_text = "".join(chunk_lines)
    user_prompt = build_user_prompt(log_text, ctx)
    raw_text = ""

    for attempt in range(1, LLM_RETRIES + 2):
        try:
            raw_text = strip_fences(
                chat_completion(base_url, api_key, model, SYSTEM_PROMPT, user_prompt,
                                timeout=LLM_TIMEOUT, response_schema=RESPONSE_SCHEMA)
            )
        except Exception as e:
            # Network/timeouts are not worth an automatic second full generation.
            # Deterministic findings remain authoritative and the UI can retry the
            # explanation on demand.
            return {
                "findings": [{
                    "severity": "low",
                    "category": "api_error",
                    "summary": f"API call failed: {e}",
                    "evidence": "",
                    "recommended_action": "Retry explanation on demand or check API connectivity",
                    "confidence": "low",
                    "source": "analyzer",
                }],
                "chunk_summary": "API error on this chunk",
            }

        parsed = None
        problem = None
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            problem = "unparseable"
        else:
            if not validate_response(parsed):
                problem = "off-schema"

        if problem is None:
            break

        if attempt > LLM_RETRIES:
            if problem == "unparseable":
                return {
                    "findings": [{
                        "severity": "low",
                        "category": "analysis_error",
                        "summary": "Model response could not be parsed as JSON",
                        "evidence": raw_text[:200],
                        "recommended_action": "Review chunk manually",
                        "confidence": "low",
                        "source": "analyzer",
                    }],
                    "chunk_summary": "Parsing error on this chunk",
                }
            return {
                "findings": [{
                    "severity": "HIGH",
                    "category": "analyzer_error",
                    "summary": "Model returned off-schema response; chunk not analyzed",
                    "evidence": describe_schema_failure(parsed),
                    "recommended_action": (
                        "This chunk was NOT analyzed by the model. "
                        "Retry with a smaller --lines-per-chunk or a stronger model."
                    ),
                    "confidence": "high",
                    "rule_id": "analyzer_error",
                    "source": "analyzer",
                }],
                "chunk_summary": "Off-schema response on this chunk",
            }

        nudge = RETRY_NUDGE if problem == "unparseable" else SCHEMA_NUDGE
        print(f"    chunk {chunk_index + 1}: {problem} response, retrying once...")
        user_prompt = build_user_prompt(log_text, ctx, suffix=nudge)

    parsed["chunk_index"] = chunk_index
    return parsed


def explain_single(base_url, api_key, model, chunk_lines, chunk_index, ctx,
                   rule_id=None, ident=None):
    """Ask for the prose of ONE finding and return it, or "" if nothing usable came back.

    The context names a single finding, so an explanation with no rule id is taken to
    be about it. `ident` (an IP or host) is the tie-break for the one case where that
    assumption breaks: two findings of the same type in the same chunk. Prose about the
    wrong host is worse than no prose, so a reply that never names `ident` is refused.

    Shared by the analyzer's second pass and the console's on-demand button so both
    accept an answer on exactly the same terms.
    """
    result = analyze_chunk(base_url, api_key, model, chunk_lines, chunk_index, ctx)
    for ex in result.get("explanations", []):
        text = ex.get("explanation")
        if not text:
            continue
        rid = ex.get("rule_id")
        if rid and rule_id and rid != rule_id:
            continue
        if ident and ident not in text:
            continue
        return text
    return ""


def anomaly_ident(anomaly):
    """The address or host that identifies a finding, when it has one."""
    ents = anomaly.get("entities") or {}
    return next((str(ents[k]) for k in ("ip", "dest_ip", "host") if ents.get(k)), None)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_rank(finding):
    """Sort key. Case-insensitive: detector findings carry uppercase severities."""
    return SEVERITY_ORDER.get(str(finding.get("severity", "info")).lower(), 5)



# ---------------------------------------------------------------------------
# Generic ZooKeeper / QuorumCnxManager detection
# ---------------------------------------------------------------------------
# ZooKeeper logs often contain no ERROR/CRITICAL records even when the cluster
# is unhealthy.  The supplied Zookeeper_2k.log is a good example: the useful
# signals are repeated WARN sequences such as "Connection broken",
# "Interrupting SendWorker", "Send worker leaving thread", and
# "Interrupted while waiting for message on queue".  The generic ruleset used
# by older anomaly_detector/rules_syslog versions does not reliably promote
# these application-specific patterns to findings.
#
# These rules are deterministic, local, and conservative:
#   * INFO connection/session messages are only promoted when a related failure
#     pattern is also present.
#   * repeated WARN patterns become findings with severity based on recurrence.
#   * one finding is kept per semantic condition, while occurrences preserves
#     the real count.
#   * this does NOT claim that a WARN line is a security attack. It is a
#     reliability/availability alert and can be mapped to MITRE separately.

_ZK_RULES = (
    {
        "type": "zookeeper_connection_broken",
        "pattern": re.compile(r"\bConnection broken for id\b", re.I),
        "category": "zookeeper_quorum",
        "summary": "ZooKeeper quorum connection repeatedly broke between peer nodes",
        "rationale": "Repeated quorum connection breaks can indicate unstable peer communication, network loss, or a failing ZooKeeper peer.",
        "action": "Check ZooKeeper peer connectivity on the quorum port, packet loss/latency, firewall rules, node health, and ZooKeeper server logs on both peers.",
        "base": "MEDIUM",
        "thresholds": ((20, "HIGH"), (5, "MEDIUM"), (1, "LOW")),
    },
    {
        "type": "zookeeper_sendworker_exit",
        "pattern": re.compile(r"\bSend worker leaving thread\b", re.I),
        "category": "zookeeper_quorum",
        "summary": "ZooKeeper SendWorker thread repeatedly exited",
        "rationale": "Repeated SendWorker exits are consistent with churn in the quorum communication layer and should be correlated with peer connection failures.",
        "action": "Correlate SendWorker exits with Connection broken and Interrupting SendWorker events; verify peer reachability and ZooKeeper JVM/node health.",
        "base": "MEDIUM",
        "thresholds": ((30, "HIGH"), (10, "MEDIUM"), (1, "LOW")),
    },
    {
        "type": "zookeeper_sendworker_interrupted",
        "pattern": re.compile(r"\bInterrupted while waiting for message on queue\b", re.I),
        "category": "zookeeper_quorum",
        "summary": "ZooKeeper SendWorker was repeatedly interrupted while waiting for quorum messages",
        "rationale": "Frequent queue interruptions can accompany quorum connection churn and thread shutdown/restart activity.",
        "action": "Review quorum connection stability, JVM/thread health, and the surrounding ZooKeeper WARN/ERROR sequence.",
        "base": "LOW",
        "thresholds": ((50, "MEDIUM"), (10, "LOW"), (1, "INFO")),
    },
    {
        "type": "zookeeper_sendworker_interrupt",
        "pattern": re.compile(r"\bInterrupting SendWorker\b", re.I),
        "category": "zookeeper_quorum",
        "summary": "ZooKeeper RecvWorker repeatedly interrupted a SendWorker",
        "rationale": "This is a quorum communication lifecycle event. High recurrence together with broken connections indicates instability rather than a normal isolated shutdown.",
        "action": "Correlate with Connection broken and SendWorker exit events and inspect network and peer health.",
        "base": "LOW",
        "thresholds": ((30, "MEDIUM"), (10, "LOW"), (1, "INFO")),
    },
    {
        "type": "zookeeper_peer_connection_request",
        "pattern": re.compile(r"\bReceived connection request\s+/\S+", re.I),
        "category": "zookeeper_quorum",
        "summary": "ZooKeeper received a quorum peer connection request",
        "rationale": "Peer connection requests are normally informational, but a high rate alongside connection failures can indicate reconnect churn.",
        "action": "Review the rate of peer reconnects and correlate the source peer with Connection broken events.",
        "base": "INFO",
        "thresholds": ((50, "LOW"), (10, "INFO"), (1, "INFO")),
    },
    {
        "type": "zookeeper_session_expired",
        "pattern": re.compile(r"\bExpiring session\b.*\btimeout of\b.*\bexceeded\b", re.I),
        "category": "zookeeper_session",
        "summary": "ZooKeeper session expired because its timeout was exceeded",
        "rationale": "An expired session means the client did not maintain its ZooKeeper session within the negotiated timeout.",
        "action": "Identify the client, check client-to-ZooKeeper connectivity and latency, and correlate with server load and quorum instability.",
        "base": "MEDIUM",
        "thresholds": ((10, "HIGH"), (3, "MEDIUM"), (1, "LOW")),
    },
    {
        "type": "zookeeper_socket_closed",
        "pattern": re.compile(r"\bClosed socket connection for client\b", re.I),
        "category": "zookeeper_session",
        "summary": "ZooKeeper closed a client socket connection",
        "rationale": "A single socket close is common lifecycle activity; repeated closes should be correlated with session expiration or connection churn.",
        "action": "Correlate the client address with session expiration, reconnects, and application health before treating it as an incident.",
        "base": "INFO",
        "thresholds": ((30, "LOW"), (1, "INFO")),
    },
    {
        "type": "zookeeper_leader_election",
        "pattern": re.compile(r"\bFastLeaderElection\b.*\b(LOOKING|leader)\b", re.I),
        "category": "zookeeper_cluster",
        "summary": "ZooKeeper leader-election activity was recorded",
        "rationale": "Leader-election activity can be normal during startup, but repeated elections during an established cluster can indicate quorum instability.",
        "action": "Correlate election events with quorum connection failures, node restarts, latency, and cluster membership.",
        "base": "LOW",
        "thresholds": ((5, "HIGH"), (2, "MEDIUM"), (1, "LOW")),
    },
)

def _zk_severity(count, thresholds):
    for minimum, severity in thresholds:
        if count >= minimum:
            return severity
    return "INFO"

def _record_text(record):
    return str(record.get("msg") or record.get("message") or record.get("raw") or "")

def _zookeeper_extra_anomalies(records):
    """Detect application-specific ZooKeeper conditions missed by generic rules.

    The function deliberately operates on the already-normalized record stream,
    so it works with plain ZooKeeper logs as well as logs coming through the
    universal parser.
    """
    if not records:
        return []

    matched = {rule["type"]: [] for rule in _ZK_RULES}
    for rec in records:
        text = _record_text(rec)
        if not text:
            continue
        for rule in _ZK_RULES:
            if rule["pattern"].search(text):
                matched[rule["type"]].append(rec)

    # Only activate this ruleset when the input actually looks like ZooKeeper.
    zk_total = sum(len(v) for v in matched.values())
    zk_marker = any(
        re.search(r"(?:QuorumCnxManager|ZooKeeperServer|FastLeaderElection|NIOServerCnxn)", _record_text(r), re.I)
        for r in records[:1000]
    )
    if not zk_marker and zk_total == 0:
        return []

    findings = []
    for rule in _ZK_RULES:
        hits = matched[rule["type"]]
        if not hits:
            continue

        count = len(hits)
        sev = _zk_severity(count, rule["thresholds"])

        # Build a compact evidence timeline.  Keep first/last and up to 8 samples
        # so a 2,000-line file does not create a huge report.
        timeline = []
        for r in hits[:8]:
            timeline.append({
                "line": r.get("line") or r.get("n"),
                "timestamp": str(r.get("timestamp") or r.get("ts") or ""),
                "message": _record_text(r)[:300],
            })
        if count > 8:
            timeline.append({
                "line": hits[-1].get("line") or hits[-1].get("n"),
                "timestamp": str(hits[-1].get("timestamp") or hits[-1].get("ts") or ""),
                "message": f"... {count - 8} additional matching event(s)",
            })

        first = _record_text(hits[0])[:500]
        last = _record_text(hits[-1])[:500]
        line_numbers = [r.get("line") or r.get("n") for r in hits if r.get("line") or r.get("n")]
        entities = {}

        # Extract peer/client IPs where present.
        ips = []
        for h in hits:
            ips.extend(re.findall(r"/((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?", _record_text(h)))
        if ips:
            uniq = list(dict.fromkeys(ips))
            entities["ips"] = uniq[:20]

        summary = rule["summary"]
        if count > 1:
            summary += f" ({count} occurrences)"

        findings.append({
            "severity": sev,
            "type": rule["type"],
            "summary": summary,
            "evidence": (
                f"{first}"
                + (f" | last matching event: {last}" if last != first else "")
                + (f" | source lines: {min(line_numbers)}-{max(line_numbers)}" if line_numbers else "")
            ),
            "rationale": rule["rationale"],
            "entities": entities,
            "occurrences": count,
            "timeline": timeline,
            "predicate": f"ZooKeeper pattern '{rule['type']}' matched {count} record(s)",
            "recommended_action": rule["action"],
            "source": "zookeeper_rules",
        })

    # Correlation alert: the combination is more useful than any single WARN.
    broken = len(matched["zookeeper_connection_broken"])
    exits = len(matched["zookeeper_sendworker_exit"])
    interrupted = len(matched["zookeeper_sendworker_interrupt"])
    queue_wait = len(matched["zookeeper_sendworker_interrupted"])
    if broken and (exits or interrupted or queue_wait):
        total = broken + exits + interrupted + queue_wait
        if broken >= 20 and (exits + interrupted + queue_wait) >= 20:
            sev = "CRITICAL"
        elif broken >= 5 and (exits + interrupted + queue_wait) >= 5:
            sev = "HIGH"
        else:
            sev = "MEDIUM"

        findings.append({
            "severity": sev,
            "type": "zookeeper_quorum_instability",
            "summary": (
                "ZooKeeper quorum communication instability detected: "
                f"{broken} connection-break event(s), {exits} SendWorker exit(s), "
                f"{interrupted} SendWorker interrupt(s), and {queue_wait} queue interruption(s)"
            ),
            "evidence": (
                "Multiple ZooKeeper quorum failure lifecycle patterns occurred in the same log. "
                "This is a correlation alert, not a claim of malicious activity."
            ),
            "rationale": "The combination of repeated broken peer connections and worker interruption/exit activity is a stronger availability signal than any single WARN event.",
            "entities": {},
            "occurrences": total,
            "timeline": [],
            "predicate": "Correlated ZooKeeper quorum communication instability",
            "recommended_action": (
                "Check all ZooKeeper peers on the quorum ports, packet loss/latency, "
                "firewall/load-balancer behavior, JVM saturation, disk I/O, and cluster health."
            ),
            "source": "zookeeper_rules",
        })

    return findings


# ---------------------------------------------------------------------------
# Universal application/OS high-signal detection
# ---------------------------------------------------------------------------
# These rules complement, rather than replace, anomaly_detector/rules_syslog.
# They intentionally collapse repeated occurrences into semantic findings while
# preserving the occurrence count and source-line evidence.

_GENERIC_RULES = (
    ("generic_fatal_error", re.compile(r"\b(?:FATAL|CRITICAL|PANIC)\b", re.I), "CRITICAL", "Critical/fatal condition reported by the application or OS", "Investigate the surrounding events, process/service state, and recent configuration or deployment changes."),
    ("generic_out_of_memory", re.compile(r"(?:out of memory|oom-killer|oom kill|cannot allocate memory|java\.lang\.OutOfMemoryError|memory allocation failed)", re.I), "CRITICAL", "Out-of-memory condition detected", "Check memory pressure, OOM-killer events, process limits, JVM/container limits, and recent workload changes."),
    ("generic_disk_full", re.compile(r"(?:no space left on device|disk (?:is )?full|filesystem.*(?:full|100%|9[5-9]%))", re.I), "HIGH", "Disk/filesystem capacity exhaustion detected", "Check filesystem utilization, inode usage, application logs, and safe cleanup/retention."),
    ("generic_service_failed", re.compile(r"(?:failed to start|start request repeated too quickly|service.*failed|unit .* failed|failed with result|Main process exited.*failure)", re.I), "HIGH", "Service startup or runtime failure detected", "Check service status, dependencies, recent configuration changes, and the service journal/log."),
    ("generic_kernel_fault", re.compile(r"(?:kernel panic|segfault|general protection fault|BUG: unable to handle kernel|Oops:|call trace:)", re.I), "CRITICAL", "Kernel-level fault detected", "Investigate kernel/module changes, hardware health, crash dumps, and the affected host."),
    ("generic_connection_refused", re.compile(r"(?:connection refused|connect\(\).*refused|connection reset by peer|connection timed out|connect timeout)", re.I), "MEDIUM", "Network connection failure detected", "Check endpoint reachability, listening ports, firewall rules, routing, service health, and packet loss/latency."),
    ("generic_tls_failure", re.compile(r"(?:SSL(?:_ERROR)?|TLS).*(?:handshake|certificate|verify|alert|failed|error)|certificate.*(?:expired|invalid|verify failed)", re.I), "HIGH", "TLS/SSL or certificate failure detected", "Verify certificate validity/chain, system time, trust stores, protocol/cipher compatibility, and the peer configuration."),
    ("generic_auth_failure", re.compile(r"(?:authentication failure|auth(?:entication)? failed|failed password|invalid password|login failed|user authentication failed)", re.I), "MEDIUM", "Authentication failure detected", "Correlate source, account, time, and recurrence; investigate brute-force or misconfiguration when repeated."),
    ("generic_permission_denied", re.compile(r"(?:permission denied|access denied|operation not permitted|unauthorized)", re.I), "MEDIUM", "Permission or authorization failure detected", "Verify the account, requested resource, ACL/role policy, and whether the access was expected."),
    ("generic_file_integrity", re.compile(r"(?:integrity check failed|checksum mismatch|hash mismatch|modified unexpectedly|tamper(?:ed|ing) detected)", re.I), "HIGH", "File/integrity validation failure detected", "Validate the affected file/object against a trusted baseline and review the initiating process and account."),
    ("generic_security_block", re.compile(r"(?:blocked|denied|dropped).*(?:connection|packet|request|traffic)|(?:firewall|ids|ips).*(?:block|deny|drop)", re.I), "MEDIUM", "Security/network control blocked or denied activity", "Identify source, destination, rule/policy, and recurrence; determine whether the blocked activity was malicious or expected."),
    ("generic_http_server_error", re.compile(r"(?:HTTP/[12](?:\.\d)?\s+5\d\d|\b(?:status|response)\s+5\d\d\b|\b5\d\d\s+(?:GET|POST|PUT|DELETE))", re.I), "MEDIUM", "HTTP server-side error detected", "Correlate the endpoint, application error, upstream dependency, and request volume."),
    ("generic_database_failure", re.compile(r"(?:database|db|sql).*(?:connection failed|connection refused|deadlock|too many connections|query failed|timeout|unavailable)", re.I), "HIGH", "Database availability or query failure detected", "Check database health, connection pool limits, locks/deadlocks, latency, and application dependency status."),
)

def _generic_extra_anomalies(records):
    if not records:
        return []
    hits = {rid: [] for rid, *_ in _GENERIC_RULES}
    for rec in records:
        text = _record_text(rec)
        if not text:
            continue
        for rid, pattern, sev, *_ in _GENERIC_RULES:
            if pattern.search(text):
                hits[rid].append(rec)
    findings=[]
    for rid, pattern, base_sev, summary, action in _GENERIC_RULES:
        rows=hits[rid]
        if not rows:
            continue
        sev=base_sev
        # Repeated medium/high-signal failures are promoted one level.
        if len(rows) >= 10:
            sev={"INFO":"LOW","LOW":"MEDIUM","MEDIUM":"HIGH","HIGH":"CRITICAL","CRITICAL":"CRITICAL"}[base_sev]
        lines=[r.get("line") or r.get("n") for r in rows if r.get("line") or r.get("n")]
        sample=_record_text(rows[0])[:500]
        findings.append({
            "severity":sev, "type":rid, "summary":f"{summary} ({len(rows)} occurrences)",
            "evidence":sample + (f" | source lines: {min(lines)}-{max(lines)}" if lines else ""),
            "rationale":f"Deterministic high-signal pattern matched {len(rows)} log record(s). Severity is rule-derived and recurrence-aware.",
            "entities":{}, "occurrences":len(rows), "timeline":[{"line":r.get("line") or r.get("n"),"message":_record_text(r)[:300]} for r in rows[:8]],
            "predicate":f"Generic high-signal pattern '{rid}' matched {len(rows)} record(s)",
            "recommended_action":action, "source":"generic_rules"
        })
    return findings

def detector_to_findings(anomalies):
    """Map deduped detector anomalies into the analyzer's finding schema.

    These are authoritative: severity comes from the rules, not the model.
    """
    findings = []
    for a in anomalies:
        findings.append({
            "severity": str(a.get("severity", "info")).upper(),
            "category": "rule_detection",
            "summary": a.get("summary", ""),
            "evidence": a.get("evidence", ""),
            "rationale": a.get("rationale", ""),
            "recommended_action": "",   # filled from the model's explanation when available
            "confidence": "high",
            "rule_id": a.get("type"),
            "source": "detector",
            "entities": a.get("entities", {}),
            "occurrences": a.get("occurrences", 1),
            "predicate": a.get("predicate", ""),
            "timeline": a.get("timeline", []),
        })
    return findings


TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:]+(?:Z|[+-]\d{2}:\d{2})?")

# v1's canonical auth-failure phrasing, read back out of the record stream.
CANON_AUTH_FAIL_RE = re.compile(r"auth failed for user '(?P<user>[^']*)' from (?P<ip>\S+)")

SPRAY_MIN_USERS = 2          # below this it isn't a spray, it's one target
SPRAY_NAMES_SHOWN = 4


def usernames_by_ip(records):
    """Distinct usernames each IP attempted, in first-seen order.

    v1's brute-force finding names only the first username it saw, which is
    accurate but misleading when an attacker sprays many accounts. The record
    stream already holds every attempt, so the full picture is derivable here
    without touching the detector.
    """
    seen = {}
    for r in records:
        m = CANON_AUTH_FAIL_RE.search(r.get("msg", ""))
        if not m:
            continue
        user = m.group("user")
        bucket = seen.setdefault(m.group("ip"), [])
        if user not in bucket:
            bucket.append(user)
    return seen


def enrich_username_spray(anomalies, records):
    """Add distinct-username context to brute-force findings. Mutates copies only."""
    users = usernames_by_ip(records)
    for a in anomalies:
        if a.get("type") not in ("auth_bruteforce", "auth_bruteforce_success"):
            continue
        ip = a.get("entities", {}).get("ip")
        attempted = users.get(ip, [])
        a.setdefault("entities", {})["distinct_usernames"] = len(attempted)
        a["entities"]["usernames_sample"] = attempted[:SPRAY_NAMES_SHOWN]
        if len(attempted) < SPRAY_MIN_USERS:
            continue
        shown = ", ".join(attempted[:SPRAY_NAMES_SHOWN])
        more = f", +{len(attempted) - SPRAY_NAMES_SHOWN} more" if len(attempted) > SPRAY_NAMES_SHOWN else ""
        a["summary"] = (f"{a['summary']} — {len(attempted)} distinct usernames sprayed "
                        f"({shown}{more})")
    return anomalies


def restates_detector(finding, anomalies):
    """Best-effort: does this LLM finding just restate a pre-flagged anomaly?

    Matches on distinctive markers only — IPs, ports, and the timestamps of the exact
    log lines the rule fired on. Hosts and usernames are deliberately excluded: they
    recur across unrelated lines, so matching on them would discard legitimate
    additional findings. A shared timestamp means the same log line, so it is safe.
    """
    text = " ".join(f"{finding.get('summary', '')} {finding.get('evidence', '')}".lower().split())
    for a in anomalies:
        ents = a.get("entities", {})
        markers = [str(ents[k]).lower() for k in ("ip", "dest_ip") if ents.get(k)]
        if ents.get("port"):
            markers.append(f":{ents['port']}")
        markers += [t.lower() for t in TIMESTAMP_RE.findall(a.get("evidence", ""))]
        if markers and any(m in text for m in markers):
            return True
    return False


def preflight(base_url, api_key, model):
    """Check the endpoint is reachable. Warn (don't fail) if the model isn't listed."""
    req = urllib.request.Request(
        f"{base_url}/models",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=min(10, LLM_TIMEOUT)) as resp:
            available = [m.get("id") for m in json.loads(resp.read()).get("data", [])]
    except urllib.error.HTTPError as e:
        # Some providers don't expose /models, or gate it behind other scopes.
        # Not fatal — the real call will surface a clearer error if it matters.
        print(f"WARNING: could not list models at {base_url} (HTTP {e.code}); continuing.")
        return
    except urllib.error.URLError as e:
        print(f"ERROR: cannot reach LLM endpoint at {base_url} ({e.reason}).")
        print("  Local Ollama? Start it with: ollama serve")
        print("  Hosted API? Check LLM_BASE_URL (it should end in /v1).")
        sys.exit(1)

    # Best-effort: ask Ollama to keep the model resident for the run. Ignored by
    # non-Ollama endpoints, and never fatal — it is a latency optimisation only.
    try:
        pin = json.dumps({"model": model, "prompt": "", "keep_alive": OLLAMA_KEEP_ALIVE,
                          "stream": False}).encode()
        root = base_url[:-3] if base_url.rstrip("/").endswith("/v1") else base_url
        req = urllib.request.Request(root.rstrip("/") + "/api/generate", data=pin,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=min(20, LLM_TIMEOUT)):
            pass
    except Exception:
        pass

    if available and model not in available:
        print(f"WARNING: model '{model}' not listed at {base_url}.")
        print(f"  available: {', '.join(available) or '(none)'}")
        print(f"  If this is local Ollama, pull it with: ollama pull {model}")



# ---------------------------------------------------------------------------
# Optional Nmap vulnerability / service discovery
# ---------------------------------------------------------------------------

def _nmap_anomaly(severity, atype, summary, evidence, rationale, entities=None, action=""):
    return {
        "severity": severity,
        "type": atype,
        "summary": summary,
        "evidence": evidence,
        "rationale": rationale,
        "entities": entities or {},
        "recommended_action": action,
        "source": "nmap",
    }


def _nse_vulnerability_verdict(output: str):
    """Return (is_vulnerable, severity) using conservative NSE output parsing.

    Nmap's vuln scripts use several formats. Do not treat the mere presence of
    the word 'vulnerable' or a CVE reference as a positive result because many
    scripts explicitly say NOT VULNERABLE.
    """
    text = str(output or "").strip()
    low = text.lower()

    # Explicit negative results take precedence.
    negative = (
        "not vulnerable",
        "not currently vulnerable",
        "state: not vulnerable",
        "state: safe",
        "vulnerable: false",
        "is_vulnerable: false",
        "risk factor: none",
    )
    if any(x in low for x in negative):
        return False, "info"

    positive_patterns = (
        r"\bstate\s*:\s*vulnerable\b",
        r"\bvulnerable\s*:\s*(?:true|yes)\b",
        r"\bis_vulnerable\s*:\s*(?:true|yes)\b",
        r"\bvulnerable\b.{0,100}\b(?:yes|true)\b",
        r"\b(?:remote\s+)?code\s+execution\b",
        r"\bsecurity\s+risk\b",
        r"\bexploit(?:ed|able|ation)?\b",
        r"\b(?:cve|cwe)-\d{4}-\d+\b",
    )
    positive = any(re.search(p, low, re.I | re.S) for p in positive_patterns)

    # Common NSE positive language.
    if not positive and any(x in low for x in (
        "vulnerability detected",
        "vulnerable service",
        "target is vulnerable",
        "may be vulnerable",
        "appears vulnerable",
        "likely vulnerable",
    )):
        positive = True

    if not positive:
        return False, "info"

    sev = "high"
    if any(x in low for x in (
        "critical", "remote code execution", "rce", "unauthenticated code execution",
        "root access", "arbitrary command",
    )):
        sev = "critical"
    elif any(x in low for x in ("high", "high risk")):
        sev = "high"
    elif any(x in low for x in ("medium", "moderate", "moderate risk")):
        sev = "medium"
    elif any(x in low for x in ("low", "low risk")):
        sev = "low"

    return True, sev


def run_nmap_scan(target, vuln=False, extra_args=None, timeout=300):
    """Run Nmap against an explicitly supplied/authorized target.

    The scan is deliberately local. -Pn is used because private/internal
    targets frequently block ICMP and would otherwise be reported as "down".
    When a target is supplied, vulnerability NSE scripts are enabled unless
    the caller explicitly requests a discovery-only scan through nmap_vuln=False
    AND the caller passes --nmap-extra --script-... themselves.
    """
    if not target:
        return [], {"enabled": False, "reason": "no target supplied"}

    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        raise RuntimeError(
            "Nmap is not installed or not in PATH. "
            "Install with: sudo apt update && sudo apt install -y nmap"
        )

    # Validate target enough to prevent accidental empty/option-only execution.
    target = str(target).strip()
    if not target or target.startswith("-"):
        raise ValueError("Invalid Nmap target. Supply an authorized host, IP, or CIDR.")

    # Use XML to stdout so the analyzer never has to scrape human-readable output.
    # -Pn is important for private targets with blocked ICMP.
    args = [nmap_bin, "-Pn", "-sV", "-oX", "-"]

    # Explicit vulnerability mode. We also accept --script supplied by advanced
    # callers through nmap-extra.
    extra = list(extra_args or [])
    extra_text = " ".join(extra).lower()
    extra_has_script = "--script" in extra_text or "-sC" in extra_text
    if vuln and not extra_has_script:
        args += ["--script", "vuln"]

    # Advanced args go before the target and are passed without a shell.
    args += extra
    args.append(target)

    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Nmap timed out after {timeout}s for target {target}. "
            "Increase --nmap-timeout for large networks."
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Unable to execute Nmap: {exc}") from exc

    stderr = (proc.stderr or "").strip()
    stdout = proc.stdout or ""

    if proc.returncode != 0:
        raise RuntimeError(
            f"Nmap failed ({proc.returncode}) for {target}: {stderr[:1200]}"
        )

    if not stdout.strip():
        raise RuntimeError(
            f"Nmap returned no XML for {target}. stderr: {stderr[:800]}"
        )

    try:
        root = ET.fromstring(stdout)
    except ET.ParseError as exc:
        raise RuntimeError(
            f"Nmap returned invalid XML: {exc}. stderr: {stderr[:800]}"
        ) from exc

    findings = []
    service_inventory = []
    hosts = 0
    services = 0
    scripts = 0
    vuln_findings = 0

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        hosts += 1
        addr = next(
            (a.get("addr") for a in host.findall("address") if a.get("addr")),
            "unknown",
        )
        names = [
            n.get("name") for n in host.findall("hostnames/hostname")
            if n.get("name")
        ]
        hostname = names[0] if names else addr

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            services += 1
            portid = port.get("portid", "?")
            proto = port.get("protocol", "tcp")
            service = port.find("service")
            sname = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            cpe = service.find("cpe") if service is not None else None
            cpe_text = cpe.text if cpe is not None else ""

            service_record = {
                "host": hostname,
                "ip": addr,
                "port": int(portid) if str(portid).isdigit() else portid,
                "protocol": proto,
                "service": sname,
                "product": product,
                "version": version,
                "cpe": cpe_text,
            }
            service_inventory.append(service_record)

            # NSE scripts can appear directly below <port>. Parse all of them.
            for script in port.findall("script"):
                scripts += 1
                sid = script.get("id", "nse")
                output = script.get("output", "").strip()
                if not output:
                    continue

                is_vuln, sev = _nse_vulnerability_verdict(output)
                if is_vuln:
                    vuln_findings += 1
                    entities = dict(service_record)
                    entities["nse_script"] = sid
                    cves = sorted(set(re.findall(
                        r"\bCVE-\d{4}-\d{4,7}\b", output, re.I
                    )))
                    if cves:
                        entities["cves"] = [c.upper() for c in cves]

                    findings.append(_nmap_anomaly(
                        sev,
                        "vulnerability_nmap_nse",
                        f"Nmap NSE {sid} reported a potential vulnerability on "
                        f"{hostname}:{portid}/{proto}",
                        output[:6000],
                        "Nmap NSE produced positive vulnerability/risk evidence. "
                        "Validate the affected service/version and CVE/vendor "
                        "advisory before remediation.",
                        entities,
                        "Validate the service/version, identify the CVE/vendor "
                        "advisory, then patch, mitigate, or restrict exposure.",
                    ))

            # Exposure is useful even when NSE does not identify a CVE.
            if sname.lower() in {"telnet", "ftp", "rlogin", "rsh"}:
                findings.append(_nmap_anomaly(
                    "medium",
                    "insecure_service_exposure",
                    f"Insecure service {sname} exposed on "
                    f"{hostname}:{portid}/{proto}",
                    f"{addr}:{portid}/{proto} {sname} {product} {version}".strip(),
                    "The discovered service commonly provides weak or clear-text "
                    "authentication and should be reviewed for necessity.",
                    service_record,
                    "Disable the service where unnecessary or replace it with a "
                    "secure alternative; restrict access if it must remain.",
                ))

    return findings, {
        "enabled": True,
        "target": target,
        "command": " ".join(args),
        "vulnerability_scripts": bool(vuln),
        "hosts_up": hosts,
        "open_services": services,
        "nse_scripts": scripts,
        "vulnerability_count": vuln_findings,
        "vulnerabilities": [
            f for f in findings if f.get("type") == "vulnerability_nmap_nse"
        ],
        "services": service_inventory,
        "stderr": stderr[-2000:] if stderr else "",
    }


def run(input_path: str, output_prefix: str, lines_per_chunk: int, model: str,
        base_url: str, api_key: str, compare: bool = False, deep_scan: bool = False,
        rules_only: bool = False, nmap_target: str = None, nmap_vuln: bool = False,
        nmap_extra_args=None, nmap_timeout: int = 300):
    # rules_only is a COMPUTE switch, not an analysis switch: the deterministic
    # pass below runs identically; only the model calls (and their preflight)
    # are skipped. The console uses it when explanations are produced later
    # through its gated remote path, so no log text leaves during the run.
    if not rules_only:
        preflight(base_url, api_key, model)

    path = Path(input_path).expanduser()

    if not path.exists():
        print(f"ERROR: file not found: {path}")
        return 2
    if not path.is_file():
        print(f"ERROR: input is not a file: {path}")
        return 2
    if path.stat().st_size == 0:
        print(f"ERROR: input log is empty: {path}")
        return 2

    output_parent = Path(output_prefix).expanduser().parent
    if str(output_parent) not in ("", "."):
        output_parent.mkdir(parents=True, exist_ok=True)

    # --- Deterministic pre-pass: rules run over the WHOLE file before any LLM call ---
    records, stats = load_log_file(path)
    print(f"Format: {stats['format']} — {stats['parsed']}/{stats['total_lines']} line(s) parsed"
          + (f", {stats['unparsed']} unparsed" if stats["unparsed"] else ""))
    if stats["unparsed"]:
        for raw in stats["unparsed_examples"][:3]:
            print(f"    unparsed: {raw[:88]}")

    nmap_anomalies = []
    nmap_stats = {"enabled": False}
    if nmap_target:
        try:
            nmap_anomalies, nmap_stats = run_nmap_scan(
                nmap_target, vuln=(nmap_vuln or True), extra_args=nmap_extra_args, timeout=nmap_timeout
            )
            print(f"Nmap: {nmap_stats.get('hosts_up', 0)} host(s), "
                  f"{nmap_stats.get('open_services', 0)} open service(s), "
                  f"{nmap_stats.get('nse_scripts', 0)} NSE result(s), "
                  f"{nmap_stats.get('vulnerability_count', 0)} vulnerability finding(s), "
                  f"{len(nmap_anomalies)} total finding(s)")
        except Exception as exc:
            print(f"WARNING: Nmap scan failed: {exc}")

    # Universal deterministic rule pass: every recognized format goes through
    # the same vocabulary, Windows/vendor rules and threat rules. This phase is
    # authoritative and must finish before any LLM work.
    rules_started = time.monotonic()
    print("Rules: starting deterministic normalization/detection...", flush=True)
    progress(phase="rules", done=0, findings=0, chunks=0)
    try:
        records, counts = rules_syslog.canonicalize(records)
    except Exception as exc:
        print(f"WARNING: rule vocabulary enrichment failed: {exc}")
        counts = {"auth_fail": 0, "auth_ok": 0}
    print(f"Vocabulary: translated {counts.get('auth_fail', 0)} auth-failure and "
          f"{counts.get('auth_ok', 0)} auth-success message(s)")
    try:
        extra_anomalies = rules_syslog.detect_extra(records)
    except Exception as exc:
        print(f"WARNING: cross-platform rule detection failed: {exc}")
        extra_anomalies = []

    # Application-aware gap fill.  Keep the existing rules authoritative, but
    # add deterministic ZooKeeper findings for patterns that are represented as
    # WARN/INFO lifecycle messages rather than generic security signatures.
    try:
        zk_anomalies = _zookeeper_extra_anomalies(records)
        if zk_anomalies:
            print(f"ZooKeeper rules: {len(zk_anomalies)} application finding(s)")
        extra_anomalies.extend(zk_anomalies)
        generic_anomalies = _generic_extra_anomalies(records)
        if generic_anomalies:
            print(f"Generic high-signal rules: {len(generic_anomalies)} finding(s)")
        extra_anomalies.extend(generic_anomalies)
    except Exception as exc:
        print(f"WARNING: ZooKeeper rule detection failed: {exc}")

    records, dropped = rules_syslog.dedupe_auth_attempts(records)
    if dropped:
        print(f"Dedupe: collapsed {dropped} companion authentication line(s)")

    raw_anomalies = detect(records) + extra_anomalies + nmap_anomalies
    # Derived from the same record stream v1 just consumed — v1 itself is untouched.
    raw_anomalies = enrich_username_spray(raw_anomalies, records)
    # Rule predicate + event sequence for the report and the review console.
    # Deterministic: restated constants and reordered records, no model call.
    raw_anomalies = rule_context.enrich(raw_anomalies, records)
    anomalies = dedupe_anomalies(raw_anomalies)
    collapsed = len(raw_anomalies) - len(anomalies)
    rules_elapsed = time.monotonic() - rules_started
    print(f"Detector: {len(anomalies)} anomaly(ies)"
          + (f" ({collapsed} duplicate(s) collapsed)" if collapsed else "")
          + f" in {rules_elapsed:.1f}s")
    if rules_elapsed > RULE_WARNING_SECONDS:
        print(
            f"WARNING: deterministic rules took {rules_elapsed:.1f}s. "
            f"For large files this is the rules/correlation phase, not the LLM."
        )
    progress(
        phase="rules", done=1, findings=len(anomalies),
        seconds=round(rules_elapsed, 1)
    )
    ctx = to_llm_context(anomalies)

    run_model = should_run_model(stats) and not rules_only
    all_chunks = list(chunk_log_file(path, lines_per_chunk)) if run_model else []

    llm_findings = []
    chunk_summaries = []
    explanations = {}

    # Which chunks does the model actually need to see?
    if run_model:
        finding_chunks = chunks_with_findings(anomalies, lines_per_chunk, len(all_chunks))
        gap_fill = deep_scan or len(all_chunks) <= GAP_FILL_MAX_CHUNKS
        if gap_fill:
            selected = sorted(range(len(all_chunks)))
        else:
            # Only the chunks holding the most severe findings are explained up front.
            # Everything else is explained when a reviewer actually opens it.
            top = sorted(anomalies, key=severity_rank)[:EAGER_EXPLANATIONS]
            # One chunk per finding — the one where it culminates — not every chunk it
            # touches. A brute-force cluster spans several chunks; explaining all of
            # them up front triples first-paint for no extra explanation.
            eager = set()
            for a in top:
                lines = finding_line_numbers(a)
                if lines:
                    eager.add((max(lines) - 1) // lines_per_chunk)
            selected = sorted(eager)
        deferred = sorted(finding_chunks - set(selected))
        # Per-chunk context: only the findings that live IN each chunk. Sending the
        # whole run's context to every chunk made each prompt grow with the number of
        # findings — and asking the model to explain a finding from lines it cannot
        # see was never coherent anyway.
        by_chunk = {}
        for pos, a in enumerate(anomalies):
            for line in finding_line_numbers(a):
                i = (line - 1) // lines_per_chunk
                if 0 <= i < len(all_chunks) and pos not in by_chunk.setdefault(i, []):
                    by_chunk[i].append(pos)
        chunk_ctx = {i: to_llm_context([anomalies[j] for j in v])
                     for i, v in by_chunk.items()}
        empty_ctx = to_llm_context([])
    else:
        gap_fill, selected, chunk_ctx, empty_ctx = False, [], {}, ""
        deferred = []

    if not run_model:
        if rules_only:
            print("Skipping the model: --rules-only. Rules, severities and correlation are "
                  "complete and local; explanations are produced later, on demand.")
        else:
            print(f"Skipping the model: {stats["parsed"]} record(s) ingested but no model "
                  "analysis was requested/required.")
    else:
        print(f"Loaded {path.name} — {len(all_chunks)} chunk(s) of ~{lines_per_chunk} lines each")
        print(f"Model: {model} (via {base_url})")
        if gap_fill:
            why = "--deep-scan" if deep_scan else f"small input (<= {GAP_FILL_MAX_CHUNKS} chunks)"
            print(f"  Explaining all {len(selected)} chunk(s) — {why}, so sub-threshold notes "
                  f"are included.")
        else:
            print(f"  Explaining {len(selected)} chunk(s) now — the {EAGER_EXPLANATIONS} most "
                  f"severe finding(s). {len(deferred)} more chunk(s) are explained on demand "
                  f"when a finding is opened.")
            print(f"  The detector already read all {len(all_chunks)} chunk(s); "
                  f"--deep-scan explains everything up front instead.")

    # Detector findings are instant; explanations are not. Publish a rules-only report
    # immediately so the console can show real findings in about a second, then
    # overwrite it when explanations land. A multi-minute blank screen is
    # indistinguishable from a hang, and the findings were ready the whole time.
    if run_model and selected:
        early = detector_to_findings(anomalies)
        early.sort(key=severity_rank)
        Path(f"{output_prefix}.json").write_text(json.dumps({
            "partial": True, "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_file": str(path), "model": model, "endpoint": base_url,
            "temperature": LLM_TEMPERATURE, "ruleset": RULESET_VERSION,
            "structured_output": structured_output_status(),
            "lines_parsed": stats["parsed"], "lines_unparsed": stats["unparsed"],
            "input_sha256": file_sha256(path),
            "detector_sha256": file_sha256(Path(__file__).resolve().parent / "anomaly_detector.py"),
            "total_chunks": len(all_chunks), "total_chunks_analyzed": len(selected),
            "gap_fill": gap_fill,
        "deferred_chunks": list(deferred),
        "eager_explanations": EAGER_EXPLANATIONS, "total_findings": len(early),
            "findings_by_source": {"detector": len(early), "llm": 0, "analyzer": 0},
            "findings": early, "chunk_summaries": [],
        }, indent=2))
        progress(phase="rules", partialReady=True, findings=len(anomalies))

    progress(phase="explain", done=0, total=len(selected), findings=len(anomalies),
             chunks=len(all_chunks), gapFill=gap_fill)

    # Explanations are independent. Run a small bounded worker pool so a slow
    # local/remote model does not serialize every chunk. Rules have already completed
    # and are published before this phase.
    def _explain_one(item):
        step, idx = item
        start_line, chunk_lines = all_chunks[idx]
        started = time.monotonic()
        result = analyze_chunk(
            base_url, api_key, model, chunk_lines, idx,
            chunk_ctx.get(idx, empty_ctx)
        )
        elapsed = time.monotonic() - started
        return step, idx, start_line, chunk_lines, result, elapsed

    if selected:
        chunks_done = 0
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(LLM_WORKERS, len(selected))
        ) as pool:
            futures = [pool.submit(_explain_one, (step, idx))
                       for step, idx in enumerate(selected, start=1)]

            for future in concurrent.futures.as_completed(futures):
                chunks_done += 1
                try:
                    step, idx, start_line, chunk_lines, result, elapsed = future.result()
                except Exception as exc:
                    print(f"    explanation worker failed: {exc}")
                    progress(
                        phase="explain", done=chunks_done, total=len(selected),
                        findings=len(anomalies)
                    )
                    continue

                print(
                    f"  Explained chunk {idx + 1}/{len(all_chunks)} "
                    f"(worker {step}/{len(selected)}, "
                    f"{elapsed:.1f}s, lines {start_line}-{start_line + len(chunk_lines)})"
                )
                progress(
                    phase="explain", done=chunks_done, total=len(selected),
                    chunk=idx + 1, seconds=round(elapsed, 1), findings=len(anomalies)
                )

                here = by_chunk.get(idx, [])
                for ex in result.get("explanations", []):
                    rid, text = ex.get("rule_id"), ex.get("explanation")
                    if not text:
                        continue
                    targets = [j for j in here if anomalies[j].get("type") == rid] or \
                              ([here[0]] if len(here) == 1 and not rid else [])
                    for j in targets:
                        ident = anomaly_ident(anomalies[j])
                        if ident and ident not in text:
                            continue
                        explanations.setdefault(j, text)

                for finding in result.get("findings", []):
                    if finding.get("source") == "analyzer":
                        finding["chunk_index"] = idx
                        finding["approx_line_start"] = start_line
                        llm_findings.append(finding)
                        continue
                    if restates_detector(finding, anomalies):
                        print(
                            f"    dropped LLM finding (restates a pre-flagged anomaly): "
                            f"{finding.get('summary', '')[:60]}"
                        )
                        continue
                    finding["chunk_index"] = idx
                    finding["approx_line_start"] = start_line
                    finding["rule_id"] = None
                    finding["source"] = "llm"
                    finding.setdefault("severity", "info")
                    finding.setdefault(
                        "summary", "(model omitted a summary for this finding)"
                    )
                    llm_findings.append(finding)

                chunk_summaries.append(result.get("chunk_summary", ""))

    # Second pass: findings whose chunk we already explained but which came back
    # without prose. Asking again for one finding at a time removes the ambiguity that
    # lost them the first time — the context names one finding, so there is nothing for
    # the model to conflate. Deferred chunks are deliberately NOT pulled in here; those
    # are the on-demand budget and re-asking them would undo the wall-time bound.
    missing = [j for idx in selected for j in by_chunk.get(idx, [])
               if j not in explanations]
    if missing:
        retry, skipped = missing[:SECOND_PASS_MAX], missing[SECOND_PASS_MAX:]
        print(f"  {len(missing)} finding(s) came back unexplained; re-asking for "
              f"{len(retry)} individually...")
        if skipped:
            print(f"    {len(skipped)} left for on-demand (cap is {SECOND_PASS_MAX} "
                  f"per run) — they keep their rule verdict and evidence either way.")
        # Each re-ask targets ONE finding with its own context, so they are
        # independent — run them through the same bounded pool as the eager
        # batch instead of serially (H2: worst case was SECOND_PASS_MAX
        # sequential model calls of wall time). Results attach by finding
        # index, so completion order cannot change the report.
        def _reask_one(j):
            idx = next(i for i in selected if j in by_chunk.get(i, []))
            _, chunk_lines = all_chunks[idx]
            same_type = sum(1 for k in by_chunk.get(idx, [])
                            if anomalies[k].get("type") == anomalies[j].get("type"))
            return j, explain_single(
                base_url, api_key, model, chunk_lines, idx,
                to_llm_context([anomalies[j]]),
                rule_id=anomalies[j].get("type"),
                # Only enforce the identity check when there is actually a same-type
                # sibling in this chunk to confuse it with.
                ident=anomaly_ident(anomalies[j]) if same_type > 1 else None)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(LLM_WORKERS, len(retry))
        ) as pool:
            for future in concurrent.futures.as_completed(
                    [pool.submit(_reask_one, j) for j in retry]):
                try:
                    j, text = future.result()
                except Exception as exc:
                    print(f"    re-ask worker failed: {exc}")
                    continue
                if text:
                    explanations[j] = text
                else:
                    print(f"    still unexplained: {anomalies[j].get('type')} "
                          f"(kept as pending, not as an empty answer)")

    # Detector findings are authoritative and added ONCE, not per chunk.
    detector_findings = detector_to_findings(anomalies)
    # detector_to_findings preserves anomaly order, so position maps 1:1.
    for pos, f in enumerate(detector_findings):
        if pos in explanations:
            f["recommended_action"] = explanations[pos]

    # --- Optional ablation: what would the model alone have said? ---------------
    # Strictly additive. Runs a SECOND, unprimed pass over the same chunks and
    # annotates the detector findings; it never touches their severities.
    compare_stats = None
    if compare and not run_model:
        print("Compare mode skipped: nothing was parsed, so there is no rule verdict to "
              "compare the model against.")
    if compare and run_model:
        import compare as compare_mod
        print("Compare mode: second unprimed pass (no rules, no pre-flags)...")

        def chat_fn(system, user):
            return chat_completion(base_url, api_key, model, system, user)

        # Same scoping: an LLM-alone verdict only means something for a chunk that
        # has a rule verdict to compare it against.
        compare_chunks = [all_chunks[i][1] for i in selected]
        progress(phase="compare", done=0, total=len(compare_chunks))
        llm_alone, statuses = compare_mod.run_llm_alone(
            compare_chunks, chat_fn, model, LLM_TEMPERATURE, strip_fences,
            workers=LLM_WORKERS)
        ok = sum(1 for s in statuses if s in compare_mod.USABLE_STATUSES)
        coverage_ok = ok == len(statuses)
        print(f"  unprimed pass: {ok}/{len(statuses)} chunk(s) usable, "
              f"{len(llm_alone)} finding(s)")
        if not coverage_ok:
            bad = [s for s in statuses if s not in compare_mod.USABLE_STATUSES]
            print(f"  WARNING: {len(bad)} chunk(s) gave no usable answer ({', '.join(sorted(set(bad)))}).")
            print("           Findings in those ranges are UNKNOWN, not 'missed' — the")
            print("           comparison cannot speak for lines the model never rated.")

        compare_mod.align(detector_findings, llm_alone, records, coverage_ok=coverage_ok)
        compare_stats = {
            "chunks_total": len(statuses),
            "chunks_usable": ok,
            "chunk_status": statuses,
            "llm_alone_findings": len(llm_alone),
            "underrated_count": compare_mod.underrated_count(detector_findings),
            "prompt": compare_mod.PROMPT_VERSION,
        }
        print(f"  under-rated by the model alone: {compare_stats['underrated_count']}"
              f"/{len(detector_findings)} rule finding(s)")

    # Sort each group by severity (critical first); detector findings lead the report.
    detector_findings.sort(key=severity_rank)
    llm_findings.sort(key=severity_rank)
    all_findings = detector_findings + llm_findings

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(path),
        "model": model,
        "endpoint": base_url,
        "temperature": LLM_TEMPERATURE,
        "ruleset": RULESET_VERSION,
        "structured_output": structured_output_status(),
        "lines_parsed": stats["parsed"],
        "lines_unparsed": stats["unparsed"],
        "input_sha256": file_sha256(path),
        "detector_sha256": file_sha256(Path(__file__).resolve().parent / "anomaly_detector.py"),
        "total_chunks": len(all_chunks),
        "total_chunks_analyzed": len(selected),
        "gap_fill": gap_fill,
        "deferred_chunks": list(deferred),
        "eager_explanations": EAGER_EXPLANATIONS,
        "total_findings": len(all_findings),
        # An analyzer_error is a failure to analyze, not a contribution. Counting it
        # under "llm" overstated model participation in exactly the runs where the
        # model produced nothing at all.
        "findings_by_source": {
            "detector": len(detector_findings),
            "llm": len([f for f in llm_findings if f.get("source") == "llm"]),
            "analyzer": len([f for f in llm_findings if f.get("source") == "analyzer"]),
        },
        "findings": all_findings,
        "chunk_summaries": chunk_summaries,
    }
    if compare_stats:
        report["compare"] = compare_stats

    json_path = f"{output_prefix}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = f"{output_prefix}.md"
    write_markdown_report(report, md_path)

    model_count = report["findings_by_source"]["llm"]
    analyzer_count = report["findings_by_source"]["analyzer"]
    parts = [f"{len(detector_findings)} from rules"]
    parts.append(f"{model_count} from the model" if model_count
                 else "the model contributed none")
    if analyzer_count:
        parts.append(f"{analyzer_count} chunk(s) the model could not analyze")
    print(f"\nDone. {len(all_findings)} finding(s) across {len(all_chunks)} chunk(s) "
          f"({', '.join(parts)}).")
    print(f"  JSON report: {json_path}")
    print(f"  Markdown report: {md_path}")


def write_markdown_report(report: dict, path: str):
    counts = {}
    for f in report["findings"]:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    by_source = report.get("findings_by_source", {})

    lines = []
    lines.append(f"# Log Analysis Report\n")
    lines.append(f"**Source:** `{report['source_file']}`  ")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Model:** {report.get('model', 'n/a')}  ")
    lines.append(f"**Chunks analyzed:** {report['total_chunks_analyzed']}  ")
    lines.append(f"**Total findings:** {report['total_findings']} "
                 f"({by_source.get('detector', 0)} rule-based, {by_source.get('llm', 0)} model)\n")

    if counts:
        lines.append("## Severity breakdown\n")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                lines.append(f"- **{sev.upper()}**: {counts[sev]}")
        lines.append("")

    detector = [f for f in report["findings"] if f.get("source") == "detector"]
    llm = [f for f in report["findings"] if f.get("source") != "detector"]

    def render(f):
        occ = f.get("occurrences", 1)
        title = f"### [{str(f.get('severity', 'info')).upper()}] {f.get('summary', '(no summary)')}"
        lines.append(title + (f" _(x{occ})_" if occ > 1 else ""))
        if f.get("rule_id"):
            lines.append(f"- **Rule:** `{f['rule_id']}`")
        lines.append(f"- **Source:** {f.get('source', 'llm')}")
        lines.append(f"- **Category:** {f.get('category', 'n/a')}")
        lines.append(f"- **Confidence:** {f.get('confidence', 'n/a')}")
        lines.append(f"- **Evidence:** `{f.get('evidence', '')}`")
        if f.get("rationale"):
            lines.append(f"- **Why the rule fired:** {f['rationale']}")
        # "n/a" read like "nothing to do here". A detector finding without prose is a
        # finding the model has not been asked about yet — the rule verdict, evidence
        # and rationale above it are complete and unaffected.
        action = f.get("recommended_action") or (
            "_not generated — open this finding in the console to explain it_"
            if f.get("source") == "detector" else "n/a")
        label = "Analyst explanation" if f.get("source") == "detector" else "Recommended action"
        lines.append(f"- **{label}:** {action}")
        if f.get("source") != "detector":
            lines.append(f"- **Location:** chunk {f.get('chunk_index')}, near line {f.get('approx_line_start')}")
        lines.append("")

    lines.append("## Rule-based findings (authoritative)\n")
    if not detector:
        lines.append("No rule-based anomalies detected.\n")
    for f in detector:
        render(f)

    lines.append("## Additional findings (model + analyzer)\n")
    if not llm:
        lines.append("None — the model surfaced nothing beyond the pre-flagged anomalies.\n")
    for f in llm:
        render(f)

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-powered log analysis (Phase 1: read-only)")
    parser.add_argument("--input", required=True, help="Path to log file to analyze")
    parser.add_argument("--output", default="report", help="Output file prefix (default: report)")
    parser.add_argument("--lines-per-chunk", type=int, default=25,
                        help="Lines per chunk sent to the model (default 25 — larger "
                             "chunks make an 8B model drop the response schema; the "
                             "detector is unaffected either way)")
    parser.add_argument("--model", default=LLM_MODEL, help=f"Model to use (default: $LLM_MODEL or {LLM_MODEL})")
    parser.add_argument("--base-url", default=LLM_BASE_URL, help=f"OpenAI-compatible base URL (default: $LLM_BASE_URL or {LLM_BASE_URL})")
    parser.add_argument("--compare", action="store_true",
                        help="Also run an unprimed LLM-alone pass and record what the model "
                             "would have rated each finding without the rules. Doubles "
                             "inference cost; never changes an authoritative severity.")
    parser.add_argument("--rules-only", action="store_true",
                        help="Deterministic pass only: rules, severities and correlation, "
                             "no model calls at all. Used by the console when explanations "
                             "run on a remote compute node through its redaction gate.")
    parser.add_argument("--deep-scan", action="store_true",
                        help="Ask the model about every chunk, not just those with a "
                             "rule finding. Finds sub-threshold notes anywhere in the "
                             "file; cost then scales with file size, not findings.")
    parser.add_argument("--nmap-target", default=None,
                        help="Explicit host/CIDR to scan with Nmap (no scan occurs without this option).")
    parser.add_argument("--nmap-vuln", action="store_true",
                        help="Run Nmap NSE vulnerability scripts against --nmap-target. Use only on authorized assets.")
    parser.add_argument("--nmap-extra", nargs="*", default=None,
                        help="Additional Nmap arguments, passed without a shell (advanced/authorized use).")
    parser.add_argument("--nmap-timeout", type=int, default=300,
                        help="Nmap execution timeout in seconds (default 300).")
    parser.add_argument("--nmap-diagnose", action="store_true",
                        help="Validate Nmap binary/NSE vulnerability scripts and exit.")
    parser.add_argument("--llm-timeout", type=int, default=LLM_TIMEOUT,
                        help="LLM request timeout seconds (default from SOC_LLM_TIMEOUT).")
    parser.add_argument("--llm-workers", type=int, default=LLM_WORKERS,
                        help="Parallel LLM explanation workers (default 3).")
    parser.add_argument("--llm-retries", type=int, default=LLM_RETRIES,
                        help="Extra retries for malformed model responses (default 0).")
    args = parser.parse_args()

    if args.lines_per_chunk < 1:
        parser.error("--lines-per-chunk must be >= 1")

    if args.nmap_diagnose:
        try:
            nmap_bin = shutil.which("nmap")
            if not nmap_bin:
                raise RuntimeError("nmap is not in PATH")
            v = subprocess.run([nmap_bin, "--version"], capture_output=True,
                               text=True, timeout=15, check=False)
            if v.returncode != 0:
                raise RuntimeError((v.stderr or "nmap --version failed").strip())
            h = subprocess.run([nmap_bin, "--script-help", "vuln"],
                               capture_output=True, text=True, timeout=30, check=False)
            print(v.stdout.splitlines()[0] if v.stdout else "Nmap installed")
            if h.returncode != 0:
                raise RuntimeError((h.stderr or "NSE vuln category unavailable").strip())
            print("NSE vulnerability category: OK")
            print("Nmap vulnerability engine: READY")
            sys.exit(0)
        except Exception as exc:
            print(f"Nmap diagnostics FAILED: {exc}")
            sys.exit(1)

    # CLI overrides for bounded explanation execution.
    LLM_TIMEOUT = max(10, int(args.llm_timeout))
    LLM_WORKERS = max(1, min(8, int(args.llm_workers)))
    LLM_RETRIES = max(0, min(2, int(args.llm_retries)))
    try:
        rc = run(args.input, args.output, args.lines_per_chunk, args.model, args.base_url,
                 LLM_API_KEY, compare=args.compare, deep_scan=args.deep_scan,
                 rules_only=args.rules_only, nmap_target=args.nmap_target,
                 nmap_vuln=args.nmap_vuln, nmap_extra_args=args.nmap_extra,
                 nmap_timeout=args.nmap_timeout)
        if isinstance(rc, int) and rc:
            sys.exit(rc)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
