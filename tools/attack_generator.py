#!/usr/bin/env python3
"""Generate deterministic, labelled attack-chain logs for development checks.

Outputs belong in ``tools/efficacy_data/`` and are deliberately refused anywhere
under ``tests/eval/``.  The manifests are ground truth for the generated text;
this module never invokes or imports the detector.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable


DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "efficacy_data"
EVAL_DIR = Path(__file__).resolve().parents[1] / "tests" / "eval"


@dataclass(frozen=True)
class Event:
    ts: str
    level: str
    host: str
    msg: str
    malicious: bool = False
    why: str = ""


def canonical(event: Event) -> str:
    return f"{event.ts} {event.level} {event.host} {event.msg}"


def rfc3164(event: Event) -> str:
    parsed = datetime.fromisoformat(event.ts.replace("Z", "+00:00"))
    month = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[parsed.month - 1]
    stamp = f"{month} {parsed.day:02d} {parsed:%H:%M:%S}"
    return f"{stamp} {event.host} attack-generator: {event.level} {event.msg}"


def rfc5424(event: Event) -> str:
    return f"<134>1 {event.ts} {event.host} attack-generator - - - {event.level} {event.msg}"


def jsonlog(event: Event) -> str:
    return json.dumps(
        {"timestamp": event.ts, "level": event.level, "host": event.host, "message": event.msg},
        sort_keys=True,
        separators=(",", ":"),
    )


FORMATTERS: dict[str, Callable[[Event], str]] = {
    "canonical": canonical,
    "rfc3164": rfc3164,
    "rfc5424": rfc5424,
    "jsonlog": jsonlog,
}


def _brute_force() -> list[Event]:
    events = [Event("2026-08-30T02:16:40Z", "INFO", "server-01", "sshd service ready")]
    for offset in range(7):
        events.append(Event(
            f"2026-08-30T02:16:{41 + offset:02d}Z", "WARN", "server-01",
            f"Failed password for admin from 203.0.113.44 port {49152 + offset} ssh2",
            True, "credential-guessing failure from the scenario source",
        ))
    events.append(Event("2026-08-30T02:16:49Z", "INFO", "server-01", "health check passed"))
    return events


def _failure_success() -> list[Event]:
    events = [Event("2026-08-30T03:00:00Z", "INFO", "server-02", "sshd service ready")]
    for offset in range(5):
        events.append(Event(
            f"2026-08-30T03:00:{offset + 1:02d}Z", "WARN", "server-02",
            f"Failed password for deploy from 198.51.100.23 port {50200 + offset} ssh2",
            True, "SSH credential-guessing failure preceding a success",
        ))
    events.append(Event(
        "2026-08-30T03:00:08Z", "INFO", "server-02",
        "Accepted password for deploy from 198.51.100.23 port 50205 ssh2",
        True, "authentication success after repeated failures from the same source",
    ))
    return events


def _error_burst() -> list[Event]:
    events = [Event("2026-08-30T04:00:00Z", "INFO", "api-01", "worker pool ready")]
    for offset in range(6):
        events.append(Event(
            f"2026-08-30T04:00:{offset * 4 + 1:02d}Z", "ERROR", "api-01",
            f"upstream request failed with status 503 attempt={offset + 1}",
            True, "part of a concentrated application error burst",
        ))
    return events


SCENARIOS: dict[str, Callable[[], list[Event]]] = {
    "INC-4a7f": _brute_force,
    "failure-success": _failure_success,
    "error-burst": _error_burst,
}


def _assert_isolated(output_dir: Path) -> Path:
    resolved = output_dir.expanduser().resolve()
    try:
        resolved.relative_to(EVAL_DIR.resolve())
    except ValueError:
        return resolved
    raise ValueError(f"refusing generated output inside evaluation corpus: {resolved}")


def generate(scenario: str, format_name: str, output_dir: Path = DEFAULT_OUTPUT_DIR) -> tuple[Path, Path]:
    """Write one log and matching manifest, returning their paths."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    if format_name not in FORMATTERS:
        raise ValueError(f"unknown format: {format_name}")
    target = _assert_isolated(Path(output_dir))
    target.mkdir(parents=True, exist_ok=True)
    events = SCENARIOS[scenario]()
    lines = [FORMATTERS[format_name](event) for event in events]
    stem = f"{scenario.lower()}-{format_name}"
    log_path = target / f"{stem}.log"
    manifest_path = target / f"{stem}.manifest.json"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    malicious = [
        {"line": number, "raw": raw, "why": event.why}
        for number, (event, raw) in enumerate(zip(events, lines), 1)
        if event.malicious
    ]
    manifest = {
        "scenario": scenario,
        "format": format_name,
        "line_count": len(lines),
        "malicious_count": len(malicious),
        "malicious_lines": malicious,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return log_path, manifest_path


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, action="append", dest="scenarios")
    parser.add_argument("--format", choices=FORMATTERS, action="append", dest="formats")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)
    try:
        for scenario in args.scenarios or SCENARIOS:
            for format_name in args.formats or FORMATTERS:
                generate(scenario, format_name, args.output_dir)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
