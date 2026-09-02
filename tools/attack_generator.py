#!/usr/bin/env python3
"""Generate deterministic, labelled attack-chain logs for development checks.

Outputs belong in ``tools/efficacy_data/`` and are deliberately refused anywhere
under ``tests/eval/``.  The manifests are ground truth for the generated text;
this module never invokes or imports the detector.

E7a extends the coverage — and only as far as the training set needed:

* every scenario builder now optionally takes a seeded ``random.Random``.  With
  no seed the builders emit exactly the bytes they always did (the promoted
  efficacy harness keeps its fixtures unchanged); with a seed they emit a
  deterministic variant of the same scenario, which is how one template becomes
  many training rows without any of them being invented at run time;
* three scenarios join the three positive ones: two NEAR-MISS templates whose
  every line is benign but which sit just under a rule threshold, and one
  BENIGN-EXPECTED template (authorised maintenance) that the rules legitimately
  fire on.  Both kinds carry zero malicious lines in their manifest, and the
  manifest states the scenario's ground-truth analyst class outright.

``SCENARIO_CLASS`` maps each scenario to the E0 disposition vocabulary
(``confirmed`` / ``false-positive`` / ``benign-expected``) so a generated row and
a real closed incident are the same kind of label.
"""

from __future__ import annotations

import argparse
import json
import random
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


def _rng_or_default(rng: random.Random | None) -> random.Random:
    """A seeded generator, or a fixed one that reproduces the original bytes.

    ``random.Random(0)`` is never consulted when ``rng is None`` — the builders
    branch on ``rng is None`` and use their literal constants — so the promoted
    fixtures stay byte-for-byte identical.
    """
    return rng if rng is not None else random.Random(0)


def _brute_force(rng: random.Random | None = None) -> list[Event]:
    if rng is None:
        failures, user, source, base_port = 7, "admin", "203.0.113.44", 49152
    else:
        failures = rng.randint(6, 11)
        user = rng.choice(("admin", "root", "svc-deploy", "operator"))
        source = f"203.0.113.{rng.randint(20, 99)}"
        base_port = rng.randrange(40000, 60000)
    events = [Event("2026-08-30T02:16:40Z", "INFO", "server-01", "sshd service ready")]
    for offset in range(failures):
        events.append(Event(
            f"2026-08-30T02:16:{41 + offset:02d}Z", "WARN", "server-01",
            f"Failed password for {user} from {source} port {base_port + offset} ssh2",
            True, "credential-guessing failure from the scenario source",
        ))
    events.append(Event(f"2026-08-30T02:16:{41 + failures + 1:02d}Z", "INFO",
                        "server-01", "health check passed"))
    return events


def _failure_success(rng: random.Random | None = None) -> list[Event]:
    if rng is None:
        failures, user, source, base_port = 5, "deploy", "198.51.100.23", 50200
    else:
        failures = rng.randint(5, 9)
        user = rng.choice(("deploy", "jenkins", "backup", "dbadmin"))
        source = f"198.51.100.{rng.randint(10, 90)}"
        base_port = rng.randrange(50000, 59000)
    events = [Event("2026-08-30T03:00:00Z", "INFO", "server-02", "sshd service ready")]
    for offset in range(failures):
        events.append(Event(
            f"2026-08-30T03:00:{offset + 1:02d}Z", "WARN", "server-02",
            f"Failed password for {user} from {source} port {base_port + offset} ssh2",
            True, "SSH credential-guessing failure preceding a success",
        ))
    events.append(Event(
        f"2026-08-30T03:00:{failures + 3:02d}Z", "INFO", "server-02",
        f"Accepted password for {user} from {source} port {base_port + failures} ssh2",
        True, "authentication success after repeated failures from the same source",
    ))
    return events


def _error_burst(rng: random.Random | None = None) -> list[Event]:
    if rng is None:
        errors, status = 6, 503
    else:
        errors = rng.randint(6, 12)
        status = rng.choice((500, 502, 503, 504))
    events = [Event("2026-08-30T04:00:00Z", "INFO", "api-01", "worker pool ready")]
    for offset in range(errors):
        events.append(Event(
            f"2026-08-30T04:00:{offset * 4 + 1:02d}Z", "ERROR", "api-01",
            f"upstream request failed with status {status} attempt={offset + 1}",
            True, "part of a concentrated application error burst",
        ))
    return events


# --- near-miss and benign-expected templates (E7a) -------------------------
# Every line below is BENIGN. The manifests carry zero malicious lines, so the
# efficacy harness reads any finding here as a false positive — which is exactly
# the training signal the second-opinion model needs and could not get from the
# positive templates alone. Nothing is labelled by guess: the scenario states
# its ground-truth class and the lines are generated to match it.

def _near_miss_auth(rng: random.Random | None = None) -> list[Event]:
    """A handful of fat-fingered logins, under every brute-force threshold."""
    r = _rng_or_default(rng)
    if rng is None:
        failures, user, source = 2, "alice", "10.10.4.7"
    else:
        failures = r.randint(1, 3)
        user = r.choice(("alice", "bob", "carol", "dave"))
        source = f"10.10.{r.randint(1, 40)}.{r.randint(2, 250)}"
    events = [Event("2026-08-30T09:00:00Z", "INFO", "server-02", "sshd service ready")]
    for offset in range(failures):
        events.append(Event(
            f"2026-08-30T09:{offset * 7 + 3:02d}:00Z", "WARN", "server-02",
            f"Failed password for {user} from {source} port {51000 + offset} ssh2",
        ))
    events.append(Event(
        f"2026-08-30T09:{failures * 7 + 5:02d}:00Z", "INFO", "server-02",
        f"Accepted publickey for {user} from {source} port {51100} ssh2"))
    events.append(Event("2026-08-30T09:59:00Z", "INFO", "server-02", "health check passed"))
    return events


def _near_miss_errors(rng: random.Random | None = None) -> list[Event]:
    """Sparse upstream errors, spread far too wide to be a burst."""
    r = _rng_or_default(rng)
    if rng is None:
        errors, status = 2, 502
    else:
        errors = r.randint(1, 3)
        status = r.choice((500, 502, 503))
    events = [Event("2026-08-30T10:00:00Z", "INFO", "api-01", "worker pool ready")]
    for offset in range(errors):
        events.append(Event(
            f"2026-08-30T{10 + offset * 3:02d}:12:00Z", "ERROR", "api-01",
            f"upstream request failed with status {status} attempt=1"))
        events.append(Event(
            f"2026-08-30T{10 + offset * 3:02d}:12:30Z", "INFO", "api-01",
            "upstream request succeeded on retry"))
    return events


def _benign_maintenance(rng: random.Random | None = None) -> list[Event]:
    """Authorised patch window: a real, expected error burst on a real host.

    The rules SHOULD fire here — a burst is a burst — and the honest analyst
    outcome is `benign-expected`, not `false-positive`. That distinction is the
    third class, and it is why the taxonomy has three members.
    """
    r = _rng_or_default(rng)
    if rng is None:
        errors, window = 6, "CHG-1042"
    else:
        errors = r.randint(6, 10)
        window = f"CHG-{r.randint(1000, 1999)}"
    events = [Event("2026-08-30T01:00:00Z", "INFO", "server-01",
                    f"maintenance window {window} opened by change management")]
    for offset in range(errors):
        events.append(Event(
            f"2026-08-30T01:00:{offset * 5 + 2:02d}Z", "ERROR", "server-01",
            f"service restart failed during patching, retrying attempt={offset + 1}"))
    events.append(Event("2026-08-30T01:59:00Z", "INFO", "server-01",
                        f"maintenance window {window} closed, all services healthy"))
    return events


SCENARIOS: dict[str, Callable[..., list[Event]]] = {
    "INC-4a7f": _brute_force,
    "failure-success": _failure_success,
    "error-burst": _error_burst,
    "near-miss-auth": _near_miss_auth,
    "near-miss-errors": _near_miss_errors,
    "benign-maintenance": _benign_maintenance,
}

# Ground-truth analyst class per scenario, in E0's disposition vocabulary. This
# is the scenario's designed outcome, declared here and written into every
# manifest — it is never inferred from what the detector happened to do.
SCENARIO_CLASS: dict[str, str] = {
    "INC-4a7f": "confirmed",
    "failure-success": "confirmed",
    "error-burst": "confirmed",
    "near-miss-auth": "false-positive",
    "near-miss-errors": "false-positive",
    "benign-maintenance": "benign-expected",
}

# The host each scenario is about, so a consumer can resolve the configured
# asset criticality without re-parsing the log. Observed, not invented: it is
# the host on the scenario's own event lines.
SCENARIO_HOST: dict[str, str] = {
    "INC-4a7f": "server-01",
    "failure-success": "server-02",
    "error-burst": "api-01",
    "near-miss-auth": "server-02",
    "near-miss-errors": "api-01",
    "benign-maintenance": "server-01",
}


def _assert_isolated(output_dir: Path) -> Path:
    resolved = output_dir.expanduser().resolve()
    try:
        resolved.relative_to(EVAL_DIR.resolve())
    except ValueError:
        return resolved
    raise ValueError(f"refusing generated output inside evaluation corpus: {resolved}")


def generate(
    scenario: str,
    format_name: str,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    seed: int | None = None,
) -> tuple[Path, Path]:
    """Write one log and matching manifest, returning their paths.

    ``seed=None`` reproduces the original fixture byte-for-byte. An integer seed
    produces a deterministic variant of the same scenario: same seed, same
    bytes, forever — which is what makes a seeded training set reproducible.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    if format_name not in FORMATTERS:
        raise ValueError(f"unknown format: {format_name}")
    target = _assert_isolated(Path(output_dir))
    target.mkdir(parents=True, exist_ok=True)
    rng = None if seed is None else random.Random(f"{scenario}|{format_name}|{seed}")
    events = SCENARIOS[scenario](rng)
    lines = [FORMATTERS[format_name](event) for event in events]
    stem = f"{scenario.lower()}-{format_name}"
    if seed is not None:
        stem = f"{stem}-s{seed}"
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
        "seed": seed,
        # Ground truth for the whole scenario, in E0's disposition vocabulary.
        "scenario_class": SCENARIO_CLASS[scenario],
        "host": SCENARIO_HOST[scenario],
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
    parser.add_argument("--seed", type=int, action="append", dest="seeds",
                        help="deterministic variant seed; repeatable. Omitted "
                             "= the original unseeded fixture.")
    args = parser.parse_args(argv)
    try:
        for scenario in args.scenarios or SCENARIOS:
            for format_name in args.formats or FORMATTERS:
                for seed in args.seeds or [None]:
                    generate(scenario, format_name, args.output_dir, seed)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
