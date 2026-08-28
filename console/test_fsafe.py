#!/usr/bin/env python3
"""
test_fsafe.py — durability checks for console/fsafe.py.

fsafe is the only thing standing between the flat-file stores (and now the
append-only audit ledger) and two failure modes that are silent by nature: a
crash mid-write leaving a truncated file, and two writers interleaving bytes.
Both are the kind of bug that shows up as "the history is just wrong" weeks
later, so they are tested with REAL processes and REAL kills, not mocks:

  * atomic write vs. interrupt — a child process is SIGKILLed while
    atomic_write_text() is running, repeatedly. The target file must always be
    the complete old content or the complete new content, never a torn mixture.
  * concurrent append — eight separate processes append long lines to one file
    at the same time. Every line must arrive whole and intact.

Usage:
  python3 console/test_fsafe.py
"""

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fsafe  # noqa: E402

RESULTS = []


def check(label, cond, detail=""):
    RESULTS.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}"
          + ("" if cond or not detail else f" — {detail}"))


# ---------------------------------------------------------------------------
# atomic_write_text
# ---------------------------------------------------------------------------

_KILL_CHILD = r'''
import sys, time
sys.path.insert(0, %(here)r)
import fsafe
target = %(target)r
# A payload big enough that the write genuinely takes time to hit the disk.
payload = ("NEW" * 40) + "\n"
payload = payload * 60000
open(%(ready)r, "w").close()
while True:
    fsafe.atomic_write_text(target, payload)
'''


def check_atomic_write():
    print("\nfsafe.atomic_write_text — atomicity under interrupt:")
    with tempfile.TemporaryDirectory(prefix="fsafe-atomic-") as tmp:
        tmp = Path(tmp)
        target = tmp / "state.json"
        old = ("OLD" * 40 + "\n") * 60000
        target.write_text(old)
        new = ("NEW" * 40 + "\n") * 60000

        # --- deterministic: an interrupt lands between fsync and os.replace ---
        real_replace = os.replace
        boom = []

        def exploding_replace(src, dst):
            boom.append((src, dst))
            raise KeyboardInterrupt("simulated interrupt before the swap")

        os.replace = exploding_replace
        try:
            fsafe.atomic_write_text(target, new)
        except KeyboardInterrupt:
            pass
        finally:
            os.replace = real_replace
        check("an interrupt at the swap point leaves the ORIGINAL file byte-identical",
              target.read_text() == old)
        # (the sidecar state.json.lock is fsafe's own flock target and is
        # expected to persist; a leftover *.tmp would be the real debris)
        debris = sorted(p.name for p in tmp.iterdir()
                        if p.name not in ("state.json", "state.json.lock"))
        check("...and removes its temp file (no *.tmp debris in the directory)",
              not debris, str(debris))
        check("...and the swap really was the point that was interrupted", len(boom) == 1)

        # --- real: SIGKILL a live writer, repeatedly -------------------------
        script = tmp / "writer.py"
        ready = tmp / "ready"
        script.write_text(_KILL_CHILD % {"here": str(HERE), "target": str(target),
                                         "ready": str(ready)})
        torn = None
        kills = 0
        for attempt in range(12):
            if ready.exists():
                ready.unlink()
            proc = subprocess.Popen([sys.executable, str(script)])
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.005)
            time.sleep(0.004 + attempt * 0.0035)      # land inside a write
            proc.send_signal(signal.SIGKILL)
            proc.wait()
            kills += 1
            got = target.read_text()
            if got not in (old, new):
                torn = (len(got), got[:60])
                break
        check(f"a SIGKILL during atomic_write_text never leaves a torn target "
              f"({kills} real kills)", torn is None, f"torn file: {torn}")
        leftovers = sorted(p.name for p in tmp.iterdir()
                           if p.name.startswith("state.json.") and p.name.endswith(".tmp"))
        # A SIGKILLed process cannot run its own cleanup, so a stale .tmp may
        # survive. That is debris, not corruption: it is never the target path
        # and no reader ever opens it. Reported, not asserted away.
        print(f"  [note] stale temp files left by the killed writers: {len(leftovers)}"
              f" (never the target; readers only open {target.name})")


# ---------------------------------------------------------------------------
# durable append
# ---------------------------------------------------------------------------

_APPENDER = r'''
import sys, os
sys.path.insert(0, %(here)r)
import fsafe
target, n = %(target)r, %(n)d
pid = os.getpid()
body = "X" * 60000            # far past PIPE_BUF: unlocked writers WOULD tear
for i in range(n):
    fsafe.durable_append_line(target, "%%06d|%%04d|%%s" %% (pid, i, body))
'''


def check_concurrent_append():
    print("\nfsafe.durable_append_line — real concurrent appenders do not interleave:")
    procs_n, lines_n = 8, 25
    with tempfile.TemporaryDirectory(prefix="fsafe-append-") as tmp:
        tmp = Path(tmp)
        target = tmp / "chain.jsonl"
        script = tmp / "appender.py"
        script.write_text(_APPENDER % {"here": str(HERE), "target": str(target),
                                       "n": lines_n})
        procs = [subprocess.Popen([sys.executable, str(script)])
                 for _ in range(procs_n)]
        codes = [p.wait() for p in procs]
        check(f"{procs_n} concurrent appender processes all exited 0", set(codes) == {0}, str(codes))

        raw = target.read_text()
        lines = raw.split("\n")
        check("the file ends with exactly one newline (no partial trailing line)",
              lines and lines[-1] == "" and not raw.endswith("\n\n"))
        lines = [ln for ln in lines if ln]
        check(f"every line arrived: {procs_n * lines_n} expected",
              len(lines) == procs_n * lines_n, f"got {len(lines)}")
        bad = [i for i, ln in enumerate(lines)
               if len(ln) != 6 + 1 + 4 + 1 + 60000
               or ln[6] != "|" or ln[11] != "|"
               or set(ln[12:]) != {"X"}]
        check("no line is torn or interleaved with another writer's bytes",
              not bad, f"{len(bad)} malformed line(s), first at index {bad[:1]}")
        seen = {}
        for ln in lines:
            pid, idx = ln[:6], ln[7:11]
            seen.setdefault(pid, []).append(idx)
        check(f"all {procs_n} writers are represented, each with its {lines_n} lines "
              "in its own order",
              len(seen) == procs_n
              and all(v == sorted(v) and len(v) == lines_n for v in seen.values()),
              str({k: len(v) for k, v in seen.items()}))

        # append only ADDS bytes — it never rewrites what is already committed
        before = target.read_bytes()
        fsafe.durable_append_line(target, "tail")
        after = target.read_bytes()
        check("an append leaves every previously written byte untouched",
              after.startswith(before) and after == before + b"tail\n")


def main():
    print("fsafe — atomic write + durable append (console/fsafe.py)")
    check_atomic_write()
    check_concurrent_append()
    if all(RESULTS):
        print(f"\nPASSED — {len(RESULTS)} fsafe checks green")
        return 0
    print(f"\nFAILED — {RESULTS.count(False)}/{len(RESULTS)} fsafe checks failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
