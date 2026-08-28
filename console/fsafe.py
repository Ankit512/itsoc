"""
fsafe.py — atomic, lock-guarded writes for the flat-file JSON stores.

The run-history files (console/.runs/*.json), the live state file
(console/console_state.json) and the SOC derived stores (console/.soc/*.json)
were written with plain Path.write_text(). Two real failure modes follow:

  * a crash mid-write leaves a truncated file — the saved run no longer parses
    and minutes of analyzer work are silently gone from history;
  * two writers race — POST /api/mark persisting reviewer state while a re-run
    saves the same history file — and the interleaved bytes corrupt it.

This module closes both with stdlib only, without changing the storage format
(same paths, same JSON):

  * atomic replace: the payload is written to a temp file in the SAME
    directory, fsynced, then swapped in with os.replace() — readers see the
    old complete file or the new complete file, never a half-written one;
  * a per-target lock serializes concurrent writers: fcntl.flock on a sidecar
    .lock file where fcntl exists (macOS/Linux), a portable O_CREAT|O_EXCL
    spin lock elsewhere.

console/store.py (embedded sqlite3) has its own transactional guarantees and
does not go through here.
"""

import os
import tempfile
import time
from contextlib import contextmanager

try:
    import fcntl
except ImportError:                    # non-POSIX: fall back to the spin lock
    fcntl = None

# The spin-lock fallback must not wedge writes forever behind a lock file left
# by a crashed holder; past the timeout the stale file is removed and retried.
_LOCK_TIMEOUT = 10.0
_LOCK_POLL = 0.05


@contextmanager
def locked(path):
    """Serialize writers of `path` via a sidecar `<path>.lock` file."""
    lock_path = os.fspath(path) + ".lock"
    if fcntl is not None:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    else:
        deadline = time.monotonic() + _LOCK_TIMEOUT
        while True:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    try:
                        os.unlink(lock_path)
                    except OSError:
                        pass
                time.sleep(_LOCK_POLL)
        try:
            yield
        finally:
            os.close(fd)
            try:
                os.unlink(lock_path)
            except OSError:
                pass


def atomic_write_text(path, text):
    """Write `text` to `path` so a reader can never observe a partial file.

    Raises OSError like Path.write_text would; on any failure the target file
    is left exactly as it was and the temp file is removed.
    """
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    with locked(path):
        fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".",
                                   suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


# ---------------------------------------------------------------------------
# Durable APPEND (added for Stage C C0-T2 — the hash-chained audit log).
#
# atomic_write_text() above is a WHOLE-FILE write: it rewrites the target from
# scratch every time. That is wrong for an append-only ledger — rewriting the
# whole file on every entry is O(n) per append and, worse, it puts every prior
# byte back on the write path, so a crash mid-swap could lose already-committed
# history. An append-only chain must only ever ADD bytes.
#
# So the append path is built on the SAME `locked()` primitive instead:
#   * the sidecar lock serializes writers, so two appenders can never interleave
#     partial lines (the acceptance test proves this with real processes);
#   * O_APPEND makes the kernel seek-to-end and write as one operation, so the
#     write lands past every existing byte even if a non-cooperating writer
#     exists;
#   * flush + fsync of the file (and of the directory on creation) makes the
#     line durable before the lock is released, so a reader that acquires the
#     lock next sees a complete line, never a torn one.
# Existing bytes are never opened for writing, never truncated, never replaced.
# ---------------------------------------------------------------------------


def append_line_holding_lock(path, line):
    """Durably append one `line` to `path`. THE CALLER MUST ALREADY HOLD
    `locked(path)`.

    Exists because a chained ledger has to read its own tail and append the
    successor inside ONE critical section; `locked()` is not reentrant (flock is
    per-fd), so such a caller cannot go through durable_append_line().

    `line` is written verbatim with exactly one trailing newline added if it
    does not already end in one. Embedded newlines are the caller's problem —
    the audit chain serializes compact JSON, which contains none.
    """
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    if not line.endswith("\n"):
        line += "\n"
    existed = os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if not existed:
        # A brand-new file also needs its directory entry on disk, or a crash
        # could leave the durable bytes unreachable.
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)


def durable_append_line(path, line):
    """Lock-guarded durable append — the standalone form of the above."""
    with locked(path):
        append_line_holding_lock(path, line)
