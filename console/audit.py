#!/usr/bin/env python3
"""
audit.py — the append-only, hash-chained audit ledger (Stage C, build doc D4).

WHAT THIS IS
  Every consequential act in the SOC console — an eligibility decision, an
  approval, a rejection, an execution, a failure — lands here as one JSON line
  in `console/.soc/audit/chain.jsonl`, linked to its predecessor by hash. The
  file is the SOURCE OF TRUTH. The sqlite table `audit_index` in store.py is a
  DERIVED, rebuildable index that exists only so the UI can query without
  parsing the ledger; if the two ever disagree, the JSONL wins and the index is
  rebuilt from it (never the other way round).

THE CHAIN
  entry_hash = sha256(canonical_json(entry_without_entry_hash))
  and the entry being hashed already carries `prev_hash`, so every hash commits
  to the entire history behind it. The first entry's prev_hash is GENESIS
  (64 zeros). Canonical JSON = sorted keys, no whitespace, UTF-8, so the hash of
  a re-serialized entry is stable.

HONESTY — the load-bearing property of this module (guardrail 2)
  `verify_chain()` runs on read and REPORTS a break: the index, the reason, and
  the hashes it expected vs found. There is deliberately NO repair path in this
  file. Nothing here rewrites, re-chains, truncates, or deletes an existing
  line — the only write is an O_APPEND of one new line through fsafe. A broken
  chain stays broken and stays visible. That is the point of an audit log: an
  audit trail that can quietly fix itself is not evidence of anything.

  `append()` on a chain that is already broken still appends (refusing would let
  anyone who corrupts one byte silently stop the ledger from recording their
  next action). It links to the real current tail; the earlier break remains
  reported at its own index by verify_chain(). Appending is not repairing.

Stdlib only (hashlib, json, os, pathlib) plus console/fsafe.py for durability.
No execution, no connectors, no approval flow live here — this module only
records what its caller tells it.
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fsafe  # noqa: E402

# Module-level so tests can repoint them at a temp dir. Read live on every call.
SOC_DIR = HERE / ".soc"
AUDIT_DIR = SOC_DIR / "audit"
CHAIN_NAME = "chain.jsonl"

GENESIS = "0" * 64

# The entry contract, exactly as specified by build doc D4. Order matters only
# for readability — the hash is over sorted keys.
FIELDS = (
    "ts",
    "actor",
    "incident_id",
    "runbook_id",
    "step",
    "eligibility_proof",
    "evidence_refs",
    "request_redacted",
    "response_verbatim",
    "status",
    "prev_hash",
    "entry_hash",
)
HASHED_FIELDS = tuple(f for f in FIELDS if f != "entry_hash")

STATUSES = ("approved", "rejected", "executed", "failed")


def chain_path():
    """Live path to the ledger (honours a test override of SOC_DIR/AUDIT_DIR)."""
    return Path(AUDIT_DIR) / CHAIN_NAME


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def canonical_json(payload):
    """The exact bytes that get hashed: sorted keys, no whitespace, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def compute_hash(entry):
    """sha256 over the canonical JSON of the entry minus its own entry_hash.
    `prev_hash` is inside that payload, so each hash commits to all of history."""
    payload = {k: entry[k] for k in HASHED_FIELDS}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _normalize(actor, incident_id, runbook_id, step, eligibility_proof,
               evidence_refs, request_redacted, response_verbatim, status, ts):
    """Coerce a caller's arguments into the fixed field contract. Unknown status
    values are rejected loudly rather than stored as an invented one."""
    status = str(status)
    if status not in STATUSES:
        raise ValueError(
            f"status must be one of {'|'.join(STATUSES)}, got {status!r}")
    refs = list(evidence_refs or [])
    return {
        "ts": str(ts or now_iso()),
        "actor": str(actor),
        "incident_id": str(incident_id),
        "runbook_id": str(runbook_id),
        "step": str(step),
        # Whatever runbooks.eligible() returned, carried verbatim.
        "eligibility_proof": eligibility_proof,
        "evidence_refs": [str(r) for r in refs],
        "request_redacted": request_redacted,
        "response_verbatim": response_verbatim,
        "status": status,
    }


def read_lines():
    """Raw ledger lines (blank lines dropped). Missing file = honest empty."""
    path = chain_path()
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return [ln for ln in text.split("\n") if ln.strip()]


def read_entries():
    """Parsed entries. Raises ValueError on a malformed line — a caller that
    wants the honest diagnosis instead should call verify_chain()."""
    out = []
    for i, line in enumerate(read_lines()):
        try:
            out.append(json.loads(line))
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"chain line {i} is not valid JSON: {exc}") from exc
    return out


def _tail_hash_from_lines(lines):
    """entry_hash of the last line, or GENESIS for an empty ledger.

    Reads the tail AS IT IS. It does not check, and must not check, whether the
    tail is consistent with what precedes it — repairing history is not this
    module's job, and a broken chain must remain broken.
    """
    if not lines:
        return GENESIS
    try:
        last = json.loads(lines[-1])
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(
            "cannot append: the last chain line is not valid JSON "
            f"({exc}). The ledger is damaged; verify_chain() will report it. "
            "Nothing here will rewrite it.") from exc
    prev = last.get("entry_hash")
    if not isinstance(prev, str) or len(prev) != 64:
        raise ValueError(
            "cannot append: the last chain line has no usable entry_hash. "
            "The ledger is damaged; verify_chain() will report it.")
    return prev


def append(actor, incident_id, runbook_id, step, status,
           eligibility_proof=None, evidence_refs=None,
           request_redacted=None, response_verbatim=None, ts=None,
           index=True):
    """Append one entry and return it (including prev_hash + entry_hash).

    Read-tail-and-append happen inside ONE fsafe lock, so two concurrent
    appenders cannot both chain off the same predecessor, and cannot interleave
    partial lines. The write is O_APPEND + fsync: existing bytes are never
    reopened for writing.

    `index=True` mirrors the entry into the derived sqlite index. An indexing
    failure is NEVER allowed to lose a ledger entry — the JSONL is already
    committed at that point — so it is reported on the returned entry under
    `_index_error` rather than raised.
    """
    entry = _normalize(actor, incident_id, runbook_id, step, eligibility_proof,
                       evidence_refs, request_redacted, response_verbatim,
                       status, ts)
    path = chain_path()
    Path(AUDIT_DIR).mkdir(parents=True, exist_ok=True)
    with fsafe.locked(path):
        lines = read_lines()
        entry["prev_hash"] = _tail_hash_from_lines(lines)
        entry["entry_hash"] = compute_hash(entry)
        seq = len(lines)
        ordered = {k: entry[k] for k in FIELDS}
        fsafe.append_line_holding_lock(path, canonical_json(ordered))
    if index:
        try:
            import store
            store.index_audit_entry(ordered, seq)
        except Exception as exc:                  # noqa: BLE001 — reported, not swallowed
            ordered = dict(ordered)
            ordered["_index_error"] = f"{type(exc).__name__}: {exc}"
    return ordered


def verify_chain():
    """Walk the ledger and report its integrity HONESTLY.

    Returns:
      {"ok": bool, "count": int, "break": None | {...}, "head": str|None,
       "path": str}

    `break` (when present) names the FIRST index that fails and why:
      {"index": i, "reason": "...", "expected": ..., "found": ...}
    Indices are 0-based line numbers in the ledger.

    This function only reads. It never writes, moves, truncates or re-chains
    anything, on any code path — a break is a finding, not a task.
    """
    path = chain_path()
    result = {"ok": True, "count": 0, "break": None, "head": None,
              "path": str(path)}
    lines = read_lines()
    result["count"] = len(lines)

    def broken(i, reason, expected=None, found=None):
        result["ok"] = False
        result["break"] = {"index": i, "reason": reason,
                           "expected": expected, "found": found}
        return result

    prev = GENESIS
    head = None
    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except (ValueError, json.JSONDecodeError) as exc:
            return broken(i, f"line is not valid JSON: {exc}")
        if not isinstance(entry, dict):
            return broken(i, "line is not a JSON object")
        missing = [f for f in FIELDS if f not in entry]
        if missing:
            return broken(i, "entry is missing required field(s): "
                             + ", ".join(missing))
        extra = [k for k in entry if k not in FIELDS]
        if extra:
            return broken(i, "entry carries unknown field(s): " + ", ".join(sorted(extra)))
        if entry["status"] not in STATUSES:
            return broken(i, "status is not one of "
                             + "|".join(STATUSES), "|".join(STATUSES), entry["status"])
        if entry["prev_hash"] != prev:
            return broken(i, "prev_hash does not match the previous entry_hash "
                             "(the chain is cut here)", prev, entry["prev_hash"])
        recomputed = compute_hash(entry)
        if recomputed != entry["entry_hash"]:
            return broken(i, "entry_hash does not match the entry's contents "
                             "(this entry was modified after it was written)",
                          entry["entry_hash"], recomputed)
        prev = entry["entry_hash"]
        head = prev
    result["head"] = head
    return result


def rebuild_index():
    """Rebuild the DERIVED sqlite index from the JSONL alone.

    Refuses on a broken chain and returns the verification result instead: an
    index silently built over a corrupted ledger would launder the corruption
    into the UI. This rebuilds the INDEX only; it never touches the ledger.
    """
    verdict = verify_chain()
    if not verdict["ok"]:
        return {"rebuilt": False, "indexed": 0, "verification": verdict}
    import store
    entries = read_entries()
    store.rebuild_audit_index(entries)
    return {"rebuilt": True, "indexed": len(entries), "verification": verdict}


def _cli():
    """`python3 console/audit.py` — print the verification verdict, exit 1 on a
    break. Read-only, like everything else here."""
    verdict = verify_chain()
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    sys.exit(_cli())
