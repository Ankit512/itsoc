#!/usr/bin/env python3
"""
test_audit_drift.py — Audit ledger routes & cross-engine DRIFT-GUARD (Stage C, C4-T2b).

    python3 tests/test_audit_drift.py
    python3 tests/test_audit_drift.py --generate   # regenerate fixture from audit.py authority

Proven here:
  (a) GET /api/audit returns 200 with {entries: [...], verification: {...}}
      against a clean chain, tampered chain, and empty ledger.
  (b) GET /api/audit/verify returns 200 with the live audit.verify_chain() verdict.
  (c) soc.audit_chain() and soc.audit_verify() delegate cleanly without server judgement.
  (d) DRIFT-GUARD: asserts that the committed test fixture (tests/fixtures/audit_drift_corpus.json)
      matches console/audit.py authority byte-for-byte. When audit.py changes, this test
      and the TypeScript test reading the fixture fail loudly unless the TS port and fixture
      are updated.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "console"))

import audit  # noqa: E402
import soc    # noqa: E402

FIXTURE_PATH = ROOT / "tests" / "fixtures" / "audit_drift_corpus.json"


def _build_corpus_from_audit_py():
    """Build canonical test corpus and verification outcomes using console/audit.py authority."""
    # 1. Single entry test vectors across all 4 statuses and various optional field shapes
    vector_definitions = [
        {
            "ts": "2026-08-29T12:00:00Z",
            "actor": "analyst",
            "incident_id": "inc-4a7f",
            "runbook_id": "rb-block-ip",
            "step": "approve",
            "eligibility_proof": {"eligible": True, "technique": "T1110"},
            "evidence_refs": ["rec-101", "rec-102"],
            "request_redacted": "nft add element inet itsoc blacklist { [IP-1] comment \"itsoc:appr-4a7f\" }",
            "response_verbatim": None,
            "status": "approved",
            "prev_hash": audit.GENESIS,
        },
        {
            "ts": "2026-08-29T12:05:00Z",
            "actor": "analyst",
            "incident_id": "inc-4a7f",
            "runbook_id": "rb-block-ip",
            "step": "execute",
            "eligibility_proof": None,
            "evidence_refs": ["rec-101"],
            "request_redacted": "nft add element inet itsoc blacklist { [IP-1] comment \"itsoc:appr-4a7f\" }",
            "response_verbatim": "element added to inet itsoc blacklist",
            "status": "executed",
            "prev_hash": "3a5ce218f8aa99af25856af38965e5a1911b79192387a00596222b6880a280c6",
        },
        {
            "ts": "2026-08-29T12:10:00Z",
            "actor": "analyst",
            "incident_id": "inc-4a7f",
            "runbook_id": "rb-isolate-host",
            "step": "reject",
            "eligibility_proof": None,
            "evidence_refs": [],
            "request_redacted": None,
            "response_verbatim": None,
            "status": "rejected",
            "prev_hash": "d1d89bc76c6c6b96a572a8a31109f59cc17d487bcf5911b4aadb4851a015897d",
        },
        {
            "ts": "2026-08-29T12:15:00Z",
            "actor": "analyst",
            "incident_id": "inc-4a7f",
            "runbook_id": "rb-block-ip",
            "step": "execute",
            "eligibility_proof": None,
            "evidence_refs": [],
            "request_redacted": "nft add element inet itsoc blacklist { [IP-1] }",
            "response_verbatim": "ssh: connection refused",
            "status": "failed",
            "prev_hash": "c3f17f3c85ba4fc1d1851f7e31cec938627cbac84006fd3378ce3a1eab161fc9",
        },
    ]

    single_vectors = []
    for raw in vector_definitions:
        canonical = audit.canonical_json({k: raw[k] for k in audit.HASHED_FIELDS})
        h = audit.compute_hash(raw)
        single_vectors.append({
            "raw": raw,
            "canonical_json": canonical,
            "entry_hash": h,
            "entry": {**raw, "entry_hash": h},
        })

    # 2. Build full chain scenarios and run audit.verify_chain() on each
    with tempfile.TemporaryDirectory() as tmp_dir:
        orig_soc = audit.SOC_DIR
        orig_audit = audit.AUDIT_DIR
        audit.SOC_DIR = Path(tmp_dir)
        audit.AUDIT_DIR = Path(tmp_dir) / "audit"
        audit.AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            # Scenario A: Clean 3-entry chain with fixed timestamps for deterministic zero-churn fixtures
            e0 = audit.append(actor="analyst", incident_id="inc-4a7f", runbook_id="rb-block-ip",
                              step="approve", status="approved", ts="2026-08-29T12:00:00Z", index=False)
            e1 = audit.append(actor="analyst", incident_id="inc-4a7f", runbook_id="rb-block-ip",
                              step="execute", status="executed",
                              request_redacted="nft add element inet itsoc blacklist { [IP-1] }",
                              response_verbatim="element added", ts="2026-08-29T12:05:00Z", index=False)
            e2 = audit.append(actor="analyst", incident_id="inc-4a7f", runbook_id="rb-isolate-host",
                              step="reject", status="rejected", ts="2026-08-29T12:10:00Z", index=False)
            clean_entries = [e0, e1, e2]
            v_clean = audit.verify_chain()

            # Scenario B: Tampered middle entry
            path = audit.chain_path()
            lines = path.read_text().strip().split("\n")
            e1_tampered = json.loads(lines[1])
            e1_tampered["request_redacted"] = "nft add element inet itsoc blacklist { 198.51.100.99 }"
            lines[1] = json.dumps(e1_tampered)
            path.write_text("\n".join(lines) + "\n")
            tampered_entries = [e0, e1_tampered, e2]
            v_tampered = audit.verify_chain()

            # Scenario C: Severed chain link (prev_hash modified on e2)
            lines = path.read_text().strip().split("\n")
            # Restore line 1, break line 2 prev_hash
            lines[1] = json.dumps(e1)
            e2_cut = json.loads(lines[2])
            e2_cut["prev_hash"] = "deadbeef" * 8
            lines[2] = json.dumps(e2_cut)
            path.write_text("\n".join(lines) + "\n")
            severed_entries = [e0, e1, e2_cut]
            v_severed = audit.verify_chain()

            # Scenario D: Empty ledger
            path.unlink()
            v_empty = audit.verify_chain()

            # Normalize volatile temp path to stable canonical relative path
            for v in (v_clean, v_tampered, v_severed, v_empty):
                v["path"] = "console/.soc/audit/chain.jsonl"
        finally:
            audit.SOC_DIR = orig_soc
            audit.AUDIT_DIR = orig_audit

    return {
        "genesis": audit.GENESIS,
        "fields": list(audit.FIELDS),
        "hashed_fields": list(audit.HASHED_FIELDS),
        "statuses": list(audit.STATUSES),
        "single_vectors": single_vectors,
        "scenarios": {
            "clean": {
                "entries": clean_entries,
                "verification": v_clean,
            },
            "tampered_content": {
                "entries": tampered_entries,
                "verification": v_tampered,
            },
            "severed_link": {
                "entries": severed_entries,
                "verification": v_severed,
            },
            "empty": {
                "entries": [],
                "verification": v_empty,
            },
        },
    }


def write_fixture_file():
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    corpus = _build_corpus_from_audit_py()
    FIXTURE_PATH.write_text(json.dumps(corpus, indent=2, sort_keys=True) + "\n")
    print(f"Wrote audit drift corpus fixture to {FIXTURE_PATH}")


class TestAuditRoutesAndDriftGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.soc_dir = Path(self.tmp.name)
        self.audit_dir = self.soc_dir / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.orig_soc = audit.SOC_DIR
        self.orig_audit = audit.AUDIT_DIR
        audit.SOC_DIR = self.soc_dir
        audit.AUDIT_DIR = self.audit_dir

    def tearDown(self):
        audit.SOC_DIR = self.orig_soc
        audit.AUDIT_DIR = self.orig_audit
        self.tmp.cleanup()

    def test_audit_routes_empty_ledger(self):
        """On a missing/empty ledger, audit_chain and audit_verify return honest empty state."""
        status, chain_resp = soc.audit_chain()
        self.assertEqual(status, 200)
        self.assertEqual(chain_resp["entries"], [])
        self.assertTrue(chain_resp["verification"]["ok"])
        self.assertEqual(chain_resp["verification"]["count"], 0)
        self.assertIsNone(chain_resp["verification"]["break"])
        self.assertIsNone(chain_resp["verification"]["head"])

        status_v, verify_resp = soc.audit_verify()
        self.assertEqual(status_v, 200)
        self.assertTrue(verify_resp["ok"])
        self.assertEqual(verify_resp["count"], 0)

    def test_audit_routes_intact_chain(self):
        """On a real intact chain, audit_chain returns entries and valid verification."""
        audit.append(actor="analyst", incident_id="inc-4a7f", runbook_id="rb-block-ip",
                     step="approve", status="approved", index=False)
        audit.append(actor="analyst", incident_id="inc-4a7f", runbook_id="rb-block-ip",
                     step="execute", status="executed",
                     request_redacted="nft add element inet itsoc blacklist { [IP-1] }",
                     response_verbatim="element added", index=False)

        status, chain_resp = soc.audit_chain()
        self.assertEqual(status, 200)
        self.assertEqual(len(chain_resp["entries"]), 2)
        self.assertTrue(chain_resp["verification"]["ok"])
        self.assertEqual(chain_resp["verification"]["count"], 2)
        self.assertIsNotNone(chain_resp["verification"]["head"])

        status_v, verify_resp = soc.audit_verify()
        self.assertEqual(status_v, 200)
        self.assertTrue(verify_resp["ok"])
        self.assertEqual(verify_resp["count"], 2)

    def test_audit_routes_tampered_chain(self):
        """On a tampered chain, audit_chain reports the break and returns readable entries."""
        audit.append(actor="analyst", incident_id="inc-4a7f", runbook_id="rb-block-ip",
                     step="approve", status="approved", index=False)
        audit.append(actor="analyst", incident_id="inc-4a7f", runbook_id="rb-block-ip",
                     step="execute", status="executed",
                     request_redacted="nft add element inet itsoc blacklist { [IP-1] }", index=False)

        # Tamper entry 0
        path = audit.chain_path()
        lines = path.read_text().strip().split("\n")
        e0 = json.loads(lines[0])
        e0["actor"] = "attacker"  # TAMPER!
        lines[0] = json.dumps(e0)
        path.write_text("\n".join(lines) + "\n")

        status, chain_resp = soc.audit_chain()
        self.assertEqual(status, 200)
        self.assertFalse(chain_resp["verification"]["ok"])
        self.assertEqual(chain_resp["verification"]["break"]["index"], 0)
        self.assertIn("entry_hash does not match", chain_resp["verification"]["break"]["reason"])

        status_v, verify_resp = soc.audit_verify()
        self.assertEqual(status_v, 200)
        self.assertFalse(verify_resp["ok"])
        self.assertEqual(verify_resp["break"]["index"], 0)

    def test_drift_guard_fixture_matches_audit_py(self):
        """DRIFT-GUARD: asserts that committed fixture matches console/audit.py byte-for-byte."""
        self.assertTrue(FIXTURE_PATH.exists(), f"Missing fixture file: {FIXTURE_PATH}")
        committed_corpus = json.loads(FIXTURE_PATH.read_text())
        fresh_corpus = _build_corpus_from_audit_py()

        self.assertEqual(
            committed_corpus["fields"], fresh_corpus["fields"],
            "FIELDS in audit.py diverged from committed fixture"
        )
        self.assertEqual(
            committed_corpus["hashed_fields"], fresh_corpus["hashed_fields"],
            "HASHED_FIELDS in audit.py diverged from committed fixture"
        )
        self.assertEqual(
            committed_corpus["statuses"], fresh_corpus["statuses"],
            "STATUSES in audit.py diverged from committed fixture"
        )

        for i, (comm_vec, fresh_vec) in enumerate(zip(committed_corpus["single_vectors"],
                                                      fresh_corpus["single_vectors"])):
            self.assertEqual(comm_vec["canonical_json"], fresh_vec["canonical_json"],
                             f"Canonical JSON vector {i} diverged from audit.py")
            self.assertEqual(comm_vec["entry_hash"], fresh_vec["entry_hash"],
                             f"SHA256 vector {i} diverged from audit.py")

        for s_name, fresh_scen in fresh_corpus["scenarios"].items():
            comm_scen = committed_corpus["scenarios"][s_name]
            self.assertEqual(comm_scen["verification"]["ok"], fresh_scen["verification"]["ok"],
                             f"Scenario '{s_name}' ok flag diverged from audit.py")
            if fresh_scen["verification"]["break"]:
                self.assertEqual(comm_scen["verification"]["break"]["index"],
                                 fresh_scen["verification"]["break"]["index"],
                                 f"Scenario '{s_name}' break index diverged")
                self.assertEqual(comm_scen["verification"]["break"]["reason"],
                                 fresh_scen["verification"]["break"]["reason"],
                                 f"Scenario '{s_name}' break reason diverged")


if __name__ == "__main__":
    if "--generate" in sys.argv:
        write_fixture_file()
    else:
        unittest.main()
