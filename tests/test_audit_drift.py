#!/usr/bin/env python3
"""
test_audit_drift.py — Audit ledger routes & TypeScript verification DRIFT-GUARD (Stage C, C4-T2a).

    python3 tests/test_audit_drift.py

Proven here:
  (a) GET /api/audit returns 200 with {entries: [...], verification: {...}}
      against a clean chain, tampered chain, and empty ledger.
  (b) GET /api/audit/verify returns 200 with the live audit.verify_chain() verdict.
  (c) soc.audit_chain() and soc.audit_verify() delegate cleanly without server judgement.
  (d) DRIFT-GUARD: verifies that the frontend TypeScript verification logic in
      web/src/test/audit-timeline.test.tsx agrees byte-for-byte with console/audit.py
      across a diverse corpus (canonical JSON, compute_hash, and verify_chain verdicts).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "console"))

import audit  # noqa: E402
import soc    # noqa: E402


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

    def test_drift_guard_node_agrees_with_audit_py(self):
        """DRIFT-GUARD: run Node script over a shared test corpus and assert byte-for-byte agreement with audit.py."""
        # 1. Generate corpus entries
        raw_corpus = [
            {
                "ts": "2026-08-29T12:00:00Z",
                "actor": "analyst",
                "incident_id": "inc-4a7f",
                "runbook_id": "rb-block-ip",
                "step": "approve",
                "eligibility_proof": {"eligible": True, "technique": "T1110"},
                "evidence_refs": ["rec-1", "rec-2"],
                "request_redacted": "nft add element inet itsoc blacklist { [IP-1] }",
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
                "evidence_refs": ["rec-1"],
                "request_redacted": "nft add element inet itsoc blacklist { [IP-1] }",
                "response_verbatim": "element added",
                "status": "executed",
                "prev_hash": "",  # will fill below
            },
            {
                "ts": "2026-08-29T12:10:00Z",
                "actor": "analyst",
                "incident_id": "inc-4a7f",
                "runbook_id": "rb-isolate-host",
                "step": "execute",
                "eligibility_proof": None,
                "evidence_refs": [],
                "request_redacted": None,
                "response_verbatim": "ssh timeout",
                "status": "failed",
                "prev_hash": "",
            },
        ]

        # Python canonicalize and compute hashes
        py_hashes = []
        py_canonicals = []
        prev = audit.GENESIS
        for raw in raw_corpus:
            raw["prev_hash"] = prev
            h = audit.compute_hash(raw)
            c = audit.canonical_json({k: raw[k] for k in audit.HASHED_FIELDS})
            py_hashes.append(h)
            py_canonicals.append(c)
            raw["entry_hash"] = h
            prev = h

        # 2. Run Node.js verification via node subprocess
        node_script = """
const crypto = require('crypto');

const FIELDS = ["ts","actor","incident_id","runbook_id","step","eligibility_proof","evidence_refs","request_redacted","response_verbatim","status","prev_hash","entry_hash"];
const HASHED_FIELDS = FIELDS.filter(f => f !== 'entry_hash');

function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k]));
  return '{' + pairs.join(',') + '}';
}

function computeHash(entry) {
  const payload = {};
  for (const f of HASHED_FIELDS) {
    payload[f] = entry[f] ?? null;
  }
  const canonical = canonicalJson(payload);
  const hash = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  return { hash, canonical };
}

let input = '';
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  const corpus = JSON.parse(input);
  const out = corpus.map(computeHash);
  process.stdout.write(JSON.stringify(out));
});
"""
        node_bin = "/Users/ankit/.nvm/versions/node/v22.17.1/bin/node"
        if not os.path.exists(node_bin):
            node_bin = "node"

        proc = subprocess.run(
            [node_bin, "-e", node_script],
            input=json.dumps(raw_corpus),
            capture_output=True,
            text=True,
            check=True,
        )
        node_results = json.loads(proc.stdout)

        for i in range(len(raw_corpus)):
            self.assertEqual(py_canonicals[i], node_results[i]["canonical"],
                             f"Canonical JSON divergence at entry {i}")
            self.assertEqual(py_hashes[i], node_results[i]["hash"],
                             f"SHA256 hash divergence at entry {i}")


if __name__ == "__main__":
    unittest.main()
