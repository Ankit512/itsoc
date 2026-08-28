#!/usr/bin/env python3
"""
test_approvals.py — the gated-response approvals flow with per-action step-up
authentication (Stage C, C3-T2 / decision D3).

    python3 tests/test_approvals.py

Each of the six card invariants is proven by a RUN here, not asserted in prose:

  (a) step-up verification creates ZERO sessions, never leaks the passphrase, and
      exposes only the verified username (for the audit actor);
  (b) the state machine is pending -> approved -> executed | failed, and
      pending -> rejected;
  (c) POST creates a pending record; approve/reject require a successful step-up;
      the connector is invoked ONLY inside approve, ONLY after that verification;
  (d) an ineligible runbook returns 409 with `missing` copied VERBATIM from
      runbooks.eligible() — the API cannot disagree with the engine;
  (e) the approve handler RE-RUNS eligibility immediately before firing, so an
      approval cannot execute against evidence that no longer holds;
  (f) every approve/reject/execute appends to the hash-chained ledger and
      verify_chain() passes on a clean run.

The step-up passphrase is GENERATED AT RUNTIME (secrets) and never written to
the repo, a fixture, a log line, or a CLI argument.
"""

import json
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "console"))

import soc          # noqa: E402
import audit        # noqa: E402
import auth         # noqa: E402
import store        # noqa: E402
import runbooks     # noqa: E402
from actions.base import BaseConnector  # noqa: E402

FROZEN_DETECTOR_SHA = "364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876"


class SpyConnector(BaseConnector):
    """A connector that records every call so a test can prove the connector is
    reached ONLY through a verified approve, and never fabricates output."""
    executes = []
    previews = []
    result = {"ok": True, "connector": "firewall", "action": "block_ip",
              "output": "1 element added to set", "error": None}

    def preview(self, params, context=None):
        SpyConnector.previews.append((dict(params), dict(context or {})))
        return {"connector": "firewall", "action": "block_ip",
                "command": "nft add element ... [IP-1] ...", "description": "block",
                "params": {}, "redacted": True}

    def execute(self, params, context=None):
        SpyConnector.executes.append((dict(params), dict(context or {})))
        return dict(SpyConnector.result)

    def revoke(self, params, context=None):
        return {"ok": True, "connector": "firewall", "action": "unblock_ip",
                "output": "", "error": None}


def _eligible_state():
    """A run state whose single incident is genuinely eligible for rb-block-ip:
    ip entity, a brute-force verdict, a real host, occurrences, record refs, and
    both timestamps — every requirement met from rule output alone."""
    return {"runId": "r1", "findings": [{
        "id": "detector-0", "type": "auth_bruteforce_success", "sev": "CRITICAL",
        "stamp": "2026-08-13T02:16:52+00:00", "host": "server-01", "hostDerived": True,
        "occurrences": 7, "chips": [{"text": "203.0.113.44"}],
        "lines": [{"n": 5}, {"n": 11}],
        "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
        "timeline": [{"t": "02:16:44", "label": "first", "line": 5,
                      "ts": "2026-08-13T02:16:44+00:00"}],
    }]}


class ApprovalsTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="c3-approvals-")
        tmp = Path(self._tmpdir.name)
        soc_dir = tmp / ".soc"
        soc_dir.mkdir(parents=True, exist_ok=True)
        # Repoint every module's storage at the temp dir; restore in tearDown.
        self._real = (soc.SOC_DIR, audit.SOC_DIR, audit.AUDIT_DIR,
                      store.SOC_DIR, store.DB_PATH)
        soc.SOC_DIR = soc_dir
        audit.SOC_DIR = soc_dir
        audit.AUDIT_DIR = soc_dir / "audit"
        store.SOC_DIR = soc_dir
        store.DB_PATH = soc_dir / "soc_history.db"

        # A fresh local profile with a RUNTIME-ONLY passphrase (never committed).
        self.provider = auth.LocalDemoAuth(soc_dir=soc_dir)
        self.passphrase = "stepup-" + secrets.token_hex(8)
        self.provider.signup("analyst", self.passphrase)

        # One eligible incident derived from real rule output.
        self.state = _eligible_state()
        soc.sync_incidents(self.state)
        self.incident = next(iter(soc._load("incidents.json").values()))

        SpyConnector.executes = []
        SpyConnector.previews = []
        SpyConnector.result = {"ok": True, "connector": "firewall", "action": "block_ip",
                               "output": "1 element added to set", "error": None}

    def tearDown(self):
        (soc.SOC_DIR, audit.SOC_DIR, audit.AUDIT_DIR,
         store.SOC_DIR, store.DB_PATH) = self._real
        self._tmpdir.cleanup()

    def _spy_factory(self):
        return lambda name: SpyConnector(name=name)

    def _create(self, runbook_id="rb-block-ip"):
        return soc.create_approval(
            {"incidentId": self.incident["id"], "runbookId": runbook_id}, self.state)

    # ---- (a) step-up: zero session, no leak, username only -------------------
    def test_a_stepup_zero_session_no_leak_username_only(self):
        before = dict(self.provider._sessions)
        ok, username = self.provider.verify_stepup_passphrase(self.passphrase)
        self.assertTrue(ok)
        self.assertEqual(username, "analyst")
        # ZERO session creation — the session dict is byte-for-byte unchanged.
        self.assertEqual(self.provider._sessions, before)
        # Only (bool, username) comes back — the passphrase never does.
        self.assertNotIn(self.passphrase, (username or ""))
        bad_ok, bad_user = self.provider.verify_stepup_passphrase("not-the-passphrase")
        self.assertFalse(bad_ok)
        self.assertIsNone(bad_user)
        # Still no session after a failed attempt.
        self.assertEqual(self.provider._sessions, before)

    # ---- (b)/(c) create pending, approve requires step-up, connector gated ---
    def test_c_create_pending_then_stepup_gated_execute(self):
        st, rec = self._create()
        self.assertEqual(st, 201)
        self.assertEqual(rec["state"], "pending")
        self.assertIsNone(rec["actor"])
        self.assertEqual(soc.get_approval(rec["id"])["state"], "pending")

        # Wrong passphrase: refused, connector NEVER invoked, still pending.
        st, body = soc.approve_approval(rec["id"], "wrong-pass", self.state,
                                        connector_factory=self._spy_factory(),
                                        provider=self.provider)
        self.assertEqual(st, 401)
        self.assertEqual(len(SpyConnector.executes), 0)
        self.assertEqual(soc.get_approval(rec["id"])["state"], "pending")

        # Correct passphrase: connector fires exactly once, state -> executed.
        st, rec2 = soc.approve_approval(rec["id"], self.passphrase, self.state,
                                        connector_factory=self._spy_factory(),
                                        provider=self.provider)
        self.assertEqual(st, 200)
        self.assertEqual(rec2["state"], "executed")
        self.assertEqual(rec2["actor"], "analyst")
        self.assertEqual(len(SpyConnector.executes), 1)
        # Unredacted params travel to the connector transport (correct), but the
        # STORED command is redacted (asserted in the redaction test below).
        exec_params, _ctx = SpyConnector.executes[0]
        self.assertEqual(exec_params.get("address"), "203.0.113.44")

    # ---- (b) state machine: reject path --------------------------------------
    def test_b_reject_requires_stepup(self):
        _st, rec = self._create()
        # Wrong passphrase cannot reject either.
        st, _ = soc.reject_approval(rec["id"], "nope", provider=self.provider)
        self.assertEqual(st, 401)
        self.assertEqual(soc.get_approval(rec["id"])["state"], "pending")
        st, rec2 = soc.reject_approval(rec["id"], self.passphrase, provider=self.provider)
        self.assertEqual(st, 200)
        self.assertEqual(rec2["state"], "rejected")
        self.assertEqual(rec2["actor"], "analyst")
        # A rejected record cannot then be approved.
        st, _ = soc.approve_approval(rec["id"], self.passphrase, self.state,
                                     connector_factory=self._spy_factory(),
                                     provider=self.provider)
        self.assertEqual(st, 409)
        self.assertEqual(len(SpyConnector.executes), 0)

    # ---- (d) 409 body is the engine's `missing`, verbatim --------------------
    def test_d_ineligible_returns_409_from_engine_verbatim(self):
        # An incident whose rule does not match the runbook's trigger.
        soc._save("incidents.json", {})
        bad_state = _eligible_state()
        bad_state["findings"][0]["type"] = "disk_full"     # not a block-ip trigger
        soc.sync_incidents(bad_state)
        bad_inc = next(iter(soc._load("incidents.json").values()))

        st, body = soc.create_approval(
            {"incidentId": bad_inc["id"], "runbookId": "rb-block-ip"}, bad_state)
        self.assertEqual(st, 409)
        rb = runbooks.load_runbooks()["rb-block-ip"]
        members = soc._incident_members(bad_inc, bad_state)
        engine = runbooks.eligible(rb, bad_inc, members)
        # Structurally incapable of disagreeing: identical list, not a reword.
        self.assertFalse(engine["eligible"])
        self.assertEqual(body["missing"], engine["missing"])
        # No approval record was created for an ineligible runbook.
        self.assertEqual(soc.list_approvals(), [])

    # ---- (e) re-evaluation refuses stale evidence ----------------------------
    def test_e_reevaluation_refuses_stale_evidence(self):
        st, rec = self._create()
        self.assertEqual(st, 201)
        # Between create and approve the incident's evidence disappears from the
        # run (a re-analysis dropped it). Approve must NOT execute on stale facts.
        stale_state = {"runId": "r1", "findings": []}
        st, body = soc.approve_approval(rec["id"], self.passphrase, stale_state,
                                        connector_factory=self._spy_factory(),
                                        provider=self.provider)
        self.assertEqual(st, 409)
        self.assertIn("missing", body)
        self.assertEqual(len(SpyConnector.executes), 0)     # connector never fired
        failed = soc.get_approval(rec["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertIsNone(failed["responseVerbatim"])       # never fake-contains
        self.assertIn("re-evaluation", failed["failureReason"])

    # ---- (f) audit entry per act + verify_chain passes -----------------------
    def test_f_audit_per_action_and_chain_verifies(self):
        _st, rec = self._create()
        soc.approve_approval(rec["id"], self.passphrase, self.state,
                             connector_factory=self._spy_factory(),
                             provider=self.provider)
        # A second approval, this one rejected, to exercise all consequential acts.
        _st, rec2 = self._create()
        soc.reject_approval(rec2["id"], self.passphrase, provider=self.provider)

        entries = audit.read_entries()
        statuses = [e["status"] for e in entries]
        self.assertEqual(statuses, ["approved", "executed", "rejected"])
        # Every entry's actor is the verified username — nothing else about the
        # credential is recorded.
        self.assertTrue(all(e["actor"] == "analyst" for e in entries))
        v = audit.verify_chain()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["count"], 3)

    # ---- redaction seam: the stored/audited command is redacted --------------
    def test_stored_and_audited_command_is_redacted(self):
        _st, rec = self._create()
        # The real ssh_firewall preview ran at create time: the raw IP must NOT
        # be in the stored record.
        self.assertNotIn("203.0.113.44", str(rec["requestRedacted"]))
        self.assertIn("[IP-1]", str(rec["requestRedacted"]))
        soc.approve_approval(rec["id"], self.passphrase, self.state,
                             connector_factory=self._spy_factory(),
                             provider=self.provider)
        for e in audit.read_entries():
            self.assertNotIn("203.0.113.44", str(e["request_redacted"]))

    # ---- connector failure is recorded honestly, never fake-contained --------
    def test_connector_failure_records_reason(self):
        _st, rec = self._create()
        SpyConnector.result = {"ok": False, "connector": "firewall", "action": "block_ip",
                               "output": "", "error": "ssh: connect to host timed out"}
        st, rec2 = soc.approve_approval(rec["id"], self.passphrase, self.state,
                                        connector_factory=self._spy_factory(),
                                        provider=self.provider)
        self.assertEqual(st, 200)
        self.assertEqual(rec2["state"], "failed")
        self.assertIn("timed out", rec2["failureReason"])
        # The real error is recorded; nothing is dressed up as success.
        self.assertEqual(rec2["responseVerbatim"]["error"], "ssh: connect to host timed out")
        # The failed execution is still audited honestly (approved, then failed).
        self.assertEqual([e["status"] for e in audit.read_entries()],
                         ["approved", "failed"])
        self.assertTrue(audit.verify_chain()["ok"])

    # ---- the passphrase never lands in any stored or logged surface ----------
    def test_passphrase_never_persisted(self):
        _st, rec = self._create()
        soc.approve_approval(rec["id"], self.passphrase, self.state,
                             connector_factory=self._spy_factory(),
                             provider=self.provider)
        # Not in the approvals store, not in the audit ledger bytes.
        approvals_blob = (soc.SOC_DIR / soc.APPROVALS_FILE).read_text()
        chain_path = audit.chain_path()
        chain_blob = chain_path.read_text() if chain_path.exists() else ""
        self.assertNotIn(self.passphrase, approvals_blob)
        self.assertNotIn(self.passphrase, chain_blob)

    # ---- the detector stays frozen -------------------------------------------
    def test_detector_frozen(self):
        import hashlib
        detector = ROOT / "anomaly_detector.py"
        sha = hashlib.sha256(detector.read_bytes()).hexdigest()
        self.assertEqual(sha, FROZEN_DETECTOR_SHA)


class ApprovalsHttpTests(unittest.TestCase):
    """The thin serve.py delegation, demonstrated over a real in-process server.

    Proves the three binding constraints on the route wiring:
      * the endpoints are REACHABLE and delegate to soc (create -> approve flow);
      * the step-up passphrase travels in the POST BODY and appears in nothing
        log-shaped, and is never echoed back — not even in an error body;
      * the routes sit INSIDE the existing bearer gate: with AUTH_REQUIRED on, an
        unauthenticated caller cannot reach the approve handler at all.
    """

    def setUp(self):
        import http.server
        import threading
        import actions

        self._tmpdir = tempfile.TemporaryDirectory(prefix="c3-approvals-http-")
        tmp = Path(self._tmpdir.name)
        soc_dir = tmp / ".soc"
        soc_dir.mkdir(parents=True, exist_ok=True)
        self._real = (soc.SOC_DIR, audit.SOC_DIR, audit.AUDIT_DIR,
                      store.SOC_DIR, store.DB_PATH)
        soc.SOC_DIR = soc_dir
        audit.SOC_DIR = soc_dir
        audit.AUDIT_DIR = soc_dir / "audit"
        store.SOC_DIR = soc_dir
        store.DB_PATH = soc_dir / "soc_history.db"

        self.provider = auth.LocalDemoAuth(soc_dir=soc_dir)
        self.passphrase = "stepup-" + secrets.token_hex(8)
        self.provider.signup("analyst", self.passphrase)
        self._real_provider = auth.AUTH_PROVIDER
        auth.AUTH_PROVIDER = self.provider          # the gate + soc use this singleton

        self.state = _eligible_state()
        soc.sync_incidents(self.state)
        self.incident = next(iter(soc._load("incidents.json").values()))

        # Register a spy under the runbook's connector name so approve does not
        # attempt a real SSH connection.
        SpyConnector.executes = []
        SpyConnector.result = {"ok": True, "connector": "firewall", "action": "block_ip",
                               "output": "1 element added to set", "error": None}
        self._real_firewall = actions.base._REGISTRY.get("firewall")
        actions.register_connector("firewall", SpyConnector)

        import serve
        self.serve = serve
        self._real_state = serve.STATE
        self._real_auth_req = serve.AUTH_REQUIRED
        serve.STATE = self.state
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), serve.ConsoleHandler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        import actions
        self.srv.shutdown()
        self.srv.server_close()
        self.serve.STATE = self._real_state
        self.serve.AUTH_REQUIRED = self._real_auth_req
        auth.AUTH_PROVIDER = self._real_provider
        if self._real_firewall is not None:
            actions.register_connector("firewall", self._real_firewall)
        (soc.SOC_DIR, audit.SOC_DIR, audit.AUDIT_DIR,
         store.SOC_DIR, store.DB_PATH) = self._real
        self._tmpdir.cleanup()

    def _post(self, path, obj):
        import urllib.request
        import urllib.error
        data = json.dumps(obj).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def _get(self, path):
        import urllib.request
        import urllib.error
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_http_create_then_approve_reachable_and_delegates(self):
        st, body = self._post("/api/approvals",
                              {"incidentId": self.incident["id"], "runbookId": "rb-block-ip"})
        self.assertEqual(st, 201)
        self.assertEqual(body["state"], "pending")
        aid = body["id"]
        self.assertEqual(self._get(f"/api/approvals/{aid}")[1]["state"], "pending")

        st, body = self._post(f"/api/approvals/{aid}/approve", {"passphrase": self.passphrase})
        self.assertEqual(st, 200)
        self.assertEqual(body["state"], "executed")
        self.assertEqual(body["actor"], "analyst")
        self.assertEqual(len(SpyConnector.executes), 1)

    def test_http_ineligible_returns_409_over_the_wire(self):
        soc._save("incidents.json", {})
        bad = _eligible_state()
        bad["findings"][0]["type"] = "disk_full"
        soc.sync_incidents(bad)
        self.serve.STATE = bad
        bad_inc = next(iter(soc._load("incidents.json").values()))
        st, body = self._post("/api/approvals",
                              {"incidentId": bad_inc["id"], "runbookId": "rb-block-ip"})
        self.assertEqual(st, 409)
        self.assertIn("missing", body)

    def test_http_passphrase_in_body_never_in_url_or_log_or_response(self):
        import contextlib
        import io
        st, body = self._post("/api/approvals",
                              {"incidentId": self.incident["id"], "runbookId": "rb-block-ip"})
        aid = body["id"]

        # Capture the server's request log while a WRONG passphrase is submitted.
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            st, body = self._post(f"/api/approvals/{aid}/approve",
                                  {"passphrase": "definitely-the-wrong-secret-123"})
        # Refused, and the wrong passphrase is NOT echoed back in the error body.
        self.assertEqual(st, 401)
        self.assertNotIn("definitely-the-wrong-secret-123", json.dumps(body))
        # http.server logs the request LINE (method + path); the passphrase is in
        # the body, so it is absent from anything log-shaped and from the URL.
        self.assertNotIn("definitely-the-wrong-secret-123", log.getvalue())
        self.assertNotIn("passphrase", log.getvalue())

        # A correct approval likewise never echoes the passphrase in its response.
        st, body = self._post(f"/api/approvals/{aid}/approve", {"passphrase": self.passphrase})
        self.assertEqual(st, 200)
        self.assertNotIn(self.passphrase, json.dumps(body))

    def test_http_step_up_is_additive_to_the_bearer_gate(self):
        # Turn the existing API gate ON. An unauthenticated caller must be stopped
        # BEFORE the approve handler — the connector must never be reached.
        self.serve.AUTH_REQUIRED = True
        st, body = self._post("/api/approvals",
                              {"incidentId": self.incident["id"], "runbookId": "rb-block-ip"})
        self.assertEqual(st, 401)
        self.assertEqual(body.get("error"), "unauthenticated")
        # And the approve route is gated too — no step-up even gets a chance.
        st, body = self._post("/api/approvals/appr-whatever/approve",
                              {"passphrase": self.passphrase})
        self.assertEqual(st, 401)
        self.assertEqual(len(SpyConnector.executes), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
