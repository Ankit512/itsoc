#!/usr/bin/env python3
"""
test_recommend.py — the copilot runbook recommendation (Stage C, C3-T4).

    python3 tests/test_recommend.py

Build doc C3 item 4: the AI copilot may recommend among ELIGIBLE runbooks and
draft justifications; recommendation payloads are advisory-typed and carry no
executable handle. Each requirement is proven by a run:

  (a) the candidate set is exactly runbooks.eligible()'s answer, computed with no
      model input, and a model id that is not eligible is dropped — the copilot
      can never widen the gate;
  (b) the payload is advisory-typed and carries NO executable handle — asserted
      on the KEYS, so it stays true regardless of today's values;
  (c) the model's justifications sit under an advisory-labelled block;
  (d) D2 — the eligible list still returns when the model raises OR hangs, with
      the advisory portion honestly timed out; never fabricated, never dropped.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "console"))

import soc          # noqa: E402
import runbooks     # noqa: E402

FROZEN_DETECTOR_SHA = "364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876"

# Anything a caller could turn into an action. A recommendation must contain NONE
# of these keys, at any depth. `incidentId`/`runbookId` are references, not
# handles (they are the same open inputs POST /api/approvals already takes, and
# acting on them still requires eligibility + step-up), so they are allowed.
EXECUTABLE_HANDLE_KEYS = {
    "approvalId", "connector", "config", "command", "rollback_command",
    "params", "params_template", "token", "key_path", "passphrase", "transport",
    "rendered", "ssh", "host", "port", "user",
}


def _keys_at_any_depth(obj):
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(k)
            keys |= _keys_at_any_depth(v)
    elif isinstance(obj, list):
        for v in obj:
            keys |= _keys_at_any_depth(v)
    return keys


def _bf_state():
    """A brute-force IP incident: eligible for BOTH shipped runbooks."""
    return {"runId": "r1", "findings": [{
        "id": "detector-0", "type": "auth_bruteforce_success", "sev": "CRITICAL",
        "stamp": "2026-08-13T02:16:52+00:00", "host": "server-01", "hostDerived": True,
        "occurrences": 7, "chips": [{"text": "203.0.113.44"}],
        "lines": [{"n": 5}, {"n": 11}],
        "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
        "timeline": [{"t": "02:16:44", "label": "first", "line": 5,
                      "ts": "2026-08-13T02:16:52+00:00"}],
    }]}


def _host_state():
    """A HOST incident (no IP entity): rb-block-ip (ip-only) is NOT eligible, so
    it is the perfect probe for 'the model cannot add an ineligible runbook'."""
    return {"runId": "r2", "findings": [{
        "id": "detector-0", "type": "error_rate_spike", "sev": "HIGH",
        "stamp": "2026-08-13T02:17:10+00:00", "host": "server-03", "hostDerived": True,
        "occurrences": 12, "chips": [],
        "lines": [{"n": 7}, {"n": 8}],
        "mitre": [], "timeline": [{"t": "02:17:10", "label": "spike", "line": 7,
                                   "ts": "2026-08-13T02:17:10+00:00"}],
    }]}


class RecommendTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="c3-recommend-")
        self._real_soc = soc.SOC_DIR
        soc.SOC_DIR = Path(self._tmpdir.name) / ".soc"
        soc.SOC_DIR.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        soc.SOC_DIR = self._real_soc
        self._tmpdir.cleanup()

    def _incident(self, state):
        soc._save("incidents.json", {})
        soc.sync_incidents(state)
        return next(iter(soc._load("incidents.json").values()))

    # ---- (a) only eligible runbooks; the model cannot widen the set ----------
    def test_a_candidate_set_is_exactly_eligible_and_model_cannot_widen(self):
        state = self._bf = _bf_state()
        inc = self._incident(state)
        # The deterministic set equals runbooks.eligible()'s own answer, exactly.
        members = soc._incident_members(inc, state)
        engine_yes = sorted(rid for rid, rb in runbooks.load_runbooks().items()
                            if runbooks.eligible(rb, inc, members)["eligible"])
        got = sorted(e["runbookId"] for e in soc.eligible_runbooks(inc, state))
        self.assertEqual(got, engine_yes)
        self.assertEqual(got, ["rb-block-ip", "rb-draft-notify"])

        # A model that lists a HALLUCINATED id has it dropped.
        def widen(*a, **k):
            return json.dumps({"ranking": ["rb-block-ip", "rb-invented", "rb-draft-notify"],
                               "justifications": [{"runbookId": "rb-invented", "text": "x"}]})
        payload = soc.recommend_runbooks(inc, state, chat_fn=widen, timeout=5)
        self.assertEqual(payload["recommendation"]["ranking"], ["rb-block-ip", "rb-draft-notify"])
        self.assertEqual(payload["recommendation"]["justifications"], [])  # invented one dropped

    def test_a_model_cannot_add_a_real_but_ineligible_runbook(self):
        state = _host_state()
        inc = self._incident(state)
        eligible_ids = [e["runbookId"] for e in soc.eligible_runbooks(inc, state)]
        # For a host incident, rb-block-ip (ip-only) is NOT eligible.
        self.assertNotIn("rb-block-ip", eligible_ids)
        self.assertIn("rb-draft-notify", eligible_ids)

        # The model tries to recommend the ineligible rb-block-ip anyway.
        def push_ineligible(*a, **k):
            return json.dumps({"ranking": ["rb-block-ip", "rb-draft-notify"],
                               "justifications": [{"runbookId": "rb-block-ip", "text": "block it"}]})
        payload = soc.recommend_runbooks(inc, state, chat_fn=push_ineligible, timeout=5)
        # rb-block-ip is filtered out — rules own eligibility, not the model.
        self.assertEqual(payload["recommendation"]["ranking"], ["rb-draft-notify"])
        self.assertNotIn("rb-block-ip",
                         [j["runbookId"] for j in payload["recommendation"]["justifications"]])

    # ---- (b) advisory-typed, NO executable handle (asserted on keys) ---------
    def test_b_advisory_typed_no_executable_handle(self):
        state = _bf_state()
        inc = self._incident(state)

        def ok(*a, **k):
            return json.dumps({"ranking": ["rb-block-ip"],
                               "justifications": [{"runbookId": "rb-block-ip", "text": "Block the source IP."}]})
        payload = soc.recommend_runbooks(inc, state, chat_fn=ok, timeout=5)
        self.assertEqual(payload["type"], "runbook_recommendation")
        self.assertIs(payload["advisory"], True)
        # No executable handle anywhere in the payload — a KEY assertion, so it
        # holds no matter what the model returned.
        leaked = _keys_at_any_depth(payload) & EXECUTABLE_HANDLE_KEYS
        self.assertEqual(leaked, set(), f"executable handle leaked: {leaked}")
        # Each eligible entry references a runbook by id only — no step/connector.
        # triggerRules (C4-F1) is a list of rule-id references, the same class of
        # fact as runbookId — NOT an executable handle (asserted above).
        for e in payload["eligible"]:
            self.assertEqual(set(e.keys()),
                             {"runbookId", "name", "severityFloor", "eligibilityProof",
                              "triggerRules"})

    def test_b_recommendation_cannot_be_replayed_as_an_approval(self):
        # create_approval needs incidentId AND runbookId; the recommendation
        # carries incidentId + runbook ids but NOTHING that skips the gate, and
        # even those still hit eligibility + step-up. Prove no approval id / no
        # connector / no command is present to short-circuit anything.
        state = _bf_state()
        inc = self._incident(state)
        payload = soc.recommend_runbooks(inc, state, chat_fn=lambda *a, **k: "{}", timeout=5)
        blob = json.dumps(payload)
        for forbidden in ("approvalId", "\"connector\"", "\"command\"", "passphrase", "token"):
            self.assertNotIn(forbidden, blob)

    # ---- (c) justifications labelled advisory --------------------------------
    def test_c_justifications_labelled_advisory(self):
        state = _bf_state()
        inc = self._incident(state)

        def ok(*a, **k):
            return json.dumps({"ranking": ["rb-block-ip"],
                               "justifications": [{"runbookId": "rb-block-ip", "text": "Block the source IP."}]})
        rec = soc.recommend_runbooks(inc, state, chat_fn=ok, timeout=5)["recommendation"]
        self.assertIn("advisory", rec["label"].lower())
        self.assertEqual(rec["status"], "complete")
        self.assertEqual(rec["justifications"][0]["text"], "Block the source IP.")

    # ---- (d) D2: deterministic never waits on the model ----------------------
    def test_d_deterministic_survives_model_raise(self):
        state = _bf_state()
        inc = self._incident(state)

        def boom(*a, **k):
            raise ConnectionError("model unreachable")
        payload = soc.recommend_runbooks(inc, state, chat_fn=boom, timeout=5)
        self.assertEqual([e["runbookId"] for e in payload["eligible"]],
                         ["rb-block-ip", "rb-draft-notify"])
        self.assertEqual(payload["recommendation"]["status"], "timed_out")
        self.assertEqual(payload["recommendation"]["ranking"], [])

    def test_d_deterministic_survives_model_hang_within_timeout(self):
        state = _bf_state()
        inc = self._incident(state)

        def hang(*a, **k):
            time.sleep(30)      # far longer than the timeout below
            return "{}"
        t0 = time.perf_counter()
        payload = soc.recommend_runbooks(inc, state, chat_fn=hang, timeout=0.25)
        elapsed = time.perf_counter() - t0
        # Bounded: it returned about at the timeout, NOT after the 30s sleep.
        self.assertLess(elapsed, 5, f"waited {elapsed:.2f}s — the model blocked the response")
        self.assertTrue(payload["eligible"])
        self.assertEqual(payload["recommendation"]["status"], "timed_out")

    def test_d_absent_when_no_model_offered(self):
        # No chat_fn AND no eligible runbook -> advisory honestly absent, and the
        # (empty) eligible list is still the deterministic truth.
        state = _host_state()
        inc = self._incident(state)
        # Force zero eligibility by clearing evidence the runbooks require.
        empty = {"runId": "r2", "findings": []}
        payload = soc.recommend_runbooks(inc, empty, chat_fn=None, timeout=1)
        self.assertEqual(payload["eligible"], [])
        self.assertEqual(payload["recommendation"]["status"], "absent")

    # ---- (a) eligible() is never modified — its signature stays closed -------
    def test_eligible_signature_stays_closed_to_the_llm(self):
        import inspect
        names = tuple(inspect.signature(runbooks.eligible).parameters)
        self.assertEqual(names, ("runbook", "incident", "findings"))

    # ---- C4-F1: the additive triggerRules field, emitted VERBATIM ------------
    def test_c4f1_trigger_rules_emitted_verbatim_and_additive(self):
        state = _bf_state()
        inc = self._incident(state)
        loaded = runbooks.load_runbooks()
        out = soc.eligible_runbooks(inc, state)
        self.assertTrue(out, "a brute-force incident has eligible runbooks")
        for e in out:
            rb = loaded[e["runbookId"]]
            # Present, and EXACTLY the runbook definition's trigger.rule_ids —
            # no derivation, no filtering, no reordering, no prettifying.
            self.assertIn("triggerRules", e)
            self.assertEqual(e["triggerRules"], list(rb["trigger"]["rule_ids"]))
        # Additive ONLY: the pre-existing keys and the eligibility verdict are
        # left exactly as they were.
        self.assertTrue(
            {"runbookId", "name", "severityFloor", "eligibilityProof"} <= set(out[0]))
        self.assertEqual(out[0]["eligibilityProof"], {"eligible": True, "missing": []})

    def test_detector_frozen(self):
        import hashlib
        sha = hashlib.sha256((ROOT / "anomaly_detector.py").read_bytes()).hexdigest()
        self.assertEqual(sha, FROZEN_DETECTOR_SHA)


class RecommendHttpTests(unittest.TestCase):
    """The serve.py delegation, reachable over a real in-process server."""

    def setUp(self):
        import http.server
        import threading
        self._tmpdir = tempfile.TemporaryDirectory(prefix="c3-recommend-http-")
        self._real_soc = soc.SOC_DIR
        # The real model is unreachable here; cap its deadline so the honest
        # timeout is fast instead of waiting the production default.
        self._real_timeout = soc._RECO_TIMEOUT
        soc._RECO_TIMEOUT = 0.4
        soc.SOC_DIR = Path(self._tmpdir.name) / ".soc"
        soc.SOC_DIR.mkdir(parents=True, exist_ok=True)
        soc.sync_incidents(_bf_state())
        self.incident = next(iter(soc._load("incidents.json").values()))

        import serve
        self.serve = serve
        self._real_state = serve.STATE
        serve.STATE = _bf_state()
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), serve.ConsoleHandler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.serve.STATE = self._real_state
        soc.SOC_DIR = self._real_soc
        soc._RECO_TIMEOUT = self._real_timeout
        self._tmpdir.cleanup()

    def _get(self, path):
        import urllib.request
        import urllib.error
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_http_recommendation_reachable_and_advisory_typed(self):
        # The real model is unreachable in the test env, so the advisory portion
        # is honestly timed out — but the deterministic eligible list arrives.
        st, body = self._get(f"/api/incidents/{self.incident['id']}/runbook-recommendation")
        self.assertEqual(st, 200)
        self.assertEqual(body["type"], "runbook_recommendation")
        self.assertIs(body["advisory"], True)
        self.assertEqual([e["runbookId"] for e in body["eligible"]],
                         ["rb-block-ip", "rb-draft-notify"])
        self.assertIn(body["recommendation"]["status"], ("timed_out", "absent", "complete"))
        # No executable handle over the wire either.
        self.assertNotIn("\"connector\"", json.dumps(body))
        self.assertNotIn("\"command\"", json.dumps(body))

    def test_http_unknown_incident_404(self):
        st, body = self._get("/api/incidents/inc-nope/runbook-recommendation")
        self.assertEqual(st, 404)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
