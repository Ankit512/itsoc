#!/usr/bin/env python3
"""Focused regressions for the local-demo auth security boundary.

WHICH MODE THIS ASSERTS
-----------------------
Every assertion below is about the FAIL-CLOSED login gate: unauthenticated
/api/* is 401, and a state-mutating PATCH is rejected before it reaches
soc.patch_case. That gate is OFF by an explicit owner decision dated 2026-08-27
(console/serve.py lines 113-127), mitigated by binding 127.0.0.1 only, with the
restore switch documented there as `AUTH_REQUIRED = True` / `ITSOC_AUTH=1`.

This suite previously asserted 401 WITHOUT enabling the mode that produces it,
so it received 200 and failed — for an unknown length of time, because
scripts/gate.sh never ran it. The bug was in the test, not the product.

So the suite now turns the gate ON for its own duration (the same
`serve.AUTH_REQUIRED = True` pin console/test_console.py uses), restores the
process default afterwards, and SAYS SO in its output. It does not change the
product default, and it does not accept 200: a security test rewritten to pass
against the insecure result would be worse than a failing one.
"""
import http.server
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
import auth
import serve


def request(base, path, method="GET", payload=None, token=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def main():
    # The product default is the owner's decision and is NOT touched: assert it
    # is still the documented env-driven switch, so a future "fix" that flips
    # the default on cannot hide behind this suite.
    expected_default = os.environ.get("ITSOC_AUTH", "").strip() == "1"
    assert serve.AUTH_REQUIRED == expected_default, (
        "console/serve.py AUTH_REQUIRED is no longer the documented "
        f"ITSOC_AUTH-driven switch (env implies {expected_default}, "
        f"module says {serve.AUTH_REQUIRED})")
    print(f"auth security: process default AUTH_REQUIRED={serve.AUTH_REQUIRED} "
          f"(owner decision, 2026-08-27) — pinning it ON for these assertions")

    original = auth.AUTH_PROVIDER
    original_required = serve.AUTH_REQUIRED
    serve.AUTH_REQUIRED = True          # assert the fail-closed gate, not 200
    try:
        with tempfile.TemporaryDirectory(prefix="auth-security-") as tmp:
            auth.AUTH_PROVIDER = auth.LocalDemoAuth(Path(tmp))
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), serve.ConsoleHandler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{server.server_address[1]}"

            status, _ = request(base, "/api/overview")
            assert status == 401, status
            status, created = request(base, "/api/auth/signup", "POST", {
                "username": "owner", "passphrase": "correct horse", "role": "admin"})
            assert status == 201, (status, created)
            assert created["user"]["role"] == "analyst", created
            token = created["token"]

            status, takeover = request(base, "/api/auth/signup", "POST", {
                "username": "attacker", "passphrase": "overwrite", "role": "admin"})
            assert status == 409, (status, takeover)
            status, login = request(base, "/api/auth/login", "POST", {
                "username": "owner", "passphrase": "correct horse"})
            assert status == 200 and login["user"]["username"] == "owner", (status, login)

            status, _ = request(base, "/api/overview", token=token)
            assert status == 200, status

            # PATCH is a state mutation and must be gated fail-closed too: an
            # unauthenticated PATCH /api/cases/{id} must be rejected before it
            # ever reaches soc.patch_case.
            status, patched = request(base, "/api/cases/some-id", "PATCH", {"status": "closed"})
            assert status == 401, (status, patched)
            # With a valid token the gate lets it through (404 = no such case,
            # proving auth was not the blocker).
            status, patched = request(base, "/api/cases/some-id", "PATCH",
                                      {"status": "closed"}, token=token)
            assert status == 404, (status, patched)
            server.shutdown()
    finally:
        serve.AUTH_REQUIRED = original_required
        auth.AUTH_PROVIDER = original
    print("auth security regressions: PASS (fail-closed mode, AUTH_REQUIRED=True)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
