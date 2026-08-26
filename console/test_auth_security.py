#!/usr/bin/env python3
"""Focused regressions for the local-demo auth security boundary."""
import http.server
import json
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
    original = auth.AUTH_PROVIDER
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
            server.shutdown()
    finally:
        auth.AUTH_PROVIDER = original
    print("auth security regressions: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
