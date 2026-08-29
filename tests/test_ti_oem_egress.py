"""Adversarial wire/error capture for the TI/OEM outbound HTTP seam."""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "console"))

import ti_oem  # noqa: E402


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b'{"ok": true}'


def _request_headers(req):
    return {k.lower(): v for k, v in req.header_items()}


class EgressTests(unittest.TestCase):
 def test_wire_keeps_required_values_but_observable_surfaces_are_redacted(self):
    """Non-vacuous: capture real Request fields, then make the transport echo them."""
    marker = "SENSITIVE-OPEN5-7f3"
    wire = []

    def succeeds(req, timeout):
        wire.append({"url": req.full_url, "data": req.data,
                     "headers": _request_headers(req), "timeout": timeout})
        return _Response()

    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.object(ti_oem.urllib.request, "urlopen", succeeds), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = ti_oem._http_request(
            f"https://provider.invalid/check?ipAddress=203.0.113.9&key={marker}",
            {"Authorization": f"Bearer {marker}", "X-New-Token": marker,
             "Content-Type": "application/json"},
            "POST", f'{{"username":"analyst","password":"{marker}"}}'.encode())

    captured = wire[0]
    assert result == '{"ok": true}'
    assert marker in captured["url"]
    assert marker.encode() in captured["data"]
    assert marker in captured["headers"]["authorization"]
    assert marker in captured["headers"]["x-new-token"]
    assert marker not in stdout.getvalue() + stderr.getvalue()

    def fails(req, timeout):
        # Adversarial transport: the underlying exception includes every raw
        # request field. The seam must not let any of it propagate.
        raise RuntimeError(
            f"transport rejected url={req.full_url} data={req.data!r} "
            f"headers={dict(req.header_items())} timeout={timeout}")

    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.object(ti_oem.urllib.request, "urlopen", fails), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        with self.assertRaises(Exception) as caught:
            ti_oem._http_request(
                f"https://provider.invalid/check?ipAddress=203.0.113.9&key={marker}",
                {"Authorization": f"Bearer {marker}", "X-New-Token": marker,
                 "Content-Type": "application/json"},
                "POST", f'{{"username":"analyst","password":"{marker}"}}'.encode())

    observable = str(caught.exception) + stdout.getvalue() + stderr.getvalue()
    assert marker not in observable
    assert "203.0.113.9" not in observable
    assert "analyst" not in observable
    assert "[REDACTED]" in str(caught.exception)


 def test_secret_masking_is_by_field_name_not_known_value(self):
    first = ti_oem._sanitized_request(
        "https://provider.invalid/api/?key=value-never-seen-before&query=src%3D203.0.113.9",
        {"X-Chkp-Sid": "session-never-seen-before", "Accept": "application/json"},
        b'{"user":"new-user","password":"password-never-seen-before"}')
    second = ti_oem._sanitized_request(
        "https://provider.invalid/api/?key=a-different-secret",
        {"X-Chkp-Sid": "a-different-session"},
        b'{"user":"another-user","password":"a-different-password"}')
    for safe in (first, second):
        rendered = str(safe)
        assert "[REDACTED]" in rendered
        assert "never-seen-before" not in rendered
        assert "a-different" not in rendered
        assert "203.0.113.9" not in rendered

 def test_poll_error_return_and_persisted_last_error_are_sanitized(self):
    marker = "PERSISTED-SECRET-OPEN5"
    store = ti_oem.store
    real = store.SOC_DIR, store.DB_PATH
    wire = []

    def fails(req, timeout):
        wire.append({"url": req.full_url, "data": req.data,
                     "headers": _request_headers(req)})
        raise RuntimeError(f"raw transport echo {req.full_url} {dict(req.header_items())}")

    try:
        with tempfile.TemporaryDirectory(prefix="tioem-egress-") as tmp:
            store.SOC_DIR = Path(tmp)
            store.DB_PATH = Path(tmp) / "soc_history.db"
            store.init_db()
            ti_oem.create_connector(
                "AdversarialOEM",
                {"vendor": "generic", "baseUrl": "https://provider.invalid",
                 "eventsPath": "/events", "params": {"ip": "203.0.113.9"}},
                enabled=True, token=marker)
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(ti_oem.urllib.request, "urlopen", fails), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = ti_oem.poll_connector("AdversarialOEM")
            stored = ti_oem.connector_view("AdversarialOEM")["lastError"]

            # Non-vacuity: the functional token and indicator reached the Request.
            assert marker in wire[0]["headers"]["authorization"]
            assert "203.0.113.9" in wire[0]["url"]

            observable = result["error"] + stored + stdout.getvalue() + stderr.getvalue()
            assert result["ok"] is False
            assert marker not in observable
            assert "203.0.113.9" not in observable
            assert "[REDACTED]" in observable
    finally:
        store.SOC_DIR, store.DB_PATH = real


if __name__ == "__main__":
    unittest.main(verbosity=2)
