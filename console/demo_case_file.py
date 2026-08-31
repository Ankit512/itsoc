#!/usr/bin/env python3
"""Seed a LAB case file from a REAL analyzed run.

The log (samples/case-file-demo.log) is ordinary canonical syslog the detector
already understands. This script does not invent findings or change sev.

  1. Analyze the demo log in the console (picker: case-file-demo.log), or:
       python3 console/serve.py --input samples/case-file-demo.log
  2. python3 console/demo_case_file.py
  3. Hard-refresh /cases and open the seeded case.

Attachments are real files under samples/case-file-demo/. Observables use
TEST-NET / example.test plus IPs the detector already named on this run.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FILES = ROOT / "samples" / "case-file-demo"
DEFAULT = "http://127.0.0.1:8765"
LAB_URL = "https://walmart.example.test/track"


def req(base, method, path, obj=None, raw=None, content_type=None):
    data = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else None)
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    elif obj is not None:
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r) as resp:
            body = resp.read()
            if not body:
                return resp.status, {}
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except json.JSONDecodeError:
            return e.code, {"error": e.reason}


def upload(base, case_id, path: Path):
    bound = "----itsocLabBoundary"
    blob = path.read_bytes()
    raw = (
        f"--{bound}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + blob + f"\r\n--{bound}--\r\n".encode()
    return req(base, "POST", f"/api/cases/{case_id}/attachments",
               raw=raw, content_type=f"multipart/form-data; boundary={bound}")


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT).rstrip("/")
    status, state = req(base, "GET", "/console_state.json")
    if status != 200:
        print(f"console not reachable at {base} ({status}). Start: python3 console/serve.py",
              file=sys.stderr)
        return 1
    if state.get("idle") or state.get("unrecognized"):
        print("No analyzed run. In the picker open samples/case-file-demo.log "
              "(or: python3 console/serve.py --input samples/case-file-demo.log)",
              file=sys.stderr)
        return 1
    findings = list(state.get("findings") or [])
    if not findings:
        print("This run has 0 findings — dummy case objects will not fake a verdict.",
              file=sys.stderr)
        return 1
    status, listed = req(base, "GET", "/api/cases")
    cases = (listed or {}).get("cases") or []
    if status != 200 or not cases:
        print("No cases after GET /api/cases. Analyze the demo log first.", file=sys.stderr)
        return 1
    case = cases[0]
    cid = case["id"]
    import re
    ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = []
    for f in findings:
        blob = " ".join(str(f.get(k) or "") for k in ("host", "ip", "title", "msg", "raw"))
        ents = f.get("entities") or {}
        if isinstance(ents, dict):
            blob += " " + " ".join(str(v) for v in ents.values())
        ips.extend(ipv4.findall(blob))
    ip = next((i for i in ips if i.startswith(("203.0.113.", "198.51.100.", "192.0.2."))), None)
    if not ip and ips:
        ip = ips[0]
    if ip:
        req(base, "POST", f"/api/cases/{cid}/observables",
            {"type": "ip", "value": ip, "verdict": "Named by a rule finding on this run (lab)."})
    req(base, "POST", f"/api/cases/{cid}/observables",
        {"type": "url", "value": LAB_URL})
    for name in ("email_headers.txt", "email_body.html"):
        path = FILES / name
        if path.is_file():
            st, out = upload(base, cid, path)
            if st not in (200, 201):
                print(f"attach {name}: {st} {out}", file=sys.stderr)
    case = req(base, "GET", f"/api/cases/{cid}")[1]
    for obs in case.get("observables") or []:
        if obs.get("id"):
            req(base, "POST", f"/api/cases/{cid}/observables/{obs['id']}/enrich", {})
    req(base, "POST", f"/api/cases/{cid}/summary", {})
    req(base, "POST", f"/api/cases/{cid}/comment",
        {"text": "LAB seed: dummy email files + example.test URL. Rule severity is unchanged.",
         "actor": "lab"})
    print(f"Seeded {cid} from run {state.get('runId')} ({len(findings)} finding(s)).")
    print(f"Open {base}/cases?sel={cid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
