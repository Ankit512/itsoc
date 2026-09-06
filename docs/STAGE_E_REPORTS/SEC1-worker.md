# SEC-1 — the console API accepts cross-site requests. Closed.

**Branch:** `Ankit512/sec1-origin-guard` (the card named `feat/sec1-origin-guard`; the name is a
warning only, and the worktree was already on this branch).
**Base HEAD:** `53ecb68cfda817e7876fc1471aeeb386be532bbf` — identical to `origin/main`.
**Date:** 2026-09-06.

---

## 1. Base checks — all three, before the first edit

| # | Check | Result |
|---|---|---|
| 1 | `git rev-parse HEAD` | `53ecb68cfda817e7876fc1471aeeb386be532bbf` |
| 2 | `git merge-base --is-ancestor HEAD origin/main` | **PASS** — and `HEAD == origin/main` exactly (both `53ecb68`), so this is not a stale worktree; the reverse ancestor test also holds, which is what equality means. |
| 3 | `scripts/gate.sh` carries GS-1's expanded inventory | **PASS** — 20 Python suites listed (not the pre-GS-1 three), the `COVERAGE (GS-1, 2026-09-06)` header block is present, `test_auth_security` and `test_battlecard_efficacy` are both in it, and rule 5 ("NEVER leave a suite unlisted") is stated with a DELIBERATELY OUT block. |

**Detector freeze:** `shasum -a 256 anomaly_detector.py` =
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — verified before the first
edit and again after the last one. Unchanged. Never opened for writing.

**`web/node_modules`** was **absent**; `npm --prefix web install` was run (exit 0) so the
`--web` gates could run rather than SKIP. `web/package.json` and `web/package-lock.json` were
not modified — the `vitest` advisory (GHSA-5xrq-8626-4rwp) is out of scope by the card, and a
test-toolchain upgrade must not ride along with a security fix whose evidence is those same tests.

---

## 2. Allowlist audit

```
$ git status --porcelain
 M console/serve.py
 M console/test_auth_security.py
 M console/test_console.py
 (+ docs/STAGE_E_REPORTS/SEC1-worker.md, docs/SECURITY_REVIEW.md)
```

Every path is on the card's allowlist. Nothing on the FORBIDDEN list was touched:
`anomaly_detector.py`, the rules, the eval corpus, `console/runbooks.py`,
`console/triage_model.py`, `console/soc.py`, `tools/train_triage.py`,
`tools/attack_generator.py`, `tools/efficacy_harness.py` and its tests, every eligibility path,
and the `AUTH_REQUIRED` default.

**The `AUTH_REQUIRED` default is byte-identical.** `console/serve.py` still reads
`AUTH_REQUIRED = os.environ.get("ITSOC_AUTH", "").strip() == "1"`, and
`console/test_auth_security.py` still asserts that line is the documented env-driven switch, so a
future change that flips the default cannot hide behind this work. This card makes the **OFF** state
safe against the analyst's own browser. It does not turn the gate on.

---

## 3. What was built

**One place.** `ConsoleHandler.parse_request` — `http.server` calls it after the request line and
headers are read and **before** it dispatches to `do_GET`/`do_POST`/`do_PATCH`, so returning
`False` aborts the request without a route ever being looked up. That is what makes it one place
rather than a per-endpoint checklist: **a route that does not exist yet is already guarded**, and its
author does not have to know this file exists. There is a live check asserting exactly that.

It calls `request_guard_reason(command, path, headers)` — a pure, header-only function, so the
truth table is unit-testable without a socket. It returns `None` (proceed) or
`(status, honest_reason)`.

| Door | Rule | Status | What it closes |
|---|---|---|---|
| **Host** | must be a loopback authority — `127.0.0.0/8`, `::1`, `localhost` and friends — on **any port** | `403` | **DNS rebinding.** This, and nothing else, defeats it: an attacker domain that re-resolves to `127.0.0.1` is same-origin to the browser, but it still sends its own name in `Host`. |
| **Origin** | if present, must be an `http(s)` loopback origin. `null` (sandboxed iframe, `file://`) is foreign. Applied to **every** method | `403` | Cross-site reads and writes both. |
| **Content-Type** | a request that carries a body must declare `application/json` — or `multipart/form-data` on the three routes that genuinely parse it | `415` | **The no-preflight smuggling path.** |

### Choices, stated

- **Origin is validated on every method, not only the state-changing ones.** The card allowed the
  narrower reading; the wider one costs nothing and is strictly better. No caller on this machine
  ever sends a foreign `Origin`, so nothing legitimate breaks, and refusing it on `GET` too
  replaces the *incidental* protection of a never-sent `Access-Control-Allow-Origin` header — which
  the review correctly called incidental rather than designed — with a deliberate one.
- **An absent Content-Type on a body is refused, not waved through.** `text/plain` and
  `application/x-www-form-urlencoded` are the obvious two; the third is a `Blob` with an empty
  type, which makes the browser send **no** `Content-Type` at all and is still a CORS simple
  request. Waving that through would have left the smuggling path half open. Probe **P4c** is that
  case.
- **A bodiless request needs no Content-Type.** The React app fires several bodiless POSTs
  (`/api/reports`, `/api/syslog/stop`, `/api/incidents/<id>/case`) with no `Content-Type`.
  There is nothing to smuggle in an empty body, and the Origin door already covers the cross-site
  version of those calls. Asserted, so a later tightening cannot silently break the app.
- **`multipart/form-data` is allowed only where a route really parses it** — `/api/analyze`,
  `/api/evtx/ingest`, `/api/cases/<id>/attachments`. On a JSON route it is a `415`.
- **Refusals are honest.** A real status, the reason in the JSON body, and a `log_error` line. The
  connection is closed and the refused body drained first, so the peer reads the refusal instead of a
  reset. A `HEAD` refusal correctly carries headers and no body.

### The trap, and why it did not catch this build

`web/vite.config.ts` proxies `/api` to `http://127.0.0.1:8765` and does **not** set
`changeOrigin` (verified by reading the file), so the forwarded `Host` is `localhost:5173` and
the browser's `Origin` is `http://localhost:5173`. An allowlist of exactly `127.0.0.1:8765`
would have broken dev mode. **The boundary is loopback on ANY port**, which is why
`_authority_is_loopback` is deliberately port-blind. The guard was never relaxed to make a test or
the dev server pass; the dev path is asserted as *accepted* in both suites and in the live probes.

### The mitigation comment

`console/serve.py:113-127` said: *"bind() listens on 127.0.0.1 only, so the API is reachable from
this machine alone — it is not exposed to the network."* That was wrong in the direction that
matters, and it has been rewritten to say so explicitly, to state what is true now (loopback bind
**and** the guard, neither sufficient alone), and to record that the guard does not replace the login
gate and is not a reason to leave it off. The same wrong claim had propagated into
`console/test_auth_security.py`'s docstring; that is corrected too.

---

## 4. The probes — before and after, exact output

Live server, `python3 console/serve.py --port <p> --no-open`. **Before** = `console/serve.py`
restored to `53ecb68` with `git checkout HEAD -- console/serve.py` (working tree confirmed clean for
that path), served on port 8795; the card's own four probes were also run first against the untouched
base on port 8791 with identical results. **After** = this build on port 8794. Every collector a
probe started was stopped afterwards and the state re-read to confirm it.

### P1 — `GET /api/overview`, plain, loopback context, unauthenticated — **must still succeed**

| | Result |
|---|---|
| before | `HTTP 200` |
| after | `HTTP 200` |

The gate is off by owner decision and this card did not change that.

### P2 — `GET /api/overview` with `Origin: https://evil.example`

**before**
```
{"error": "no run yet \u2014 analyze a log first"}
HTTP 200
```
**after**
```
{"error": "refused: cross-origin request from Origin 'https://evil.example'. This console is not a cross-site API; only pages served from a loopback origin may call it."}
HTTP 403
```

### P3 — `GET /api/overview` with `Host: attacker.test` (DNS rebinding)

**before**
```
{"error": "no run yet \u2014 analyze a log first"}
HTTP 200
```
**after**
```
{"error": "refused: this console answers loopback requests only, and the Host header 'attacker.test' is not a loopback address. A request reaching 127.0.0.1 under some other name is DNS rebinding."}
HTTP 403
```

### P4 — `POST /api/syslog/start`, `Origin: https://evil.example`, `Content-Type: text/plain;charset=UTF-8`, body `{"port":15140,"bind":"127.0.0.1"}`

**before** — the CSRF, reproduced. A malicious page started a live network listener:
```
... "ports": [15140], "listeners": [{"port": 15140, "protocol": "TCP", "bind": "127.0.0.1", "running": true, ...},
                                    {"port": 15140, "protocol": "UDP", "bind": "127.0.0.1", "running": true, ...}], "error": ""}
HTTP 200
```
**after**
```
{"error": "refused: cross-origin request from Origin 'https://evil.example'. This console is not a cross-site API; only pages served from a loopback origin may call it."}
HTTP 403
```

### P4b / P4c / P4d — the Content-Type door on its own, with **no** `Origin` at all

Added because P4 is refused on `Origin` before `Content-Type` is even reached, and the card calls
Content-Type enforcement the single highest-value line. These prove it bites independently — which
matters, because a cross-site `<form>` post or a `Blob` body is the case where `Origin` alone
would not be enough to rely on.

| Probe | Body type | before | after |
|---|---|---|---|
| **P4b** | `text/plain;charset=UTF-8` | `HTTP 200`, listener started on **15141** | `HTTP 415` |
| **P4c** | **no `Content-Type` header at all** (a `Blob` with an empty type) | `HTTP 200`, listener started on **15142** | `HTTP 415` |
| **P4d** | `application/x-www-form-urlencoded` | `HTTP 200`, listener started on **15143** | `HTTP 415` |

after, P4b:
```
{"error": "refused: Content-Type text/plain on a request body. This endpoint reads JSON and requires 'Content-Type: application/json', which a browser cannot send cross-site without a preflight."}
HTTP 415
```
after, P4c:
```
{"error": "refused: Content-Type (absent) on a request body. This endpoint reads JSON and requires 'Content-Type: application/json', which a browser cannot send cross-site without a preflight."}
HTTP 415
```
after, P4d:
```
{"error": "refused: Content-Type application/x-www-form-urlencoded on a request body. This endpoint reads JSON and requires 'Content-Type: application/json', which a browser cannot send cross-site without a preflight."}
HTTP 415
```

### The effect check — not just the status code

`GET /api/syslog/status` after all six attack probes:

| | Result |
|---|---|
| before (guard absent) | `listeners: [{"port": 15143, "protocol": "TCP", ... "running": true}, {"port": 15143, "protocol": "UDP", ... "running": true}]  ports: [15143]` |
| after | `listeners: []  ports: []` |

Nothing was started. The refusals are refusals, not cosmetics.

---

## 5. The dev path still works

Vite's proxy does not set `changeOrigin`, so these are the exact headers it forwards. Run against
the live server (the real `vite dev` process was not started; the forwarded headers were reproduced
exactly, which is what is being asserted):

| Request | Headers | Result |
|---|---|---|
| `GET /api/overview` | `Host: localhost:5173`, `Origin: http://localhost:5173` | **`HTTP 200`** |
| `POST /api/compute` | same, `Content-Type: application/json`, body `{"mode":"local"}` | **`HTTP 200`** `{"mode": "local"}` |

A loopback origin on a non-default port is accepted, which is the whole point of the port-blind
boundary.

---

## 6. Proof the guard bites

`request_guard_reason` was temporarily neutered with a single `return None` at its top, the
server restarted, the probe set re-run, then the file restored from a pre-demo copy and the probe set
run again.

**Guard disabled** — every attack succeeds again:

```
P2  foreign Origin           HTTP 200
P3  foreign Host             HTTP 200
P4  text/plain + foreign Origin   HTTP 200   listener started on 15140
P4b text/plain, no Origin         HTTP 200   listener started on 15141
P4c no Content-Type               HTTP 200   listener started on 15142
P4d form-urlencoded               HTTP 200   listener started on 15143
STATE  listeners: [15143 TCP running, 15143 UDP running]  ports: [15143]
```

**The regression tests fail too**, which is the other half of the claim — a test that cannot fail is
not a test:

`console/test_console.py :: check_origin_guard` with the guard off, 15 failures, section `RC = 1`:
```
  [FAIL] foreign Origin on GET is refused with 403
  [FAIL] ...and the refusal is honest: a stated reason, never a silent drop
  [FAIL] foreign Origin on a state-changing POST is refused with 403
  [FAIL] Origin: null (sandboxed iframe / file:// page) is refused
  [FAIL] foreign Host 'attacker.test' is refused with 403 (DNS rebinding)
  [FAIL] foreign Host 'attacker.test:8765' is refused with 403 (DNS rebinding)
  [FAIL] foreign Host '127.0.0.1.attacker.test' is refused with 403 (DNS rebinding)
  [FAIL] JSON smuggled as text/plain is refused with 415
  [FAIL] ...and the text/plain refusal says why
  [FAIL] JSON smuggled as form-urlencoded is refused with 415
  [FAIL] ...and the form-urlencoded refusal says why
  [FAIL] a body with NO Content-Type at all is refused with 415
  [FAIL] no smuggled request started a syslog listener
  [FAIL] multipart is REFUSED on a JSON route
  [FAIL] a route that does not exist yet is guarded too (one place, not per-endpoint)
  SECTION RC = 1
```

`console/test_auth_security.py` with the guard off:
```
AssertionError: (False, 'foreign Origin', 200)
```

**Restored** — `grep -c 'TEMPORARY SEC-1 GUARD-BITES DEMO' console/serve.py` → `0`, detector sha
re-verified, and the full probe set re-run on port 8794 gives §4's "after" column exactly.

---

## 7. Regression tests, and where they run

Both files are already in `scripts/gate.sh`, so these run on every gate and in CI (`ci.yml` runs
the same script).

**`console/test_console.py :: check_origin_guard`** — 49 checks, registered in `main()` and in
the summary line as `sec1-origin-guard`. It covers, in order: the pure `_authority_is_loopback` /
`_origin_is_loopback` truth tables (15 loopback and foreign authorities including
`127.0.0.1.attacker.test`, `localhost.attacker.test`, `0.0.0.0:8765`, `LOCALHOST:5173`,
`[::1]:8765`); then live over a real socket — the **baseline** that an unauthenticated loopback GET
is still 200 (so the guard can never quietly become a login gate), foreign Origin on GET **and** on a
state-changing POST, `Origin: null`, three foreign Hosts, `text/plain` and form-urlencoded and
absent Content-Type, the effect check that no listener started, the honesty of the refusal body, the
absence of any `Access-Control-Allow-Origin`, the **dev path accepted on a non-default port**, a
bodiless POST still reaching its handler, multipart allowed on the upload routes and refused on a
JSON route, and finally that a **nonexistent** route is guarded and that `parse_request` is the
seam.

**`console/test_auth_security.py :: origin_guard_regressions`** — the same three doors plus the dev
path, asserted in **both** auth modes (`AUTH_REQUIRED` `False` and `True`), because the auth-off
mode is the one the owner ships and the one the finding was reproduced in. It asserts the guard is
**ahead of** the login gate: a cross-site request is refused `403` (cross-site), not `401`
(unauthenticated). The suite passes with the process default and with `ITSOC_AUTH=1`:

```
$ python3 console/test_auth_security.py
auth security: process default AUTH_REQUIRED=False (owner decision, 2026-08-27) — pinning it ON for these assertions
auth security regressions: PASS (fail-closed mode, AUTH_REQUIRED=True)
origin-guard regressions: PASS (AUTH_REQUIRED=False)
origin-guard regressions: PASS (AUTH_REQUIRED=True)

$ ITSOC_AUTH=1 python3 console/test_auth_security.py
auth security: process default AUTH_REQUIRED=True (owner decision, 2026-08-27) — pinning it ON for these assertions
auth security regressions: PASS (fail-closed mode, AUTH_REQUIRED=True)
origin-guard regressions: PASS (AUTH_REQUIRED=False)
origin-guard regressions: PASS (AUTH_REQUIRED=True)
```

**No existing test was weakened.** `console/test_console.py` and `console/test_auth_security.py`
already sent `Content-Type: application/json` on their JSON POSTs, so nothing had to be relaxed to
accommodate the new door; the only edits to existing content are the two docstring corrections and
the registration lines. `git diff` shows no assertion removed or loosened.

---

## 8. Gate

`scripts/gate.sh --web`, exit **0**. Evidence: `gate-logs/20260906-141019` (final run, after the docs landed).

```
================ GATE SUMMARY (20260906-141019) ================
  PASS  run_eval
  PASS  validate_real_selftest
  PASS  threat_intel
  PASS  test_auth_security
  PASS  test_copilot_workspace
  PASS  test_overview
  PASS  test_fsafe
  PASS  test_mcp
  PASS  test_intake
  PASS  test_audit_drift
  PASS  test_ti_oem_egress
  PASS  test_stage_e_wall
  PASS  test_e7a_feature_contract
  PASS  test_battlecard_efficacy
  PASS  test_approvals
  PASS  test_attack_generator
  PASS  test_train_triage
  PASS  test_efficacy_harness
  PASS  test_console
  PASS  test_recommend
  PASS  web_vitest
  PASS  web_build
  PASS  detector_freeze
  evidence: gate-logs/20260906-141019

  DELIBERATELY OUT of this gate (rule 5 — named, never silently unlisted):
    tests/eval/validate_real.py (full mode) — scores the detector against an
      OPERATOR-SUPPLIED real log plus a hand-labelled ground-truth file, and
      asserts nothing; it reports metrics. Its --selftest, which does assert,
      IS in the gate above.
    web/src/test (vitest) and the web build — in the gate behind --web, since
      they need web/node_modules; absent, they SKIP loudly (never a pass).
=======================================================
GATE GREEN.
```

The named numbers the card asked for:

| Suite | Result |
|---|---|
| `tests/eval/run_eval.py` | `cases: 20 passed, 0 failed, 20 total` · `false positives: 0` · precision/recall/f1 `1.000` |
| `tests/test_stage_e_wall.py` | `135/135 checks passed` · `Stage E wall intact.` |
| `console/test_console.py` | PASSED — all sections green, now including `sec1-origin-guard` |
| `console/test_auth_security.py` | PASS in both auth modes (§7) |
| `npm --prefix web test` | `Test Files 44 passed (44)` · `Tests 313 passed (313)` |
| `npm --prefix web run build` | `✓ built in 1.28s` |
| detector sha256 | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — matches |
| `git diff --check` | clean, exit 0 |
| allowlist audit | clean (§2) |

---

## 9. Deviations, and what is deliberately not here

- **Branch name.** `Ankit512/sec1-origin-guard`, not `feat/sec1-origin-guard`. The worktree was
  already on it; the card marks the name a warning only. No new branch was cut.
- **The real `vite dev` server was not started.** The dev-path demonstration reproduces the exact
  headers Vite forwards (`Host: localhost:5173`, `Origin: http://localhost:5173`), verified by
  reading `web/vite.config.ts` and confirming it does not set `changeOrigin`. Stated here rather
  than left implicit, as the card asked.
- **Probes P4b/P4c/P4d are additions, not substitutions.** The card's four probes are all present and
  unmodified; these three isolate the Content-Type door, which P4 alone cannot demonstrate because
  `Origin` refuses it first.
- **The login gate is untouched.** `AUTH_REQUIRED` still reads exactly
  `os.environ.get("ITSOC_AUTH", "").strip() == "1"`. Nothing in this work concluded the gate must
  be on, so there was no owner escalation to raise.
- **`web/package.json` untouched.** The `vitest` critical advisory (GHSA-5xrq-8626-4rwp) is a
  separate change by the card's instruction.
- **No push, no merge.** Committed locally with explicit paths; `git add -A` was never used.

## 10. What this does not fix

The guard defends against **the browser**. It does not authenticate anything: a non-browser process
running as the analyst's user — a script, another local app, a terminal — can still set
`Host: 127.0.0.1:8765`, omit `Origin`, send `application/json`, and reach every endpoint
unauthenticated. That is the login-gate decision, which this card was explicitly forbidden to reopen
and did not. The honest statement of the posture after SEC-1 is: **the console API is safe against
cross-site requests from the analyst's browser, and remains open to any local process.** The rewritten
comment in `serve.py` says exactly that, so the next reader is not told a second time that something
is protected when it is not.
