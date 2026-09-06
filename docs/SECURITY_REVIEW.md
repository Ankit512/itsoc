# itsoc — security and leak review

**Date:** 2026-09-06. **Scope:** whole repository at `5cc5d45`, plus the running console.
**Method:** secret scan over full git history, tracked-artefact audit, live probing of the
console's HTTP surface, static review of egress and dual-use paths, dependency audit.
**Not covered:** fuzzing, authenticated-mode penetration testing, Python dependency CVEs,
the Vercel project's own configuration.

Findings are ranked by what an attacker can actually do, not by how alarming they sound.

---

## Correction to a premise this session was working from

The repo is **PRIVATE** (`gh repo view` → `isPrivate: true`). Earlier in this session the push was
authorized partly on the basis of a "public repo link in an investor-advisor's inbox." Whatever was
shared, GitHub reports the repository as private today. Everything below is written for the risk
profile the repo has **if it is ever made public**, because that is the decision this review should
inform — but nothing here is currently world-readable.

---

## SEV-1 — the console's HTTP API accepts cross-site requests. Reproduced. **CLOSED (SEC-1, 2026-09-06).**

> **Outcome.** Fixed on `Ankit512/sec1-origin-guard` by `console/serve.py`'s browser-origin guard:
> `request_guard_reason()` plus the `ConsoleHandler.parse_request` seam. All three foreign-context
> probes below now return **403 / 415**; the plain unauthenticated loopback `GET` still returns 200,
> because this card did **not** reopen the login-gate decision. The wrong mitigation comment at
> `serve.py:113-127` was rewritten to state what is actually true. Evidence, including a
> disable-and-restore demonstration that the guard bites:
> [`docs/STAGE_E_REPORTS/SEC1-worker.md`](STAGE_E_REPORTS/SEC1-worker.md). Regression tests live in
> `console/test_console.py` (`check_origin_guard`, 49 checks) and `console/test_auth_security.py`
> (`origin_guard_regressions`, both auth modes) — both inside `scripts/gate.sh`.


**The mitigation in the code is incomplete, and that is the actual finding.**
`console/serve.py:113-127` disables the login gate by owner decision and states the mitigation:

> *"bind() listens on 127.0.0.1 only, so the API is reachable from this machine alone — it is not
> exposed to the network."*

Binding to loopback stops other **hosts**. It does not stop the **browser running on that host**.
Any web page the analyst visits while the console is running can issue requests to
`http://127.0.0.1:8765`, and nothing in the request path rejects them.

**Verified live** against `serve.py --port 8791` (server and collector stopped afterwards; port
confirmed clear):

| Probe | Result |
|---|---|
| `GET /api/overview`, unauthenticated | **200** |
| Same, `Origin: https://evil.example` | **200** — no Origin validation |
| Same, `Host: attacker.test` | **200** — no Host validation |
| `POST /api/syslog/start`, `Content-Type: text/plain`, foreign `Origin` | **200 — `{"running": true, "port": 15140}`** |

That last row is a real cross-site request forgery: `text/plain` makes it a CORS *simple request*, so
a browser sends it cross-origin with **no preflight**, and the handler parses the body as JSON
without checking the content type. A malicious page started a network listener in the analyst's
console.

**What is reachable this way, unauthenticated, today:** `/api/syslog/start` (which accepts
`bind: "0.0.0.0"`, explicitly exposing a port to the network), `/api/discovery/scan` (nmap),
`/api/analyze`, case-attachment upload, and the store purge.

**What limits it.** No `Access-Control-Allow-Origin` header is ever sent, so a cross-origin page
**cannot read the responses** — this blocks straightforward data exfiltration. That protection is
incidental rather than designed, and it does not survive **DNS rebinding**: with no `Host` validation
(row 3), an attacker domain that rebinds to `127.0.0.1` becomes same-origin and can then read
everything — incidents, findings, raw log lines, case files.

nmap targets are correctly restricted to private/loopback/link-local ranges
(`discovery.authorized_target`), so the scan cannot be aimed outward — but it can still be triggered
against the analyst's own network without their intent.

**The fix is small and does not reopen the login-gate decision:** validate the `Host` header against
an expected loopback value and reject requests carrying a cross-origin `Origin`, on state-changing
methods at minimum. Both are a few lines in one place, in the same spirit as the existing single
`AUTH_REQUIRED` switch.

### What was actually built (SEC-1)

One place — `ConsoleHandler.parse_request`, which `http.server` calls after the headers are read and
**before** it dispatches to any `do_*` method, so a route added tomorrow is guarded on the day it is
written. Three checks:

| Check | Rule | Refusal |
|---|---|---|
| **Host** | must be a loopback authority — `127.0.0.0/8`, `::1`, `localhost` — on **any port** | `403` |
| **Origin** | if present, must be an `http(s)` loopback origin; `null` is foreign. Applied to **every** method, GET included | `403` |
| **Content-Type** | a request that carries a body must declare `application/json`, or `multipart/form-data` on the three routes that really parse it (`/api/analyze`, `/api/evtx/ingest`, case attachments) | `415` |

The Content-Type check is the one that closes the no-preflight path: `text/plain`,
`application/x-www-form-urlencoded` and an **absent** Content-Type (a `Blob` with an empty type) are
exactly the three bodies a browser will send cross-site without a preflight, and a JSON endpoint has
no business accepting any of them. Origin validation was widened past state-changing methods on
purpose: no caller on this machine ever sends a foreign `Origin`, and refusing it on `GET` too
replaces the *incidental* protection of a missing `Access-Control-Allow-Origin` header with a
deliberate one.

The boundary is **loopback on any port**, not one port. `web/vite.config.ts` does not set
`changeOrigin`, so in dev the forwarded `Host` is `localhost:5173` and the browser `Origin` is
`http://localhost:5173`. An allowlist of exactly `127.0.0.1:8765` would have broken dev mode, and the
answer to that is not to relax the guard — the dev path is asserted as accepted in both suites.

Refusals are honest: a real status, the reason in the JSON body, and a server log line. Never a
silent drop, never a fake success. **Not** addressed by this card, and deliberately so: the login
gate stays off by owner decision, and the `vitest` advisory below remains a separate change.

---

## SEV-2 — `vitest` critical advisory in the web toolchain

`npm audit`: **1 critical, 1 high, 5 moderate.**

- **critical — `vitest` < 3.2.6**, GHSA-5xrq-8626-4rwp, CVSS 9.8: with the Vitest UI server
  listening, an arbitrary file can be read and executed.
- **high — `vite`**; moderate — `esbuild`, `react-router`/`react-router-dom`, `vite-node`,
  `@vitest/mocker`.

These are **devDependencies**: they do not ship in `web/dist`, so the deployed SPA is unaffected. The
exposure is to whoever runs the test suite — which, in this project, is every worker on every card.
`react-router` is the one to check for production reach.

---

## Clean — verified, not assumed

**No secrets, in the working tree or in history.** A full-history scan for AWS keys, GitHub PATs,
OpenAI keys, Slack tokens, Google API keys and PEM private-key headers returned two hits, both
**test fixtures** with literal placeholder strings. `.env` is gitignored; `.env.example` contains
only a localhost Ollama placeholder.

**No runtime state is tracked.** `console/.soc/` (incidents, cases, auth store) and `console/.runs/`
are gitignored, as are `graphify-out/`, `.claude/` and the model artefacts. The single tracked
`cases.json` is a deliberate migration fixture under `tests/fixtures/`.

**No default external egress of log content.** `LLM_BASE_URL` defaults to
`http://localhost:11434/v1` (local Ollama). Reaching a hosted API is an explicit, documented opt-in.

**Static file serving is not traversable.** `serve.py:1728-1729` resolves the candidate path and
calls `relative_to(WEB_DIST)`, which is the correct shape.

**The listener defaults to loopback.** `ThreadingHTTPServer(("127.0.0.1", port))` is hardcoded for
the console itself; `0.0.0.0` exists only as an explicit opt-in on the syslog collector, and an
arbitrary bind address is refused rather than coerced.

**Committed log corpora are synthetic.** `samples/` and `tests/eval/cases/` are public LogHub
samples and constructed fixtures — documentation-range addresses, no customer data.

---

## Recommendation

~~One card, narrowly scoped: **Host-header and Origin validation on the console API**, plus a
`Content-Type` check on JSON endpoints, plus a regression test that asserts a foreign `Origin` and a
foreign `Host` are both refused.~~ **Done — SEC-1, 2026-09-06.** It did not touch the login-gate
decision, the detector, or any verdict path.

The `vitest` bump is separate and should be its own change, since a test-toolchain upgrade can move
test results and must not ride along with a security fix whose evidence is those same tests.
