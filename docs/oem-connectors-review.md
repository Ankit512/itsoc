# OEM / TI connector review (`console/ti_oem.py`)

Review of the adopted app's Threat-Intel enrichment + OEM vendor pollers,
requested on conversation `ti-oem-review`. Baseline: main `cb8c47c`.
**Recommendation: FENCE** (implemented on `feat/oem-fence`, off by default).

## What the module actually does

Two sibling subsystems, both stdlib-only (`urllib`), both writing to the
persistent store (`console/store.py`):

1. **TI enrichment** (`enrich_ip`, `POST /api/ti/enrich`): on-demand lookup of
   one IP against **OTX** (`otx.alienvault.com`) and **AbuseIPDB**
   (`api.abuseipdb.com`) — hardcoded provider hosts, module-level so tests can
   stub them. A provider is called **only** if the user stored an API key for
   it; verdict/score come from the provider's real response (pulse count /
   abuse confidence), never keyword-guessed. Results stored as IOCs.
2. **OEM pollers** (`poll_connector` + background `PollerEngine`): user-created
   connectors from 8 vendor templates (FortiGate, Check Point, Splunk, Trend
   Vision One, PAN-OS, Firepower, SmartZone, Log360). Three vendor-specific
   protocols — Check Point Management API (`login` → `show-logs` → `logout`,
   username+password), Splunk oneshot search export (bearer token), PAN-OS XML
   API (API key **in the URL query string**) — plus a generic bearer-token JSON
   GET. All polls are *read-only queries* against the vendor's log/event API;
   nothing mutates the target (the Check Point session login/logout is the one
   state it creates, and it logs out). Ingested events keep vendor-reported
   severity only (empty if none) and verbatim JSON in `raw` — consistent with
   the honesty rules.

## Does it egress by default?

**No outbound call happens without explicit user configuration**, by four
independent guards (pre-fence):

- No connectors exist until one is created via `POST /api/oem/connectors`;
  the `connectors` table default is `enabled=0`.
- Template base URLs are uppercase placeholders (`https://FORTIGATE` …) and
  `poll_connector` refuses any URL still containing a placeholder host.
- Check Point / Splunk / PAN-OS refuse to poll without their credential
  (honest error, no call). TI providers are skipped without a key
  (`notConfigured`, no call).
- The server binds `127.0.0.1` only.

**But** the `PollerEngine` daemon thread started unconditionally at server
boot (`serve.py`, `ti_oem.POLLER.start()`) — idle, waking every 10 s to scan
for enabled connectors. So pre-fence, "no egress" was *data-dependent* (an
empty table), not *structural*.

## Credential handling

- All credentials are user-supplied at connector-create / settings-write time;
  nothing is hardcoded. They land in the sqlite settings table under
  secret-hinted keys; `store.public_settings()` and `_safe_row()` return
  **presence booleans only** — no read path returns a value to the browser.
- At rest they are **plaintext in `soc_history.db`** (no OS keychain /
  encryption). Acceptable for a local single-user console, but worth stating.
- The PAN-OS key travels in the query string — standard for the PAN-OS XML
  API, but it can persist in proxy/target access logs.
- TLS: `urllib` verifies certificates by default; no verification bypass
  anywhere in the module. All calls carry a 15 s timeout.

## Risks vs the read-only / local-by-default posture

1. **Expanded outbound surface.** These are the only components (besides the
   user-triggered LLM/Ollama path) that dial out of the machine, to
   user-chosen hosts.
2. **CSRF → SSRF (the concrete pre-fence hole).** The console has no auth and
   `_read_json_body` parses the body regardless of Content-Type. A hostile web
   page in the same browser could fire `no-cors` POSTs at
   `127.0.0.1:8765/api/oem/connectors` + `/api/oem/poll` and make the console
   issue GET/POST requests to an attacker-chosen (including internal) URL, and
   ingest the JSON response into the user's event store. It could not read
   responses or steal stored secrets (masked + same-origin), but
   request-forging from the user's machine is real.
3. **Credential entry surface** — same CSRF vector could *overwrite* (not
   read) stored tokens; plaintext-at-rest as above.
4. **Log-store poisoning by egress** — polled vendor JSON enters the store as
   events; content is untrusted input (already the repo's stance) and severity
   is copied, not verified. Fine under "source-reported", but only when the
   user *chose* the source.

## Recommendation: FENCE (implemented)

`KEEP EXCLUDED` would discard genuinely well-built, honest code;
`INTEGRATE-WITH-CONDITIONS` (unconditional) leaves the CSRF→SSRF hole and
makes egress opt-out rather than opt-in. FENCE gives the local-by-default
posture structurally:

- **Off by default:** `ITSOC_OEM=1` (environment, checked per request) is now
  required for `POST /api/ti/enrich`, `POST /api/oem/connectors`,
  `POST /api/oem/poll`, and for starting the background `PollerEngine`.
  Without it every egress/credential route returns an honest
  `403 {"error": "... Start the server with ITSOC_OEM=1 to opt in to external
  egress."}` — which the web UI already surfaces verbatim — and the startup
  banner states the fence state either way.
- **Read-only views stay open** (`/api/oem/templates`, `/api/oem/connectors`
  GET, `/api/ti/keys`): no external call, no secret values.
- The fence also closes the CSRF→SSRF vector in the default configuration
  (the dangerous POSTs are refused before the body is read).

Note: the dispatch referenced an existing `ITSOC_EXPERIMENTAL` pattern; no
such flag exists on current main, so `ITSOC_OEM` introduces the pattern in
the same spirit.

### Conditions for a later full INTEGRATE (if ever wanted)

1. An Origin/Host check (or CSRF token) on all mutating `/api/*` routes, so
   enabling the fence doesn't re-open the forged-POST vector.
2. TI keys via `POST /api/store/settings` should sit behind the same fence.
3. Document plaintext-at-rest credentials (or move to a keychain).
4. UI shows an explicit "external egress" banner whenever `ITSOC_OEM=1`.
