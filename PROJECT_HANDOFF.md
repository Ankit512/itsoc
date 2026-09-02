# itsoc — Project Handoff

> Purpose: a self-contained summary so this work can be continued in a new session
> without losing context. Covers the goal, what's been built, the architecture, how to
> run it, known issues, and what's next.

_Last updated: 2026-09-02 · Repo: `~/Projects/log-analyzer` · GitHub: `Ankit512/log-anomaly-detector` (public, `main` green)_

---

## 1. Goal & context

Building the first stages of a larger **AI Operations Platform for DC / NOC / SOC**. Full vision:

```
Agent → Agentic Skills → MCP → API/Security Gateway → Certificate/Token → Infrastructure
```

with a mandatory security principle: **API-first + certificate/token auth, no
username/password integration, human approval before any write action.**

We started at the bottom-left — **log analysis** — and now have a working local SOC workspace.
The React dashboard includes a guided tour, focused copilot with separate reasoning, incidents,
assignable cases, a bounded kanban board, approval-gated runbook templates, live-source status,
optional Splunk polling, threat-intel enrichment, and reports. A **read-only** MCP server
(`itsoc_mcp/`) exposes the same backend to MCP clients; it computes no verdicts and only relays
them.

### Hard requirements / decisions (unchanged)
- **Open-source models only** (Llama / Mistral / Qwen); avoid Claude/Anthropic in the runtime.
- **Run locally via Ollama** (`qwen3:8b` by default; `llama3.1:8b` is supported) so log data never leaves the machine.
- **No training / fine-tuning** — in-context reasoning + deterministic rules.
- **Chunk logs** (~100 lines) rather than relying on a huge context window.
- **Human-gated actions only.** Analysis is read-only by default; connector writes require an
  explicit approval and step-up verification. The copilot never executes them.

### Hardware
MacBook Air M4, 16GB RAM. Target a 7B–8B model at Q4/Q5. Do not attempt 70B locally.

---

## 2. Current status

| Stage | Description | Status |
|-------|-------------|--------|
| **A** | Log triage on a local open-source model | ✅ Done |
| **B** | Anomaly detection (deterministic + LLM), real-format support, eval harness | ✅ Done & regression-guarded (20/20) |
| **C** | Ops platform (live input, MCP tools, RCA, gated remediation) | ✅ SOC workspace, live collector surfaces, optional Splunk polling, cases/ownership, runbook templates, threat-intel enrichment, reports, and read-only MCP landed; unattended remediation and MCP writes remain out of scope |
| **UI-1** | Local vanilla-JS review console + `serve.py`, log-source picker, run history, standalone export | ✅ Built, live, CI-tested |
| **UI-2** | **React SOC workspace** (`web/`, "itsoc-web"): Overview, Findings, Incidents, Cases, Approvals, Intel, Network, Assets, Sources, Integrations, History, Reports, Settings | ✅ Built, live, vitest-tested |

**What works today:** the full detect-and-explain loop runs locally on the canonical format,
real RFC 3164 syslog (sshd/PAM), ManageEngine **Log360** exports (CSV + forwarded syslog), and
**Android logcat**. Deterministic rules own severity and correlation; the LLM only explains and
fills gaps below rule thresholds. On top of the engine, a Phase-B **SOC subsystem layer**
(`console/soc.py`) derives incidents (correlated finding-clusters with an analyst lifecycle),
observed assets/users, analyst cases, saved/downloadable reports, an offline threat-intel
summary, and honest metrics — every value derived from real data or returned as `null`/*n/a*.
Two front-ends read the same API: the vanilla-JS review console and a React SOC dashboard. A
labeled evaluation corpus guards every fix against regression.

**Current boundaries:** production-log validation still needs representative customer data;
live connectors are opt-in and only analyse events actually returned by the configured source;
the copilot cannot change severity, assign a ticket, approve an action, or execute remediation.

---

## 3. Architecture

Two layers, deliberately separated:

- **Detector** (`anomaly_detector.py`) — the validated original. A pure function
  `detect(records)` applying windowed rules: brute-force (≥5 real attempts/IP within a
  sliding 120s window), failure→success compromise, error-burst, suspicious-port, disk.
  Rules are **authoritative on severity**. Kept effectively frozen (see §4 for the one
  bounded edit); the pristine import is preserved in `archive/anomaly_detector_original.py`.
- **Analyzer** (`log_analyzer.py`) — chunks the log, runs the detector first, and feeds the
  pre-flagged anomalies to the LLM as authoritative context so the model **explains** rather
  than guesses severity. Anything below a rule's threshold (e.g. disk at 78%) is the model's
  to catch.

**The key design unlock (T5):** the reuse seam is the **record dict**
(`{n, ts, level, host, msg, raw}`), not a typed-event API. Real formats are supported by
converting them into that record shape:

```
raw log → normalize.py (envelope)  → rules_syslog.py (vocabulary) → anomaly_detector.detect() → LLM
          timestamp/host/level        real sshd/PAM phrasing →         (unchanged)
          year inference, WARN         the frozen regexes' wording
```

- **Envelope vs vocabulary are separate files** because they evolve at different rates
  (new sources touch the envelope; new phrasings touch the vocabulary).
- **`raw` is always the real log line.** Matching runs against canonicalized `msg`, but
  evidence shown to a human is the true line — honest, not a rewrite.
- New formats become **new sibling modules**, not edits to the validated core. Live siblings:
  `console/formats/log360.py` (Log360 CSV export + `|PRI|`-enveloped forwarded syslog) and
  `console/formats/logcat.py` (Android `threadtime` logcat). `normalize.sniff_format()`
  content-sniffs each strictly, so a new format can never steal another's lines.

### The SOC subsystem layer (Phase B)

Above the detect-and-explain loop sits `console/soc.py` — **display aggregations, never new
verdicts.** It reads the current run's findings/events (and small analyst-owned JSON stores in
`console/.soc/`) and derives:

- **Incidents** — findings clustered by shared primary entity + ≤30-min time chaining, with a
  deterministic id and an analyst lifecycle (`new → acknowledged → investigating → resolved`).
  Severity is the max member verdict (a roll-up); lifecycle timestamps record what actually
  happened, so MTTD/MTTR can't be faked.
- **Assets & users** — only entities the parser actually observed (hosts from events, IPs from
  finding entities, usernames via the same patterns `console/redact.py` masks). No inventory is
  invented; idle → an honest error, not an empty list.
- **Cases** — analyst-entered CRUD with lifecycle, notes, observables, attachments, workflow
  template links, and an explicit responsible-person field. The React board constrains scrolling
  to the board region so tickets cannot overflow the page.
- **Reports** — lists real files in `console/.soc/reports/`; generate renders the current run;
  export serializes it to CSV/XML/JSON/HTML/Markdown (`console/export.py`).
- **Threat-intel summary & metrics** — surfaces the offline STIX bundle + each rule's MITRE
  map; metrics are computed from real lifecycle data or returned `null` (rendered *n/a*).

Contract: [`docs/soc_subsystems.md`](docs/soc_subsystems.md). `console/serve.py` only routes;
`anomaly_detector.py` is never imported by any of it.

### Front-ends and egress

- Two UIs read the one API: the **vanilla-JS review console** (`console/anomaly_console.html`,
  served at `/`, no build step) and the **React SOC platform** (`web/`, Vite + React + TS +
  Tailwind + shadcn/Radix + TanStack Query/Table; a *pure consumer* that never computes a
  verdict). In dev, `web` runs on `:5173` and proxies `/api/*` to `serve.py` on `:8765`.
- The React workspace keeps the tour overlay on top of a real route, and the copilot separates
  concise answer, evidence, reasoning, and suggested next steps so dense dashboards remain usable.
- **One egress choke point:** `console/redact.py`. When the console is pointed at a remote
  compute node, every outbound byte passes through `redact()` first — the raw log is never
  transmitted; only redacted finding-lines go out. Local mode is the default (no egress).

---

## 4. What was built (commit by commit)

Feature commits, in order:

| Commit | Milestone | What shipped |
|--------|-----------|--------------|
| `fe696d8` | T1 | Endpoint-agnostic analyzer: OpenAI-compatible `/v1/chat/completions`, env config (`LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL`), deterministic default (`LLM_TEMPERATURE=0`), configurable chunk size (`--lines-per-chunk` CLI flag, default 100). Ollama local by default; Anthropic original archived. |
| `ef3ddf1` | T3 | Detector→analyzer integration. Detector runs in-process before the LLM; anomalies authoritative; retry-safe context via a shared `build_user_prompt` (closes the retry-path blind spot); in-analyzer dedupe; timestamp-based restatement matcher. 5/5 validation. |
| `05bf5b7` | T5 | Real syslog: `normalize.py` (RFC 3164 envelope, year inference w/ Dec→Jan rollover, proc/pid) + `rules_syslog.py` (sshd/PAM vocabulary → frozen regexes; POSSIBLE BREAK-IN sibling rule). Reuses `detect()` over the record dict; detector byte-identical; `raw` preserved. |
| `1585b1a` | T5a | Schema-drift fix: `validate_response()` checks top-level **and** item-level shape, retries on mismatch, emits a loud `analyzer_error` instead of a silent all-clear. Markdown-writer crash hardened. Auth-failure level → WARN to cut error-rate-spike noise. |
| `f8825f4` | T4 | Sliding-window brute-force severity replaces whole-file span (fixes sustained-attack under-rating). **The one bounded edit to the detector** — pristine original archived; sha baseline reset. |
| `867bcb6` | T4 | Username-spray enrichment: findings report distinct-username count at merge time (derived in the analyzer, detector untouched). |
| `21c96f0` | T4 | Variant A auth dedupe in `rules_syslog.dedupe_auth_attempts()`: one event per real attempt (OpenSSH 1122→524 events); entities carry true attempt counts; FP anchors all preserved. |
| `cc86b93` | T6 | Labeled eval corpus (`tests/eval/`) + `run_eval.py` scoring harness. 15/15 pass; mutation-tested to prove it can fail; non-zero exit = CI-ready. |
| `9d92674` | T9 (Stage C) | Threat-intel enrichment prototype in `threat_intel/` (branch `stage-c-threat-intel`). Matches the analyzer's flagged IPs against STIX/TAXII indicators → MITRE ATT&CK techniques. Offline-first (stdlib-only), downstream of the analyzer, core untouched. Import guard + `export_iocs.py` + demo + network-free smoke test. |
| `79880dd` | UI | Self-contained vanilla-JS **review console** (`console/anomaly_console.html`), ported from a Nocturne design export — no build step, no framework, no network (dropped the Google-Fonts import). |
| `677affb` | UI/audit | `rule_context.py`: emits a readable **rule predicate** (from the detector's live constants, so it can't drift) + an **event timeline** per finding. Deterministic, no model call. |
| `d3dc4fd` | Compare | Opt-in `--compare` **LLM-alone ablation**: a second *unprimed* pass records what the model rates each finding on its own → `llm_alone_severity` / `llm_alone_delta` / `compare.underrated_count`. Additive, default OFF, authoritative severities unchanged. Results cached; degraded chunks reported UNKNOWN (never counted as under-rated). |
| `9c706db` | UI | **Log-source picker** — `serve.py` runs with no `--input` and offers three sources: bundled samples, a local file (multipart upload, read locally), and fetch-from-URL (the only networked source; downloads public test data). `--input` still works as a shortcut. |
| `914fee9` | Honesty | 0-parsed input **skips the LLM entirely** and shows an "unrecognized format" state independent of finding count. Measured on a macOS log: 21 spurious model findings → 0. |
| `18a24d6` | Perf | LLM scoped to **chunks containing findings** (OpenSSH_2k: 80 chunks → 22), per-chunk context (87% smaller prompts), async `/api/analyze` (202 + progress polling), rules-only results published in ~8s. |
| `89f41a8` `9466352` `6f0df1b` | Perf | Ollama `keep_alive` pinned; **lazy explanations** (eager top-3, rest on demand via `/api/explain`); explanations tied to the specific finding they describe, never pasted across same-type findings. Diagnosis: warm call ≈14s; the earlier 72–131s was model reload + swap on a 16GB machine. |
| `9653e83` | UI | **Run history + navigation pane** — completed runs persist to `console/.runs/`; a restart restores the last run; the Runs button reopens any of the last 25. |
| `12998bb` | Docs | **`RUNBOOK.md` + `RUNBOOK.pdf`** — beginner-friendly, covers every use case. PDF generated by a stdlib-only writer (macOS 15 dropped the cups html/rtf filters). |
| `5f71a90` | UI | **Standalone HTML export** (`console/export.py`, "Download standalone") — one self-contained file, opens anywhere with **zero network requests**, no install. |
| `ac2e7db` | UI wiring | `console/serve.py` + `console/adapter.py`: one command runs the analyzer, adapts `report.json` → console state, and serves the reviewed run at `127.0.0.1`. `report.json` made **self-describing** (input + detector sha256, parsed/unparsed counts, ruleset). Integrity manifest (recomputable hashes, **not** a signature); target host derived from the log line; honest compare-not-run / partial / all-clear states. |

**Detector integrity:** current `anomaly_detector.py` sha256
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` (the 2026-08-25 pivot
baseline, after an owner-authorized defensive-hardening edit; the prior freeze was
`43f0560f…8312d05`, and before that the pristine import `d1b2ae80…b96d936` in `archive/`).
All UI, compare, and threat-intel work is **additive** — the detector stays byte-identical
through every commit above.

### Since the handoff (Aug 2026) — the SOC platform

A run of feature branches (each merged to `main` only after `run_eval.py` + `test_console.py`
stayed green and the detector sha256 was re-verified) built the platform on top of the frozen
engine. By theme:

| Theme | What shipped |
|---|---|
| **More formats** | Broadened accepted file types with honest rejection (`feat/formats`); **ManageEngine Log360** ingest as a sibling parser — CSV export + forwarded syslog (`feat/log360-ingest`); **Android logcat** parser — enables parsing only, no rule changes (`feat/android-logcat-format`). Eval held 17/17 throughout. |
| **MITRE surface** | Per-finding offline MITRE ATT&CK tag, labelled *derived, not a verdict* (`feat/mitre-surface`). |
| **Remote compute** | Optional remote compute-node toggle behind the `redact.py` egress choke point — raw log never leaves; only redacted finding-lines (`feat/remote-compute`). |
| **SOC backend (Phase B)** | Six real subsystems in `console/soc.py` — incidents, assets/users, cases, reports, threat-intel, metrics — with the data-model contract in `docs/soc_subsystems.md` (`feat/soc-subsystems`). `/api/overview` + `/api/ask` + attacker-status + all-runs aggregate (`feat/soc-overview-backend`, `feat/allruns-backend`). |
| **React SOC platform (Phase A→C)** | `web/` foundation — Vite + React + TS + Tailwind + shadcn shell, Overview + Alerts (`feat/web-foundation`); v6 SOC Overview reskin wired to real data (`feat/overview-v6-reskin`); real upload progress + run/version history + analyst streaming + persistent notifications + light/dark theme (`feat/overview-*`); URL-or-file upload dialog (`feat/upload-link-ingest`); honest unrecognized-format banner (`feat/overview-unrecognized-honesty`). |
| **Phase C pages** | Incidents, Threat Intel, Assets, Reports (`feat/phaseC-dwight`); Cases CRUD, Settings, honest Logout (`feat/phaseC-jim`). |
| **Downloadable exports** | `/api/export?format=csv\|html\|xml\|json\|md` — real serializations of the run's findings, `Content-Disposition: attachment`, honest `409` when idle (`feat/report-export-formats`). |
| **Read-only MCP server** | `itsoc_mcp/` — seven read-only tools (`analyze_log`, `list_runs`, `get_findings`, `get_evidence`, `explain_finding`, `export_run`, `threat_intel_lookup`) that a **client** of the local API (`http://127.0.0.1:8765`) exposes to MCP clients (Claude Code/Desktop) over stdio. It **computes no verdicts** — severity/correlation stay rule-owned; explanations are advisory; MITRE tags are derived. Raw log text is **redacted by default** through the existing `console/redact.py` egress choke point (raw only with `ITSOC_MCP_TRUSTED_LOCAL=1`); every response carries a provenance block with the detector sha256. Dependency-isolated (`requirements-mcp.txt` = the `mcp` SDK only; core `serve.py` still runs with zero installs); `test_mcp.py` is network-free (81 assertions) (`feat/itsoc-mcp`). |

Every one of these is **additive**: the detector is untouched, `raw` stays the real line, and
each subsystem shows real data or an honest empty/`n/a` state.

---

## 5. Files in the project

| File | What it is |
|------|------------|
| `log_analyzer.py` | Analyzer: format sniff → parser → `detect()` → LLM; schema validation, dedupe/restatement, username enrichment, JSON+MD report. |
| `anomaly_detector.py` | Validated detector (v1). One bounded edit (sliding-window severity). Rules own severity. |
| `normalize.py` | RFC 3164 envelope parsing: timestamp/host/proc-pid, year inference, level synthesis (`LEVEL_HINTS`, auth→WARN). |
| `rules_syslog.py` | Vocabulary canonicalization (sshd/PAM → frozen phrasing), `possible_break_in` sibling rule, `dedupe_auth_attempts()`. |
| `rule_context.py` | Emits the readable rule predicate (from live detector constants) + event timeline per finding. Deterministic. |
| `compare.py` | Opt-in `--compare` LLM-alone ablation → `llm_alone_severity`/`_delta` + `compare.underrated_count`. Additive; cache is gitignored. |
| `console/serve.py` | Stdlib local server + JSON API: picker, run history, port reclaim, `/api/*` routes (analysis, overview, incidents, assets, users, cases, reports, exports, metrics, threat-intel, live sources, integrations, and copilot). Routing only — no verdict logic. |
| `console/adapter.py` | `report.json` → console state (findings, events, severity counts, MITRE frequency, integrity manifest). |
| `console/soc.py` | Phase-B SOC subsystems: `derive_incidents`/`list_incidents`/`set_incident_state`, `derive_assets`/`derive_users`, cases CRUD, `list_reports`/`generate_report`, `threat_intel_summary`, `metrics`. Display aggregations; never a new verdict. Stores in `console/.soc/` (gitignored). |
| `console/export.py` | Standalone HTML export **plus** CSV/XML/JSON/Markdown serializers (`serialize()` / `SERIALIZERS`) behind `/api/export`. |
| `console/redact.py` | The single egress choke point — every byte leaving for a remote compute node passes through `redact()`. |
| `console/formats/` | Sibling format parsers feeding the record dict: Log360, logcat, RFC 5424, JSON, Loghub, ISO-8601 syslog, and auth CSV. Content-sniffed, strict. |
| `console/anomaly_console.html` | Vanilla-JS review console (served at `/`, no build step). |
| `console/test_console.py` | Backend/render suite: routing, log360, logcat, remote-compute, dashboard-data, layout, all-runs, SOC overview, SOC subsystems, export. |
| `web/` | React SOC workspace ("itsoc-web", Vite + TS + Tailwind + shadcn/Radix + TanStack). `src/pages/` covers Overview, Findings, Incidents, Cases, Approvals, Intel, Network, Assets, Sources, Integrations, History, Reports, and Settings; `src/lib/api.ts` is the typed client and `src/test/` contains the vitest suites. Pure API consumer. |
| `docs/soc_subsystems.md` | The SOC data-model + API contract (incidents/assets/cases/reports/threat-intel/metrics). |
| `RUNBOOK.md` / `.pdf` | Step-by-step guide for a first-time, non-technical user. Covers all use cases, troubleshooting, timings, limits. |
| `tests/eval/` | Labeled corpus (`manifest.json` + `.log` fixtures) and `run_eval.py` scoring harness (20/20 current baseline). |
| `archive/` | `anomaly_detector_original.py` (pristine detector reference). Obsolete model backups are intentionally not tracked. |
| `samples/` | Real LogHub datasets: `Linux_2k.log`, `OpenSSH_2k.log`, `Android_2k.log`; plus `log360_export.csv` / `log360_syslog.log`. |
| `sample-2.log` | 19-line synthetic baseline (canonical format, 3 planted issues). |
| `threat_intel/` | Offline-first enrichment: `threat_detector.py` (match IOCs→MITRE ATT&CK), `taxii_client.py` (STIX/TAXII, import-guarded), `mitre_attack.py` (ATT&CK mapper), exporters, demo bundle, tests, and live-mode requirements. Offline mode is stdlib-only. |
| `itsoc_mcp/` | Read-only MCP server (Stage C, read-only): `server.py` (MCP stdio wiring + tool registry, `main()` entry point), `tools.py` (the seven read-only tool implementations), `client.py` (stdlib urllib proxy to the local API), `redaction.py` (egress guard delegating to `console/redact.py`), `threat_intel_offline.py` (offline STIX→MITRE path reusing `threat_intel/`), `__main__.py` (`python -m itsoc_mcp`), `requirements-mcp.txt` (the `mcp` SDK only), `pyproject.toml` (packaging + `itsoc-mcp` console script), `test_mcp.py` (network-free, 81 assertions), `README.md` / `PUBLISHING.md`. Client of the backend; computes no verdicts. |
| `LICENSE` | MIT license (top level). |
| `.env.example`, `.gitignore`, `README.md` | Setup. Copy `.env.example` → `.env`; local Ollama needs no real key. |

### How to run
```bash
# LLM triage + integrated detection (canonical or syslog)
python3 log_analyzer.py --input samples/OpenSSH_2k.log --output report
# -> report.json, report.md

# Deterministic detector only (no model)
python3 anomaly_detector.py --input samples/OpenSSH_2k.log --output anomalies

# Review console (the app): one command → reviewed run at http://127.0.0.1:8765/
python3 console/serve.py                       # picker: bundled / local file / URL
python3 console/serve.py --input sample-2.log --compare
#   --compare  = also run the LLM-alone ablation (opt-in, doubles inference)
#   --report report.json      = review an existing report instead of re-analyzing
#   --threat-intel <report>   = merge MITRE/threat-intel chips

# React SOC dashboard (optional): backend + frontend
python3 console/serve.py --no-open             # API on :8765
cd web && npm install && npm run dev           # dashboard on :5173, proxies /api → :8765

# Share a run: one self-contained HTML file, or a CSV/XML/JSON/MD export
python3 console/export.py report.json -o run.html      # or --latest
#   or GET /api/export?format=csv|html|xml|json|md     # attachment, 409 when idle

# Tests (all run headless, no network, no model — CI-guarded)
python3 tests/eval/run_eval.py            # 20/20 expected
python3 threat_intel/test_threat_intel.py
python3 console/test_console.py           # backend + render + subsystems + export
cd web && npm test                        # React dashboard (vitest, jsdom)
```

### Configuration
- **Env (`.env`, 4 keys):** `LLM_BASE_URL` (default `http://localhost:11434/v1`),
  `LLM_API_KEY` (`ollama`), `LLM_MODEL` (`llama3.1:8b`), `LLM_TEMPERATURE` (default `0`).
- **Chunk size:** CLI flag `--lines-per-chunk` (default 25) on `log_analyzer.py` — not an env var.
- **Detector constants:** `BRUTE_FORCE_MIN_FAILURES` (5), `BRUTE_FORCE_WINDOW_SEC` (120),
  `COMPROMISE_SUCCESS_WINDOW_SEC` (120), `ERROR_BURST_MIN` (5), `ERROR_BURST_WINDOW_SEC` (60),
  `DISK_WARN_PCT` (80), `DISK_CRIT_PCT` (90), `SUSPICIOUS_PORTS`.
- **`normalize.py` `LEVEL_HINTS`:** maps synthesized levels (auth failures → WARN).

---

## 6. Known issues / tech debt

- **Disk severity is a parked product decision.** Current: ≥90% → high, 80–89% → medium.
  Arguably ≥90% should be critical. Changing it edits the detector and shifts every report —
  and now also requires updating `tests/eval/manifest.json` in the same commit (by design).
- **`possible_break_in` = medium** (arguably high). Documented; a reverse-DNS mismatch is a
  lower-confidence signal, so medium was chosen to avoid severity inflation.
- **Auth dedupe is a heuristic** (Variant A: drop IU/PAM lines when their PID has a
  Failed-password anchor). PAM-only logs (e.g. `Linux_2k`) have no anchors, so they are not
  deduped — intentional bias toward under-deduping over suppressing real attempts.
- **Small-model drift.** `llama3.1:8b` abandons the JSON schema on dense 100-line chunks. It
  now **fails loudly** (`analyzer_error`), not silently. Mitigate with a smaller
  `--lines-per-chunk` or a larger model.
- **LLM explanation coverage.** The model occasionally skips a `rule_id`, or writes one
  explanation for two same-type findings and names only one host. Those findings used to
  render `n/a` forever. A second pass now re-asks for each one individually (capped at
  `SECOND_PASS_MAX`, 6 per run); whatever it still cannot explain stays pending and is
  explained on demand, never filled with a placeholder. Deferred chunks are deliberately
  excluded — pulling them in would undo the wall-time bound.
- **Eval baseline caveat.** 15/15 / precision 1.000 means "unchanged vs known behaviour," not
  "correct in the wild." Its value is the next regression it catches; true accuracy needs
  production logs.
- **Compare-mode headline is ~21%, not a landslide.** A six-input benchmark at 25-line chunks
  (`benchmark_compare.md`, in the repo) measured 3 of 14 comparable findings under-rated, with
  the model *over*-rating 4 — and 2 of the 3 under-rated cases come from the synthetic
  `sample-2.log`. On real syslog it is 1 of 10. The defensible claim is narrower than a
  percentage: **the rules catch correlation the model doesn't** (failure→success compromise,
  blocked-but-suspicious egress). Chunk size was the other finding: 0 of 21 chunks degraded at
  25 lines vs 100% at 100 lines.
- **Explanations are partial by design on large logs.** Only the top-3 findings are explained
  eagerly; the rest are generated on demand when opened (~14s each). Anything deterministic —
  severity, evidence, rule predicate, timeline — is always complete.
- **Persisted since Aug 2026:** analyst marks and on-demand explanations are written back
  into the saved run (`POST /api/mark` → `persist_state()`), so a refresh, a restart or
  reopening a run tomorrow shows the review already done. Run history is ordered by the
  timestamp in the filename, not mtime — rewriting a run on every mark would otherwise
  have promoted it to "newest". Runs started from the shell (`--input` / `--report`) are
  saved to history too, which they previously were not.

---

## 7. Next steps

**Presentation layer — BUILT (beyond the original A/B/C roadmap)**
- Two front-ends over one local API: the vanilla-JS review console **and** the React SOC
  workspace (`web/`, Overview / Findings / Incidents / Cases / Approvals / Intel / Network /
  Assets / Sources / Integrations / History / Reports / Settings). Both are fully local;
  `--compare` shows the RULE-vs-LLM-alone contrast. CI runs
  the eval, threat-intel, console/backend, and dashboard (vitest) tests headless on every push.
- The Phase-B **SOC subsystem layer** (`console/soc.py`) + its contract (`docs/soc_subsystems.md`)
  are in: incidents with an analyst lifecycle, observed assets/users, cases, generated + saved
  reports, downloadable multi-format exports, an offline threat-intel summary, and honest
  metrics. Every value is derived or `null` — never a fabricated fill.
- The console was verified in a real browser earlier (headless Chrome, 1440px/820px, standalone
  `file://`): fixed a sub-1000px clipping (a breakpoint now stacks the panes) and a
  `var(--space-5)` typo (an undefined token zeroes the declaration) that `test_console.py` now
  guards for every stylesheet variable.

**Demand-driven follow-ups**
- **Real-log validation** on production logs for true FP/FN — blocked on data availability.
- **Remaining formats:** more vendor exports and multi-line stack traces; each new parser must be
  a sibling module with the fixed record shape. Existing support includes canonical, RFC 3164,
  RFC 5424, JSON, **Log360** CSV/syslog, **Android logcat**, Loghub, auth CSV, and EVTX history.
- **Deferred T4 tuning:** thresholds + `SUSPICIOUS_PORTS` to the real environment; the disk
  severity decision; optional LLM explanation second pass.

**Safety-boundary follow-ups (only when a real environment / need exists)**
- **MCP enrichment — DONE (read-only).** A read-only MCP server (`itsoc_mcp/`) exposes the
  local backend's existing analysis to MCP clients over stdio: `analyze_log`, `list_runs`,
  `get_findings`, `get_evidence`, `explain_finding`, `export_run`, `threat_intel_lookup`. It is a
  *client* of the API and computes no verdicts; raw log text is redacted by default via
  `console/redact.py`; every response carries a provenance block with the detector sha256.
  **Remaining:** any MCP tool that *writes* (analyst actions) and gated remediation stay out of
  scope until the security-gateway path exists (see T11).
- **T7 Continuous input** — broaden the existing collector and optional Splunk polling to more
  SIEM sources, with explicit back-pressure and connector health.
- **T8 Analyst feedback loop** — capture true/false-positive marks; refine rules + few-shot.
- **T9 Read-only enrichment** — offline threat-intel matching + MITRE ATT&CK is shipped. Live
  TAXII remains opt-in and certificate/token-only; offline stays the default (no log egress).
- **T10 RCA narratives** — incident correlation, evidence timelines, and copilot investigation
  guidance are shipped; richer root-cause narratives can be added without changing verdicts.
- **T11 Gated remediation (last)** — human-approved actions above a severity threshold, with
  a mandatory verify step; certificate/token via the API/security gateway, never
  username/password.

---

## 8. Design constraints (held throughout)

Data stays local (Ollama) · no model training · advisory AI · approval before every write or
connector action · certificate/token auth only · secrets never in prompts, code, `.env`, or logs
sent to any model.

---

## 9. Quick prompt to resume

> "Continuing itsoc in `~/Projects/log-analyzer`. Read PROJECT_HANDOFF.md. The local
> detect-and-explain loop runs via Ollama on canonical, RFC 3164, RFC 5424, JSON, Log360,
> Android-logcat, and other sibling formats, with a 20/20 regression harness. The SOC workspace
> includes the guided tour, focused copilot with separate reasoning, incidents, assignable cases,
> bounded kanban, approval-gated runbook templates, live collectors, optional Splunk polling,
> threat intel, reports, and a read-only MCP server. The detector is frozen at SHA-256
> `364577c5…a4a876`; rules own severity. The copilot is advisory and cannot assign, approve, or
> execute actions. Keep data local, require human approval for writes, and treat unavailable
> connectors as unavailable rather than inventing results."
