# Stage C Phase C5 — Preparation Dossier & Reconnaissance (Card C5-P1)

**Audited Base Commit:** `3c0e6addbe934cde986d8ad4776569dd9facaaf4` (`main` @ `3c0e6ad`)  
**Branch:** `prep/c5-dossier`  
**Author:** Oscar (`oscar-mtcvctka`)  
**Status:** COMPLETE (Report-Only Dossier — Phase C5 Execution Remains Strictly Prohibited Until Phase C4 Formally Closes)

---

## Executive Summary & Epistemic Boundaries

Per **CARD C5-P1** directives, the phase order `C0 -> C1 -> C2 -> C3 -> C4 -> C5` is binding. Stage C Phase C4 is currently pending final integration closure. This dossier delivers the pre-work inventory, architectural reconnaissance, and procedural specifications required to begin Phase C5 execution cleanly and without mid-flight discoveries.

### Epistemic Method & Scope
- **What this audit establishes:** Exact filesystem paths, verified static code structures, line-number citations confirmed via repository greps, explicit call-site mappings for metric renames, and architectural gaps in collector back-pressure.
- **What this audit does NOT do (strictly forbidden):**
  - Zero demo execution or script runs.
  - Zero store resets or filesystem deletions (`.soc/`, `.runs/`, etc. are untouched).
  - Zero modifications to product code, backend services, frontend components, or tests.
  - Zero modifications to `web/dist/` or `anomaly_detector.py` (SHA-256 remains byte-identical `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`).

---

## 1. Fresh-Store Reset Procedure

Phase C5's Torq-comparison demo requires running two consecutive, clean executions from a verified pristine store state.

### 1.1 Verified Store Paths in Repository

All paths are defined relative to the repository root:

| Store Artifact | Repo Location Code Definition | Purpose & State on Reset | Reset Action |
| :--- | :--- | :--- | :--- |
| **Audit Hash-Chain** | `console/.soc/audit/chain.jsonl`<br>(`console/audit.py:51-53`) | Append-only ledger of approval, execution, and verification records. | **Delete file** (`unlink`). |
| **Derived Incidents** | `console/.soc/incidents.json`<br>(`console/soc.py:17, 46`) | Persisted incident state, lifecycle stamps, and absorbed case metadata. | **Reset to empty object `{}`**. |
| **Analyst Cases** | `console/.soc/cases.json`<br>(`console/soc.py:18, 46`) | User-created case management records. | **Reset to empty object `{}`**. |
| **SQLite History Store** | `console/.soc/soc_history.db`<br>(`console/store.py:22, 36-37`) | Relational store for ingested events, discovered assets, vulnerabilities, and IOCs. | **Delete file** (`unlink`) or recreate via `store.init_db()`. |
| **Generated Reports** | `console/.soc/reports/*`<br>(`console/soc.py:19, 1374`) | Generated HTML/JSON standalone report artifacts. | **Clear directory contents** (`rm -rf console/.soc/reports/*`). |
| **Run History** | `console/.runs/*.json`<br>(`console/serve.py:103`, `console/export.py:34`) | Historical log analysis snapshots. | **Clear directory contents** (`rm -rf console/.runs/*`). |
| **Live Console State** | `console/console_state.json`<br>(`console/serve.py:102`) | Live server state buffer. | **Reset to empty/idle state** (`rm console/console_state.json`). |
| **Target Host Firewall** | Target VM / Container (`demo/target`) | Active nftables ruleset with blocked source IPs. | **Flush firewall ruleset** (`nft flush ruleset` on target). |

---

### 1.2 CRITICAL PERSISTENCE NOTICE: `.soc/auth.json` MUST PERSIST

> **CRITICAL PERSISTENCE REQUIREMENT: `console/.soc/auth.json` MUST PERSIST ACROSS RESETS.**
> 
> - **Code Location:** `console/auth.py:26-27, 126` (`SOC_DIR / AUTH_FILE`).
> - **Rationale:** `console/.soc/auth.json` stores the PBKDF2/scrypt salt and password hash for the step-up authorization provider (`LocalDemoAuthProvider`). 
> - **Impact of Accidental Deletion:** If a reset script blindly wipes `console/.soc/` recursively with `rm -rf console/.soc`, the step-up authentication profile is destroyed. The Phase C5 demo's central gate — human approval with passphrase verification before firewall command dispatch — will fail closed (requiring manual re-registration and breaking the scripted, timed flow).
> - **Rule:** Any automated reset script or operator checklist **MUST EXPLICITLY PRESERVE** `console/.soc/auth.json` (and `console/.soc/keys/target_ed25519` if present).

---

### 1.3 Operator Reset Checklist (Human-Executable, Not Run)

```markdown
### Fresh-Store Reset Checklist (Execute Before Each C5 Demo Run)

1. [ ] Stop backend and collector processes:
       pkill -f "python3 console/serve.py" || true
2. [ ] Preserve Step-Up Auth profile:
       test -f console/.soc/auth.json && cp console/.soc/auth.json /tmp/itsoc_auth_backup.json
3. [ ] Reset JSON entity stores:
       echo "{}" > console/.soc/incidents.json
       echo "{}" > console/.soc/cases.json
4. [ ] Remove audit chain ledger:
       rm -f console/.soc/audit/chain.jsonl
5. [ ] Remove SQLite history database:
       rm -f console/.soc/soc_history.db
6. [ ] Clear generated reports and runs:
       rm -f console/.soc/reports/*
       rm -f console/.runs/*
       rm -f console/console_state.json
7. [ ] Restore Step-Up Auth profile:
       test -f /tmp/itsoc_auth_backup.json && mv /tmp/itsoc_auth_backup.json console/.soc/auth.json
8. [ ] Flush firewall state on demo target:
       ssh -i console/.soc/keys/target_ed25519 root@127.0.0.1 -p 2222 "nft flush ruleset"
9. [ ] Initialize clean schema:
       python3 -c "import store; store.init_db()"
10. [ ] Start backend server:
       python3 console/serve.py
```

*(Note: In accordance with Card C5-P1, this procedure was audited from source code and NOT executed).*

---

## 2. Battlecard Number Inventory (`docs/BATTLECARD_TORQ.md`)

To protect product honesty, every quantitative claim considered for customer-facing or competitor-comparison battlecards is categorized as either **SUPPORTED** (traceable to in-repo code/tests/benchmarks) or **UNSUPPORTED** (lacking in-repo basis; requires external literature citation or exclusion).

### 2.1 Three Non-Negotiable Citation Rules

The following three rules are binding and reproduced verbatim from `docs/research/CITATIONS.md` (`CITATIONS.md:10-26`):

1. **The arXiv 2604.19533 figure — best frontier LLM flagged ~3.8% of malicious events, no model passed 50% per-tactic — is a LITERATURE CITATION and never an in-repo measurement.** Nothing in this repository computes or contains this figure.
2. **It is never rounded.**
3. **It is never inverted into 'LLMs miss 96%'.**

---

### 2.2 Quantitative Claims Matrix

| Candidate Claim | Value / Metric | Status | Repo Verification / Provenance Source | Epistemic Boundary / Honesty Note |
| :--- | :--- | :--- | :--- | :--- |
| **Deterministic Detection Quality** | $F_1 = 1.000$<br>(Precision 1.000, Recall 1.000) | **SUPPORTED** | `tests/eval/run_eval.py:1-68`<br>(19/19 test cases pass) | Measured on the 19 standard evaluation cases. Does not imply $F_1 = 1.0$ on arbitrary zero-day telemetry. |
| **Deterministic Assembly Latency** | $< 120\text{ s}$ target<br>(measured $\approx 3.8\text{ ms}$) | **SUPPORTED** | `console/investigate.py:32-40`<br>`console/test_console.py` (C2-T1 check) | Assembles timeline, IOCs, entities, and blast radius from SQLite/rules in $< 5\text{ ms}$ without model calls. |
| **Advisory Grounding Score** | $\ge 0.95$<br>(measured $1.000$) | **SUPPORTED** | `console/investigate.py:270-310`<br>`console/test_console.py` (C2-T2 check) | Measured on `INC-4a7f` scenario via `explanation_guard.py` verifying `{n}` citations against source lines. |
| **Advisory Parallel Timeout** | Exactly $45\text{ s}$ | **SUPPORTED** | `console/investigate.py:27`<br>(`AGENT_TIMEOUT_SECONDS = 45`) | Hard limit on ThreadPoolExecutor futures for parallel advisory agents. |
| **Rule Severity Immutability** | $0\%$ mutation | **SUPPORTED** | `console/org_context.py:40-65`<br>`console/test_console.py` (C2-T3 check) | Severity is strictly immutable (`derive_priority` only adjusts priority P1..P4). Model has 0 input path. |
| **Step-Up Execution Guarantee** | $0$ bypass paths | **SUPPORTED** | `console/auth.py:100-140`<br>`console/actions/base.py:45-80` | Actions reject execution without cryptographic proof and valid approval ID. |
| **Frontier LLM Malicious Event Recall** | $\sim 3.8\%$ malicious events flagged;<br>no model $> 50\%$ per-tactic | **SUPPORTED<br>(EXTERNAL)** | `docs/research/CITATIONS.md:10-26`<br>(arXiv:2604.19533) | **External literature citation only.** Never claim as an in-repo measurement. Never round or invert. |
| **End-to-End Demo Duration** | $< 5\text{ minutes}$ wall-clock | **PENDING LIVE MEASUREMENT** | `docs/ITSOC_STAGE_C_BUILD.md:107` | Target only. Must be measured live during C5 execution and reported honestly (even if it exceeds 5 min). |
| **Redaction Choke Point** | $100\%$ masking of private IPs/hosts/users | **SUPPORTED** | `console/redact.py:1-180`<br>`tests/test_intake.py:24-40` | Masks sensitive identifiers before LLM egress and in action previews. |
| **Vendor Market Share / Competitor Latency** | Any Torq / SOAR speed claims | **UNSUPPORTED** | None | Must not make unverified claims regarding third-party vendor performance without pinned citations. |

---

### 2.3 Required Threat Intelligence Egress Disclosure

The battlecard must **explicitly disclose** the external threat intelligence egress exception rather than papering over it:
- **Code Reference:** `web/src/pages/OemEngine.tsx:34, 185`, `console/ti_oem.py:1-40`.
- **Disclosure Statement:** While itsoc maintains a sovereign local-compute boundary by default, enabling external Threat Intelligence enrichment (OTX, AbuseIPDB) transmits specific queried indicators (IPs, hashes) and credentials over HTTPS to external APIs. It does not send raw log files wholesale.

---

## 3. KPI Panel Feasibility & Metric Rename Audit

### 3.1 Store Timestamps Inventory

The following timestamps exist in the current store schema:

| Subsystem | Field Name | Format | Source / Setter |
| :--- | :--- | :--- | :--- |
| **Raw Events** (`store.py`) | `ts` | String / ISO | Verbatim source log timestamp (`normalize.py` / `syslog_collector.py`). |
| **Raw Events** (`store.py`) | `ingestedAt` | ISO UTC | SQLite insertion timestamp (`store.py:180`). |
| **Incidents** (`soc.py`) | `createdAt` | ISO UTC | Timestamp when incident was correlated/derived (`soc.py:145`). |
| **Incidents** (`soc.py`) | `acknowledgedAt` | ISO UTC | Timestamp when transitioned to `acknowledged` (`soc.py:278`). |
| **Incidents** (`soc.py`) | `investigatingAt` | ISO UTC | Timestamp when transitioned to `investigating` (`soc.py:284`). |
| **Incidents** (`soc.py`) | `resolvedAt` | ISO UTC | Timestamp when transitioned to `resolved` (`soc.py:290`). |
| **Cases** (`soc.py`) | `createdAt`, `updatedAt` | ISO UTC | Case creation and edit timestamps (`soc.py:760, 786`). |
| **Audit Ledger** (`audit.py`)| `ts` | ISO UTC | Timestamp of requested/approved/executed action step (`audit.py:60`). |

---

### 3.2 Computable vs. Necessarily `n/a` KPIs

| Metric | Calculation Formula | Computable? | Honesty & Prior-Run Basis |
| :--- | :--- | :--- | :--- |
| **MTTA (Mean Time to Acknowledge)** | $\text{mean}(\text{acknowledgedAt} - \text{createdAt})$ | **YES** | Null / `n/a` when basis $= 0$ (no incidents acknowledged). |
| **MTTR (Mean Time to Resolve)** | $\text{mean}(\text{resolvedAt} - \text{createdAt})$ | **YES** | Null / `n/a` when basis $= 0$ (no incidents resolved). |
| **Time to Approval (MTTAppr)** | $\text{mean}(\text{ts}_{\text{approved}} - \text{ts}_{\text{requested}})$ | **YES** | Derived from audit chain entries for corresponding `incident_id`. |
| **Time to Contain (MTTC)** | $\text{mean}(\text{ts}_{\text{executed}} - \text{ts}_{\text{approved}})$ | **YES** | Derived from audit chain entries. |
| **True MTTD (Mean Time to Detect)** | $\text{mean}(\text{createdAt} - \text{event.ts}_{\text{initial}})$ | **NOT RELIABLE** | **Must render `n/a`**. Raw event timestamps come from heterogeneous sources (RFC3164, RFC5424, custom logs) with varying clocks and timezone representations. Without normalized UTC parsing on all event sources, calculating true detection delta risks negative or inaccurate numbers. |

---

### 3.3 Metric Rename Analysis: `mttdSeconds` $\rightarrow$ `mttaSeconds`

#### The Problem
In `console/soc.py:1019-1020`:
```python
mttd, mttd_basis = _mean_seconds(
    (i.get("createdAt"), i.get("acknowledgedAt")) for i in incidents)
```
- `createdAt` is the time the incident was detected and derived by the system.
- `acknowledgedAt` is the time an analyst clicked to acknowledge the incident.
- **The calculation measures Time-to-Acknowledge (MTTA), but exports it under the label `mttdSeconds` (Time-to-Detect).**
- This is a mislabelled metric that contradicts the product's core commitment to honesty.

#### Call Sites Affected by Rename (Audit Only — No Edits Made)

1. **Backend Derivation:**
   - `console/soc.py:1019, 1028` (Function `metrics()`: calculate `mtta, mtta_basis` and return keys `"mttaSeconds"`, `"mttaBasis"`).
2. **Backend Tests:**
   - `console/test_console.py:2093-2095` (`check("metrics: no acknowledgements -> mtta/mttr are null", m["mttaSeconds"] is None ...)`).
   - `console/test_console.py:2121-2123` (`check("metrics: one resolved incident -> real mtta/mttr, basis 1", m["mttaSeconds"] is not None ...)`).
3. **Frontend API Types & Bindings:**
   - `web/src/lib/api.ts:138-142` (Interface `Metrics`: change `mttdSeconds` / `mttdBasis` to `mttaSeconds` / `mttaBasis`).
4. **Frontend Components:**
   - `web/src/components/OpsMetrics.tsx:5, 25-28` (Change tile label to `"MTTA"`, value `fmtDuration(m.mttaSeconds)`, description `"Mean time to acknowledge"`).
5. **Frontend Tests & Mocks:**
   - `web/src/test/helpers.tsx:96` (`METRICS` mock object).
   - `web/src/test/unrecognized-honesty.test.tsx:23, 39, 54, 93` (Mock metrics payload).
6. **Documentation:**
   - `docs/soc_subsystems.md:203-206`.
   - `docs/STAGE_C_HANDOFF.md:162`.
   - `docs/STAGE_C_PROGRESS.md:113`.
   - `docs/STAGE_C_OPEN_ITEMS.md:238`.

---

## 4. Collector Back-Pressure — Current State Reconnaissance

For Phase C5's collector hardening, this reconnaissance documents how `console/syslog_collector.py` behaves under overload today.

### 4.1 Architectural Breakdown of Ingestion Today

```
[UDP Datagram / TCP Stream]
          │
          ▼
   Listener Thread (_UDPListener._run / _TCPListener._client)
          │
          ▼  (Synchronous Parse)
   parse_syslog()
          │
          ▼  (Direct Synchronous SQLite Call)
   SyslogCollector._store(event)
          │
          ▼
   store.insert_event(event)  ───>  console/.soc/soc_history.db (SQLite)
```

### 4.2 Overload Failure Modes in Code Today

1. **Absence of Ingestion Queue:**
   - There is **no in-memory queue** (`queue.Queue`) between the listener thread and the SQLite store in `console/syslog_collector.py`.
   - Ingestion is purely synchronous: `self.stored += self.owner._store(event)` (`syslog_collector.py:146`).

2. **Silent UDP Datagram Drops in Kernel Stack:**
   - `_UDPListener._run()` (`syslog_collector.py:165-180`) loops on `self.sock.recvfrom(MAX_DATAGRAM)`.
   - If SQLite disk I/O slows down during heavy ingest, the single listener thread blocks on `_store()`.
   - The OS kernel UDP socket receive buffer fills up and drops arriving datagrams.
   - **Userland impact:** Drops occur at the OS network layer; `syslog_collector.py` has **zero drop counter** and cannot detect or display these drops.

3. **Silent Exception Drops on SQLite Lock/Failure:**
   - In `SyslogCollector._store()` (`syslog_collector.py:346-351`):
     ```python
     def _store(self, event):
         try:
             return 1 if store.insert_event(event) else 0
         except Exception as exc:
             self._last_error = f"store insert failed: {exc}"
         return 0
     ```
   - If SQLite encounters `OperationalError: database is locked` or transaction timeout under burst load, the exception is caught, recorded in `self._last_error`, and `_store` returns `0`.
   - The event is **silently dropped** without incrementing a dedicated `droppedCount` metric or emitting an alert.

4. **Unthrottled Thread Spawning on TCP Connection Bursts:**
   - `_TCPListener._run()` (`syslog_collector.py:196-209`):
     ```python
     threading.Thread(target=self._client, args=(conn, addr),
                      name=f"syslog-tcp-client-{self.port}", daemon=True).start()
     ```
   - Every incoming TCP connection spawns a new unpooled thread. Under a connection flood, thread exhaustion occurs.

5. **Status API Deficiencies:**
   - `SyslogCollector.status()` (`syslog_collector.py:353-393`) reports:
     - `receivedCount: sum(x["received"])`
     - `storedCount: sum(x["stored"])`
     - `error: self._last_error`
   - **Missing Metrics:** `droppedCount`, `laggingCount`, `queueCapacity`, `queueUsed`.

---

### 4.3 Contrast with Existing SSE Streaming Queue (`console/serve.py`)

A mature bounded-queue pattern already exists in `console/serve.py:808-855` for SSE tailing (`StreamQueue`):
- `STREAM_QUEUE_LIMIT = 500`
- Explicit overflow handling: on overflow, the oldest item is evicted, `self._dropped` is incremented.
- Stream frames emit `("gap", {"dropped": dropped}, None)` so downstream consumers (and the UI) are explicitly notified of lost telemetry.

**Phase C5 Recommendation:** Adapt the `StreamQueue` bounded pattern into `SyslogCollector`, introducing an in-memory ring buffer/queue between listeners and SQLite, with explicit `ingested`, `dropped`, and `lagging` counters exposed to the Sources screen.

---

## 5. Summary & Hand-Off Status

| Dossier Deliverable | Status | Verification Reference |
| :--- | :--- | :--- |
| **1. Fresh-Store Reset Procedure** | **COMPLETE** | Exact paths verified; `.soc/auth.json` persistence prominently flagged. |
| **2. Battlecard Number Inventory** | **COMPLETE** | All claims classified; verbatim arXiv 2604.19533 citation rules included; TI egress noted. |
| **3. KPI Feasibility & MTTA Audit** | **COMPLETE** | Available timestamps catalogued; all 10+ call sites for `mttdSeconds` $\rightarrow$ `mttaSeconds` mapped. |
| **4. Collector Back-Pressure Recon** | **COMPLETE** | Failure modes in `syslog_collector.py` documented; architectural recommendation drafted. |

**Execution Boundary:** Zero product code or test files were modified. Allowlist strictly limited to `docs/C5_PREP.md`. Ready for review by `god`.
