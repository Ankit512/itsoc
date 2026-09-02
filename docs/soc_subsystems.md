# SOC subsystems — data model and API contract (Phase B)

The contract the React frontend (Phase A) builds against. Every subsystem
below follows one honesty rule: **a value is either derived from data that
actually exists (parsed events, rule findings, saved runs, files on disk) or
entered by the analyst — never fabricated.** Where the honest answer is "not
enough data", the API returns `null` (and says why here), and the UI must
render that as *n/a*, never as zero-that-looks-like-good-news.

Rules own severity; the LLM only explains. Nothing in these subsystems can
change, suppress, or escalate a finding's severity. Incident/asset severity
labels below are **aggregations for display**, not new verdicts.

All stores live in `console/.soc/` (gitignored, like `console/.runs/`):

    console/.soc/incidents.json     derived incidents + analyst lifecycle
    console/.soc/cases.json         analyst-created cases (pure user data)
    console/.soc/reports/           generated report artifacts (HTML exports)

Logic lives in the sibling module `console/soc.py`; `console/serve.py` only
routes. The detector (`anomaly_detector.py`) is frozen and untouched.

---

## 1. Incidents — `GET /api/incidents`, `GET /api/incidents/<id>`, `POST /api/incidents/<id>/state`

**What an incident is.** A correlated cluster of the current run's findings.
The correlation rule (deterministic, documented here, implemented in
`soc.derive_incidents`):

1. Each finding's **primary entity** is the first IP among its chips; else its
   derived host; else its rule type. (These are values the parser actually
   observed — nothing is inferred.)
2. Findings with the same primary entity are sorted by timestamp and
   **chain-linked**: a gap of ≤ 30 minutes extends the cluster; a larger gap
   starts a new incident. Findings without timestamps join the entity's first
   cluster (stated in `timeUncertain`).
3. An incident is only ever created from ≥ 1 real finding. Empty incidents
   cannot exist.

Derived incidents are upserted into the store by a **deterministic id**
(`inc-<sha1(runId|entity|firstStamp)[:12]>`), so re-analyzing the same run
does not duplicate them and analyst lifecycle edits survive re-derivation.

**Lifecycle** (analyst-entered, the only mutable part):
`new → acknowledged → investigating → resolved`. `createdAt` = the earliest
finding timestamp (detection time, from the log itself — not "when the row
was written"). `acknowledgedAt` is stamped on the first transition out of
`new`; `resolvedAt` when entering `resolved`. Timestamps the analyst never
caused stay `null`.

Shape (list returns `{"incidents": [...]}`; `?state=<state>` filters; item
endpoint returns one object; unknown id → 404):

```json
{
  "id": "inc-3f2a9c1b04de",
  "runId": "attack-2026-08-18",
  "entity": "203.0.113.44",
  "entityKind": "ip | host | rule",
  "title": "203.0.113.44 — 3 correlated finding(s)",
  "severity": "CRITICAL",              // max member severity (display aggregation)
  "state": "new | acknowledged | investigating | resolved",
  "findingIds": ["detector-0", "detector-1"],
  "findingCount": 2,
  "techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
  "attackerStatus": "Spreading Inside",   // via tactic_phase_map; "" when unmapped
  "createdAt": "2026-08-13T02:16:44+00:00",   // earliest finding time = detection
  "firstSeen": "…", "lastSeen": "…",
  "acknowledgedAt": null,               // set by the analyst, else null
  "resolvedAt": null,
  "timeUncertain": false,               // true when a member had no timestamp
  "disposition": null,                  // E0 — analyst outcome, set only on close
  "dispositionReason": null,            // optional free text (<= 500 chars)
  "dispositionAt": null,
  "dispositionHistory": []              // append-only set/cleared audit trail
}
```

`POST /api/incidents/<id>/state` body `{"state": "acknowledged"}` — allowed
values above; the response is the updated incident. Moving backwards is
allowed (a mistaken resolve can be reopened) but never erases a timestamp
already earned; `resolvedAt` clears only when leaving `resolved` (documented
so MTTR can't be gamed by accident).

### 1a. Disposition (E0) — analyst-captured outcome on close

An incident closed by an analyst can carry a **disposition**: one of
`confirmed | false-positive | benign-expected`, plus an optional free-text
`dispositionReason` (≤ 500 characters). It answers "how did this actually turn
out?" — a question no rule can answer.

**Where it can be set.** ONLY on the lifecycle transition:

```
POST /api/incidents/<id>/state
{ "state": "closed", "disposition": "false-positive",
  "dispositionReason": "known internal scanner" }
```

The handler reads exactly `state`, `disposition` and `dispositionReason`
(`reason` is accepted as an alias) and ignores every other key, so a
disposition cannot be smuggled in beside another field. There is no PATCH/PUT
incident route, so this is the entire write surface. Rejected with **400**:

- a disposition outside the vocabulary,
- a disposition on any transition that is not a close,
- a `dispositionReason` with no disposition (no orphan reasons),
- a reason longer than 500 characters.

Closing **without** a disposition stays legal — an analyst who has not decided
is not made to invent one, and `null` reads as "none recorded".

**Lifecycle.** `disposition` describes a *closed* outcome, so re-opening an
incident clears it exactly as it clears `resolvedAt`. `dispositionHistory` is
append-only: every `set` (on a close) and every `cleared` (on a re-open) is
recorded with the analyst's reason, the from/to states and a timestamp, and is
never rewritten or erased. That trail is what the Incident History & Audit Log
panel renders, alongside the disposition chip.

**Additive by construction.** A store written before E0 has none of these keys.
It is never rewritten to gain them: `_public_incident` projects the neutral
defaults on read, `sync_incidents` carries the stored values across every
re-derivation (the same preserve block that protects absorbed case metadata),
and the cases→incidents migration only ever `setdefault`s them. `derive_incidents`
never produces a disposition, and `_strip_disposition` removes one from a
derived dict before it can reach the store — the transition is the only writer.

**Fence.** Disposition is analyst-captured *structured state*, never a control
signal. It does not affect detector severity, incident priority, runbook
eligibility, runbook execution, or any advisory/learned path. This is
structural, not a promise: `runbooks.eligible()` has a closed three-parameter
signature and projects its incident through `RULE_OWNED_INCIDENT_KEYS`, which
contains no disposition key — so eligibility cannot receive the field at all
and returns identical answers for every disposition value (asserted in
`console/test_console.py::check_incident_disposition`). `runbooks.py` does not
contain the word.

**Reports.** `soc.generate_report()` passes the dispositioned incidents to
`export.build(state, incidents=…)`, which appends an "Analyst dispositions"
section (id `analyst-dispositions`) listing incident, entity, state,
disposition, reason and timestamp — every field HTML-escaped, and an honest
"No incident has been dispositioned yet." when there are none. The plain
`/api/export` HTML path passes no incidents and is byte-for-byte unchanged.

## 2. Assets & users — `GET /api/assets`, `GET /api/users`

Derived **only from entities the parser actually observed** in the current
run: hosts come from parsed events, IPs from finding entities/chips, usernames
extracted from event messages and finding titles with the same patterns the
redaction module uses (`console/redact.py` — one vocabulary, two uses). There
is no inventory to invent: an asset that never appeared in a log does not
exist here.

```json
GET /api/assets -> { "assets": [
  { "id": "asset-host-app-01", "name": "app-01", "kind": "host | ip",
    "events": 143, "findings": 2, "atRisk": true,     // atRisk = ≥1 finding
    "lastSeen": "2026-08-13T02:18:00+00:00" } ] }     // null if no timestamps

GET /api/users -> { "users": [
  { "id": "user-admin", "name": "admin",
    "events": 6, "findings": 1, "atRisk": true } ] }
```

Both return `{"error": "no run yet…"}` when the server is idle — an empty
inventory would be indistinguishable from "no assets are at risk".

## 3. Cases — `GET/POST /api/cases`, `GET/PATCH /api/cases/<id>`

Pure analyst-entered data (that is what makes storing it honest). CRUD over
`cases.json`:

```json
{ "id": "case-1", "title": "Investigate 203.0.113.44",
  "notes": "…", "assignee": "",
  "status": "open | investigating | closed",
  "links": { "findings": ["detector-0"], "incidents": ["inc-…"] },
  "createdAt": "…", "updatedAt": "…" }
```

`POST /api/cases` requires `title`; `notes/assignee/links` optional; status
starts `open`. `PATCH /api/cases/<id>` accepts any subset of
`title, notes, assignee, status, links` and bumps `updatedAt`. Unknown id →
404; unknown status → 400. List returns `{"cases": [...]}` newest first.

### 3a. Cases → Incidents merge (C1-T1, additive; owner-ratified 2026-08-28)

Cases **absorb into incidents** so the merged Incidents screen carries the case
surface. The merge is ADDITIVE — nothing is dropped, no verdict is derived, and
the case endpoints above keep working unchanged. `soc.migrate_cases_to_incidents()`
projects `cases.json` into `incidents.json` (idempotent; run at server boot and
after every case create/patch):

- **A case linked to incident(s)** is projected onto **each** linked incident
  under `incident["cases"]` — an embedded, loss-free copy keyed by `caseId`.
  Many-to-many is explicit: the whole case travels to every incident it names,
  never folded into one. The incident keeps `origin: "rule"`. `linkedFindings`
  on the embedded record is the analyst's chosen findings and is kept **separate
  from** the incident's derived `findingIds` (which is recomputed every sync).
- **An incident-less case** (no resolvable incident link) becomes a **first-class
  MANUAL incident**: `origin: "manual"`, `findingIds: []`, `findingCount: 0`.
  Honesty is the point — a manual incident must never be confusable with a
  rule-detected one. It carries `manualBadge` = `"MANUAL — analyst-created, no
  rule verdict"`, `severity: null` (never a rule verdict), and `analystSeverity`
  is shown **only** if the analyst assigned one (label it *analyst-assigned*).

**Status map** (case status → incident operational `state`, explicit and
documented — never collapsed blindly). The analyst's real case status is also
preserved verbatim as `caseStatus`, so nothing is flattened away:

| case status   | incident `state` |
|---------------|------------------|
| `open`        | `new`            |
| `investigating` | `investigating` |
| `closed`      | `resolved`       |

The 5-state target lifecycle (`… → pending-approval → contained → …`) is **not**
introduced as incident states in C1: `pending-approval`/`contained` belong to the
C3/C4 approval/containment flow (phase order), so C1 maps into the existing
operational states and keeps the analyst's `caseStatus` intact.

**Preserve block (the silent-killer fix).** `sync_incidents` recomputes an
incident's derived fields on every analysis and previously preserved only
`state/acknowledgedAt/resolvedAt`. It now also carries `origin` and `cases`
across re-derivation — without that, absorbed case metadata would be silently
wiped on the next run.

**Legacy export.** `export.build_legacy_cases(cases)` writes a read-only, honest
JSON snapshot of the pre-merge case records with every free-text field
(`title/notes/assignee`) routed through `console/redact.py` (IPs, usernames,
hostnames masked). Empty means no cases existed — nothing is invented.

## 4. Reports — `GET /api/reports`, `POST /api/reports`

Lists **files that exist** in `console/.soc/reports/`; nothing is listed that
was not generated. `POST /api/reports` (no body needed) renders the CURRENT
run through the existing standalone exporter (`console/export.py`) and saves
it as `<runId>-<UTC stamp>.html`; 409 when no run is loaded.

```json
GET /api/reports -> { "reports": [
  { "name": "attack-2026-08-18-20260818T190301Z.html",
    "bytes": 48213, "createdAt": "2026-08-18T19:03:01+00:00" } ] }
POST /api/reports -> the new entry (same shape)
```

## 5. Threat intel — `GET /api/threat-intel`

Surfaces what `threat_intel/` already holds — no new data is created:

```json
{ "indicators": [ { "id": "indicator--…", "name": "Known brute-force source IP",
                    "pattern": "[ipv4-addr:value = '203.0.113.44']",
                    "types": ["malicious-activity"], "validFrom": "…" } ],
  "indicatorSource": "threat_intel/demo_threat_intel.json (offline STIX bundle)",
  "ruleTechniques": { "auth_bruteforce": [ {"id": "T1110", "name": "…", "tactic": "…"} ] },
  "attackCacheWarm": false }        // is ~/.cache/mitre_attack populated?
```

## 6. Metrics — `GET /api/metrics`

Every field is computed from real lifecycle data or is `null`:

```json
{ "openIncidents": 3,                  // store incidents not resolved
  "mttaSeconds": 420,                  // mean(acknowledgedAt−createdAt), only over
                                       // incidents an analyst acknowledged; null if none
  "mttrSeconds": null,                 // mean(resolvedAt−createdAt) over resolved; null if none
  "mttaBasis": 2, "mttrBasis": 0,      // how many incidents each mean is built on
  "assetsAtRisk": 2, "usersAtRisk": 1, // from the current run; null when idle
  "dataSources": 3 }                   // distinct source labels across saved runs
```

MTTA/MTTR are means over incidents that genuinely carry both timestamps; the
`*Basis` counts say how many that was, so a mean of one incident reads as
what it is. **The UI must render null as "n/a", never 0.**

---

## Phase D design (doc only — NOT built yet): real-time via SSE

`GET /api/stream?source=<bundled sample value>` — `text/event-stream`.

- **Source selection**: only whitelisted sources (the same `resolve_sample`
  whitelist the picker uses, or the currently loaded run's log). No arbitrary
  paths from the browser — same security boundary as `/api/analyze`.
- **Mechanism**: a server thread tails the file (`seek` to EOF, poll every
  0.5 s; inotify/kqueue later). New lines run through the SAME pipeline —
  `normalize` for the envelope, then the frozen detector's rules over a
  sliding window of recent records — so a streamed event is parsed exactly
  like a batch one. No separate "realtime parser" to drift.
- **Event shape**: `event: log` with the standard event dict
  (`{n, ts, level, host, msg, raw, bucket}`), and `event: finding` with the
  adapted finding when a rule fires on the window. A heartbeat
  (`event: ping`) every 15 s keeps proxies from killing the stream.
- **Backpressure**: per-client bounded queue (e.g. 500 events). On overflow
  the server drops oldest **and emits `event: gap` with the dropped count** —
  a silent drop would fake a quiet log. Client reconnect uses
  `Last-Event-ID` = last line number to resume without replaying the file.
- **Honesty**: streaming never bypasses rules; severities still come from the
  detector; LLM explanations stay on-demand only.
