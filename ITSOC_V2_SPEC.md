# itsoc v2 — Product Spec & Phased Build Plan (for Claude Code)

**How to use this file:** this is the single guiding spec for itsoc's next chapter. Execute it
**one phase at a time**, each on its own branch, **detector-frozen** (`anomaly_detector.py`
sha256 `43f0560f…8312d05` must never change), **additive only**, all tests green before merge,
**stop-and-report after each phase**. The principles in §2 are absolute and override any task
that would violate them. Commit this file to the repo as the north star.

---

## 1. Identity — what itsoc IS

**A local, honest, rules-first log-anomaly detector with an AI analyst on top.**
Feed it a log (file or live stream) → deterministic rules decide the verdict → the LLM explains,
trends, and advises → everything it can't prove, it says so. Runs on your own machine.

The one line to hold: **"AI-first experience, rules-first verdict, honest by construction."**
The AI is first in *how you interact and understand*; the rules are first in *what is true*.

**What itsoc is NOT** (and must not drift into): not a SIEM/log-lake, not a network scanner,
not a vuln manager, not a black-box AI that decides. It sits *on top of* the tools SRE/SOC teams
already run; it never replaces them.

---

## 2. Non-negotiable principles (guardrails for EVERY phase)

1. **Rules own the verdict.** Severity and correlation come only from the frozen detector. The
   LLM explains, trends, forecasts, and advises — it **never sets, changes, suppresses, or
   escalates** a severity.
2. **AI-first = experience, not authority.** The AI drives the interface and the insight; it
   never drives the decision.
3. **Honest surfaces, always.** No invented data. `n/a` not a fake zero. "unparsed / 0 lines"
   not a false all-clear. **Deltas render only when a prior run exists.** **Live = real received
   events** only, never a simulated ticker. **Forecast = labeled extrapolation of real observed
   trend, never a conjured future attack.** Advisory output carries an advisory label and passes
   `explanation_guard` where it references findings.
4. **Read-only.** No active scanning, no remediation, no writes to the user's systems.
5. **Local by default / zero egress.** Anything that leaves the machine passes `console/redact.py`.
6. **Detector frozen.** New formats = sibling modules feeding the record dict. Any severity
   change updates `tests/eval/manifest.json` in the same commit.

**Do NOT rebuild what already exists and works:** the frozen detector, `explanation_guard`,
structured-output enforcement, `redact.py`, `fsafe.py`, `soc.derive_rca` (the RCA engine +
`/api/incidents/<id>/rca` + `api.incidentRca`), and `api.askStream` (SSE analyst streaming).

---

## 3. Feature disposition (the audit, decided)

The current build has ~13 nav items for ~4 ideas, plus a whole SIEM-shaped "Command Center"
grafted on. Refocus:

| Page | Decision | Action |
|---|---|---|
| **Overview** | KEEP | Becomes the honest metrics dashboard (§5). |
| **Alerts** → **Findings** | KEEP — the core | Rename. This is the product. Add the Review detail (§ below). |
| **Collectors** → **Sources** | KEEP | Read-only syslog receiver / tail = the sanctioned live ingest. |
| **Settings** | KEEP | Already honest. |
| **Incidents** | REBUNDLE | A facet of "Review"; the RCA panel lives in the incident detail. |
| **Assets / Users** | REBUNDLE | Observed-entities facet of Review. |
| **Threat Intel** | REBUNDLE | MITRE/IOC context facet (tag already on findings). |
| **Reports** | REBUNDLE + trim | Fold into Review; collapse exports to **HTML + JSON** (drop XML/MD). |
| **Cases** | REBUNDLE | Annotation facet of Review. |
| **Discovery** (nmap) | **CUT** | Active network scanning — violates read-only. |
| **Vulnerabilities** (nmap NSE) | **CUT** | Active scanning — violates read-only. |
| **Enrichment** (OTX/AbuseIPDB) | **CUT / fence** | External third-party egress — violates zero-egress. |
| **OEM Engine** (vendor polling) | **FENCE** | Behind an off-by-default experimental flag. |
| **History** (EVTX / Command-Center store) | **FENCE** | Behind the same experimental flag. |
| **Logout** | **CUT** | No real auth — a fake control. |

**Target nav after Phase 0:** `Overview · Findings · Sources · Settings`, plus an
**Experimental** section (hidden unless a flag is on) housing the fenced Command-Center pages.
The rebundled facets (Incidents/Assets/Threat-Intel/Reports/Cases) live *inside* the Findings/
Review experience, not as top-level nav.

**Fencing, not deleting:** the Command-Center code (`store.py`, syslog/EVTX/OEM) stays in the
repo behind the flag — nothing is lost, it's just out of the default first impression. The three
CUT pages (Discovery/Vulnerabilities/Enrichment) are removed from the nav and their scan/egress
actions disabled by default (they break principles 4 and 5).

---

## 4. The Review experience (rebundled)

Clicking a finding or incident opens a **master–detail Review** (not a page per facet): the
finding/incident, its evidence lines, the rule predicate + timeline, its MITRE tags (derived,
not verdict), related assets/users, the **RCA panel** (from the existing engine), and inline
lifecycle/case actions. One clear scope banner: **"You are reviewing THIS run"** — fixing the
current bleed where 5 findings coexist with 65 incidents and 73 store events from different
sources.

---

## 5. Overview — honest metrics dashboard (Grafana/Splunk-grade)

Replace the equal-weight cards with a real metrics dashboard. Each KPI is **derived or `n/a`**,
deltas **only with a prior run**, and every tile drills down (click → filtered Findings; brush
the time chart → filter the window).

| Metric | Source | Honest now? | Chart |
|---|---|---|---|
| Findings over time (by severity) | current run + history | yes | time-series (stacked) |
| Severity mix | run | yes | donut |
| Top rules / MITRE tactics (+ trend) | run + history | yes | bar + trend arrow |
| Findings volume, parsed/unparsed | run | yes | counters |
| MTTD / MTTR | incident lifecycle stamps | **n/a until stamps exist** | trend + basis count |
| False-positive rate | analyst marks | **n/a until marks exist** | trend |
| Explanation/automation coverage | run | yes | gauge |
| Data sources | run history | yes | counter |

Run header stays (filename, window+dates, lines parsed/unparsed, severity bar, findings count)
with the provenance line (ruleset + detector sha, model, generated-at) visible.

---

## 6. AI Analyst (chatbot → intelligent analyst)

Turn the chat rail into an **analyst that greets you with the state of things** and is
interactive. Five grounded roles, all advisory, all reading rule-owned verdicts:

1. **Trend digest** — "what threat types are common / rising" — deterministic counts by rule/
   tactic over the run + history; the LLM narrates.
2. **Honest forecast** — extrapolate the real observed trend ("brute-force on server-01 rose 3
   runs running"), **labeled `forecast · based on N runs`**, with a plain-language confidence.
   **Rules:** only extrapolate real counts; never name a specific future attack the data can't
   support; if history is too thin, say **"not enough runs to forecast."**
3. **Prioritized "look here first"** — reads rule severities + incident correlation and orders
   the queue with reasons. A reading of the verdicts, never a new one.
4. **Cited resolution** — remediation grounded in `console/.soc/runbooks/` via the **existing
   RCA runbook-citation engine**; honest "no runbook match" when nothing clears the bar.
5. **Run-over-run diff** — "what changed since last run" — deterministic diff, LLM narrates.

Build on the existing `api.askStream` SSE. All analyst output advisory-labeled; anything that
names a finding/entity passes `explanation_guard`.

---

## 7. Streaming / live activities

**Architecture:** read-only live source (the Sources syslog receiver / a tailed file) → rules
detect (**sub-second, instant verdicts**) → findings stream to the UI over **SSE** (live feed +
live-ticking metrics) → LLM explains **async/lazy** so it never blocks the stream. Bursts handled
with a ~15s window. **Live = real received events only.**

**Concurrency:** streaming = continuous writers + reviewers marking = the moment flat files stop
being enough. This is the documented **SQLite trigger** — live events persist to the existing
`console/store.py` (embedded sqlite3, atomic), reviewer state stays in the fsafe flat stores.

---

## 8. Phased roadmap — execute in order, one branch each

**Phase 0 — Refocus (do this first).** Collapse nav to `Overview · Findings · Sources ·
Settings`; rename Alerts→Findings; rebundle Incidents/Assets/Threat-Intel/Reports/Cases into the
Review detail; **cut** Discovery/Vulnerabilities/Enrichment/Logout from the nav and disable their
scan/egress actions by default; **fence** OEM Engine + History behind an off-by-default
`experimental` flag; trim exports to HTML+JSON; add the "reviewing THIS run" scope banner and fix
the multi-source data bleed. Tests + detector sha. Report.

**Phase 1 — RCA UI (backend already done).** Incident detail + RCA panel calling
`api.incidentRca` (facts always; runbook matched/no-match honestly; hypothesis advisory-labeled
or withheld-with-note); seed 2–3 real runbooks in `console/.soc/runbooks/`. vitest for each
honest state. Report.

**Phase 2 — Honest metrics Overview.** Build §5: time-series + top-N + trend arrows, deltas
only with a prior run, `n/a` for MTTD/MTTR/FP-rate until real data, drill-down on every tile.
Report.

**Phase 3 — AI Analyst.** Build §6: the greeting digest (trend + prioritize + cited resolution),
then the honest forecast with its labeling rules. Reuse `askStream` + the RCA runbook engine +
`explanation_guard`. Report.

**Phase 4 — Streaming live.** Build §7: SSE findings feed from the Sources collector, live
metrics, windowing, sqlite-backed event persistence. Report.

**Phase 5 — Interactivity polish.** Brush charts, click-to-explain, inline mark/lifecycle,
master–detail everywhere, live updates. Report.

Every phase: own branch, additive, `anomaly_detector.py` sha unchanged, and green
`tests/eval/run_eval.py` (17/17) + `console/test_console.py` + `web` vitest before merge.

---

## 9. Reality checks (honest, non-optional)

- **Metrics, forecast, and streaming only become meaningful with real history and real streams.**
  Build the frames now; they light up when real runs/streams flow. Show honest `n/a` /
  "not enough runs" until then — that honesty is itself a trust signal.
- **The binding constraint is unchanged:** a design partner with real production logs is what
  turns "impressive build" into "validated product." No phase here substitutes for that.
- **This is the Tier-2 leap** (live, multi-source, AI-driven). It fires the concurrency/sqlite
  trigger and reopens the production-data dependency — expected, just build accordingly.
- **Reuse, don't rebuild:** RCA engine, `explanation_guard`, structured output, `redact`,
  `fsafe`, `askStream`, and the sqlite store already exist. Wire them; don't re-create them.
