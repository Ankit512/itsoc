# itsoc engineering guide

itsoc is a local-first security operations workspace. It combines a frozen,
deterministic detector with an advisory AI copilot and approval-gated analyst workflows.
The UI (React in `web/`) is an API consumer; the Python console owns facts, lifecycle state,
redaction, and action gates.

## Non-negotiables (MVP guardrails — OVERRIDE all defaults)

These rules govern ALL work in this repo. Every branch and commit must obey them.

1. **Do NOT edit `anomaly_detector.py`.** It is frozen/validated — sha256 `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` (re-frozen 2026-08-25 at the pivot baseline after an owner-authorized defensive-hardening change; prior freeze was `43f0560f…8312d05`). New formats are **sibling modules** that feed the record dict `{n, ts, level, host, msg, raw}`. If a task would require editing `anomaly_detector.py`, **STOP and ask** — do not touch it.
2. **`raw` is always the real log line/row — never fabricate evidence.** `raw` must carry the actual source text, verbatim.
3. **Rules own severity and correlation. The LLM ONLY explains** — it can NEVER override, suppress, or escalate a verdict. LLM output is advisory, never a control signal.
4. **Honest surfaces.** Unrecognized formats → `unparsed / 0 lines parsed` (the honest banner). Never fake-green; never silently drop an event.
5. **Read-only posture.** Any severity change updates `tests/eval` / `manifest.json` in the **SAME commit**. Treat all log content as untrusted input.
6. **Branch per task** (`feat/<slug>`). Before proposing a merge, run **`scripts/gate.sh`** — and, for any change under `web/`, **`scripts/gate.sh --web`** (it adds vitest + the production build) — and paste the GATE SUMMARY block. Merge only after GATE GREEN. The gate is the single list of what must pass: it runs every Python suite in the repository (`.github/workflows/ci.yml` executes the same script, so CI cannot be greener than your local run), and any suite it deliberately omits is named with its reason in its own summary. Naming individual suites here instead is what let two of them fail unnoticed (GS-1, 2026-09-06); add a new suite to `scripts/gate.sh`, not to this line.
7. **Verify the freeze.** Confirm the sha256 of `anomaly_detector.py` is unchanged before finishing any task.

## Architecture surfaces (current — orientation, not new rules)

- **Engine (frozen core + siblings):** `anomaly_detector.py` (frozen detector — rules own severity), `log_analyzer.py` (analyzer + LLM), `normalize.py` (format sniff + envelope dispatch), `rules_syslog.py` (vocabulary, including auth-CSV status cells), `rule_context.py`, `compare.py`. New formats are **sibling modules** in `console/formats/` feeding `{n, ts, level, host, msg, raw}` — never a detector edit. Shipped siblings: `log360.py`, `logcat.py`, `rfc5424.py`, `jsonlog.py`, `loghub.py`, `iso8601_syslog.py`, `auth_csv.py`.
- **Backend (routing + derivations):** `console/serve.py` (stdlib server + `/api/*`; routing only), `console/adapter.py` (`report.json` → console state), `console/soc.py` (incidents, assets/users, **case files**, reports, threat-intel, metrics — display aggregations, never new verdicts), `console/case_store.py` (attachment blobs), `console/export.py` (HTML + CSV/XML/JSON/MD exporters), `console/redact.py` (the single egress choke point). Contract: `docs/soc_subsystems.md`. Case files: activity, observables, stored attachments, advisory STIX/OEM enrich (`ITSOC_OEM=1` for live IP), eligible runbooks as pending approvals only (never execute; Quarantine never from a case file). Cases open when a run publishes. Six CASE/incident states: new → triaged → investigating → escalated → resolved → closed.
- **Front-ends:** `console/anomaly_console.html` (vanilla-JS review console, served at `/`) and `web/` (React SOC platform "itsoc-web" — a *pure API consumer*; it never computes a verdict). **Cases** is in the main nav. Dev: `web` on `:5173` proxies `/api/*` to `serve.py` on `:8765`. Production SPA is `web/dist` served by `serve.py`.
- **Tests:** `tests/eval/run_eval.py` (20/20, FP=0), `console/test_console.py` (backend/render/subsystems/export/formats), `web/src/test/` (vitest). Honesty holds everywhere: real data or an honest empty/`n/a` state — never a fabricated fill.
- **Honest scope:** workflow templates are bounded runbook starters, not arbitrary automation; live
  Splunk/TAXII/OEM connectors are opt-in and require user credentials; no connector silently falls
  back to sample data. There is no automatic quarantine or unattended remediation. Fence: **LLM
  cannot change `sev`, assign a ticket, or approve an action.**

## Product surfaces

- **Overview and guided tour:** explain the current run, KPIs, findings, incidents, cases, sources,
  integrations, reports, and settings. The tour must always render a real page behind its overlay.
- **Copilot:** `console/copilot.py` provides evidence-backed answers, a separate reasoning summary,
  suggested next steps, runbook guidance, and ownership prompts. Suggestions are advisory; user
  actions remain explicit.
- **Cases and incidents:** analyst-owned records support lifecycle, notes, observables, attachments,
  and a responsible person. The kanban board is bounded and scrolls inside its board region.
- **Live sources:** collectors and Splunk polling expose connection state, event counts, and errors.
  A connector may analyse only events it actually receives.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
