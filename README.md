# itsoc. — Local-first AI-assisted security operations

A local-first SOC workspace for turning raw logs into explainable, assignable work. The
deterministic detector owns every severity verdict; the AI copilot reasons over the evidence,
explains the dashboard, recommends next steps, and drafts work without changing a verdict or
executing an action. The default deployment keeps logs on your machine.

> **Design principle — honesty by construction.** Every number shown is derived from real data
> or reported as `n/a`. Severity comes only from the rules. MITRE tags are *derived context, not
> a verdict*. Unrecognized log formats are reported as "unparsed", never a false all-clear.

---

## What it does

- **Log anomaly detection** — deterministic rules (brute-force, failure→success compromise,
  error-burst, suspicious-port, disk pressure) over a wide range of formats: canonical
  `timestamp LEVEL host msg`, RFC 3164 syslog, ISO-8601 journald/rsyslog, RFC 5424, JSON-line,
  auth CSV (`timestamp,ip,username,status`), ManageEngine Log360 (CSV + forwarded syslog),
  Android logcat, Windows EVTX, Loghub envelopes, and more via the universal format layer.
- **Plain-language explanations** — the local model narrates each rule-caught finding with its
  evidence, rule predicate, and timeline. Advisory only.
- **SOC subsystems** — correlated incidents with a six-state analyst lifecycle, observed
  assets/users, a **Cases** board and case file (activity, observables, real attachments,
  eligible runbooks → pending approval only), generated/exported reports, offline STIX plus
  optional OEM IP lookup (`ITSOC_OEM=1`), and honest metrics.
- **Live ingestion** — a UDP syslog collector streams real events into a persistent store and
  surfaces dropped/lagging counts honestly.
- **Analyst workspace** — guided tour, focused copilot with separate reasoning, responsive
  dashboard cards, incident ownership, and a bounded kanban board for cases.
- **Response workflows** — reusable, approval-gated runbooks for investigations such as phishing
  triage and IP containment. Templates create a plan; a human still approves execution.
- **Live log analysis** — collector status and optional Splunk polling surface only events actually
  returned by an authorised connector; unavailable streams are shown as unavailable, never as fake
  live data.
- **Enrichment & connectors** — offline MITRE ATT&CK mapping; optional threat-intel provider
  lookups and vendor (OEM) API connectors, all with user-supplied, write-only credentials.
- **MCP server** — a read-only Model Context Protocol server exposes the analysis to MCP clients
  (Claude Desktop / Claude Code); it computes no verdicts.

### Active-scanning modules (opt-in, use with authorization)

The Discovery and Vulnerabilities modules run **real nmap scans** (host discovery + NSE vuln
scripts) against **private/loopback targets you own**. These are **active network operations**,
not read-only — every scan is user-initiated, public targets are refused, and results are stored
verbatim with source-reported severity.

---

## Quick start

**Requirements:** Python 3.9+, and [Ollama](https://ollama.com/download) for local explanations.

```bash
# 1. (once) pull the local model
ollama pull qwen3:8b

# 2. run the console
python3 console/serve.py
# -> opens the SOC dashboard at http://127.0.0.1:8765/
```

Upload a log (or pick a bundled sample) and you're analyzing. The rules run in under a second;
explanations fill in behind them. **The rules engine runs even without a model** — you get
verdicts and evidence, with explanations honestly skipped and marked as such.

Developing the React frontend (optional):
```bash
python3 console/serve.py --no-open      # API on :8765
cd web && npm install && npm run dev     # dashboard on :5173, proxies /api → :8765
```

---

## Tests

```bash
python3 tests/eval/run_eval.py        # labeled detection eval (20/20)
python3 console/test_console.py       # backend + subsystems
cd web && npm test                    # React dashboard (vitest)
```

---

## Design constraints

Data stays local (Ollama) · no model training · rules own severity, the LLM only explains ·
`raw` is always the real log line, never a rewrite · secrets are stored write-only and never
returned to the browser · the UI never claims more than it can prove.

## License

MIT — see [LICENSE](LICENSE).
