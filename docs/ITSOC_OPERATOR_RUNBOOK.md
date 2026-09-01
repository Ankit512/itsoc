# itsoc Operator Runbook

**Purpose:** a practical guide for running the local SOC console, moving from raw
logs to evidence-backed triage, and recording the next safe action.

**Audience:** analysts, incident responders, and reviewers who need to understand
what each screen does and how to use it. This guide assumes the repository is
already checked out locally.

**Operating principle:** rules own severity and workflow eligibility. The analyst
copilot explains real evidence, proposes next steps, and drafts work; it does not
change severity, silently assign people, execute a connector, or approve a response.

## 1. Start the console

1. Install Python 3.9+ and, optionally, Ollama for local explanations.
2. From the repository root, start the console:

   ```bash
   python3 console/serve.py
   ```

3. Open <http://127.0.0.1:8765/>. The server binds to loopback only.
4. For frontend development, run a second terminal with:

   ```bash
   npm --prefix web run dev -- --host 127.0.0.1
   ```

   Then open <http://127.0.0.1:5173/>.

5. Stop the console with `Ctrl-C` in the server terminal. Do not expose the
   console on a public interface.

### Optional model setup

The rules engine works without a model. To enable richer explanations, start
Ollama and install the configured model:

```bash
ollama serve
ollama pull qwen3:8b
```

The UI labels model-offline states honestly; deterministic findings and evidence
remain available. Model output is advisory and never controls severity.

## 2. First-use tour and navigation

The `itsoc.` wordmark is a home control: click it from any screen to return to
Overview. The left navigation contains:

| Screen | What it does | How to use it |
| --- | --- | --- |
| Overview | Current-run posture, severity counts, trends, ATT&CK tactics, and latest findings. | Start here after ingest; click a finding to open its evidence. |
| Findings | The rule-owned finding inventory and source-line evidence. | Filter by severity or search; open a row for the full investigation. |
| Incidents | Correlated finding clusters and lifecycle state. | Select an incident, review its timeline, add an owner, and use the response checklist. |
| Cases | Analyst-entered case files and the bounded kanban board. | Create a case, link findings/incidents, set status, and record a responsible person. |
| Approvals | The single review surface for eligible response requests. | Verify evidence, eligibility, approver, and scope before approving. |
| Intel | Offline STIX/MITRE context plus clearly marked optional enrichment. | Use derived tags as context, never as a replacement for a finding. |
| Network | Private-target discovery and vulnerability views. | Confirm the target is authorised before starting a scan. |
| Assets | Observed hosts and entities from the current data. | Use it to pivot from a finding to affected infrastructure. |
| Sources | File uploads, URL ingestion, and local collectors. | Choose a source, verify the privacy note, then ingest. |
| Integrations | Connector catalog and configuration status. | Configure a connector, test it, and inspect the masked result. |
| History | Saved runs and persistent event history. | Reopen a prior run to compare evidence without changing it. |
| Reports | Generated evidence reports and action trail. | Generate or open a report after triage to preserve the review record. |
| Settings | Compute location, theme, and local configuration. | Keep local mode for sensitive logs; remote mode is explicit and redacted. |

Use **Learn the workspace** in the copilot or **Start guided tour** in the command
palette for a step-by-step tour. The tour always starts at Overview and each step
contains the purpose, the visible control, and the next move.

## 3. Ingest a log

1. Click **Upload logs** in the top bar.
2. Choose one of the supported local text formats (`.log`, `.txt`, `.csv`, `.tsv`,
   `.json`, `.xml`, `.html`, `.raw`) or a Windows `.evtx` file.
3. Alternatively, paste a trusted public text URL. URL ingestion is the only
   normal path that makes an outbound request; it downloads data to this machine.
4. Wait for the progress notification. Do not navigate away to cancel it—the job
   continues and the notification links to its result.
5. If the format is unsupported or empty, use the honest error message to correct
   the source. A zero-finding result is not an all-clear.

The analyzer parses locally, stores the run, and links every finding back to source
line numbers. It does not connect back to the system that produced the log.

### Compare mode

Enable **Run compare (LLM-alone)** only when evaluating model/rule differences. It
runs a second, slower pass without rule findings supplied to the model. Use this
for quality review, not routine triage. The rule-owned result remains authoritative.

## 4. Read Overview and Findings

1. In Overview, read the run banner first: source, time window, parsed lines, and
   whether a model explanation is available.
2. Read the severity cards as counts, not as a verdict about the whole environment.
3. Use **Latest alerts** to open the strongest candidate in Findings.
4. In Findings, inspect the rule name, rule severity, predicate, matched lines,
   timeline, host, and ATT&CK tags.
5. Use the source-line link to verify the evidence. Keep the line reference in any
   external ticket or report.
6. Add an analyst mark only after reviewing the evidence. A mark records judgement;
   it does not rewrite the rule result.

## 5. Use the copilot as an analyst

Open the floating **itsoc Analyst** button. The panel is intentionally compact:

- **Interpret** answers a focused question using the current page, current run,
  selected finding/incident, and cited source lines.
- **Plan** is a separate, inspectable reasoning summary. It shows scope, available
  evidence, prioritisation, and the safe next move. It is a plan—not hidden
  chain-of-thought and not an execution control.
- **Start here** identifies the highest-priority rule-owned finding.
- **Trend** compares saved runs when enough history exists.
- **Forecast** shows statistical watch conditions only when the run history supports
  them; it never invents a future detection.
- **Runbook** shows shipped response definitions and rule-owned eligibility. It
  does not execute them.

### Recommended copilot workflow

1. Click **Explain this page** to get a current-screen briefing.
2. Read **What the dashboard says**, then **Next best actions**.
3. Ask a narrow question such as `Why was detector-12 classified as HIGH?`.
4. Open the cited finding and verify the source line yourself.
5. Use the suggested deep link to move to Findings, Incidents, Cases, or Reports.
6. Ask **Which tickets need a responsible person?** before handing work off.

The copilot can recommend an owner or show unassigned cases, but it never changes
ownership automatically. Model responses are streamed when available; the local
evidence-grounded answer is used when the model is unavailable.

## 6. Triage an incident and assign responsibility

1. Open **Incidents** and select the correlated cluster.
2. Confirm the member finding IDs, entity, first/last seen times, and rule-owned
   severity.
3. Use the timeline and live log panel to distinguish repeated noise from a chain
   with a successful login or other corroborating evidence.
4. Set the lifecycle state (`New`, `In progress`, `Resolved`, or `Closed`) only
   after recording why.
5. Set the **Responsible person** on the incident/case. Choose the analyst or team
   who owns the next investigation step; do not use ownership to change severity.
6. Complete the response checklist and record useful notes.
7. If a shipped runbook is eligible, request approval. The approval surface—not the
   copilot—is where an authorised reviewer makes the decision.

## 7. Manage cases and the kanban board

1. Open **Cases** and click **New case**.
2. Give the case a concise title, add notes, and link the relevant finding or
   incident IDs.
3. Choose a lifecycle status and add a responsible person.
4. Use the bounded board columns to move work through its lifecycle. Each column
   scrolls within the board, so a large ticket set stays inside the page.
5. Use the case file to record observables, attachments, activity, and related
   cases. The case copilot is scoped to that file.
6. For email phishing, use the phishing workflow template: preserve the message,
   inspect sender/authentication and links, contain affected accounts or URLs only
   through approved controls, then document user notification and recovery.

## 8. Integrations and live log analysis

The Integrations page separates local connectors from outbound feeds. Each card
shows status, egress policy, endpoint/configuration location, and a **Configure**
and **Test connection** path. Credentials are masked and never shown in the UI.

For optional Splunk live analysis:

1. Open **Integrations** and locate the Splunk/live log connector.
2. Configure its endpoint and credential through the connector form; do not paste
   secrets into chat or a report.
3. Enable the explicitly labelled OEM/outbound mode only when your organisation
   authorises egress:

   ```bash
   ITSOC_OEM=1 python3 console/serve.py
   ```

4. Test the connector and verify the masked response.
5. Open the live stream panel from Sources/Integrations and start polling. Review
   the connection state, last event time, and error state.
6. Stop the stream before changing its query or endpoint. A stream can feed new
   lines into the local analyzer; it does not grant permission to take response
   actions automatically.

Keep OEM mode off for offline/local-only operation. When a connector is disabled,
the UI reports that state instead of displaying sample events as live data.

## 9. Reports and audit trail

1. After triage, open **Reports**.
2. Generate a report for the current run or open an existing saved artifact.
3. Verify the report includes run identity, findings, evidence references, analyst
   decisions, ownership, and approval history.
4. Share the generated report through your approved channel. It is an artifact of
   the local run, not a command to a connector.

## 10. Safety and data-handling rules

- Treat rule severity and runbook eligibility as authoritative inputs.
- Treat copilot prose, forecasts, tags, and enrichment as advisory context.
- Verify source lines before containment or escalation.
- Never paste credentials, API keys, or raw sensitive logs into chat.
- Keep the server bound to `127.0.0.1` unless an approved deployment explicitly
  provides authentication and network controls.
- Use approvals for response actions. The console is not a silent SOAR executor.

## 11. Troubleshooting

| Symptom | Check | Resolution |
| --- | --- | --- |
| Blank page | Browser console and network request for the hashed asset. | Rebuild with `npm --prefix web run build`, then hard-refresh. A stale asset must return 404 rather than HTML. |
| Backend is not reachable | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8765/` | Start `python3 console/serve.py` from the repository root. |
| Copilot says model offline | Overview run banner and Ollama status. | Start Ollama/pull the configured model, or continue with deterministic evidence-grounded answers. |
| No findings | Run banner, parser error, and source format. | Confirm the file is text, non-empty, and recognised; do not interpret zero findings as safe. |
| Splunk stream unavailable | Integrations status, OEM flag, endpoint, and masked credential state. | Enable authorised OEM mode, test the connector, and inspect the last connector error. |
| A ticket is still unassigned | Case/incident responsible-person field. | Assign a named analyst/team manually after reviewing the copilot recommendation. |
| Board cards overflow | Browser width and board column scrollbars. | Use the board's internal column scroll; reduce zoom or widen the window on small screens. |

## 12. Verification commands for maintainers

Run these before handing a change to an operator:

```bash
npm --prefix web test -- --run --testTimeout 10000 --silent
npm --prefix web run build
python3 console/test_console.py
python3 console/test_copilot_workspace.py
```

The first two commands verify the UI and production bundle. The console tests
verify backend invariants, including rule-owned severity, evidence grounding,
ownership guidance, and safe copilot actions.
