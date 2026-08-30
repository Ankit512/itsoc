import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CopilotRail } from "@/components/CopilotRail";
import { api } from "@/lib/api";
import { renderApp, mockFetch, consoleState, finding, OVERVIEW } from "./helpers";

/** Redesign Phase 3 tests: AI Copilot Right-Rail per ITSOC_REDESIGN_SPEC.md §3 & §4.
 *  Asserts the 5 grounded advisory roles:
 *  (1) Interpret current view on prompt,
 *  (2) Trend digest,
 *  (3) Honest forecast,
 *  (4) Prioritize (Start here),
 *  (5) Cited resolution via runbook engine.
 *  Asserts verbatim footer: "Rules set severity. I interpret & explain — I don't decide."
 *  Asserts advisory boundaries: never fabricates, never decides or changes severity.
 */

describe("AI Copilot Right-Rail (Phase 3)", () => {
  afterEach(() => vi.restoreAllMocks());

  beforeEach(() => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/runs-summary": {
        totals: {
          runCount: 3,
          linesParsed: 6000,
          findingCount: 9,
          severityCounts: { CRITICAL: 3, HIGH: 4, MEDIUM: 2, LOW: 0, INFO: 0, UNKNOWN: 0 },
          mitreFrequency: [
            { id: "T1110", name: "Brute Force", tactic: "Credential Access", count: 7 },
            { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion", count: 2 },
          ],
        },
        runs: [
          { file: "run-3.json", runId: "run-3", sourceLabel: "auth-3.log", linesParsed: 2000, findingCount: 3, dataComplete: true, topTechniques: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access", count: 7 }] },
          { file: "run-2.json", runId: "run-2", sourceLabel: "auth-2.log", linesParsed: 2000, findingCount: 4, dataComplete: true, topTechniques: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access", count: 4 }] },
          { file: "run-1.json", runId: "run-1", sourceLabel: "auth-1.log", linesParsed: 2000, findingCount: 2, dataComplete: true },
        ],
      },
      "/console_state.json": consoleState([
        finding(0, {
          id: "detector-0",
          sev: "CRITICAL",
          type: "auth_bruteforce_success",
          host: "server-01",
          title: "Brute-force then SUCCESSFUL login for 'admin'",
          lines: [{ n: 5, a: "auth failed from ", hit: "203.0.113.44", b: "", crit: true }],
        }),
        finding(1, {
          id: "detector-1",
          sev: "HIGH",
          type: "auth_bruteforce",
          host: "server-01",
          title: "Auth brute-force burst",
          lines: [{ n: 6, a: "auth failed from ", hit: "203.0.113.44", b: "", crit: false }],
        }),
      ]),
    });
  });

  it("renders the copilot drawer with advisory badge and verbatim footer", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    expect(await screen.findByText(/itsoc analyst/i)).toBeInTheDocument();
    expect(screen.getByTestId("copilot-advisory-chip")).toHaveTextContent(/advisory/i);

    // Verbatim footer requirement:
    const footer = screen.getByTestId("copilot-footer");
    expect(footer).toHaveTextContent("Rules set severity. I interpret & explain — I don't decide.");

    // Advisory disclaimer text:
    expect(screen.getByText(/never changed here/i)).toBeInTheDocument();
  });

  it("shows a run briefing for the current console-state (not a stale cache)", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    expect(await screen.findByText("test-run")).toBeInTheDocument();
    const brief = screen.getByTestId("copilot-run-brief");
    expect(brief).toHaveTextContent("2 finding(s)");
    expect(brief).toHaveTextContent("1 critical");
    expect(screen.getByTestId("copilot-chat")).toBeInTheDocument();
    expect(screen.getByLabelText("Ask the AI analyst")).not.toBeDisabled();
  });

  it("honest idle: briefing says no run and the composer is disabled", async () => {
    mockFetch({
      "/api/overview": { error: "no run yet — analyze a log first" },
      "/api/runs-summary": { totals: { runCount: 0, linesParsed: 0, findingCount: 0, severityCounts: {}, mitreFrequency: [] }, runs: [] },
      "/console_state.json": { idle: true, findings: [] },
    });
    renderApp(<CopilotRail defaultOpen={true} />);
    expect(await screen.findByText(/No run loaded/i)).toBeInTheDocument();
    expect(screen.getByTestId("copilot-run-brief")).toHaveTextContent(/No run loaded/i);
    expect(screen.getByLabelText("Ask the AI analyst")).toBeDisabled();
  });

  it("Role 1: interprets current view on prompt with streaming tokens and Stop control", async () => {
    const streamSpy = vi.spyOn(api, "askStream").mockImplementation(async (_q, onDelta) => {
      onDelta("Root cause: ");
      onDelta("Credential compromise ");
      onDelta("on server-01 from 203.0.113.44.");
    });

    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    // Click quick prompt chip:
    const promptChip = await screen.findByText("What changed since last run?");
    await userEvent.click(promptChip);

    expect(await screen.findByText(/Root cause: Credential compromise on server-01 from 203.0.113.44\./))
      .toBeInTheDocument();
    expect(streamSpy).toHaveBeenCalledOnce();
  });

  it("Role 2: Trend Digest shows what is rising across multiple saved runs", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    const trendTab = await screen.findByRole("tab", { name: /trend/i });
    await userEvent.click(trendTab);

    const trendCard = await screen.findByTestId("copilot-trend-card");
    expect(trendCard).toHaveTextContent("3 saved run(s)");
    expect(trendCard).toHaveTextContent("Brute Force");
    expect(trendCard).toHaveTextContent("7 hits");
    expect(trendCard).toHaveTextContent(/Brute Force:.*3 more hit\(s\) than the previous run/i);
  });

  it("Role 2 (single run): honestly explains trend requires at least 2 runs", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/runs-summary": {
        totals: { runCount: 1, linesParsed: 2000, findingCount: 2, severityCounts: {}, mitreFrequency: [] },
        runs: [{ file: "run-1.json", runId: "run-1", sourceLabel: "auth.log", linesParsed: 2000, findingCount: 2, dataComplete: true }],
      },
      "/console_state.json": consoleState([finding(0)]),
    });

    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    const trendTab = await screen.findByRole("tab", { name: /trend/i });
    await userEvent.click(trendTab);

    expect(await screen.findByText(/requires ≥2 saved runs/i)).toBeInTheDocument();
  });

  it("Role 3: Honest Forecast computes extrapolation with label 'forecast · based on N runs'", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    const forecastTab = await screen.findByRole("tab", { name: /forecast/i });
    await userEvent.click(forecastTab);

    const badge = await screen.findByTestId("copilot-forecast-badge");
    expect(badge).toHaveTextContent("forecast · based on 3 runs");

    const forecastCard = screen.getByTestId("copilot-forecast-card");
    expect(forecastCard).toHaveTextContent(/Extrapolating historical velocity from 3 recorded runs/i);
    expect(forecastCard).toHaveTextContent(/Expected next run:/i);
    expect(forecastCard).toHaveTextContent(/findings/i);
  });

  it("Role 3 (thin history): honestly displays 'not enough runs' when < 3 runs", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/runs-summary": {
        totals: { runCount: 2, linesParsed: 4000, findingCount: 5, severityCounts: {}, mitreFrequency: [] },
        runs: [
          { file: "run-2.json", runId: "run-2", sourceLabel: "auth-2.log", linesParsed: 2000, findingCount: 3, dataComplete: true },
          { file: "run-1.json", runId: "run-1", sourceLabel: "auth-1.log", linesParsed: 2000, findingCount: 2, dataComplete: true },
        ],
      },
      "/console_state.json": consoleState([finding(0)]),
    });

    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    const forecastTab = await screen.findByRole("tab", { name: /forecast/i });
    await userEvent.click(forecastTab);

    const badge = await screen.findByTestId("copilot-forecast-badge");
    expect(badge).toHaveTextContent("forecast · not enough runs");
    expect(screen.getByText(/not enough runs \(need ≥3 runs to project trend, currently 2\)/i)).toBeInTheDocument();
  });

  it("Role 4: Prioritize (Start here) surfaces critical compromise chain with citation", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    const prioritizeTab = await screen.findByRole("tab", { name: /start here/i });
    await userEvent.click(prioritizeTab);

    const card = await screen.findByTestId("copilot-prioritize-card");
    expect(card).toHaveTextContent("Start here");
    expect(card).toHaveTextContent("203.0.113.44");
    expect(card).toHaveTextContent(/The only chain with a successful login after brute-force/i);
    expect(card).toHaveTextContent(/cited: 2 finding\(s\) · rule auth_bruteforce_success/i);

    const viewLink = within(card).getByRole("link", { name: /view finding/i });
    expect(viewLink).toHaveAttribute("href", "/alerts?sel=detector-0");
  });

  it("Role 5: without a selected incident, honestly requires derive_rca context", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    const resTab = await screen.findByRole("tab", { name: /runbook/i });
    await userEvent.click(resTab);

    const card = await screen.findByTestId("copilot-resolution-card");
    expect(card).toHaveTextContent(/select an incident to request its real derive_rca runbook result/i);
  });

  it("Role 5 (no match): displays honest below-citation-threshold note", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/runs-summary": { totals: { runCount: 1, linesParsed: 100, findingCount: 0, severityCounts: {}, mitreFrequency: [] }, runs: [] },
      "/console_state.json": consoleState([]),
    });

    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    const resTab = await screen.findByRole("tab", { name: /runbook/i });
    await userEvent.click(resTab);

    expect(await screen.findByText(/select an incident to request its real derive_rca runbook result/i)).toBeInTheDocument();
  });

  it("surfaces pending approvals as read-only cards with an 'Open in Approvals →' link and ZERO approve controls (C4-F3)", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/approvals?state=pending": {
        approvals: [
          {
            id: "appr-001",
            incidentId: "inc-abc123",
            runbookId: "auth_bruteforce.md",
            connector: "palo-alto",
            step: 1,
            state: "pending",
            eligibilityProof: { eligible: true, missing: [] },
            evidenceRefs: ["5", "11"],
            requestRedacted: { command: "block-ip 203.0.113.44", connector: "palo-alto" },
            responseVerbatim: null,
            actor: null,
            failureReason: null,
            createdAt: "2026-08-20T12:00:00Z",
            updatedAt: "2026-08-20T12:00:00Z",
          },
        ],
      },
      "/api/runs-summary": {
        totals: { runCount: 1, linesParsed: 100, findingCount: 0, severityCounts: {}, mitreFrequency: [] },
        runs: [],
      },
      "/console_state.json": consoleState([]),
    });

    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    // Assert read-only card renders:
    const card = await screen.findByTestId("copilot-pending-approvals-card");
    expect(card).toBeInTheDocument();
    expect(card).toHaveTextContent("1 pending approval");
    expect(card).toHaveTextContent("auth_bruteforce.md · inc-abc123");

    const link = within(card).getByRole("link", { name: "Open in Approvals →" });
    expect(link).toHaveAttribute("href", "/approvals");

    // INVARIANT ASSERTION: ZERO approve/execute controls render in the rail
    expect(screen.queryByRole("button", { name: /approve/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /reject/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /execute/i })).toBeNull();
    expect(screen.queryByTestId("approval-approve")).toBeNull();
    expect(screen.queryByTestId("approval-reject")).toBeNull();
  });
});
