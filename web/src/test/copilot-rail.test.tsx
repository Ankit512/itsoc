import { screen, within, waitFor } from "@testing-library/react";
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
      "/api/copilot/suggest": {
        questions: [
          "Walk me through Brute-force then SUCCESSFUL login for 'admin'",
          "Walk the brute-force timeline with evidence line citations",
        ],
      },
      "/api/copilot/runbooks": {
        runbooks: [
          {
            id: "rb-block-ip",
            name: "Block source IP at the perimeter",
            eligible: true,
            missing: [],
            incidentId: "inc-1000",
            severityFloor: "HIGH",
            triggerRules: ["auth_bruteforce", "auth_bruteforce_success"],
          },
          {
            id: "rb-draft-notify",
            name: "Draft a notification for analyst review",
            eligible: true,
            missing: [],
            incidentId: "inc-1000",
            severityFloor: "LOW",
            triggerRules: ["auth_bruteforce"],
          },
        ],
        incidentCount: 1,
        note: "2 of 2 shipped runbook(s) eligible on this run. Eligibility is rule-owned. Nothing is executed from here.",
      },
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
    expect(screen.getByTestId("copilot-composer")).toBeInTheDocument();
    expect(screen.getByLabelText("Ask the AI analyst")).not.toBeDisabled();
    expect(screen.getByLabelText("Ask the AI analyst").tagName.toLowerCase()).toBe("textarea");
    expect(await screen.findByText(/Walk me through Brute-force then SUCCESSFUL/i)).toBeInTheDocument();
  });

  it("keeps a type-and-send chat box pinned (not clipped under chrome)", async () => {
    const streamSpy = vi.spyOn(api, "askStream").mockImplementation(async (_q, onDelta) => {
      onDelta("Cited the matching lines.");
    });
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    const box = await screen.findByLabelText("Ask the AI analyst");
    expect(box.tagName.toLowerCase()).toBe("textarea");
    expect(box).not.toBeDisabled();
    await userEvent.type(box, "show hidden matching lines");
    await userEvent.click(screen.getByRole("button", { name: "Send" }));
    expect(streamSpy).toHaveBeenCalled();
    expect(await screen.findByText(/Cited the matching lines/)).toBeInTheDocument();
  });

  it("run-aware suggestions do not ask for critical alerts the run does not have", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    const chips = await screen.findAllByTestId("copilot-suggested-q");
    const text = chips.map((el) => el.textContent || "").join(" | ");
    expect(text.toLowerCase()).not.toMatch(/top 5 critical/);
    expect(text.toLowerCase()).not.toMatch(/summarize today's threats/);
  });

  it("showcase chips drop 'critical incidents' when the run has 0 CRITICAL findings", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/copilot/suggest": {
        questions: [
          "Walk me through CBS HRESULT CBS_E_MANIFEST_INVALID_ITEM",
          "Are these CBS HRESULTs a security incident or servicing noise?",
        ],
      },
      "/api/runs-summary": { totals: { runCount: 1, linesParsed: 2000, findingCount: 2, severityCounts: {}, mitreFrequency: [] }, runs: [] },
      "/console_state.json": consoleState([
        finding(0, {
          id: "detector-0",
          sev: "HIGH",
          type: "windows_cbs_hresult",
          host: "CBS",
          title: "CBS HRESULT CBS_E_MANIFEST_INVALID_ITEM ×448",
          occurrences: 448,
        }),
      ]),
    });
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    expect(await screen.findByText(/Walk me through CBS HRESULT/i)).toBeInTheDocument();
    await waitFor(() => {
      const showcase = screen.getByTestId("copilot-showcase-chips");
      expect(showcase.textContent?.toLowerCase() || "").not.toMatch(/critical incidents/);
    });
    const suggested = (await screen.findAllByTestId("copilot-suggested-q")).map((el) => el.textContent || "").join(" | ");
    expect(suggested.toLowerCase()).not.toMatch(/top 5 critical/);
    expect(suggested.toLowerCase()).not.toMatch(/attack patterns/);
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
    expect(screen.getByTestId("copilot-composer")).toBeInTheDocument();
    expect(screen.getByLabelText("Ask the AI analyst")).toBeDisabled();
  });

  it("Role 1: interprets current view on prompt with streaming tokens and Stop control", async () => {
    const streamSpy = vi.spyOn(api, "askStream").mockImplementation(async (_q, onDelta, _s, onInv) => {
      onInv?.({
        citations: [{ n: 5, raw: "auth failed from 203.0.113.44", findingId: "detector-0" }],
        followups: ["Walk the brute-force timeline with evidence line citations"],
        source: "rules",
      });
      onDelta("Root cause: ");
      onDelta("Credential compromise ");
      onDelta("on server-01 from 203.0.113.44.");
    });

    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    // Click a run-aware suggested question (not a generic "critical/attack" chip).
    const promptChip = await screen.findByText(/Walk me through Brute-force then SUCCESSFUL/i);
    await userEvent.click(promptChip);

    expect(await screen.findByText(/Root cause: Credential compromise on server-01 from 203.0.113.44\./))
      .toBeInTheDocument();
    expect(streamSpy).toHaveBeenCalledOnce();
    expect(screen.getByTestId("copilot-citations")).toHaveTextContent("{5}");
    expect(screen.getByTestId("copilot-citations")).toHaveTextContent("auth failed from 203.0.113.44");
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

  it("Role 5: lists shipped runbooks against THIS run without requiring an incident URL", async () => {
    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);

    const resTab = await screen.findByRole("tab", { name: /runbook/i });
    await userEvent.click(resTab);

    const card = await screen.findByTestId("copilot-resolution-card");
    expect(card).toHaveTextContent(/Block source IP at the perimeter/i);
    expect(card).toHaveTextContent(/eligible/i);
    expect(card).toHaveTextContent(/Nothing is executed from here/i);
    expect(within(card).queryByRole("button", { name: /approve|execute|block/i })).toBeNull();
  });

  it("Role 5 (no match): shows shipped runbooks as not eligible with a reason", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/runs-summary": { totals: { runCount: 1, linesParsed: 100, findingCount: 0, severityCounts: {}, mitreFrequency: [] }, runs: [] },
      "/console_state.json": consoleState([]),
      "/api/copilot/runbooks": {
        runbooks: [
          {
            id: "rb-block-ip",
            name: "Block source IP at the perimeter",
            eligible: false,
            missing: ["no derived incident on this run"],
            incidentId: null,
          },
        ],
        incidentCount: 0,
        note: "0 of 1 shipped runbook(s) eligible on this run. Eligibility is rule-owned. Nothing is executed from here.",
      },
    });

    renderApp(<CopilotRail defaultOpen={true} model="llama3.1:8b" />);
    const resTab = await screen.findByRole("tab", { name: /runbook/i });
    await userEvent.click(resTab);

    const card = await screen.findByTestId("copilot-resolution-card");
    expect(card).toHaveTextContent(/Block source IP at the perimeter/i);
    expect(card).toHaveTextContent(/not eligible/i);
    expect(card).toHaveTextContent(/no derived incident on this run/i);
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
