import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, consoleState, finding } from "./helpers";

describe("Alerts page", () => {
  it("renders the findings table from the current run state", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1), finding(2)]) });
    renderApp(<App />, { route: "/alerts" });

    await screen.findByText(/3 of 3 finding\(s\)/);
    expect(screen.getAllByTestId("alert-row").length).toBe(3);
    expect(screen.getAllByText("HIGH").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("T1110").length).toBe(3);
    expect(screen.getByText(/3 of 3 finding\(s\)/)).toBeInTheDocument();
  });

  it("filters findings", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1)]) });
    renderApp(<App />, { route: "/alerts" });
    await screen.findByText(/2 of 2 finding\(s\)/);

    await userEvent.type(screen.getByLabelText("Filter findings"), "burst #1");
    const [row] = screen.getAllByTestId("alert-row");
    expect(row).toHaveTextContent("server-1");
    expect(within(row).queryByText("server-0")).toBeNull();
  });

  it("virtualizes large runs: only a window of rows is in the DOM", async () => {
    const many = Array.from({ length: 500 }, (_, i) => finding(i));
    mockFetch({ "/console_state.json": consoleState(many) });
    renderApp(<App />, { route: "/alerts" });

    expect(await screen.findByText(/500 of 500 finding\(s\)/)).toBeInTheDocument();
    expect(screen.getByTestId("alerts-scroll")).toBeInTheDocument();
    // jsdom has no viewport height, so the virtualizer materializes at most a
    // small overscan window — the point is: nowhere near all 500 rows.
    expect(screen.queryAllByTestId("alert-row").length).toBeLessThan(50);
  });

  it("row click (or ?sel=) opens the finding detail with evidence", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1)]) });
    renderApp(<App />, { route: "/alerts?sel=detector-1" });

    expect(await screen.findByText("Rule verdict · authoritative")).toBeInTheDocument();
    expect(screen.queryByTestId("ai-triage")).not.toBeInTheDocument();
    expect(screen.getByText(/verbatim from the source log/)).toBeInTheDocument();
    expect(screen.getByText("203.0.113.44")).toBeInTheDocument();
    expect(screen.getByText("failures_from(ip) >= 5")).toBeInTheDocument();
  });

  it("grouped finding names the matching-line count in detail", async () => {
    mockFetch({
      "/console_state.json": consoleState([
        finding(0, { occurrences: 448, title: "CBS HRESULT CBS_E_MANIFEST_INVALID_ITEM ×448" }),
      ]),
    });
    renderApp(<App />, { route: "/alerts?sel=detector-0" });
    expect(await screen.findByTestId("finding-occurrences")).toHaveTextContent("448 matching lines");
    expect(screen.getByText("×448")).toBeInTheDocument();
  });

  // --- E7a: AI TRIAGE · LEARNED, ADVISORY ---------------------------------
  const learned = (over: Record<string, unknown> = {}) => ({
    advisory: true as const,
    learned: true,
    modelAvailable: true,
    status: "agrees" as const,
    ruleSeverity: "HIGH",
    aiSeverity: "HIGH",
    aiLabel: "confirmed",
    confidence: 0.9123,
    agrees: true,
    unavailableReason: null,
    note: "Learned second opinion — ADVISORY. It never changes the rule verdict.",
    ...over,
  });

  it("renders the learned advisory block when the model AGREES, without replacing the rule verdict", async () => {
    mockFetch({
      "/console_state.json": consoleState([
        finding(0, { sev: "HIGH", ruleSev: "HIGH", aiTriage: learned() }),
      ]),
    });
    renderApp(<App />, { route: "/alerts?sel=detector-0" });

    const block = await screen.findByTestId("ai-triage");
    expect(block).toHaveAttribute("data-status", "agrees");
    expect(screen.getByText("AI triage · learned, advisory")).toBeInTheDocument();
    expect(screen.getByTestId("ai-triage-severity")).toHaveTextContent("HIGH");
    expect(screen.getByTestId("ai-triage-status")).toHaveTextContent("Agrees with the rule verdict");
    expect(screen.getByTestId("ai-triage-confidence")).toHaveTextContent("91.2% confidence");
    expect(screen.getByTestId("ai-triage-label")).toHaveTextContent("confirmed");
    expect(screen.getByText("Rule verdict · authoritative")).toBeInTheDocument();
    expect(screen.getByText(/is unchanged/i)).toBeInTheDocument();
    expect(screen.queryByTestId("ai-triage-disagreement")).not.toBeInTheDocument();
  });

  it("renders DISAGREEMENT visibly, and still never changes the verdict", async () => {
    mockFetch({
      "/console_state.json": consoleState([
        finding(0, {
          sev: "HIGH",
          ruleSev: "HIGH",
          aiTriage: learned({
            status: "disagrees", agrees: false, aiSeverity: "INFO",
            aiLabel: "false-positive", confidence: 0.7712,
          }),
        }),
      ]),
    });
    renderApp(<App />, { route: "/alerts?sel=detector-0" });

    const block = await screen.findByTestId("ai-triage");
    expect(block).toHaveAttribute("data-status", "disagrees");
    expect(block.className).toContain("is-aitriage--disagrees");
    expect(screen.getByTestId("ai-triage-status")).toHaveTextContent("Disagrees with the rule verdict");
    expect(screen.getByTestId("ai-triage-severity")).toHaveTextContent("INFO");
    expect(screen.getByTestId("ai-triage-disagreement")).toHaveTextContent(/prompt to look, not a reason/i);
    // the rule verdict block still shows the rule's own band, untouched
    expect(within(screen.getByText("Rule verdict · authoritative").parentElement as HTMLElement)
      .getByText("HIGH")).toBeInTheDocument();
  });

  it("renders the honest MODEL UNAVAILABLE state with no fabricated severity or confidence", async () => {
    mockFetch({
      "/console_state.json": consoleState([
        finding(0, {
          sev: "HIGH",
          ruleSev: "HIGH",
          aiTriage: {
            advisory: true as const,
            learned: true,
            modelAvailable: false,
            status: "unavailable" as const,
            ruleSeverity: "HIGH",
            aiSeverity: null,
            aiLabel: null,
            confidence: null,
            agrees: null,
            unavailableReason: "scikit-learn is not installed",
            note: "Learned second opinion — ADVISORY — is UNAVAILABLE here.",
          },
        }),
      ]),
    });
    renderApp(<App />, { route: "/alerts?sel=detector-0" });

    const block = await screen.findByTestId("ai-triage");
    expect(block).toHaveAttribute("data-status", "unavailable");
    expect(screen.getByTestId("ai-triage-unavailable")).toHaveTextContent("Model unavailable");
    expect(screen.getByTestId("ai-triage-reason")).toHaveTextContent("scikit-learn is not installed");
    // nothing is invented to fill the space
    expect(screen.queryByTestId("ai-triage-severity")).not.toBeInTheDocument();
    expect(screen.queryByTestId("ai-triage-confidence")).not.toBeInTheDocument();
    expect(screen.queryByTestId("ai-triage-status")).not.toBeInTheDocument();
    // and the rule verdict is completely unaffected
    expect(screen.getByText("Rule verdict · authoritative")).toBeInTheDocument();
    expect(screen.getByText(/stands unchanged/i)).toBeInTheDocument();
  });

  it("unrecognized run keeps the honest banner", async () => {
    mockFetch({ "/console_state.json": consoleState([], {
      unrecognized: true, linesParsed: 0, linesUnparsed: 100,
    }) });
    renderApp(<App />, { route: "/alerts" });
    expect(await screen.findByText(/Log format not recognized/)).toBeInTheDocument();
    // The "not" is its own <b> element, so match the adjacent text node.
    expect(screen.getByText(/evidence the log is clean/)).toBeInTheDocument();
    expect(screen.queryByText(/All clear/)).not.toBeInTheDocument();
  });
});
