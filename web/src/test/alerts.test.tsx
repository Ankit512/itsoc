import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, consoleState, finding } from "./helpers";

describe("Alerts page", () => {
  it("renders the findings table from the current run state", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1), finding(2)]) });
    renderApp(<App />, { route: "/alerts" });

    expect(await screen.findByText(/Brute-force burst #0/)).toBeInTheDocument();
    expect(screen.getAllByTestId("alert-row").length).toBe(3);
    expect(screen.getAllByText("HIGH").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("T1110").length).toBe(3);
    expect(screen.getByText(/3 of 3 finding\(s\)/)).toBeInTheDocument();
  });

  it("filters findings", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1)]) });
    renderApp(<App />, { route: "/alerts" });
    await screen.findByText(/Brute-force burst #0/);

    await userEvent.type(screen.getByLabelText("Filter findings"), "burst #1");
    expect(screen.getAllByTestId("alert-row").length).toBe(1);
    expect(screen.queryByText(/Brute-force burst #0/)).not.toBeInTheDocument();
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

  it("shows AI recommended severity as advisory and does not replace the rule verdict", async () => {
    mockFetch({
      "/console_state.json": consoleState([
        finding(0, {
          sev: "HIGH",
          ruleSev: "HIGH",
          aiTriage: {
            advisory: true,
            ruleSeverity: "HIGH",
            aiSeverity: "CRITICAL",
            confidence: "medium",
            agrees: false,
            cause: "Many auth failures",
            note: "AI recommends — analyst decides. This does not change the rule verdict.",
          },
        }),
      ]),
    });
    renderApp(<App />, { route: "/alerts?sel=detector-0" });
    expect(await screen.findByTestId("ai-triage")).toHaveTextContent("CRITICAL");
    expect(screen.getByText("AI recommended severity · advisory")).toBeInTheDocument();
    expect(screen.getByText("Rule verdict · authoritative")).toBeInTheDocument();
    expect(screen.getByText(/does not change the rule verdict/i)).toBeInTheDocument();
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
