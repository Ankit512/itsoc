import { screen } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch, consoleState, OVERVIEW, METRICS } from "./helpers";

describe("Overview page (v6)", () => {
  beforeEach(() => mockFetch({
    "/api/overview": OVERVIEW,
    "/api/metrics": METRICS,
    "/console_state.json": consoleState([], {
      sourceLabel: "samples/auth.log", runHosts: "combo",
      runWindow: "02:14–02:20 UTC", generatedAt: "2026-08-18 14:00 UTC",
      manifest: { detector_sha256: "364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876", ruleset: "v1" },
    }),
  }));

  it("renders KPIs, charts, tactics and latest alerts from /api/overview", async () => {
    renderApp(<App />);

    expect(await screen.findByText("Total")).toBeInTheDocument();
    // The severity mix reads from the five KPI tiles; the reference has no donut.
    expect(screen.getAllByText("31").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("22").length).toBeGreaterThanOrEqual(1);

    // Reference §2: "Findings over time" + "Top ATT&CK tactics" panels, no donut.
    expect(screen.queryByTestId("chart-donut")).not.toBeInTheDocument();
    expect(screen.getByTestId("chart-overtime")).toBeInTheDocument();
    expect(screen.getAllByTestId("chart-tactic").length).toBe(2);

    // Ranked descending: Credential Access (23) before Initial Access (4).
    const tactics = screen.getByRole("list", { name: "top attack tactics" });
    expect(tactics.textContent!.indexOf("Credential Access"))
      .toBeLessThan(tactics.textContent!.indexOf("Initial Access"));

    expect(screen.getByText(/Brute-force then SUCCESSFUL/)).toBeInTheDocument();
    expect(screen.getByText("Breaking In")).toBeInTheDocument();
    // The action column deep-links into the Alerts page.
    expect(screen.getByRole("link", { name: "View finding" }))
      .toHaveAttribute("href", "/alerts?sel=detector-0");
  });

  it("shows the run-facts line from the real adapter state", async () => {
    renderApp(<App />);
    // The run-facts line shows the source basename (full path in its title);
    // the alerts table also lists a source, so target the run-facts one.
    expect(await screen.findByTitle("samples/auth.log")).toHaveTextContent("auth.log");
    expect(screen.getByText(/host combo/)).toBeInTheDocument();
    expect(screen.getByText(/2,000 lines parsed · 0 unparsed/)).toBeInTheDocument();
    expect(screen.getByText(/detector 364577c5…a4a876/)).toBeInTheDocument();
  });

  it("shows a real delta ONLY where a prior period exists", async () => {
    renderApp(<App />);
    await screen.findByText("Total");
    expect(screen.getAllByText(/vs previous/).length).toBe(1);
    expect(screen.getByText(/12% vs previous/)).toBeInTheDocument();
    // The four KPIs without a prior period say so instead of showing nothing.
    expect(screen.getAllByText("no prior run — no delta").length).toBe(4);
  });

  it("wires the ops footer to /api/metrics with honest n/a states", async () => {
    renderApp(<App />);
    await screen.findByText("Open Incidents");
    expect(screen.getByText("Open Incidents").nextElementSibling).toHaveTextContent("2");
    // No acknowledge/resolve lifecycle in the fixture -> n/a, never a number.
    expect(screen.getAllByText("n/a").length).toBe(2);
    expect(screen.getByText("Assets at Risk").nextElementSibling).toHaveTextContent("3");
    expect(screen.getByText("Data Sources").nextElementSibling).toHaveTextContent("4");
    expect(screen.getByText(/derived, never invented/)).toBeInTheDocument();
  });

  it("docks the AI analyst as an advisory rail (reference §2 three-column shape)", async () => {
    renderApp(<App />);
    await screen.findByText("Total");
    // The analyst is a docked rail, always present and advisory-labeled — it
    // reads verdicts, never sets them, and says so in its footer verbatim.
    expect(screen.getByTestId("copilot-dock")).toBeInTheDocument();
    expect(screen.getByText(/never changed here/)).toBeInTheDocument();
    expect(screen.getByTestId("copilot-footer")).toHaveTextContent(
      "Rules set the severity. I explain & prioritize — I don't decide.",
    );
  });

  it("no run yet -> says so, never sample numbers", async () => {
    mockFetch({ "/api/overview": { error: "no run yet — analyze a log first" } });
    renderApp(<App />);
    expect(await screen.findByText(/no run yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId("chart-donut")).not.toBeInTheDocument();
  });
});
