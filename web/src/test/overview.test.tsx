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

    // "Total" appears on the KPI tile AND the donut center label — both valid.
    expect((await screen.findAllByText("Total")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("31").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("22").length).toBeGreaterThanOrEqual(1);

    // The donut is kept by product decision even though the v3 dc drops it:
    // donut + over-time + top-tactics are all present.
    expect(screen.getByTestId("chart-donut")).toBeInTheDocument();
    expect(screen.getByTestId("chart-overtime")).toBeInTheDocument();
    expect(screen.getAllByTestId("chart-tactic").length).toBe(2);

    // Ranked descending: Credential Access (23) before Initial Access (4).
    const tactics = screen.getByRole("list", { name: "top attack tactics" });
    expect(tactics.textContent!.indexOf("Credential Access"))
      .toBeLessThan(tactics.textContent!.indexOf("Initial Access"));

    // Latest alerts carries the v3 column set: TIME · sev · RULE · HOST · FINDING.
    expect(screen.getByText(/Brute-force then SUCCESSFUL/)).toBeInTheDocument();
    for (const col of ["Time", "Rule", "Host", "Finding"]) {
      expect(screen.getByRole("columnheader", { name: col })).toBeInTheDocument();
    }
    // The finding title itself deep-links into the Alerts page.
    expect(screen.getByRole("link", { name: "View finding" }))
      .toHaveAttribute("href", "/alerts?sel=detector-0");
  });

  it("shows the run-facts line from the real adapter state", async () => {
    renderApp(<App />);
    // The run-facts line shows the source basename (full path in its title);
    // the alerts table also lists a source, so target the run-facts one.
    expect(await screen.findByTitle("samples/auth.log")).toHaveTextContent("auth.log");
    expect(screen.getByText(/host combo/)).toBeInTheDocument();
    expect(screen.getAllByText(/2,000 lines parsed · 0 unparsed/).length).toBeGreaterThan(0);
    expect(screen.getByText(/detector 364577c5…a4a876/)).toBeInTheDocument();
  });

  it("shows a real delta ONLY where a prior period exists", async () => {
    renderApp(<App />);
    await screen.findByTestId("chart-overtime");
    expect(screen.getAllByText(/vs previous/).length).toBe(1);
    expect(screen.getByText(/12% vs previous/)).toBeInTheDocument();
    // The four KPIs without a prior period say so instead of showing nothing.
    expect(screen.getAllByText("no prior run — no delta").length).toBe(4);
  });

  // Ops footer removed in the design-v2 core reskin: the prototype's Overview
  // (DESIGN_HANDOFF §3) ends at the Latest-alerts table — no MTTD/MTTR footer.
  // The metrics still exist via /api/metrics and the History page KPIs.

  it("mounts the AI analyst as an advisory slide-in rail with a launcher (handoff §2/§4)", async () => {
    renderApp(<App />);
    await screen.findByTestId("chart-overtime");
    // The analyst is a slide-in .is-rail drawer launched by the floating fab;
    // it reads verdicts, never sets them, and says so in its footer verbatim.
    expect(screen.getByTestId("copilot-rail-drawer")).toBeInTheDocument();
    expect(screen.getByTestId("copilot-fab")).toBeInTheDocument();
    expect(screen.getByText(/rules own severity/i)).toBeInTheDocument();
    expect(screen.getByTestId("copilot-footer")).toHaveTextContent(
      "Rules set severity. I interpret & explain — I don't decide.",
    );
  });

  it("shows matching-line volume when grouped findings cover many source lines", async () => {
    mockFetch({
      "/api/overview": {
        ...OVERVIEW,
        kpis: {
          total: 5, critical: 0, high: 2, medium: 2, low: 1,
          deltas: OVERVIEW.kpis.deltas,
          matchingLines: { total: 754, critical: 0, high: 466, medium: 8, low: 280 },
        },
        latestAlerts: [{ ...OVERVIEW.latestAlerts[0], occurrences: 448, name: "CBS HRESULT ×448" }],
      },
      "/api/metrics": METRICS,
      "/console_state.json": consoleState([], {
        sourceLabel: "Windows_2k.log", runHosts: "—",
        runWindow: "04:30–04:32 UTC", generatedAt: "2026-08-31 00:00 UTC",
        manifest: { detector_sha256: "364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876", ruleset: "v1" },
      }),
    });
    renderApp(<App />);
    expect(await screen.findByTestId("kpi-matching-total")).toHaveTextContent("754 matching lines");
    expect(screen.getByText("466 matching lines")).toBeInTheDocument();
    expect(screen.getByText(/5 grouped · 754 matching lines/)).toBeInTheDocument();
    expect(screen.getByText("×448")).toBeInTheDocument();
  });

  it("no run yet -> says so, never sample numbers", async () => {
    mockFetch({ "/api/overview": { error: "no run yet — analyze a log first" } });
    renderApp(<App />);
    expect(await screen.findByText(/no run yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId("chart-donut")).not.toBeInTheDocument();
  });
});
