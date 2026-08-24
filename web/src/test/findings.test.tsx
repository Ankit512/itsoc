import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { renderApp, mockFetch, consoleState, finding } from "./helpers";

describe("Findings page (was Alerts — the core product page)", () => {
  it("renders the findings table from the current run state", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1), finding(2)]) });
    renderApp(<App />, { route: "/findings" });

    expect(await screen.findByText(/Brute-force burst #0/)).toBeInTheDocument();
    expect(screen.getAllByTestId("finding-row").length).toBe(3);
    expect(screen.getAllByText("HIGH").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("T1110").length).toBe(3);
    expect(screen.getByText(/3 of 3 finding\(s\)/)).toBeInTheDocument();
  });

  it("the old /alerts route redirects to /findings (links keep working)", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1)]) });
    renderApp(<App />, { route: "/alerts?sel=detector-1" });
    // The redirect preserves ?sel= — the detail opens exactly as before.
    expect(await screen.findByText("Rule verdict · authoritative")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
  });

  it("shows THE scope banner: you are reviewing this run", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0)], {
      sourceLabel: "/tmp/auth.log",
    }) });
    renderApp(<App />, { route: "/findings" });
    // findBy waits past the initial loading state to the loaded-run banner.
    await screen.findByText("You are reviewing THIS run");
    const banner = screen.getByTestId("scope-banner");
    expect(banner).toHaveTextContent("auth.log");
    expect(banner).toHaveTextContent("1 finding(s)");
  });

  it("scope banner is honest when no run is loaded", async () => {
    mockFetch({ "/console_state.json": { idle: true, findings: [] } });
    renderApp(<App />, { route: "/findings" });
    const banner = await screen.findByTestId("scope-banner");
    expect(banner).toHaveTextContent(/No run loaded/);
    expect(banner).not.toHaveTextContent("You are reviewing THIS run");
  });

  it("filters findings", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1)]) });
    renderApp(<App />, { route: "/findings" });
    await screen.findByText(/Brute-force burst #0/);

    await userEvent.type(screen.getByLabelText("Filter findings"), "burst #1");
    expect(screen.getAllByTestId("finding-row").length).toBe(1);
    expect(screen.queryByText(/Brute-force burst #0/)).not.toBeInTheDocument();
  });

  it("virtualizes large runs: only a window of rows is in the DOM", async () => {
    const many = Array.from({ length: 500 }, (_, i) => finding(i));
    mockFetch({ "/console_state.json": consoleState(many) });
    renderApp(<App />, { route: "/findings" });

    expect(await screen.findByText(/500 of 500 finding\(s\)/)).toBeInTheDocument();
    expect(screen.getByTestId("findings-scroll")).toBeInTheDocument();
    // jsdom has no viewport height, so the virtualizer materializes at most a
    // small overscan window — the point is: nowhere near all 500 rows.
    expect(screen.queryAllByTestId("finding-row").length).toBeLessThan(50);
  });

  it("row click (or ?sel=) opens the finding detail with evidence", async () => {
    mockFetch({ "/console_state.json": consoleState([finding(0), finding(1)]) });
    renderApp(<App />, { route: "/findings?sel=detector-1" });

    expect(await screen.findByText("Rule verdict · authoritative")).toBeInTheDocument();
    expect(screen.getByText(/verbatim from the source log/)).toBeInTheDocument();
    expect(screen.getByText("203.0.113.44")).toBeInTheDocument();
    expect(screen.getByText("failures_from(ip) >= 5")).toBeInTheDocument();
  });

  it("unrecognized run keeps the honest banner", async () => {
    mockFetch({ "/console_state.json": consoleState([], {
      unrecognized: true, linesParsed: 0, linesUnparsed: 100,
    }) });
    renderApp(<App />, { route: "/findings" });
    expect(await screen.findByText(/Log format not recognized/)).toBeInTheDocument();
    // The "not" is its own <b> element, so match the adjacent text node.
    expect(screen.getByText(/evidence the log is clean/)).toBeInTheDocument();
    expect(screen.queryByText(/All clear/)).not.toBeInTheDocument();
  });
});

describe("Review facets inside Findings (spec §3/§4 rebundle)", () => {
  const INCIDENTS = {
    incidents: [
      { id: "inc-aaa", runId: "test-run", entity: "203.0.113.44", entityKind: "ip",
        title: "203.0.113.44 — 2 correlated finding(s)", severity: "HIGH", state: "new",
        findingIds: ["detector-0", "detector-1"], findingCount: 2, techniques: [],
        attackerStatus: "", createdAt: "2026-08-13T02:16:52+00:00",
        firstSeen: "2026-08-13T02:16:52+00:00", lastSeen: "2026-08-13T02:18:00+00:00",
        acknowledgedAt: null, resolvedAt: null, timeUncertain: false },
      { id: "inc-old", runId: "some-older-run", entity: "server-9", entityKind: "host",
        title: "server-9 — 1 correlated finding(s)", severity: "LOW", state: "resolved",
        findingIds: ["detector-9"], findingCount: 1, techniques: [],
        attackerStatus: "", createdAt: "2026-07-01T00:00:00+00:00",
        firstSeen: null, lastSeen: null,
        acknowledgedAt: null, resolvedAt: null, timeUncertain: false },
    ],
  };

  it("facet tabs render and the old top-level routes redirect into them", async () => {
    mockFetch({
      "/console_state.json": consoleState([finding(0)]),
      "/api/incidents": INCIDENTS,
    });
    renderApp(<App />, { route: "/incidents" });
    // Redirected to /findings?facet=incidents — Findings shell + incident rows.
    expect(await screen.findByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(await screen.findByTestId("incident-row")).toBeInTheDocument();
    const facetNav = screen.getByRole("navigation", { name: "Review facets" });
    expect(facetNav).toHaveTextContent("Incidents");
    expect(facetNav).toHaveTextContent("Cases");
  });

  it("the incidents facet is scoped to THIS run and states what is out of scope", async () => {
    mockFetch({
      "/console_state.json": consoleState([finding(0)]),
      "/api/incidents": INCIDENTS,
    });
    renderApp(<App />, { route: "/findings?facet=incidents" });

    expect(await screen.findByTestId("incident-row")).toBeInTheDocument();
    // Only the current run's incident shows (runId "test-run")…
    expect(screen.getAllByTestId("incident-row").length).toBe(1);
    expect(screen.getByText("203.0.113.44")).toBeInTheDocument();
    expect(screen.queryByText("server-9")).not.toBeInTheDocument();
    // …and the excluded count is stated, never silently dropped.
    expect(screen.getByTestId("incident-scope-note"))
      .toHaveTextContent(/1 incident\(s\) from other runs/);
  });

  it("switching facets via the tab bar shows the facet content", async () => {
    mockFetch({
      "/console_state.json": consoleState([finding(0)]),
      "/api/incidents": INCIDENTS,
      "/api/cases": { cases: [] },
    });
    renderApp(<App />, { route: "/findings" });
    await screen.findByText(/Brute-force burst #0/);

    await userEvent.click(screen.getByRole("button", { name: "Cases" }));
    expect(await screen.findByText("No cases yet")).toBeInTheDocument();
  });
});
