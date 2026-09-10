import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { CORE_NAV, EXPERIMENTAL_NAV, HOME_NAV, NAV, NAV_GROUPS } from "@/components/layout/AppShell";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

afterEach(() => vi.restoreAllMocks());

describe("C1-T6 · Nav + Cmd-K aliases (core roster + case file)", () => {
  beforeEach(() => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/approvals": { approvals: [] },
      "/api/runs": { runs: [], current: null },
      "/api/incidents": { incidents: [], total: 0 },
      "/api/ti/keys": { otx: false, abuseipdb: false },
      "/api/store/iocs": { items: [], total: 0, limit: 100, offset: 0 },
      "/api/threat-intel": { indicators: [], indicatorSource: "offline", ruleTechniques: {}, attackCacheWarm: false },
      "/api/discovery": { subnet: "192.168.1.0/24", running: false, lastScan: null, hosts: [] },
      "/api/vulnerabilities": { items: [], total: 0 },
      "/api/collectors": { collectors: [], stats: { totalPackets: 0, droppedPackets: 0, activeListeners: 0 } },
      "/api/cases": { cases: [] },
    });
  });

  it("(a) nav shows the core roster plus Cases and OEM Engine", async () => {
    expect(NAV).toHaveLength(14);
    expect(CORE_NAV).toHaveLength(13);
    expect(EXPERIMENTAL_NAV).toHaveLength(1);

    expect(CORE_NAV.map((n) => n.label)).toEqual([
      "Overview", "Findings", "Incidents", "Cases", "Approvals", "Intel",
      "Network", "Assets", "Sources", "Integrations", "History", "Reports", "Settings"
    ]);
    expect(EXPERIMENTAL_NAV.map((n) => n.label)).toEqual(["OEM Engine"]);

    // Approvals is now built (C4-T1) — ready: true, no "unbuilt" tooltip.
    const approvalsEntry = CORE_NAV.find((n) => n.to === "/approvals");
    expect(approvalsEntry).toBeDefined();
    expect(approvalsEntry?.ready).toBe(true);

    renderApp(<App />);
    const wordmark = await screen.findByTestId("wordmark");
    expect(wordmark).toBeInTheDocument();

    // A built screen carries no honest-unbuilt tooltip.
    const approvalsLink = screen.getByRole("link", { name: "Approvals" });
    expect(approvalsLink).not.toHaveAttribute("title", "Not built yet — the page says so honestly");
  });

  it("(a2) G1 · CORE_NAV is derived from the groups the sidebar actually renders", async () => {
    // The roster is not hand-maintained alongside the rendered nav — it IS the
    // rendered nav, flattened. TOUR_STEPS and the assertions above both compare
    // against CORE_NAV, so a second hand-kept copy is how they would silently
    // drift apart. Asserting the derivation is what keeps that impossible.
    expect(CORE_NAV[0]).toBe(HOME_NAV);
    expect(CORE_NAV.slice(1)).toEqual(NAV_GROUPS.flatMap((g) => g.items));

    expect(NAV_GROUPS.map((g) => g.label)).toEqual(["Triage", "Context", "Operate"]);
    expect(NAV_GROUPS.map((g) => g.items.map((i) => i.label))).toEqual([
      ["Findings", "Incidents", "Cases", "Approvals"],
      ["Intel", "Network", "Assets", "Sources"],
      ["Integrations", "History", "Reports", "Settings"],
    ]);
    // Every group states why it exists; a group that cannot say so is a bucket.
    for (const group of NAV_GROUPS) expect(group.rationale.length).toBeGreaterThan(40);
    // No screen may appear in two groups.
    const tos = CORE_NAV.map((i) => i.to);
    expect(new Set(tos).size).toBe(tos.length);
  });

  it("(a3) G1 · no orphaned route — every route in App.tsx is reachable", async () => {
    // The full route census of web/src/App.tsx. A route reached ONLY by typing
    // its URL is orphaned, which is what regrouping a nav is most likely to
    // cause. Each route below is claimed by exactly one reachability mechanism,
    // and every mechanism is checked against the real rendered UI.
    const ROUTE_CENSUS: { route: string; via: "nav" | "palette" | "alias-of" | "shell"; target?: string }[] = [
      { route: "/", via: "nav" },
      { route: "/alerts", via: "nav" },
      { route: "/incidents", via: "nav" },
      { route: "/cases", via: "nav" },
      { route: "/approvals", via: "nav" },
      { route: "/intel", via: "nav" },
      { route: "/network", via: "nav" },
      { route: "/assets", via: "nav" },
      { route: "/sources", via: "nav" },
      { route: "/integrations", via: "nav" },
      { route: "/history", via: "nav" },
      { route: "/reports", via: "nav" },
      { route: "/settings", via: "nav" },
      { route: "/oem", via: "palette" },
      { route: "/logout", via: "shell" },
      { route: "/findings", via: "alias-of", target: "/alerts" },
      { route: "/threat-intel", via: "alias-of", target: "/intel" },
      { route: "/enrichment", via: "alias-of", target: "/intel" },
      { route: "/discovery", via: "alias-of", target: "/network" },
      { route: "/vulnerabilities", via: "alias-of", target: "/network" },
      { route: "/collectors", via: "alias-of", target: "/sources" },
    ];

    renderApp(<App />);
    await screen.findByTestId("wordmark");
    const sidebar = screen.getByRole("navigation", { name: "Main" }).closest("aside")!;
    await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
    const paletteHrefs = new Set(
      [...CORE_NAV, ...EXPERIMENTAL_NAV].map((i) => i.to),
    );

    for (const entry of ROUTE_CENSUS) {
      if (entry.via === "nav") {
        const item = CORE_NAV.find((i) => i.to === entry.route);
        expect(item, `${entry.route} claims nav reachability`).toBeDefined();
        expect(within(sidebar).getByRole("link", { name: item!.label })).toHaveAttribute("href", entry.route);
      } else if (entry.via === "palette") {
        // Reachable with experimental OFF (its default) — this is what replaced
        // the removed "Command Center · off" box as OEM Engine's way in.
        const item = EXPERIMENTAL_NAV.find((i) => i.to === entry.route) ?? CORE_NAV.find((i) => i.to === entry.route);
        expect(item, `${entry.route} claims palette reachability`).toBeDefined();
        expect(within(sidebar).queryByRole("link", { name: item!.label })).toBeNull();
        expect(screen.getByRole("button", { name: new RegExp(`^${item!.label}$`, "i") })).toBeInTheDocument();
        expect(paletteHrefs.has(entry.route)).toBe(true);
      } else if (entry.via === "alias-of") {
        // An alias is only reachable if the screen it aliases is; the (b)/(c)
        // blocks below prove each alias actually lands on that screen.
        expect(CORE_NAV.some((i) => i.to === entry.target), `${entry.route} aliases ${entry.target}`).toBe(true);
      } else {
        expect(within(sidebar).getByRole("link", { name: /log out/i })).toHaveAttribute("href", entry.route);
      }
    }

    // And the census is exhaustive over the nav: no nav item points at a route
    // the census does not list.
    const censusRoutes = new Set(ROUTE_CENSUS.map((r) => r.route));
    for (const item of NAV) expect(censusRoutes.has(item.to)).toBe(true);
  });

  describe("(b) Cmd-K aliases resolve old screen names to their new destinations", () => {
    it("typing 'Cases' filters to 'Cases' and navigates to /cases", async () => {
      renderApp(<App />);
      await screen.findByTestId("wordmark");

      await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
      const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
      await userEvent.type(input, "Cases");

      const casesOption = screen.getByRole("button", { name: /^cases$/i });
      expect(casesOption).toBeInTheDocument();
      await userEvent.click(casesOption);

      expect(screen.getByRole("link", { name: "Cases" })).toHaveClass("active");
      expect(await screen.findByText(/Analyst-entered case files/i)).toBeInTheDocument();
    });

    it("typing 'Threat Intel' filters to 'Intel' and navigates to /intel", async () => {
      renderApp(<App />);
      await screen.findByTestId("wordmark");

      await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
      const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
      await userEvent.type(input, "Threat Intel");

      const intelOption = screen.getByRole("button", { name: /^intel$/i });
      expect(intelOption).toBeInTheDocument();
      await userEvent.click(intelOption);

      expect(screen.getByRole("link", { name: "Intel" })).toHaveClass("active");
      expect(screen.getByRole("heading", { name: "Intel" })).toBeInTheDocument();
    });

    it("typing 'Enrichment' filters to 'Intel' and navigates to /intel", async () => {
      renderApp(<App />);
      await screen.findByTestId("wordmark");

      await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
      const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
      await userEvent.type(input, "Enrichment");

      const intelOption = screen.getByRole("button", { name: /^intel$/i });
      expect(intelOption).toBeInTheDocument();
      await userEvent.click(intelOption);

      expect(screen.getByRole("link", { name: "Intel" })).toHaveClass("active");
      expect(screen.getByRole("heading", { name: "Intel" })).toBeInTheDocument();
    });

    it("typing 'Discovery' filters to 'Network' and navigates to /network", async () => {
      renderApp(<App />);
      await screen.findByTestId("wordmark");

      await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
      const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
      await userEvent.type(input, "Discovery");

      const networkOption = screen.getByRole("button", { name: /^network$/i });
      expect(networkOption).toBeInTheDocument();
      await userEvent.click(networkOption);

      expect(screen.getByRole("link", { name: "Network" })).toHaveClass("active");
      expect(screen.getByRole("heading", { name: "Network" })).toBeInTheDocument();
    });

    it("typing 'Vulnerabilities' filters to 'Network' and navigates to /network", async () => {
      renderApp(<App />);
      await screen.findByTestId("wordmark");

      await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
      const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
      await userEvent.type(input, "Vulnerabilities");

      const networkOption = screen.getByRole("button", { name: /^network$/i });
      expect(networkOption).toBeInTheDocument();
      await userEvent.click(networkOption);

      expect(screen.getByRole("link", { name: "Network" })).toHaveClass("active");
      expect(screen.getByRole("heading", { name: "Network" })).toBeInTheDocument();
    });

    it("typing 'Collectors' filters to 'Sources' and navigates to /sources", async () => {
      renderApp(<App />);
      await screen.findByTestId("wordmark");

      await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
      const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
      await userEvent.type(input, "Collectors");

      const sourcesOption = screen.getByRole("button", { name: /^sources$/i });
      expect(sourcesOption).toBeInTheDocument();
      await userEvent.click(sourcesOption);

      expect(screen.getByRole("link", { name: "Sources" })).toHaveClass("active");
      expect(screen.getByRole("heading", { name: "Sources" })).toBeInTheDocument();
    });
  });

  describe("(c) Old routes still resolve cleanly without dangling links", () => {
    it("/threat-intel route resolves to Intel", async () => {
      renderApp(<App />, { route: "/threat-intel" });
      expect(await screen.findByText(/Surfaced, not generated — derived tags, not verdicts/i)).toBeInTheDocument();
    });

    it("/enrichment route resolves to Intel", async () => {
      renderApp(<App />, { route: "/enrichment" });
      expect(await screen.findByText(/Real provider responses — never fabricated/i)).toBeInTheDocument();
    });

    it("/discovery route resolves to Network", async () => {
      renderApp(<App />, { route: "/discovery" });
      expect(await screen.findByText(/Active scanning — not read-only/i)).toBeInTheDocument();
    });

    it("/vulnerabilities route resolves to Network", async () => {
      renderApp(<App />, { route: "/vulnerabilities" });
      expect(await screen.findByText(/Active scanning — not read-only/i)).toBeInTheDocument();
    });

    it("/collectors route resolves to Sources", async () => {
      renderApp(<App />, { route: "/collectors" });
      expect(await screen.findByText(/Live collectors/i)).toBeInTheDocument();
    });

    it("/approvals route resolves to the real Approvals screen (C4-T1)", async () => {
      renderApp(<App />, { route: "/approvals" });
      expect(await screen.findByRole("heading", { name: "Approvals" })).toBeInTheDocument();
      // No pending approvals in this mock → the honest empty state, not a placeholder.
      expect(await screen.findByTestId("approvals-empty")).toHaveTextContent("No pending approvals");
      expect(screen.queryByText(/Coming in a later phase/i)).toBeNull();
    });
  });
});
