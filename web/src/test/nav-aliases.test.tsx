import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { CORE_NAV, EXPERIMENTAL_NAV, NAV } from "@/components/layout/AppShell";
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
