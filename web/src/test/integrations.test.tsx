import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";
import { CATALOG } from "@/pages/Integrations";

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

describe("Integrations Page (Sovereign Connectors Gallery)", () => {
  beforeEach(() => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("navigates to Integrations via Command Palette and renders gallery", async () => {
    renderApp(<App />, { route: "/" });
    await screen.findByTestId("wordmark");

    await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
    const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
    await userEvent.type(input, "Integrations");

    const option = screen.getByRole("button", { name: /^integrations$/i });
    await userEvent.click(option);

    expect(await screen.findByTestId("integrations-page")).toBeInTheDocument();
    expect(screen.getByText("Sovereign Integrations & Connectors")).toBeInTheDocument();
    expect(screen.getByText("SSH / nftables Firewall")).toBeInTheDocument();
    expect(screen.getByText("TAXII / STIX 2.1 Threat Feeds")).toBeInTheDocument();
  });

  it("is reachable from the left sidebar nav and navigates to the gallery", async () => {
    renderApp(<App />, { route: "/incidents" });
    await screen.findByTestId("wordmark");

    const navLink = screen.getByRole("link", { name: /^integrations$/i });
    expect(navLink).toBeInTheDocument();

    await userEvent.click(navLink);
    expect(await screen.findByTestId("integrations-page")).toBeInTheDocument();
  });

  it("keeps the Integrations nav item active on the Integrations route", async () => {
    renderApp(<App />, { route: "/integrations" });
    await screen.findByTestId("integrations-page");

    const navLink = screen.getByRole("link", { name: /^integrations$/i });
    expect(navLink).toHaveAttribute("aria-current", "page");
  });

  it("renders catalog cards with explicit egress disclosure badges", async () => {
    renderApp(<App />, { route: "/integrations" });
    await screen.findByTestId("integrations-page");

    // Local compute zero-egress badge
    expect(screen.getAllByText("Zero Egress").length).toBeGreaterThan(0);
    // Outbound indicator-only disclosure badge
    expect(screen.getAllByText("Indicators HTTPS").length).toBeGreaterThan(0);
  });

  it("filters connector cards by category", async () => {
    renderApp(<App />, { route: "/integrations" });
    await screen.findByTestId("integrations-page");

    // Click Remediation & Firewalls category tab
    const firewallTab = screen.getByRole("tab", { name: "Remediation & Firewalls" });
    await userEvent.click(firewallTab);

    expect(screen.getByText("SSH / nftables Firewall")).toBeInTheDocument();
    expect(screen.queryByText("AlienVault OTX Pulse Feeds")).not.toBeInTheDocument();

    // Click Threat Intelligence category tab
    const threatIntelTab = screen.getByRole("tab", { name: "Threat Intelligence" });
    await userEvent.click(threatIntelTab);

    expect(screen.getByText("AlienVault OTX Pulse Feeds")).toBeInTheDocument();
    expect(screen.queryByText("SSH / nftables Firewall")).not.toBeInTheDocument();
  });

  it("filters connector cards using the live search input", async () => {
    renderApp(<App />, { route: "/integrations" });
    await screen.findByTestId("integrations-page");

    const searchInput = screen.getByLabelText("Search integrations");
    await userEvent.type(searchInput, "Syslog");

    expect(screen.getByText("Live Syslog Collector (UDP/TCP)")).toBeInTheDocument();
    expect(screen.queryByText("AlienVault OTX Pulse Feeds")).not.toBeInTheDocument();
  });

  it("keeps category filters and connector search together in a responsive toolbar", async () => {
    renderApp(<App />, { route: "/integrations" });
    const search = await screen.findByLabelText("Search integrations");
    const toolbar = search.closest(".is-integrations-toolbar");
    expect(toolbar).toBeTruthy();
    expect(toolbar?.querySelector("[role=tablist]")).toBeInTheDocument();
    expect(toolbar?.querySelector(".is-integrations-toolbar__search")).toContainElement(search);
  });

  it("opens configuration modal and runs test connection", async () => {
    renderApp(<App />, { route: "/integrations" });
    await screen.findByTestId("integrations-page");

    // Click Configure on SSH / nftables Firewall
    const configureBtns = screen.getAllByRole("button", { name: /configure/i });
    await userEvent.click(configureBtns[0]);

    // Modal opens
    expect(await screen.findByRole("heading", { name: /configure/i })).toBeInTheDocument();
    expect(screen.getByText(/egress boundary:/i)).toBeInTheDocument();

    // Run test connection
    const testBtn = screen.getByRole("button", { name: /test connection/i });
    await userEvent.click(testBtn);

    expect(await screen.findByText(/connected successfully/i)).toBeInTheDocument();
  });

  it("opens each connector's Configure modal and runs Test Connection with an honest ping", async () => {
    renderApp(<App />, { route: "/integrations" });
    await screen.findByTestId("integrations-page");

    // Unfiltered grid renders the full catalog, one Configure button per card.
    expect(screen.getAllByRole("button", { name: /configure/i })).toHaveLength(CATALOG.length);

    for (let i = 0; i < CATALOG.length; i++) {
      const conn = CATALOG[i];

      await userEvent.click(screen.getAllByRole("button", { name: /configure/i })[i]);

      // The modal belongs to THIS connector (not a stale/previous one).
      expect(
        await screen.findByRole("heading", { name: new RegExp(`^configure ${esc(conn.name)}$`, "i") })
      ).toBeInTheDocument();
      expect(screen.getByText(/egress boundary:/i)).toBeInTheDocument();

      await userEvent.click(screen.getByRole("button", { name: /test connection/i }));

      // None of the catalog statuses are "disabled", so every one reports the
      // honest local ping against its resolved endpoint (defaultEndpoint or name).
      const ok = await screen.findByText(/connected successfully/i);
      const endpoint = conn.defaultEndpoint || conn.name;
      expect(ok).toHaveTextContent(`Connected successfully to ${endpoint}`);

      // Close to move on to the next connector.
      await userEvent.click(screen.getByRole("button", { name: /^cancel$/i }));
      await screen.findByTestId("integrations-page");
    }
  });
});
