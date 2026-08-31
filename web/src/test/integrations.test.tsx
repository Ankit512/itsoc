import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

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
});
