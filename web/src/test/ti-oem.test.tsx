import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, vi } from "vitest";
import App from "@/App";
import { EGRESS_DISCLOSURE } from "@/pages/OemEngine";
import { renderApp, mockFetch } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const NO_KEYS = { otx: false, abuseipdb: false };
const BOTH_KEYS = { otx: true, abuseipdb: true };
const EMPTY_IOCS = { items: [], total: 0, limit: 100, offset: 0 };
const NO_CONNECTORS = { connectors: [] };

describe("Enrichment — TI panel (masked keys, honest states)", () => {
  it("shows honest not-configured key status and a no-key warning", async () => {
    mockFetch({
      "/api/ti/keys": NO_KEYS,
      "/api/store/iocs": EMPTY_IOCS,
    });
    renderApp(<App />, { route: "/enrichment" });

    expect(await screen.findAllByText(/no key configured/i)).not.toHaveLength(0);
    expect(screen.getByText(/No provider key is configured — lookups will fail until one is saved/i)).toBeInTheDocument();
    // Honest empty IOC history.
    expect(screen.getByText(/No lookups yet — results here are real provider responses only/i)).toBeInTheDocument();
  });

  it("enrich posts the IP and renders provider verdicts from the real response", async () => {
    let postBody: unknown = null;
    const reply = (body: unknown) =>
      Promise.resolve({ ok: true, status: 200, json: async () => body } as Response);
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      const url = String(u);
      if (url.includes("/api/auth/me")) return reply({ user: { username: "analyst", role: "analyst" } });
      if (url.includes("/api/auth/status")) return reply({ hasProfile: true, authType: "local_demo", provider: "LocalDemoAuth" });
      if (url.includes("/api/ti/enrich") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return reply({
          ip: "203.0.113.9",
          results: [{ id: 1, ts: "2026-08-19T17:00:00Z", ioc: "203.0.113.9", ioc_type: "ipv4",
                      provider: "OTX", score: 70, verdict: "malicious",
                      details: "{\"pulseCount\":7}", source_event_id: null }],
          errors: [], notConfigured: ["AbuseIPDB"],
        });
      }
      if (url.includes("/api/ti/keys")) return reply(BOTH_KEYS);
      if (url.includes("/api/store/iocs")) return reply(EMPTY_IOCS);
      if (url.includes("/api/runs")) return reply({ runs: [], current: null });
      return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Response);
    }));
    renderApp(<App />, { route: "/enrichment" });

    await userEvent.type(await screen.findByLabelText(/IP address to enrich/i), "203.0.113.9");
    await userEvent.click(screen.getByRole("button", { name: /^enrich$/i }));

    await waitFor(() => expect(postBody).toEqual({ ip: "203.0.113.9" }));
    const verdict = await screen.findByText("malicious");
    const row = verdict.closest("tr")!;
    expect(within(row).getByText("OTX")).toBeInTheDocument();
    expect(within(row).getByText("70")).toBeInTheDocument();
    // A provider with no key is honestly reported as skipped.
    expect(screen.getByText(/Not configured \(skipped\): AbuseIPDB/i)).toBeInTheDocument();
  });
});

describe("OEM Engine — connectors (masked creds, real poll outcome)", () => {
  it("shows the honest empty state and the add-connector form", async () => {
    mockFetch({ "/api/oem/connectors": NO_CONNECTORS });
    renderApp(<App />, { route: "/oem" });

    expect(await screen.findByText(/No connectors yet — add one on the left/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/API token/i)).toHaveAttribute("type", "password");
    const saveBtn = screen.getByRole("button", { name: /save connector/i });
    expect(saveBtn).toBeInTheDocument();
    const addPanel = saveBtn.closest(".is-panel") as HTMLElement;
    expect(within(addPanel).getByText(EGRESS_DISCLOSURE)).toBeInTheDocument();
  });

  it("renders a connector's real last-run/last-error and token presence only", async () => {
    mockFetch({
      "/api/oem/connectors": {
        connectors: [{
          name: "Prod-FW-1", kind: "oem", enabled: true, interval: 30,
          lastRun: "2026-08-19T17:00:00Z", lastError: "connector base URL is still a placeholder — set the real host",
          hasConfig: true, hasToken: true,
        }],
      },
    });
    renderApp(<App />, { route: "/oem" });

    expect(await screen.findByText("Prod-FW-1")).toBeInTheDocument();
    expect(await screen.findByText("token set")).toBeInTheDocument();
    // The real poll error is surfaced, not hidden behind a fake "connected".
    expect(screen.getByText(/still a placeholder/i)).toBeInTheDocument();
    const disableBtn = screen.getByRole("button", { name: /^disable$/i });
    expect(disableBtn).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /poll now/i })).toBeInTheDocument();
    const row = disableBtn.closest("div[style*='flex-direction: column']") as HTMLElement;
    expect(within(row).getByText(EGRESS_DISCLOSURE)).toBeInTheDocument();
  });

  it("renders the honest egress disclosure beside both the add-connector form and the enable toggle", async () => {
    mockFetch({
      "/api/oem/connectors": {
        connectors: [{
          name: "Cisco-Edge", kind: "oem", enabled: false, interval: 60,
          lastRun: null, lastError: null,
          hasConfig: true, hasToken: false,
        }],
      },
    });
    renderApp(<App />, { route: "/oem" });

    // 1. In the AddConnector panel
    const saveBtn = await screen.findByRole("button", { name: /save connector/i });
    const addPanel = saveBtn.closest(".is-panel") as HTMLElement;
    const addDisclosure = within(addPanel).getByText(EGRESS_DISCLOSURE);
    expect(addDisclosure).toBeInTheDocument();
    expect(addDisclosure.textContent?.trim()).toBe(EGRESS_DISCLOSURE);

    // 2. In the ConnectorRow beside the Enable toggle button
    expect(await screen.findByText("Cisco-Edge")).toBeInTheDocument();
    const enableBtn = await screen.findByRole("button", { name: /^enable$/i });
    const row = enableBtn.closest("div[style*='flex-direction: column']") as HTMLElement;
    const rowDisclosure = within(row).getByText(EGRESS_DISCLOSURE);
    expect(rowDisclosure).toBeInTheDocument();
    expect(rowDisclosure.textContent?.trim()).toBe(EGRESS_DISCLOSURE);

    // 3. Proved identical: both sites render the exact same shared constant value
    expect(addDisclosure.textContent?.trim()).toBe(rowDisclosure.textContent?.trim());
  });
});


