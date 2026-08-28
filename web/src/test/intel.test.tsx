import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";
import type { ThreatIntel } from "@/lib/api";

afterEach(() => vi.restoreAllMocks());

const INTEL_FEEDS: ThreatIntel = {
  indicators: [{
    id: "indicator--1", name: "Known brute-force source IP",
    pattern: "[ipv4-addr:value = '203.0.113.44']",
    types: ["malicious-activity"], validFrom: "2026-08-01T00:00:00Z",
  }],
  indicatorSource: "threat_intel/demo_threat_intel.json (offline STIX bundle)",
  ruleTechniques: { auth_bruteforce: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }] },
  attackCacheWarm: false,
};

const NO_KEYS = { otx: false, abuseipdb: false };
const BOTH_KEYS = { otx: true, abuseipdb: true };
const EMPTY_IOCS = { items: [], total: 0, limit: 100, offset: 0 };

describe("Intel merged screen (C1-T3 fan-out)", () => {
  describe("Feeds section (offline STIX + MITRE)", () => {
    it("renders offline egress banner, STIX indicators, and rule→MITRE map", async () => {
      mockFetch({
        "/api/threat-intel": INTEL_FEEDS,
        "/api/ti/keys": NO_KEYS,
        "/api/store/iocs": EMPTY_IOCS,
      });
      renderApp(<App />, { route: "/intel" });

      // Tab switcher exists with Feeds active by default
      const feedsTab = await screen.findByRole("tab", { name: /feeds/i });
      expect(feedsTab).toHaveClass("on");

      // Distinct offline egress note (waits for async query load)
      const egress = await screen.findByTestId("feeds-egress-note");
      expect(egress).toHaveTextContent(/Surfaced, not generated — derived tags, not verdicts/i);
      expect(egress).toHaveTextContent(/Indicators come from an offline STIX bundle/i);

      // Real STIX indicators + source path
      expect(screen.getByText("Known brute-force source IP")).toBeInTheDocument();
      expect(screen.getByText("threat_intel/demo_threat_intel.json (offline STIX bundle)")).toBeInTheDocument();
      expect(screen.getByTestId("ioc-row")).toBeInTheDocument();

      // Rule technique mapping + cold cache indicator
      expect(screen.getByText("auth_bruteforce")).toBeInTheDocument();
      expect(screen.getByText("T1110")).toHaveAttribute("title", "T1110 · Brute Force · Credential Access");
      expect(screen.getByText(/cold — technique names come from the static map only/i)).toBeInTheDocument();

      // Core honesty constraint: No rule severity tags on TI badges
      expect(document.querySelector(".is-tag--crit, .is-tag--high, .is-tag--med, .is-tag--low")).toBeNull();
    });

    it("handles an empty bundle honestly", async () => {
      mockFetch({
        "/api/threat-intel": { ...INTEL_FEEDS, indicators: [], ruleTechniques: {} },
        "/api/ti/keys": NO_KEYS,
        "/api/store/iocs": EMPTY_IOCS,
      });
      renderApp(<App />, { route: "/intel?tab=feeds" });

      expect(await screen.findByText(/The bundle holds no indicators/i)).toBeInTheDocument();
      expect(screen.getByText(/No rule mappings available/i)).toBeInTheDocument();
    });
  });

  describe("Live Enrichment section (outbound API calls)", () => {
    it("switches to Live Enrichment section with distinct egress note and masked key status", async () => {
      mockFetch({
        "/api/threat-intel": INTEL_FEEDS,
        "/api/ti/keys": NO_KEYS,
        "/api/store/iocs": EMPTY_IOCS,
      });
      renderApp(<App />, { route: "/intel" });

      // Click tab to switch to Live Enrichment
      const enrichTab = await screen.findByRole("tab", { name: /live enrichment/i });
      await userEvent.click(enrichTab);

      // Distinct outbound egress note (NOT collapsed into offline note)
      const egress = await screen.findByTestId("enrichment-egress-note");
      expect(egress).toHaveTextContent(/Real provider responses — never fabricated/i);
      expect(egress).toHaveTextContent(/External threat-intel lookups using your own API keys/i);

      // Masked keys note & honest unconfigured state
      expect(screen.getByText(/Your API keys are stored write-only and never sent back to the browser/i)).toBeInTheDocument();
      expect(screen.getAllByText(/no key configured/i)).not.toHaveLength(0);

      // Warning when no key configured
      expect(screen.getByText(/No provider key is configured — lookups will fail until one is saved/i)).toBeInTheDocument();

      // Honest empty IOC history
      expect(screen.getByText(/No lookups yet — results here are real provider responses only/i)).toBeInTheDocument();
    });

    it("performs live IP enrichment and renders provider verdicts with skipped provider reporting", async () => {
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
            results: [{
              id: 1, ts: "2026-08-19T17:00:00Z", ioc: "203.0.113.9", ioc_type: "ipv4",
              provider: "OTX", score: 70, verdict: "malicious",
              details: '{"pulseCount":7}', source_event_id: null,
            }],
            errors: [], notConfigured: ["AbuseIPDB"],
          });
        }
        if (url.includes("/api/ti/keys")) return reply(BOTH_KEYS);
        if (url.includes("/api/store/iocs")) return reply(EMPTY_IOCS);
        if (url.includes("/api/threat-intel")) return reply(INTEL_FEEDS);
        if (url.includes("/api/runs")) return reply({ runs: [], current: null });
        return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Response);
      }));

      renderApp(<App />, { route: "/intel?tab=enrichment" });

      await userEvent.type(await screen.findByLabelText(/IP address to enrich/i), "203.0.113.9");
      await userEvent.click(screen.getByRole("button", { name: /^enrich$/i }));

      await waitFor(() => expect(postBody).toEqual({ ip: "203.0.113.9" }));
      const verdict = await screen.findByText("malicious");
      const row = verdict.closest("tr")!;
      expect(within(row).getByText("OTX")).toBeInTheDocument();
      expect(within(row).getByText("70")).toBeInTheDocument();

      // Skipped provider honest reporting
      expect(screen.getByText(/Not configured \(skipped\): AbuseIPDB/i)).toBeInTheDocument();
    });
  });

  describe("Backwards-compatible legacy routes", () => {
    it("/threat-intel route resolves to Intel Feeds section", async () => {
      mockFetch({
        "/api/threat-intel": INTEL_FEEDS,
        "/api/ti/keys": NO_KEYS,
        "/api/store/iocs": EMPTY_IOCS,
      });
      renderApp(<App />, { route: "/threat-intel" });
      expect(await screen.findByTestId("feeds-egress-note")).toBeInTheDocument();
    });

    it("/enrichment route resolves to Intel Live Enrichment section", async () => {
      mockFetch({
        "/api/threat-intel": INTEL_FEEDS,
        "/api/ti/keys": NO_KEYS,
        "/api/store/iocs": EMPTY_IOCS,
      });
      renderApp(<App />, { route: "/enrichment" });
      expect(await screen.findByTestId("enrichment-egress-note")).toBeInTheDocument();
    });
  });
});
