import { screen } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";
import type { ThreatIntel } from "@/lib/api";

const INTEL: ThreatIntel = {
  indicators: [{
    id: "indicator--1", name: "Known brute-force source IP",
    pattern: "[ipv4-addr:value = '203.0.113.44']",
    types: ["malicious-activity"], validFrom: "2026-08-01T00:00:00Z",
  }],
  indicatorSource: "threat_intel/demo_threat_intel.json (offline STIX bundle)",
  ruleTechniques: { auth_bruteforce: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }] },
  attackCacheWarm: false,
};

describe("Threat Intel page", () => {
  it("renders indicators and rule→technique rollups from real data", async () => {
    mockFetch({ "/api/threat-intel": INTEL });
    renderApp(<App />, { route: "/threat-intel" });

    expect(await screen.findByText("Known brute-force source IP")).toBeInTheDocument();
    expect(screen.getByTestId("ioc-row")).toBeInTheDocument();
    expect(screen.getByText("auth_bruteforce")).toBeInTheDocument();
    // v3 shows this both as the page note and as the top-bar subtitle.
    expect(screen.getAllByText(/derived tags — not verdicts/).length).toBeGreaterThan(0);
    expect(screen.getByText(/cold — technique names/)).toBeInTheDocument();
  });

  it("handles an empty bundle honestly", async () => {
    mockFetch({ "/api/threat-intel": { ...INTEL, indicators: [], ruleTechniques: {} } });
    renderApp(<App />, { route: "/threat-intel" });
    expect(await screen.findByText(/The bundle holds no indicators/)).toBeInTheDocument();
  });
});
