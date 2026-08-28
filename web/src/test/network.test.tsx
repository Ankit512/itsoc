import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import type { DiscoveryStatus } from "@/lib/api";
import { renderApp, mockFetch } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const IDLE: DiscoveryStatus = {
  running: false, target: "", vuln: false, startedAt: null, finishedAt: null,
  error: "", hostsFound: 0, assetsStored: 0, vulnsStored: 0, nmapInstalled: true,
};
const NO_NMAP: DiscoveryStatus = { ...IDLE, nmapInstalled: false };

const EMPTY_ASSETS = { items: [], total: 0, limit: 100, offset: 0 };
const EMPTY_VULNS = { items: [], total: 0, limit: 200, offset: 0 };

describe("Network — merged Discovery + Vulnerabilities screen (C1-T4)", () => {
  it("renders the consolidated single active-scanning safety banner and tab controls", async () => {
    mockFetch({
      "/api/discovery/status": IDLE,
      "/api/store/assets": EMPTY_ASSETS,
      "/api/store/vulns": EMPTY_VULNS,
    });
    renderApp(<App />, { route: "/network" });

    // EXACTLY ONE top-level active scanning banner with authorization safety notice
    const banners = await screen.findAllByText(/Active scanning — not read-only/i);
    expect(banners).toHaveLength(1);
    expect(screen.getByText(/Only scan networks you are authorized to test; nothing runs on a timer/i)).toBeInTheDocument();

    // Tablist exists with ARIA attributes and Discovery is active by default
    const tablist = screen.getByRole("tablist", { name: "Network" });
    expect(tablist).toBeInTheDocument();
    const discoveryTab = screen.getByRole("tab", { name: /^discovery$/i });
    const vulnsTab = screen.getByRole("tab", { name: /^vulnerabilities$/i });
    expect(discoveryTab).toHaveAttribute("aria-selected", "true");
    expect(discoveryTab).toHaveClass("on");
    expect(vulnsTab).toHaveAttribute("aria-selected", "false");
    expect(vulnsTab).not.toHaveClass("on");

    // Discovery tab contents are visible
    expect(screen.getByRole("button", { name: /discover live nodes/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /service \+ vulnerability scan/i })).toBeInTheDocument();
    expect(screen.getByText(/No scans have run — results appear here after a user-initiated scan/i)).toBeInTheDocument();
  });

  it("locks out scanning buttons when nmap is not installed", async () => {
    mockFetch({
      "/api/discovery/status": NO_NMAP,
      "/api/store/assets": EMPTY_ASSETS,
    });
    renderApp(<App />, { route: "/network" });

    expect(await screen.findByText(/nmap is not installed/i)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/target host or cidr/i), "192.168.1.0/24");
    expect(screen.getByRole("button", { name: /discover live nodes/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /service \+ vulnerability scan/i })).toBeDisabled();
  });

  it("switches to the Vulnerabilities tab and handles cross-link back to Discovery tab", async () => {
    mockFetch({
      "/api/discovery/status": IDLE,
      "/api/store/assets": EMPTY_ASSETS,
      "/api/store/vulns": EMPTY_VULNS,
    });
    renderApp(<App />, { route: "/network" });

    // Switch to Vulnerabilities tab
    const vulnsTab = await screen.findByRole("tab", { name: /^vulnerabilities$/i });
    await userEvent.click(vulnsTab);
    expect(vulnsTab).toHaveAttribute("aria-selected", "true");
    expect(vulnsTab).toHaveClass("on");
    expect(screen.getByRole("tab", { name: /^discovery$/i })).toHaveAttribute("aria-selected", "false");

    // Shows honest empty state with button to return to Discovery tab
    const emptyMsg = await screen.findByText(/No vulnerability data yet/i);
    expect(emptyMsg).toBeInTheDocument();
    const toDiscoveryBtn = within(emptyMsg.parentElement!).getByRole("button", { name: /discovery/i });
    await userEvent.click(toDiscoveryBtn);

    // Now back on Discovery tab
    expect(screen.getByRole("tab", { name: /^discovery$/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: /^discovery$/i })).toHaveClass("on");
    expect(screen.getByRole("button", { name: /discover live nodes/i })).toBeInTheDocument();
  });

  it("renders stored vulnerabilities with NSE-derived severity and honest unknown", async () => {
    mockFetch({
      "/api/discovery/status": IDLE,
      "/api/store/assets": EMPTY_ASSETS,
      "/api/store/vulns": {
        items: [
          {
            id: 101,
            ts: "2026-08-20T10:00:00Z",
            asset_ip: "10.0.0.5",
            name: "ssl-heartbleed",
            cve: "CVE-2014-0160",
            severity: "CRITICAL",
            cvss: 9.3,
            details: "VULNERABLE: OpenSSL Heartbleed",
            source: "nmap:ssl-heartbleed",
            status: "OPEN",
          },
          {
            id: 102,
            ts: "2026-08-20T10:00:00Z",
            asset_ip: "10.0.0.5",
            name: "http-enum",
            cve: "",
            severity: "",
            cvss: 0,
            details: "Discovered directory /admin",
            source: "nmap:http-enum",
            status: "OPEN",
          },
        ],
        total: 2,
        limit: 200,
        offset: 0,
      },
    });
    renderApp(<App />, { route: "/network" });

    // Switch to Vulnerabilities tab
    await userEvent.click(await screen.findByRole("tab", { name: /^vulnerabilities$/i }));

    const cveCell = await screen.findByText("CVE-2014-0160");
    const row = cveCell.closest("tr")!;
    expect(within(row).getByText("CRITICAL")).toBeInTheDocument();
    expect(within(row).getByText("9.3")).toBeInTheDocument();

    // Unrated finding is honestly rendered as unknown
    expect(screen.getByText("unknown")).toBeInTheDocument();

    // Rule verdict tags (.is-tag--crit / .is-tag--high etc) are NOT borrowed for scanner findings
    expect(document.querySelector(".is-tag--crit, .is-tag--high, .is-tag--med, .is-tag--low")).toBeNull();
  });
});
