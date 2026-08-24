import { screen, within } from "@testing-library/react";
import App from "@/App";
import { NAV, EXPERIMENTAL_NAV } from "@/components/layout/AppShell";
import { useUi } from "@/store/ui";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("Phase 0 refocused app shell", () => {
  beforeEach(() => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS });
    useUi.setState({ experimental: false });
  });

  it("renders EXACTLY the four default nav items — nothing else", async () => {
    renderApp(<App />);
    const nav = screen.getByRole("navigation", { name: "Main" });
    const links = within(nav).getAllByRole("link");
    expect(links.map((l) => l.textContent)).toEqual(
      ["Overview", "Findings", "Sources", "Settings"]);
    expect(NAV.map((n) => n.label)).toEqual(
      ["Overview", "Findings", "Sources", "Settings"]);
    // The rebundled facets and the cut pages are gone from the nav.
    for (const gone of ["Alerts", "Incidents", "Threat Intel", "Assets", "Reports",
                        "Cases", "Discovery", "Vulnerabilities", "Enrichment",
                        "OEM Engine", "History", "Logout", "Collectors"]) {
      expect(within(nav).queryByText(gone)).not.toBeInTheDocument();
    }
    expect(screen.queryByTestId("experimental-section")).not.toBeInTheDocument();
  });

  it("experimental flag ON reveals the fenced Command-Center section", async () => {
    useUi.setState({ experimental: true });
    renderApp(<App />);
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByTestId("experimental-section")).toHaveTextContent("Experimental");
    for (const item of EXPERIMENTAL_NAV) {
      expect(within(nav).getByText(item.label)).toBeInTheDocument();
    }
    expect(within(nav).getByText("OEM Engine").closest("a")).toHaveAttribute("href", "/oem");
    expect(within(nav).getByText("History").closest("a")).toHaveAttribute("href", "/history");
  });

  it("fenced routes render the honest 'experimental off' notice when the flag is off", async () => {
    renderApp(<App />, { route: "/oem" });
    expect(await screen.findByTestId("experimental-off")).toHaveTextContent(/experimental — currently off/i);
    expect(screen.getByText(/Nothing was deleted/i)).toBeInTheDocument();
  });

  it("renders the v6 header actions on every page", async () => {
    renderApp(<App />);
    expect(screen.getByRole("heading", { name: "SOC Dashboard" })).toBeInTheDocument();
    expect(screen.getByText("Upload Logs")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /refresh/i })).toBeInTheDocument();
    // Filters exists but is honestly disabled until filtering is built.
    expect(screen.getByRole("button", { name: /filters/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /switch to dark mode/i })).toBeInTheDocument();
  });

  it("an unknown route renders the honest placeholder inside the same shell", async () => {
    renderApp(<App />, { route: "/no-such-page" });
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByText(/coming in a later phase/i)).toBeInTheDocument();
    expect(screen.getByText(/rather than invented data/i)).toBeInTheDocument();
  });
});

describe("cut pages (spec §3: they broke read-only / zero-egress)", () => {
  beforeEach(() => mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS }));

  it.each([
    ["/discovery", /active nmap network scanning/i],
    ["/vulnerabilities", /vulnerability scanning/i],
    ["/enrichment", /zero egress/i],
    ["/logout", /no accounts and no server session/i],
  ])("%s renders the honest removal notice, not the old page", async (route, reason) => {
    renderApp(<App />, { route });
    const notice = await screen.findByTestId("cut-notice");
    expect(notice).toHaveTextContent(/was removed from itsoc/i);
    expect(notice).toHaveTextContent(reason);
    expect(notice).toHaveTextContent(/actions are disabled by default/i);
    // No scan/enrich controls survive anywhere on the page.
    expect(screen.queryByRole("button", { name: /scan/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /enrich/i })).not.toBeInTheDocument();
  });
});
