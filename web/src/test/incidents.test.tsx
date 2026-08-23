import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";
import type { Incident, Rca } from "@/lib/api";

function incident(over: Partial<Incident> = {}): Incident {
  return {
    id: "inc-abc123", runId: "test-run", entity: "203.0.113.44", entityKind: "ip",
    title: "203.0.113.44 — 2 correlated finding(s)", severity: "CRITICAL", state: "new",
    findingIds: ["detector-0", "detector-1"], findingCount: 2,
    techniques: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
    attackerStatus: "Breaking In",
    createdAt: "2026-08-13T02:16:44+00:00", firstSeen: "2026-08-13T02:16:44+00:00",
    lastSeen: "2026-08-13T02:18:00+00:00", acknowledgedAt: null, resolvedAt: null,
    timeUncertain: false, ...over,
  };
}

describe("Incidents page", () => {
  it("renders the incident list from real data", async () => {
    mockFetch({ "/api/incidents": { incidents: [incident(), incident({ id: "inc-def456", entity: "app-01", entityKind: "host", severity: "HIGH", state: "acknowledged" }) ] } });
    renderApp(<App />, { route: "/incidents" });

    expect(await screen.findByText(/2 incident\(s\)/)).toBeInTheDocument();
    expect(screen.getAllByTestId("incident-row").length).toBe(2);
    expect(screen.getByText("203.0.113.44")).toBeInTheDocument();
  });

  it("shows an honest empty state when there are no incidents", async () => {
    mockFetch({ "/api/incidents": { incidents: [] } });
    renderApp(<App />, { route: "/incidents" });
    expect(await screen.findByText(/No incidents yet/)).toBeInTheDocument();
  });

  it("opens the detail with lifecycle controls and posts a state transition", async () => {
    const post = vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => incident({ state: "acknowledged", acknowledgedAt: "2026-08-13T03:00:00+00:00" }),
    } as Response));
    // Route the POST /state before the list route (substring, insertion order).
    mockFetch({ "/api/incidents/inc-abc123/state": { incidents: [] }, "/api/incidents": { incidents: [incident()] } });
    // Override fetch so the state POST is observable, everything else falls through.
    const base = globalThis.fetch as unknown as typeof fetch;
    vi.stubGlobal("fetch", vi.fn((url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).includes("/state") && init?.method === "POST") return post();
      return (base as (u: RequestInfo | URL, i?: RequestInit) => Promise<Response>)(url, init);
    }));

    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    expect(await screen.findByText(/Lifecycle · analyst-owned/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "acknowledged" }));
    expect(post).toHaveBeenCalledTimes(1);
  });

  it("renders the layered RCA: advisory-separated, cited runbook, withheld hypothesis", async () => {
    const rca: Rca = {
      incidentId: "inc-abc123",
      facts: {
        incidentId: "inc-abc123", entity: "203.0.113.44", entityKind: "ip",
        findingIds: ["detector-0", "detector-1"], membersLoaded: 2,
        rules: ["auth_bruteforce", "auth_bruteforce_success"],
        firstSeen: "2026-08-13T02:16:44+00:00", lastSeen: "2026-08-13T02:18:00+00:00",
        timeline: [{ t: "02:16:44", label: "First failed login", line: 5, findingId: "detector-0", rule: "auth_bruteforce" }],
        note: null,
      },
      runbook: { matched: true, file: "ssh-brute-force.md", title: "SSH brute-force / credential attack response", passage: "Block the source IP at the firewall.", score: 21.05, coverage: 1 },
      hypothesis: { text: null, label: "advisory · hypothesis · not a verdict", note: "withheld — failed the explanation consistency guard", reasons: ["names IP 198.51.100.7, which is not in this finding's entities or evidence"] },
    };
    // More specific route first: mockFetch matches by substring in insertion order.
    mockFetch({ "/api/incidents/inc-abc123/rca": rca, "/api/incidents": { incidents: [incident()] } });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    // The advisory frame is present and clearly labeled apart from the verdict.
    expect(await screen.findByTestId("rca-panel")).toBeInTheDocument();
    expect(screen.getByText(/severity above is rule-owned and unaffected/)).toBeInTheDocument();
    // Deterministic facts render (findBy: the inner query resolves async).
    expect(await screen.findByText("auth_bruteforce_success")).toBeInTheDocument();
    expect(screen.getByText(/First failed login/)).toBeInTheDocument();
    // The citation is the real runbook, with its bar made visible.
    expect(screen.getByText(/SSH brute-force \/ credential attack response/)).toBeInTheDocument();
    expect(screen.getByText(/Block the source IP at the firewall/)).toBeInTheDocument();
    // A guard-withheld hypothesis shows the honest note + reason, never prose.
    expect(screen.getByText(/withheld — failed the explanation consistency guard/)).toBeInTheDocument();
    expect(screen.getByText(/names IP 198\.51\.100\.7/)).toBeInTheDocument();
  });

  it("shows an honest absence when RCA cannot be served (404)", async () => {
    // No RCA route mocked → helpers 404 the fetch, the panel must not invent one.
    mockFetch({ "/api/incidents": { incidents: [incident()] } });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });
    expect(await screen.findByText(/Root-cause analysis unavailable/)).toBeInTheDocument();
  });
});
