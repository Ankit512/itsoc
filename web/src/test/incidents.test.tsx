import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";
import type { Incident } from "@/lib/api";

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
    const rows = screen.getAllByTestId("incident-row");
    expect(rows.length).toBe(2);
    // The entity also appears in the sidebar's contextual RECENT INCIDENTS list
    // on this route, so scope the table assertion to the incident row itself.
    expect(within(rows[0]).getByText("203.0.113.44")).toBeInTheDocument();
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

  it("renders the layered RCA panel with facts, matched runbook, and hypothesis", async () => {
    const rca = {
      incidentId: "inc-abc123",
      facts: {
        incidentId: "inc-abc123",
        rules: ["auth_bruteforce_success", "suspicious_outbound"],
        firstSeen: "2026-08-13T02:16:44+00:00",
        lastSeen: "2026-08-13T02:18:00+00:00",
        timeline: [
          { t: "02:16:44", label: "Failed password for admin", rule: "auth_bruteforce" },
          { t: "02:16:52", label: "Accepted password for admin", rule: "auth_bruteforce_success" },
        ],
      },
      runbook: {
        matched: true,
        file: "auth_bruteforce.md",
        title: "SSH Brute-Force & Credential Compromise",
        passage: "Rotate the credential, force session logout, block the source IP.",
        score: 4.1,
        coverage: 1.0,
      },
      hypothesis: {
        text: "A sustained brute-force from 203.0.113.44 succeeded against admin.",
        label: "advisory · hypothesis · not a verdict",
      },
    };

    mockFetch({
      "/api/incidents/inc-abc123/rca": rca,
      "/api/incidents": { incidents: [incident()] },
    });

    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    expect(await screen.findByTestId("rca-panel")).toBeInTheDocument();
    expect(await screen.findByTestId("rca-facts")).toBeInTheDocument();
    expect(screen.getByText("auth_bruteforce_success")).toBeInTheDocument();
    expect(screen.getByText("Failed password for admin")).toBeInTheDocument();

    expect(screen.getByTestId("rca-runbook")).toBeInTheDocument();
    expect(screen.getByText("SSH Brute-Force & Credential Compromise")).toBeInTheDocument();
    expect(screen.getByText(/Rotate the credential/)).toBeInTheDocument();

    expect(screen.getByTestId("rca-hypothesis")).toBeInTheDocument();
    // The hypothesis also grounds the inline itsoc-analyst card in the rail, so
    // scope the assertion to the root-cause hypothesis block itself.
    expect(within(screen.getByTestId("rca-hypothesis"))
      .getByText(/A sustained brute-force from 203.0.113.44/)).toBeInTheDocument();
  });

  it("renders honest absence notes when runbook and model are unavailable", async () => {
    const rcaHonest = {
      incidentId: "inc-abc123",
      facts: {
        rules: ["custom_rare_rule"],
        firstSeen: null,
        lastSeen: null,
        timeline: [],
        note: "some member findings are not in the loaded run",
      },
      runbook: {
        matched: false,
        note: "no runbook matched this cluster's rules with sufficient confidence",
      },
      hypothesis: {
        text: null,
        label: "advisory · hypothesis · not a verdict",
        note: "model unavailable — deterministic facts only",
      },
    };

    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaHonest,
      "/api/incidents": { incidents: [incident()] },
    });

    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    expect(await screen.findByTestId("rca-panel")).toBeInTheDocument();
    // The note appears twice now: in the RCA runbook card and in the rail's
    // response checklist, which refuses to invent steps without a runbook.
    expect((await screen.findAllByText(/no runbook matched this cluster/)).length).toBeGreaterThan(0);
    expect(screen.getByText(/model unavailable — deterministic facts only/)).toBeInTheDocument();
    expect(screen.getByText(/some member findings are not in the loaded run/)).toBeInTheDocument();
  });
});

// ── C1-T2: Cases absorbed into the merged Incidents screen ──────────────────
import type { EmbeddedCase } from "@/lib/api";

function embeddedCase(over: Partial<EmbeddedCase> = {}): EmbeddedCase {
  return {
    caseId: "case-2", title: "Analyst-only triage note",
    notes: "no rule fired — following a hunch on host web-07",
    assignee: "lee", caseStatus: "open",
    caseCreatedAt: "2026-08-20T12:00:00+00:00", caseUpdatedAt: "2026-08-20T12:00:00+00:00",
    linkedFindings: [], linkedIncidents: [], ...over,
  };
}

/** A manual incident as it arrives on the wire: severity is null (no rule
 *  verdict). We deliberately keep `severity: null` here to exercise the api
 *  wrapper's coercion — without it the shell's sevVar/sevWord would crash. */
function manualIncident(over: Record<string, unknown> = {}) {
  return {
    id: "inc-manual-abc", runId: "", entity: "lee", entityKind: "manual",
    title: "Analyst-only triage note", severity: null, state: "new",
    findingIds: [], findingCount: 0, techniques: [], attackerStatus: "",
    createdAt: "2026-08-20T12:00:00+00:00", firstSeen: null, lastSeen: null,
    acknowledgedAt: null, resolvedAt: null, timeUncertain: false,
    origin: "manual", manualBadge: "MANUAL — analyst-created, no rule verdict",
    analystSeverity: null, cases: [embeddedCase()], ...over,
  } as unknown as Incident;
}

describe("Incidents ← Cases merge (C1-T2)", () => {
  it("a manual incident shows the MANUAL badge and never a rule-severity verdict (list)", async () => {
    // severity:null on the wire — if the wrapper didn't coerce it, the shell's
    // RECENT INCIDENTS sidebar (sevVar/sevWord) would throw and this would crash.
    mockFetch({ "/api/incidents": { incidents: [manualIncident()] } });
    renderApp(<App />, { route: "/incidents" });

    const rows = await screen.findAllByTestId("incident-row");
    expect(rows.length).toBe(1);
    expect(within(rows[0]).getByTestId("manual-badge")).toHaveTextContent("MANUAL");
    // No rule-severity word renders for the manual incident's row.
    for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
      expect(within(rows[0]).queryByText(sev)).toBeNull();
    }
  });

  it("a manual incident detail carries the full badge + analyst-assigned severity, no rule verdict", async () => {
    mockFetch({ "/api/incidents": { incidents: [manualIncident({ analystSeverity: "HIGH" })] } });
    renderApp(<App />, { route: "/incidents?sel=inc-manual-abc" });

    expect(await screen.findByText("MANUAL — analyst-created, no rule verdict")).toBeInTheDocument();
    expect(screen.getByTestId("analyst-severity")).toHaveTextContent(/analyst-assigned: HIGH/);
    // The absorbed case surface renders its real notes.
    expect(screen.getByTestId("incident-cases")).toBeInTheDocument();
    expect(screen.getByText(/following a hunch on host web-07/)).toBeInTheDocument();
    // Crucial honesty assertion: NO rule-severity verdict tag anywhere.
    expect(document.querySelector(".is-tag--crit, .is-tag--high, .is-tag--med, .is-tag--low")).toBeNull();
    // Analyst-owned lifecycle is available on the manual incident too.
    expect(screen.getByText(/Lifecycle · analyst-owned/)).toBeInTheDocument();
  });

  it("a rule incident surfaces its linked analyst case (title, notes, status, analyst-linked findings)", async () => {
    const withCase = incident({
      cases: [embeddedCase({
        caseId: "case-1", title: "Investigate 203.0.113.44", notes: "checked the firewall",
        assignee: "sam", caseStatus: "investigating", linkedFindings: ["detector-9"],
      })],
    });
    mockFetch({ "/api/incidents": { incidents: [withCase] } });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    expect(await screen.findByTestId("incident-cases")).toBeInTheDocument();
    expect(screen.getByText("Investigate 203.0.113.44")).toBeInTheDocument();
    expect(screen.getByText(/checked the firewall/)).toBeInTheDocument();
    expect((screen.getByLabelText("Case status of case-1") as HTMLSelectElement).value).toBe("investigating");
    // analyst-linked finding surfaced, kept SEPARATE from derived findingIds.
    expect(screen.getByText("detector-9")).toBeInTheDocument();
    // The rule incident STILL shows its rule-owned severity verdict.
    expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
  });

  it("shows an honest empty note when a manual incident's case has no notes", async () => {
    mockFetch({ "/api/incidents": { incidents: [manualIncident({ cases: [embeddedCase({ notes: "" })] })] } });
    renderApp(<App />, { route: "/incidents?sel=inc-manual-abc" });
    expect(await screen.findByText("No notes on this case.")).toBeInTheDocument();
  });
});
