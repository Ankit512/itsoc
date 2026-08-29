import { describe, it, expect, vi, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp, mockFetch } from "./helpers";
import { Incidents, ResponsePanel } from "@/pages/Incidents";
import type { Incident } from "@/lib/api";

/** C4-F1 — the Incidents Response panel. Panel BEHAVIOUR is unit-rendered in
 *  isolation (light); the view-level invariants (one accent button, no approve
 *  control) are proven with a single full <Incidents /> render so the accent
 *  budget is scoped to the real view — and so this file adds only ONE heavy
 *  full-detail mount to the suite. */

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

const RECO = {
  type: "runbook_recommendation", advisory: true, incidentId: "inc-abc123",
  eligible: [
    { runbookId: "rb-block-ip", name: "Block source IP at the edge", severityFloor: "HIGH",
      triggerRules: ["auth_bruteforce_success", "auth_bruteforce"],
      eligibilityProof: { eligible: true, missing: [] } },
    { runbookId: "rb-draft-notify", name: "Draft a notification", severityFloor: "LOW",
      triggerRules: ["auth_bruteforce"], eligibilityProof: { eligible: true, missing: [] } },
  ],
  recommendation: { label: "advisory · recommendation · not a verdict",
                    status: "absent", ranking: [], justifications: [], note: "no model offered" },
};

/** Only what ResponsePanel itself calls — a light render. */
function panelRoutes(reco: unknown = RECO, approvals: unknown = { id: "appr-1", state: "pending" }) {
  return {
    "/api/incidents/inc-abc123/runbook-recommendation": reco,
    "/api/approvals": approvals,
  };
}

/** The full incident detail mounts many sub-panels; route what they fetch. */
function viewRoutes() {
  return {
    "/api/incidents/inc-abc123/runbook-recommendation": RECO,
    "/api/incidents/inc-abc123/rca": { error: "no rca" },
    "/api/incidents/inc-abc123/advisory": { error: "no advisory" },
    "/api/incidents/inc-abc123/bruteforce": { available: false, entity: "203.0.113.44", points: [] },
    "/api/approvals": { id: "appr-1", state: "pending" },
    "/api/incidents": { incidents: [incident()] },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Incidents Response panel — C4-F1", () => {
  it("renders the rule-eligible runbooks as is-runbook-cards with their trigger chips", async () => {
    mockFetch(panelRoutes());
    renderApp(<ResponsePanel inc={incident()} />, { route: "/incidents" });
    const cards = await screen.findAllByTestId("runbook-card");
    expect(cards).toHaveLength(2);
    expect(within(cards[0]).getByText("Block source IP at the edge")).toBeInTheDocument();
    expect(within(cards[0]).getByTestId("rb-badge-eligible")).toBeInTheDocument();
    expect(within(cards[0]).getByText("auth_bruteforce_success")).toBeInTheDocument();
  });

  it("Request approval CREATES a pending approval, then links into the Approvals screen", async () => {
    mockFetch(panelRoutes(RECO, { id: "appr-xyz", state: "pending" }));
    const user = userEvent.setup();
    renderApp(<ResponsePanel inc={incident()} />, { route: "/incidents" });
    await screen.findByTestId("request-approval");
    await user.click(screen.getByTestId("request-approval"));
    const created = await screen.findByTestId("approval-created");
    expect(created).toHaveTextContent(/pending approval created/i);
    expect(within(created).getByTestId("open-in-approvals").getAttribute("href"))
      .toContain("/approvals?sel=appr-xyz");
  });

  it("a 409 on Request approval flips that runbook to ineligible with the engine's missing[], VERBATIM", async () => {
    const MISSING = ["severity_floor: incident is MEDIUM, below the HIGH floor"];
    mockFetch(panelRoutes(RECO, { __status: 409, missing: MISSING }));
    const user = userEvent.setup();
    renderApp(<ResponsePanel inc={incident()} />, { route: "/incidents" });
    await screen.findAllByTestId("rb-badge-eligible");
    await user.click(screen.getByTestId("request-approval"));
    const missing = await screen.findByTestId("rb-missing");
    expect(within(missing).getByText(MISSING[0])).toBeInTheDocument();
    expect(screen.getByTestId("rb-badge-ineligible")).toBeInTheDocument();
  });

  it("no eligible runbook → an honest empty state that reads as information, not alarm", async () => {
    mockFetch(panelRoutes({ ...RECO, eligible: [] }));
    renderApp(<ResponsePanel inc={incident()} />, { route: "/incidents" });
    const empty = await screen.findByTestId("response-empty");
    expect(empty).toHaveTextContent(/no runbook is eligible/i);
    expect(empty).toHaveTextContent(/information, not a failure/i);
    expect(screen.queryByTestId("request-approval")).toBeNull();
  });

  it("INVARIANTS 3 & 4 — exactly one .is-btn--primary in the Incidents view (Request approval), and NO approve control", async () => {
    mockFetch(viewRoutes());
    const { container } = renderApp(<Incidents />, { route: "/incidents?sel=inc-abc123" });
    await screen.findByTestId("request-approval");
    // Invariant 3: the single accent action in the whole view is Request approval.
    expect(container.querySelectorAll(".is-btn--primary")).toHaveLength(1);
    expect(screen.getByTestId("request-approval")).toHaveClass("is-btn--primary");
    // Invariant 4: the deterministic approve control lives ONLY in the Approvals screen.
    expect(screen.queryByTestId("approval-approve")).toBeNull();
    const approveBtn = screen.queryAllByRole("button")
      .find((b) => /^\s*approve\s*$/i.test(b.textContent ?? ""));
    expect(approveBtn).toBeUndefined();
  });
});
