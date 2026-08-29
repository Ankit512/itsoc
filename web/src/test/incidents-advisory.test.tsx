import { describe, it, expect, vi, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import { renderApp, mockFetch } from "./helpers";
import App from "@/App";
import type { Incident, Rca, AdvisoryReport } from "@/lib/api";

/**
 * CARD C4-F2 — is-advisory-pending & is-advisory-timeout honesty tests.
 *
 * Invariants proven by runs:
 *  1. Real `timed_out` payload renders honest timeout state (not an infinite spinner, not a blank region).
 *  2. SELECTOR-NULL both ways: advisory elements are structurally absent from deterministic regions,
 *     and deterministic elements are structurally absent from advisory blocks.
 *  3. Pending is distinguishable from timed-out by selector (.is-advisory-pending vs .is-advisory-timeout).
 *  4. Advisory states do NOT borrow the severity/crit palette (--crit #f26d78).
 *  5. Primary button budget: ≤ 1 .is-btn--primary per view.
 */

const DEFAULT_AUTH_ME = {
  ok: true,
  user: { username: "analyst", displayName: "SOC Analyst", role: "analyst" },
};
const DEFAULT_AUTH_STATUS = {
  authenticated: true,
  requireAuth: false,
  user: { username: "analyst", role: "analyst" },
};

function incident(over: Partial<Incident> = {}): Incident {
  return {
    id: "inc-abc123",
    runId: "test-run",
    entity: "203.0.113.44",
    entityKind: "ip",
    title: "203.0.113.44 — 3 correlated finding(s)",
    severity: "CRITICAL",
    state: "new",
    findingIds: ["detector-0", "detector-1", "detector-2"],
    findingCount: 3,
    techniques: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
    attackerStatus: "Breaking In",
    createdAt: "2026-08-29T12:00:00Z",
    firstSeen: "2026-08-29T12:00:00Z",
    lastSeen: "2026-08-29T12:05:00Z",
    acknowledgedAt: null,
    resolvedAt: null,
    timeUncertain: false,
    ...over,
  };
}

function TL(n: number, isFinding: boolean, raw: string) {
  return { n, ts: "2026-08-29T12:00:00Z", level: "ERROR", host: "server-01", msg: raw, raw, isFinding };
}

function rcaWithInvestigation(): Rca {
  return {
    incidentId: "inc-abc123",
    facts: {
      incidentId: "inc-abc123",
      rules: ["auth_bruteforce_success"],
      firstSeen: "2026-08-29T12:00:00Z",
      lastSeen: "2026-08-29T12:05:00Z",
      timeline: [],
    },
    hypothesis: {
      text: "A sustained brute-force attack from 203.0.113.44 succeeded against admin on server-01.",
      label: "advisory · hypothesis · not a verdict",
      note: "advisory analysis pending",
    },
    runbook: {
      matched: true,
      file: "runbooks/isolate_host.md",
      title: "Host Isolation",
      passage: "1. Block source IP\n2. Isolate host from network\n3. Rotate credentials",
      note: "Cited runbook for T1110",
    },
    investigation: {
      entity: "203.0.113.44",
      entityKind: "ip",
      timeline: [
        TL(1, true, "2026-08-29T12:00:00Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44"),
        TL(2, true, "2026-08-29T12:01:00Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44"),
        TL(3, true, "2026-08-29T12:05:00Z INFO server-01 auth success for user 'admin' from 203.0.113.44"),
      ],
      correlation: {
        entity: "203.0.113.44",
        entityKind: "ip",
        assets: [{ name: "server-01", kind: "host", role: "target", records: [1, 2, 3], firstRecord: 1, eventCount: 3 }],
      },
      iocs: [
        { type: "ip", value: "203.0.113.44", records: [1, 2, 3], firstRecord: 1, count: 3 },
      ],
      blastRadius: {
        sourceEntity: "203.0.113.44",
        assets: ["server-01"],
        accounts: ["admin"],
        assetCount: 1,
        accountCount: 1,
        records: [1, 2, 3],
      },
      recordsConsidered: [1, 2, 3],
      note: "Deterministic reconstruction from events store.",
    },
  };
}

const advTimedOut: AdvisoryReport = {
  incidentId: "inc-abc123",
  label: "ADVISORY",
  status: "timed_out",
  note: "ADVISORY · timed out — the eligible list above is complete without it",
  blocks: [
    {
      kind: "narrative",
      label: "ADVISORY · narrative",
      status: "timed_out",
      text: null,
      sentences: [],
      rejected: [],
      grounding: { factual_sentences: 0, cited_and_resolvable: 0, ratio: 0 },
      note: "ADVISORY · timed out — the eligible list above is complete without it",
    },
  ],
  grounding: { factual_sentences: 0, cited_and_resolvable: 0, ratio: 0 },
};

describe("Incidents Advisory States (is-advisory-pending / is-advisory-timeout) (C4-F2)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders real timed_out payload honestly with timeout class and note (not spinner, not blank)", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advTimedOut,
      "/api/incidents": { incidents: [incident()] },
      "/api/auth/me": DEFAULT_AUTH_ME,
      "/api/auth/status": DEFAULT_AUTH_STATUS,
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    // 1. Assert timeout block carries the .is-advisory-timeout class selector
    const timeoutBlock = await screen.findByTestId("investigation-adv-narrative");
    expect(timeoutBlock.className).toMatch(/\bis-advisory-timeout\b/);
    expect(timeoutBlock.className).toMatch(/\bis-adv\b/);
    expect(timeoutBlock.className).not.toMatch(/\bis-advisory-pending\b/);

    // 2. Assert note is rendered verbatim
    const note = within(timeoutBlock).getByTestId("advisory-timeout-narrative");
    expect(note).toHaveTextContent("ADVISORY · timed out — the eligible list above is complete without it");

    // 3. Assert retry button is present and is NOT a spinner
    const retryBtn = screen.getByTestId("advisory-retry");
    expect(retryBtn).toBeInTheDocument();
    expect(retryBtn.tagName).toBe("BUTTON");
    expect(retryBtn.className).toMatch(/\bis-btn--ghost\b/);

    // 4. Assert deterministic timeline is completely intact alongside the timeout
    expect(screen.getByTestId("investigation-timeline")).toBeInTheDocument();
    expect(within(screen.getByTestId("investigation-correlation")).getByText("server-01")).toBeInTheDocument();
  });

  it("proves SELECTOR-NULL both ways between deterministic and advisory regions", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advTimedOut,
      "/api/incidents": { incidents: [incident()] },
      "/api/auth/me": DEFAULT_AUTH_ME,
      "/api/auth/status": DEFAULT_AUTH_STATUS,
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const detSection = await screen.findByTestId("investigation-deterministic");
    const advSection = await screen.findByTestId("investigation-adv-narrative");

    // A. Advisory classes and testids MUST NOT exist inside deterministic regions
    expect(detSection.querySelector(".is-adv")).toBeNull();
    expect(detSection.querySelector(".is-advisory-pending")).toBeNull();
    expect(detSection.querySelector(".is-advisory-timeout")).toBeNull();
    expect(detSection.querySelector(".is-chip--adv")).toBeNull();
    expect(detSection.querySelector('[data-testid^="advisory-"]')).toBeNull();

    // B. Deterministic classes and testids MUST NOT exist inside advisory regions
    expect(advSection.querySelector(".is-det")).toBeNull();
    expect(advSection.querySelector(".is-evidence")).toBeNull();
    expect(advSection.querySelector(".is-chip--ok")).toBeNull();
    expect(advSection.querySelector('[data-testid="investigation-timeline"]')).toBeNull();
  });

  it("distinguishes pending from timed-out structurally by selector (.is-advisory-pending vs .is-advisory-timeout)", async () => {
    let releaseAdvisory!: (r: Response) => void;
    const advisoryGate = new Promise<Response>((res) => {
      releaseAdvisory = res;
    });

    const routes: Record<string, unknown> = {
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents": { incidents: [incident()] },
      "/api/auth/me": DEFAULT_AUTH_ME,
      "/api/auth/status": DEFAULT_AUTH_STATUS,
    };

    vi.stubGlobal(
      "fetch",
      vi.fn((url: RequestInfo | URL) => {
        const u = String(url);
        if (u.includes("/advisory")) return advisoryGate;
        for (const [k, v] of Object.entries(routes)) {
          if (u.includes(k)) return Promise.resolve({ ok: true, status: 200, json: async () => v } as Response);
        }
        return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Response);
      }),
    );

    try {
      renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

      // 1. In PENDING state:
      const pendingEl = await screen.findByTestId("advisory-pending");
      expect(pendingEl.className).toMatch(/\bis-advisory-pending\b/);
      expect(pendingEl.className).not.toMatch(/\bis-advisory-timeout\b/);
      expect(document.querySelector(".is-advisory-pending")).not.toBeNull();
      expect(document.querySelector(".is-advisory-timeout")).toBeNull();

      // 2. Transition to TIMED_OUT:
      releaseAdvisory({ ok: true, status: 200, json: async () => advTimedOut } as Response);
      const timeoutBlock = await screen.findByTestId("investigation-adv-narrative");

      expect(timeoutBlock.className).toMatch(/\bis-advisory-timeout\b/);
      expect(timeoutBlock.className).not.toMatch(/\bis-advisory-pending\b/);
      expect(document.querySelector(".is-advisory-timeout")).not.toBeNull();
      expect(document.querySelector(".is-advisory-pending")).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("confines palette: advisory pending and timeout states do NOT borrow --crit / crit palette", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advTimedOut,
      "/api/incidents": { incidents: [incident()] },
      "/api/auth/me": DEFAULT_AUTH_ME,
      "/api/auth/status": DEFAULT_AUTH_STATUS,
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const timeoutBlock = await screen.findByTestId("investigation-adv-narrative");
    // Must not have .crit or .is-chip--failed or .is-tag--crit classes
    expect(timeoutBlock.className).not.toMatch(/\bcrit\b/);
    expect(timeoutBlock.querySelector(".crit")).toBeNull();
    expect(timeoutBlock.querySelector(".is-chip--failed")).toBeNull();
    expect(timeoutBlock.querySelector(".is-chip--crit")).toBeNull();
  });

  it("respects primary button budget: ≤ 1 .is-btn--primary per view", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advTimedOut,
      "/api/incidents": { incidents: [incident()] },
      "/api/auth/me": DEFAULT_AUTH_ME,
      "/api/auth/status": DEFAULT_AUTH_STATUS,
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    await screen.findByTestId("investigation-adv-narrative");
    const primaryButtons = document.querySelectorAll(".is-btn--primary, .is-btn--acc");
    // At most 1 primary button on the entire view
    expect(primaryButtons.length).toBeLessThanOrEqual(1);
  });

  it("handles empty blocks in a timed_out report with honest is-advisory-timeout container", async () => {
    const advEmptyTimedOut: AdvisoryReport = {
      incidentId: "inc-abc123",
      label: "ADVISORY",
      status: "timed_out",
      note: "ADVISORY · timed out — model unreachable",
      blocks: [],
      grounding: { factual_sentences: 0, cited_and_resolvable: 0, ratio: 0 },
    };

    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advEmptyTimedOut,
      "/api/incidents": { incidents: [incident()] },
      "/api/auth/me": DEFAULT_AUTH_ME,
      "/api/auth/status": DEFAULT_AUTH_STATUS,
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const emptyTimeout = await screen.findByTestId("advisory-timeout-empty");
    expect(emptyTimeout.className).toMatch(/\bis-advisory-timeout\b/);
    expect(emptyTimeout).toHaveTextContent("ADVISORY · timed out — model unreachable");
  });
});
