import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch, DEFAULT_AUTH_ME, DEFAULT_AUTH_STATUS } from "./helpers";
import type { Incident, PrecedentMatch, PrecedentReport } from "@/lib/api";

function incident(over: Partial<Incident & { priority?: string; priorityRationale?: string }> = {}): Incident {
  return {
    id: "inc-abc123", runId: "test-run", entity: "203.0.113.44", entityKind: "ip",
    title: "203.0.113.44 — 2 correlated finding(s)", severity: "CRITICAL", state: "new",
    findingIds: ["detector-0", "detector-1"], findingCount: 2,
    techniques: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
    attackerStatus: "Breaking In",
    createdAt: "2026-08-13T02:16:44+00:00", firstSeen: "2026-08-13T02:16:44+00:00",
    lastSeen: "2026-08-13T02:18:00+00:00", acknowledgedAt: null, resolvedAt: null,
    timeUncertain: false, ...over,
  } as Incident;
}

describe("Incidents page", () => {
  it("renders the incident list from real data", async () => {
    mockFetch({ "/api/incidents": { incidents: [incident(), incident({ id: "inc-def456", entity: "app-01", entityKind: "host", severity: "HIGH", state: "triaged" }) ] } });
    renderApp(<App />, { route: "/incidents" });

    expect(await screen.findByText(/2 incident\(s\)/)).toBeInTheDocument();
    const rows = screen.getAllByTestId("incident-row");
    expect(rows.length).toBe(2);
    // The entity also appears in the sidebar's contextual RECENT INCIDENTS list
    // on this route, so scope the table assertion to the incident row itself.
    expect(within(rows[0]).getByText("203.0.113.44")).toBeInTheDocument();
  });

  it("keeps the filter, summary, search, and case actions in a responsive toolbar", async () => {
    mockFetch({ "/api/incidents": { incidents: [incident()] } });
    renderApp(<App />, { route: "/incidents" });

    const search = await screen.findByLabelText("Search incidents");
    const toolbar = search.closest(".is-incidents-toolbar");
    expect(toolbar).toBeTruthy();
    expect(toolbar?.querySelector(".is-incidents-toolbar__summary")).toHaveTextContent("1 incident(s)");
    expect(toolbar?.querySelector(".is-incidents-toolbar__actions")).toContainElement(search);
  });

  it("paginates a large incident list and resets to the first page when searching", async () => {
    const incidents = Array.from({ length: 13 }, (_, index) => incident({
      id: `inc-${index + 1}`,
      entity: `host-${index + 1}`,
    }));
    mockFetch({ "/api/incidents": { incidents } });
    renderApp(<App />, { route: "/incidents" });

    expect((await screen.findAllByTestId("incident-row")).length).toBe(12);
    expect(screen.getByText("Showing 1–12 of 13")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect((await screen.findAllByTestId("incident-row")).length).toBe(1);
    expect(screen.getByText("Showing 13–13 of 13")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Search incidents"), "host-1");
    expect(screen.getByText("Showing 1–5 of 5")).toBeInTheDocument();
    expect((await screen.findAllByTestId("incident-row")).length).toBe(5);
  });

  it("shows an honest empty state when there are no incidents", async () => {
    mockFetch({ "/api/incidents": { incidents: [] } });
    renderApp(<App />, { route: "/incidents" });
    expect(await screen.findByText(/No incidents yet/)).toBeInTheDocument();
  });

  it("opens the detail with lifecycle controls and posts a state transition", async () => {
    const post = vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => incident({ state: "triaged", acknowledgedAt: "2026-08-13T03:00:00+00:00" }),
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
    const life = screen.getByText(/Lifecycle · analyst-owned/).closest(".is-lifecycle");
    const inv = screen.getByTestId("investigation-file");
    expect(life).toBeTruthy();
    expect(life!.compareDocumentPosition(inv) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "triaged" }));
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
    assignee: "lee", caseStatus: "new",
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

// ── C2-T4: the Investigation file section (deterministic case + advisory) ────
const TL = (n: number, isFinding: boolean, raw: string) => ({
  n, ts: "2026-08-13T02:16:44+00:00", level: "ERROR", host: "server-01",
  msg: raw, raw, isFinding, findingId: isFinding ? "detector-0" : null,
});

/** The deterministic INC-4a7f case as investigate.assemble() returns it. */
function invFixture() {
  return {
    entity: "203.0.113.44", entityKind: "ip",
    timeline: [
      TL(5, true, "2026-08-13T02:16:44Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44 (invalid password)"),
      TL(6, false, "2026-08-13T02:16:45Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44 (invalid password)"),
      TL(11, true, "2026-08-13T02:16:50Z ERROR server-01 auth failed for user 'admin' from 203.0.113.44 (invalid password)"),
      TL(12, false, "2026-08-13T02:16:52Z INFO server-01 auth success for user 'admin' from 203.0.113.44"),
    ],
    correlation: {
      entity: "203.0.113.44", entityKind: "ip",
      assets: [{ name: "server-01", kind: "host", role: "target", records: [5, 6, 11, 12], firstRecord: 5, eventCount: 4 }],
    },
    iocs: [
      { type: "account", value: "admin", records: [5, 6, 11, 12], firstRecord: 5, count: 4 },
      { type: "ipv4", value: "203.0.113.44", records: [5, 6, 11, 12], firstRecord: 5, count: 4 },
    ],
    blastRadius: {
      sourceEntity: "203.0.113.44", assets: ["server-01"], accounts: ["admin"],
      assetCount: 1, accountCount: 1, records: [5, 6, 11, 12],
    },
    recordsConsidered: [5, 6, 11, 12], note: null,
  };
}

function rcaWithInvestigation() {
  return {
    incidentId: "inc-abc123",
    facts: { incidentId: "inc-abc123", rules: ["auth_bruteforce_success"], firstSeen: "2026-08-13T02:16:44+00:00", lastSeen: "2026-08-13T02:16:52+00:00", timeline: [] },
    runbook: { matched: false, note: "no runbook matched" },
    hypothesis: { text: null, label: "advisory · hypothesis · not a verdict", note: "advisory analysis pending", status: "pending" },
    investigation: invFixture(),
    advisory: { status: "pending", label: "advisory · hypothesis · not a verdict", text: null, note: "dispatched separately" },
    deterministic: true, assembledInMs: 0.8,
  };
}

const advComplete = {
  incidentId: "inc-abc123", label: "ADVISORY", status: "complete",
  blocks: [
    { kind: "narrative", label: "ADVISORY · narrative", status: "complete",
      text: "A sustained brute-force from 203.0.113.44 succeeded. {5} {11}",
      sentences: [{ text: "A sustained brute-force from 203.0.113.44 succeeded against admin.", records: [5, 11] }],
      rejected: [], grounding: { factual_sentences: 1, cited_and_resolvable: 1, ratio: 1 }, note: null },
    { kind: "attack", label: "ADVISORY · attack", status: "complete",
      text: "Credential access via T1110. {5}",
      sentences: [{ text: "Credential access via brute force (T1110).", records: [5] }],
      rejected: [], grounding: { factual_sentences: 1, cited_and_resolvable: 1, ratio: 1 }, note: null },
    { kind: "pivots", label: "ADVISORY · pivots", status: "complete",
      text: "Pivot on the source IP. {99}",
      // cites record 99, which is NOT in the deterministic timeline — the UI must
      // mark it as unresolvable, never let it pass as grounded.
      sentences: [{ text: "Pivot on other logins from this source.", records: [99] }],
      rejected: [], grounding: { factual_sentences: 1, cited_and_resolvable: 0, ratio: 0 }, note: null },
  ],
  grounding: { factual_sentences: 3, cited_and_resolvable: 2, ratio: 0.667 },
  note: "ADVISORY · model prose; never a verdict or control signal",
};

const advTimedOut = {
  incidentId: "inc-abc123", label: "ADVISORY", status: "timed_out",
  blocks: [
    { kind: "narrative", label: "ADVISORY · narrative", status: "timed_out", text: null,
      sentences: [], rejected: [], grounding: { factual_sentences: 0, cited_and_resolvable: 0, ratio: 0 },
      note: "ADVISORY · timed out — retry" },
    { kind: "attack", label: "ADVISORY · attack", status: "timed_out", text: null,
      sentences: [], rejected: [], grounding: { factual_sentences: 0, cited_and_resolvable: 0, ratio: 0 },
      note: "ADVISORY · timed out — retry" },
    { kind: "pivots", label: "ADVISORY · pivots", status: "timed_out", text: null,
      sentences: [], rejected: [], grounding: { factual_sentences: 0, cited_and_resolvable: 0, ratio: 0 },
      note: "ADVISORY · timed out — retry" },
  ],
  grounding: { factual_sentences: 0, cited_and_resolvable: 0, ratio: 0 },
  note: "ADVISORY · timed out — retry",
};

describe("Incidents investigation file (C2-T4)", () => {
  it("(a) renders the deterministic case — timeline, correlation, IOCs, blast radius — for the INC-4a7f scenario", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advComplete,
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    // Timeline reconstructed from the events store (all four records, not 2).
    // (await the loaded content, not the same-testid loading placeholder.)
    const tl = await screen.findByTestId("investigation-timeline");
    expect(within(tl).getByTestId("tl-5")).toBeInTheDocument();
    expect(within(tl).getByTestId("tl-12")).toHaveTextContent("auth success for user 'admin'");
    expect(screen.getByTestId("investigation-log-count")).toHaveTextContent("4 reconstructed line");
    // Correlation → host server-01.
    expect(within(screen.getByTestId("investigation-correlation")).getByText("server-01")).toBeInTheDocument();
    // IOCs — attacker IP + targeted account.
    const iocs = screen.getByTestId("investigation-iocs");
    expect(within(iocs).getByText("203.0.113.44")).toBeInTheDocument();
    expect(within(iocs).getByText("admin")).toBeInTheDocument();
    // Blast radius.
    const blast = screen.getByTestId("investigation-blast");
    expect(within(blast).getByText("server-01")).toBeInTheDocument();
    expect(within(blast).getByText("admin")).toBeInTheDocument();
  });

  it("caps a long citation list behind +N more so chips cannot leak off-screen", async () => {
    const rca = rcaWithInvestigation();
    rca.investigation.blastRadius.records = Array.from({ length: 20 }, (_, i) => i + 1);
    mockFetch({
      "/api/incidents/inc-abc123/rca": rca,
      "/api/incidents/inc-abc123/advisory": advComplete,
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });
    const blast = await screen.findByTestId("investigation-blast");
    expect(within(blast).getByRole("button", { name: /\+12 more/ })).toBeInTheDocument();
    expect(within(blast).queryByTestId("cite-20")).not.toBeInTheDocument();
    await userEvent.click(within(blast).getByRole("button", { name: /\+12 more/ }));
    expect(within(blast).getByTestId("cite-20")).toBeInTheDocument();
  });

  it("(b) every deterministic fact carries a resolvable record {n} citation", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advComplete,
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    // Correlation, IOC and blast rows each carry {n} chips that RESOLVE.
    const corr = await screen.findByTestId("investigation-correlation");
    const cite5 = within(corr).getAllByTestId("cite-5")[0];
    expect(cite5).toHaveAttribute("data-resolves", "true");
    expect(cite5).toHaveTextContent("{5}");
    // Not one deterministic citation is unresolvable.
    for (const box of ["investigation-correlation", "investigation-iocs", "investigation-blast"]) {
      const cites = within(screen.getByTestId(box)).queryAllByText(/^\{\d+\}$/);
      expect(cites.length).toBeGreaterThan(0);
      for (const c of cites) expect(c).toHaveAttribute("data-resolves", "true");
    }
    // Honesty guard: an ADVISORY citation to a record NOT in the case (99) is
    // marked unresolvable — an ungrounded claim can never masquerade as cited.
    const miss = await screen.findByTestId("cite-99");
    expect(miss).toHaveAttribute("data-resolves", "false");
    expect(miss.className).toMatch(/miss/);
  });

  it("(c) deterministic and advisory blocks are VISUALLY DISTINCT (asserted, not merely styled)", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advComplete,
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const det = await screen.findByTestId("investigation-deterministic");
    const adv = await screen.findByTestId("investigation-adv-narrative");
    // Different composition classes — the distinction is structural.
    expect(det.className).toMatch(/\bis-det\b/);
    expect(det.className).not.toMatch(/\bis-adv\b/);
    expect(adv.className).toMatch(/\bis-adv\b/);
    // The advisory block carries the ADVISORY chip; the deterministic one never does.
    expect(within(adv).getByText(/ADVISORY · narrative/)).toBeInTheDocument();
    expect(det.querySelector(".is-chip--adv")).toBeNull();
  });

  it("(d-filled) advisory FILLED state renders the grounded model prose", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advComplete,
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });
    expect(await within(await screen.findByTestId("investigation-adv-narrative"))
      .findByText(/A sustained brute-force from 203.0.113.44 succeeded against admin/)).toBeInTheDocument();
  });

  it("(d-timeout) advisory TIMEOUT is VISIBLE with a retry — never silently omitted, never prose", async () => {
    // The timeout is the state that silently degrades if done wrong, so it is
    // asserted explicitly and in its own single-render test.
    mockFetch({
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents/inc-abc123/advisory": advTimedOut,
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const timeoutNote = await screen.findByTestId("advisory-timeout-narrative");
    expect(timeoutNote).toHaveTextContent("ADVISORY · timed out — retry");
    // The deterministic case is STILL fully present alongside the timeout.
    expect(screen.getByTestId("investigation-timeline")).toBeInTheDocument();
    // A retry affordance is offered; the timeout is never replaced by fabricated prose.
    expect(screen.getAllByTestId("advisory-retry").length).toBeGreaterThan(0);
    expect(within(screen.getByTestId("investigation-adv-narrative"))
      .queryByText(/succeeded against admin/)).toBeNull();
  });

  it("(e) the screen never BLOCKS on advisory — the deterministic file renders while advisory is pending", async () => {
    // /advisory is held OPEN (in-flight) while we assert, then released before the
    // test ends so no pending promise or fetch stub leaks into a shuffled sibling.
    let releaseAdvisory!: (r: Response) => void;
    const advisoryGate = new Promise<Response>((res) => { releaseAdvisory = res; });
    const routes: Record<string, unknown> = {
      "/api/incidents/inc-abc123/rca": rcaWithInvestigation(),
      "/api/incidents": { incidents: [incident()] },
      "/api/auth/me": DEFAULT_AUTH_ME, "/api/auth/status": DEFAULT_AUTH_STATUS,
    };
    vi.stubGlobal("fetch", vi.fn((url: RequestInfo | URL) => {
      const u = String(url);
      if (u.includes("/advisory")) return advisoryGate;      // held open
      for (const [k, v] of Object.entries(routes)) {
        if (u.includes(k)) return Promise.resolve({ ok: true, status: 200, json: async () => v } as Response);
      }
      return Promise.resolve({ ok: false, status: 404, json: async () => ({}) } as Response);
    }));

    try {
      renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

      // Deterministic content is fully rendered even though advisory has not returned.
      expect(await screen.findByTestId("investigation-timeline")).toBeInTheDocument();
      expect(within(screen.getByTestId("investigation-correlation")).getByText("server-01")).toBeInTheDocument();
      // Advisory shows an HONEST pending state, not a spinner that blocks the file.
      expect(screen.getByTestId("advisory-pending")).toHaveTextContent(/ADVISORY · pending/);
    } finally {
      // Release the held request and let React settle it, so nothing is left
      // pending; then drop the fetch stub for the next (shuffled) test.
      releaseAdvisory({ ok: true, status: 200, json: async () => advTimedOut } as Response);
      await screen.findByTestId("advisory-timeout-narrative");
      vi.unstubAllGlobals();
    }
  });
});

// ── C4-F3: Priority chip (org-context) ──────────────────────────────────────
describe("Priority chip presentation (C4-F3)", () => {
  it("renders priority chip BESIDE severity chip with the verbatim tooltip (never replacing severity)", async () => {
    const incWithPriority = incident({
      id: "inc-p1-test",
      severity: "CRITICAL",
      priority: "P1",
      priorityRationale: "Priority P1 derived from CRITICAL severity on crown-jewel asset (server-01)",
    });

    mockFetch({
      "/api/incidents": { incidents: [incWithPriority] },
    });
    renderApp(<App />, { route: "/incidents" });

    const rows = await screen.findAllByTestId("incident-row");
    expect(rows.length).toBe(1);

    // Assert BOTH chips are present simultaneously:
    const sevChip = within(rows[0]).getByText("CRITICAL");
    expect(sevChip).toBeInTheDocument();
    expect(sevChip.className).toMatch(/\bis-tag\b/);

    const priChip = within(rows[0]).getByTestId("priority-chip");
    expect(priChip).toBeInTheDocument();
    expect(priChip).toHaveTextContent("P1");
    expect(priChip.className).toMatch(/\bis-chip--priority\b/);
    expect(priChip.className).toMatch(/\bis-chip--p1\b/);
    expect(priChip).toHaveAttribute("title", "priority is rule-owned, weighted by asset criticality");
  });

  it("renders priority chip in incident detail header beside severity", async () => {
    const incWithPriority = incident({
      id: "inc-p2-test",
      severity: "HIGH",
      priority: "P2",
      priorityRationale: "Priority P2 derived from HIGH severity on standard asset",
    });

    mockFetch({
      "/api/incidents": { incidents: [incWithPriority] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-p2-test" });

    // Header has both severity tag and priority chip
    expect(await screen.findByText("HIGH")).toBeInTheDocument();
    const priChip = await screen.findByTestId("priority-chip");
    expect(priChip).toHaveTextContent("P2");
    expect(priChip.className).toMatch(/\bis-chip--p2\b/);
    expect(priChip).toHaveAttribute("title", "priority is rule-owned, weighted by asset criticality");
  });
  // --- E0: analyst disposition captured on close --------------------------

  it("captures a disposition on close and posts it on the lifecycle transition", async () => {
    const bodies: string[] = [];
    mockFetch({ "/api/incidents/inc-abc123/state": { incidents: [] }, "/api/incidents": { incidents: [incident()] } });
    const base = globalThis.fetch as unknown as typeof fetch;
    vi.stubGlobal("fetch", vi.fn((url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).includes("/state") && init?.method === "POST") {
        bodies.push(String(init.body));
        return Promise.resolve({
          ok: true, status: 200,
          json: async () => incident({ state: "closed", disposition: "false-positive", dispositionReason: "known scanner" }),
        } as Response);
      }
      return (base as (u: RequestInfo | URL, i?: RequestInit) => Promise<Response>)(url, init);
    }));

    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    // "closed" opens the disposition form instead of posting straight away —
    // capture happens on the transition, and nowhere else.
    await userEvent.click(await screen.findByRole("button", { name: "closed" }));
    expect(await screen.findByTestId("disposition-form")).toBeInTheDocument();
    expect(bodies.length).toBe(0);

    // The reason is inert until a disposition is chosen: no orphan reasons.
    expect(screen.getByLabelText("Reason (optional)")).toBeDisabled();
    await userEvent.selectOptions(screen.getByLabelText("Disposition"), "false-positive");
    await userEvent.type(screen.getByLabelText("Reason (optional)"), "known scanner");
    await userEvent.click(screen.getByRole("button", { name: "Close incident" }));

    expect(bodies.length).toBe(1);
    expect(JSON.parse(bodies[0])).toEqual({
      state: "closed", disposition: "false-positive", dispositionReason: "known scanner",
    });
  });

  it("never sends a disposition on a transition that is not a close", async () => {
    const bodies: string[] = [];
    mockFetch({ "/api/incidents/inc-abc123/state": { incidents: [] }, "/api/incidents": { incidents: [incident()] } });
    const base = globalThis.fetch as unknown as typeof fetch;
    vi.stubGlobal("fetch", vi.fn((url: RequestInfo | URL, init?: RequestInit) => {
      if (String(url).includes("/state") && init?.method === "POST") {
        bodies.push(String(init.body));
        return Promise.resolve({ ok: true, status: 200, json: async () => incident({ state: "investigating" }) } as Response);
      }
      return (base as (u: RequestInfo | URL, i?: RequestInit) => Promise<Response>)(url, init);
    }));

    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });
    await userEvent.click(await screen.findByRole("button", { name: "investigating" }));

    expect(bodies.length).toBe(1);
    expect(JSON.parse(bodies[0])).toEqual({ state: "investigating" });
    expect(screen.queryByTestId("disposition-form")).toBeNull();
  });

  it("shows the disposition chip and audit trail in Incident History", async () => {
    mockFetch({ "/api/incidents": { incidents: [incident({
      state: "closed",
      disposition: "benign-expected",
      dispositionReason: "scheduled vulnerability scan",
      dispositionAt: "2026-09-01T10:00:00+00:00",
      dispositionHistory: [{
        action: "set", disposition: "benign-expected", reason: "scheduled vulnerability scan",
        at: "2026-09-01T10:00:00+00:00", fromState: "investigating", toState: "closed",
      }],
    }) ] } });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const audit = await screen.findByTestId("incident-audit");
    const chip = within(audit).getByTestId("disposition-chip");
    expect(chip).toHaveTextContent("Disposition: Benign / expected");
    // The chip must read as analyst state, never as a rule verdict.
    expect(chip).toHaveTextContent("analyst-captured · not a rule verdict");
    expect(chip).toHaveTextContent("scheduled vulnerability scan");

    const entries = within(audit).getAllByTestId("disposition-audit-entry");
    expect(entries.length).toBe(1);
    expect(entries[0]).toHaveTextContent("Disposition Recorded");
    expect(entries[0]).toHaveTextContent("investigating → closed");
  });

  it("shows no disposition chip when none was recorded — an honest absence", async () => {
    mockFetch({ "/api/incidents": { incidents: [incident({ state: "closed", disposition: null })] } });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const audit = await screen.findByTestId("incident-audit");
    expect(within(audit).queryByTestId("disposition-chip")).toBeNull();
    expect(within(audit).queryAllByTestId("disposition-audit-entry").length).toBe(0);
  });
});

// --- E1: the Precedents panel --------------------------------------------
function precedent(over: Partial<PrecedentMatch> = {}): PrecedentMatch {
  return {
    id: "inc-prior1", overlap: 3,
    dimensions: ["ruleIds", "entity", "attackTags"],
    matched: { ruleIds: ["auth_bruteforce"], entity: ["203.0.113.44"], attackTags: ["T1110"] },
    because: ["same rule: auth_bruteforce", "same entity: 203.0.113.44",
              "same ATT&CK technique: T1110"],
    explanation: "same rule: auth_bruteforce; same entity: 203.0.113.44; same ATT&CK technique: T1110",
    title: "203.0.113.44 — 4 correlated finding(s)", state: "closed", severity: "HIGH",
    createdAt: "2026-08-20T02:00:00+00:00", runId: "prior-run",
    disposition: "confirmed", dispositionReason: "real intrusion",
    dispositionAt: "2026-08-21T09:00:00+00:00", dispositionRecorded: true,
    ...over,
  };
}

function precedentReport(over: Partial<PrecedentReport> = {}): PrecedentReport {
  return {
    incidentId: "inc-abc123",
    dimensions: ["ruleIds", "entity", "attackTags", "assetCriticality"],
    candidatesStored: 42, candidatesScored: 5, matchCount: 2,
    precedents: [precedent(), precedent({
      id: "inc-prior2", overlap: 1, dimensions: ["ruleIds"],
      matched: { ruleIds: ["auth_bruteforce"] },
      because: ["same rule: auth_bruteforce"],
      explanation: "same rule: auth_bruteforce",
      title: "198.51.100.7 — 1 correlated finding(s)", state: "new",
      disposition: null, dispositionReason: null, dispositionAt: null,
      dispositionRecorded: false,
    })],
    note: "Deterministic overlap of rule-owned facts over stored incidents. "
      + "Recall only — never a severity, a priority, or an eligibility input.",
    ...over,
  };
}

describe("Incident precedents panel (E1)", () => {
  it("ranks precedents by shared-fact count and shows the facts that matched", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport(),
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    // Await the resolved panel body, not the panel shell — the shell renders
    // immediately in its loading state.
    await screen.findByTestId("precedents-summary");
    const panel = screen.getByTestId("precedents-panel");
    const rows = within(panel).getAllByTestId("precedent-row");
    expect(rows.length).toBe(2);
    // Ranked: the 3-fact match is above the 1-fact match.
    expect(within(rows[0]).getByTestId("precedent-link")).toHaveTextContent("inc-prior1");
    expect(within(rows[0]).getByTestId("precedent-overlap")).toHaveTextContent("3 shared facts");
    expect(within(rows[1]).getByTestId("precedent-overlap")).toHaveTextContent("1 shared fact");

    // Every clause rendered is a matched fact — the explanation is sourced.
    const because = within(rows[0]).getByTestId("precedent-because");
    for (const clause of precedent().because) {
      expect(because).toHaveTextContent(clause);
    }
    expect(within(panel).getByTestId("precedents-summary"))
      .toHaveTextContent("Showing 2 of 2 prior incident(s)");
  });

  it("shows a precedent's stored disposition verbatim, labelled as analyst state", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport(),
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    await screen.findByTestId("precedents-summary");
    const rows = within(screen.getByTestId("precedents-panel"))
      .getAllByTestId("precedent-row");
    const disp = within(rows[0]).getByTestId("precedent-disposition");
    expect(disp).toHaveTextContent("Analyst disposition: Confirmed");
    expect(disp).toHaveTextContent("analyst-captured · not a rule verdict");
    expect(disp).toHaveTextContent("real intrusion");
    // A precedent with no disposition says so — it never borrows the other's.
    expect(within(rows[1]).queryByTestId("precedent-disposition")).toBeNull();
    expect(within(rows[1]).getByTestId("precedent-no-disposition"))
      .toHaveTextContent("No disposition recorded on this incident.");
  });

  it("renders an honest empty state when nothing in the store shares a fact", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport({ matchCount: 0, precedents: [] }),
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    await screen.findByTestId("precedents-empty");
    const panel = screen.getByTestId("precedents-panel");
    expect(within(panel).getByTestId("precedents-empty"))
      .toHaveTextContent("There is no precedent to show — this is information, not a failure.");
    expect(within(panel).queryAllByTestId("precedent-row").length).toBe(0);
  });

  it("states the index is unreachable rather than inventing precedents", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": { error: "no such incident", __status: 404 },
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    await screen.findByTestId("precedents-error");
    const panel = screen.getByTestId("precedents-panel");
    expect(within(panel).getByTestId("precedents-error"))
      .toHaveTextContent("Nothing is invented.");
    expect(within(panel).queryAllByTestId("precedent-row").length).toBe(0);
  });

  it("presents precedents as recall — never as a verdict or a recommendation", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport(),
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    await screen.findByTestId("precedents-summary");
    const panel = screen.getByTestId("precedents-panel");
    expect(panel).toHaveTextContent("deterministic · rule-owned facts");
    expect(panel).toHaveTextContent(
      /never affect this incident.s severity, priority or runbook\s+eligibility/);
    // No action control lives on this panel: recall cannot start a response.
    expect(within(panel).queryAllByRole("button").length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// E7a — AI TRIAGE · LEARNED, ADVISORY on Incidents
// ---------------------------------------------------------------------------
// The same component the Findings page renders, on the incident surface. Three
// visible states, and in none of them does the block touch severity, priority,
// runbook eligibility or an action. The E1 precedents panel keeps its
// deterministic numeric/labelled overlap display beside it — no model prose
// annotates it (the E4 prose part is not in this card).
const learnedTriage = (over: Record<string, unknown> = {}) => ({
  advisory: true as const,
  learned: true,
  modelAvailable: true,
  status: "agrees" as const,
  ruleSeverity: "CRITICAL",
  aiSeverity: "CRITICAL",
  aiLabel: "confirmed",
  confidence: 0.8842,
  agrees: true,
  unavailableReason: null,
  note: "Learned second opinion — ADVISORY. It never changes the rule verdict.",
  ...over,
});

describe("Incident AI triage block (E7a)", () => {
  it("renders the learned advisory opinion beside the rule-owned severity", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport(),
      "/api/incidents": { incidents: [incident({ aiTriage: learnedTriage() } as Partial<Incident>)] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const panel = await screen.findByTestId("incident-ai-triage");
    expect(panel).toHaveTextContent("learned · advisory");
    const block = within(panel).getByTestId("ai-triage");
    expect(block).toHaveAttribute("data-status", "agrees");
    expect(within(block).getByTestId("ai-triage-severity")).toHaveTextContent("CRITICAL");
    expect(within(block).getByTestId("ai-triage-confidence")).toHaveTextContent("88.4% confidence");
    expect(within(block).getByTestId("ai-triage-status"))
      .toHaveTextContent("Agrees with the rule verdict");
    // The rule-owned severity chip on the detail header is untouched.
    expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(1);
    // No control on this block can act — an advisory opinion starts nothing.
    expect(within(panel).queryAllByRole("button").length).toBe(0);
  });

  it("shows DISAGREEMENT visibly and says it is not a reason to change the verdict", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport(),
      "/api/incidents": { incidents: [incident({
        aiTriage: learnedTriage({
          status: "disagrees", agrees: false, aiSeverity: "LOW",
          aiLabel: "benign-expected", confidence: 0.6431,
        }),
      } as Partial<Incident>)] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const block = within(await screen.findByTestId("incident-ai-triage"))
      .getByTestId("ai-triage");
    expect(block).toHaveAttribute("data-status", "disagrees");
    expect(block.className).toContain("is-aitriage--disagrees");
    expect(within(block).getByTestId("ai-triage-status"))
      .toHaveTextContent("Disagrees with the rule verdict");
    expect(within(block).getByTestId("ai-triage-label")).toHaveTextContent("benign-expected");
    expect(within(block).getByTestId("ai-triage-disagreement"))
      .toHaveTextContent(/prompt to look, not a reason to change the verdict/i);
  });

  it("renders MODEL UNAVAILABLE honestly, inventing no severity and no confidence", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport(),
      "/api/incidents": { incidents: [incident({
        aiTriage: {
          advisory: true as const, learned: true, modelAvailable: false,
          status: "unavailable" as const, ruleSeverity: "CRITICAL",
          aiSeverity: null, aiLabel: null, confidence: null, agrees: null,
          unavailableReason: "no trained model on this installation",
          note: "Learned second opinion — ADVISORY — is UNAVAILABLE here.",
        },
      } as Partial<Incident>)] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    const panel = await screen.findByTestId("incident-ai-triage");
    const block = within(panel).getByTestId("ai-triage");
    expect(block).toHaveAttribute("data-status", "unavailable");
    expect(within(block).getByTestId("ai-triage-unavailable"))
      .toHaveTextContent("Model unavailable");
    expect(within(block).getByTestId("ai-triage-reason"))
      .toHaveTextContent("no trained model on this installation");
    expect(within(block).queryByTestId("ai-triage-severity")).toBeNull();
    expect(within(block).queryByTestId("ai-triage-confidence")).toBeNull();
    expect(within(block).queryByTestId("ai-triage-status")).toBeNull();

    // KILL-THE-MODEL, on screen: the deterministic surfaces are fully intact.
    await screen.findByTestId("precedents-summary");
    const precedents = screen.getByTestId("precedents-panel");
    expect(within(precedents).getAllByTestId("precedent-row").length).toBe(2);
    expect(within(precedents).getByTestId("precedents-summary"))
      .toHaveTextContent("Showing 2 of 2 prior incident(s)");
    expect(screen.getByTestId("incident-analyst")).toBeInTheDocument();
  });

  it("omits the block entirely when the API sends no advisory object at all", async () => {
    mockFetch({
      "/api/incidents/inc-abc123/precedents": precedentReport(),
      "/api/incidents": { incidents: [incident()] },
    });
    renderApp(<App />, { route: "/incidents?sel=inc-abc123" });

    await screen.findByTestId("precedents-summary");
    expect(screen.queryByTestId("incident-ai-triage")).toBeNull();
  });
});
