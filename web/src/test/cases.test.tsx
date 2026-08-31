import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

const CASE_FULL = {
  id: "case-1",
  title: "Investigate 203.0.113.44",
  notes: "Brute-force auth attempts detected from external gateway.",
  assignee: "sam",
  status: "new",
  category: "Authentication",
  summary: {
    what: "High frequency SSH attempts on port 22.",
    impact: "Potential credential access on staging bastion.",
    when: "2026-08-19 09:00 - 09:45 UTC",
  },
  activity: [
    { id: "act-1", ts: "2026-08-19T09:10:00Z", actor: "sam", action: "Assigned case to self", kind: "human" as const },
    { id: "act-2", ts: "2026-08-19T09:15:00Z", actor: "system", action: "Linked finding detector-0", kind: "system" as const },
  ],
  observables: [
    { id: "obs-1", type: "ip", value: "203.0.113.44", source: "auth.log", addedAt: "2026-08-19T09:05:00Z" },
    { id: "obs-2", type: "domain", value: "evil-proxy.org", source: "threat-feed", addedAt: "2026-08-19T09:06:00Z" },
  ],
  attachments: [
    { id: "att-1", name: "auth-traffic.pcap", size: 1048576, type: "pcap", uploadedAt: "2026-08-19T09:20:00Z" },
  ],
  events: [
    { id: "ev-1", ts: "2026-08-19 09:00:12", source: "sshd", message: "Failed password for root from 203.0.113.44 port 48212" },
  ],
  links: { findings: ["detector-0"], incidents: ["inc-101"] },
  createdAt: "2026-08-19T09:00:00Z",
  updatedAt: "2026-08-19T09:00:00Z",
};

const RUNBOOKS_MOCK = {
  runbooks: [
    { id: "rb-block-ip", name: "Block Suspicious IP", eligible: true, missing: [] },
    { id: "rb-quarantine-host", name: "Quarantine Host", eligible: false, missing: ["Requires analyst approval token"] },
  ],
};

describe("Cases page (Kanban board + Case File + Copilot)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders 6-column Kanban board with real cases and honest empty columns", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/cases": { cases: [CASE_FULL] },
      "/api/copilot/runbooks": RUNBOOKS_MOCK,
    });
    renderApp(<App />, { route: "/cases" });

    expect(await screen.findByTestId("cases-kanban-board")).toBeInTheDocument();

    // 6 columns must exist
    expect(screen.getByTestId("kanban-column-new")).toBeInTheDocument();
    expect(screen.getByTestId("kanban-column-triaged")).toBeInTheDocument();
    expect(screen.getByTestId("kanban-column-investigating")).toBeInTheDocument();
    expect(screen.getByTestId("kanban-column-escalated")).toBeInTheDocument();
    expect(screen.getByTestId("kanban-column-resolved")).toBeInTheDocument();
    expect(screen.getByTestId("kanban-column-closed")).toBeInTheDocument();

    // Empty columns show honest empty state
    expect(screen.getByTestId("empty-col-triaged")).toHaveTextContent("No cases");
    expect(screen.getByTestId("empty-col-investigating")).toHaveTextContent("No cases");

    // Case card displays title, category, assignee, and links
    expect(screen.getByText("Investigate 203.0.113.44")).toBeInTheDocument();
    expect(screen.getByText("Authentication")).toBeInTheDocument();
    expect(screen.getByText("sam")).toBeInTheDocument();
    expect(screen.getByText("detector-0")).toBeInTheDocument();
    expect(screen.getByText("inc-101")).toBeInTheDocument();
  });

  it("shows an honest empty state when there are zero cases", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/cases": { cases: [] },
    });
    renderApp(<App />, { route: "/cases" });
    expect(await screen.findByText("No cases yet.")).toBeInTheDocument();
    expect(screen.getByText(/no sample cases are invented/i)).toBeInTheDocument();
  });

  it("creates a case via POST /api/cases with title, category, assignee, and notes", async () => {
    let postBody: unknown = null;
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/cases": { cases: [] },
    });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/cases") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 200, json: async () => CASE_FULL } as Response);
      }
      return realFetch(u, init);
    }));

    renderApp(<App />, { route: "/cases" });
    await screen.findByText("No cases yet.");

    await userEvent.click(screen.getByRole("button", { name: /new case/i }));
    await userEvent.type(screen.getByLabelText("Case title"), "Follow up on root logins");
    await userEvent.type(screen.getByLabelText("Case assignee"), "alice");
    await userEvent.type(screen.getByLabelText("Case category"), "Identity");
    await userEvent.type(screen.getByLabelText("Case notes"), "Check pam logs");
    await userEvent.click(screen.getByRole("button", { name: /create case/i }));

    await waitFor(() =>
      expect(postBody).toMatchObject({
        title: "Follow up on root logins",
        assignee: "alice",
        category: "Identity",
        notes: "Check pam logs",
      }),
    );
  });

  it("opens Case File view when clicking card or navigating to /cases?sel=case-1", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/cases": { cases: [CASE_FULL] },
      "/api/copilot/runbooks": RUNBOOKS_MOCK,
    });
    renderApp(<App />, { route: "/cases?sel=case-1" });

    // Left pane checks
    expect(await screen.findByRole("heading", { name: "Investigate 203.0.113.44" })).toBeInTheDocument();
    expect(screen.getByTestId("case-file-lifecycle-case-1")).toBeInTheDocument();
    expect(screen.getByTestId("case-activity-timeline")).toBeInTheDocument();
    expect(screen.getByText(/Assigned case to self/i)).toBeInTheDocument();
    expect(screen.getByText(/Linked finding detector-0/i)).toBeInTheDocument();

    // Shipped runbook workflow picker
    expect(await screen.findByText("Block Suspicious IP")).toBeInTheDocument();
    expect(screen.getByText("Quarantine Host")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run workflow" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Ineligible" })).toBeDisabled();
    expect(screen.getByText(/Requires analyst approval token/i)).toBeInTheDocument();

    // Right Tabs check
    expect(screen.getByRole("tab", { name: "overview" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "observables" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "notes" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "attachments" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "linked" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "events" })).toBeInTheDocument();

    // Overview Tab facts & advisory summary
    expect(screen.getByTestId("case-advisory-summary")).toBeInTheDocument();
    expect(screen.getByText(/advisory · summary · not a verdict/i)).toBeInTheDocument();
    expect(screen.getByText("High frequency SSH attempts on port 22.")).toBeInTheDocument();
    expect(screen.getByText("inc-101")).toBeInTheDocument();
  });

  it("submits comment via POST /api/cases/:id/comment", async () => {
    let commentBody: unknown = null;
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/cases": { cases: [CASE_FULL] },
      "/api/copilot/runbooks": RUNBOOKS_MOCK,
    });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/cases/case-1/comment") && init?.method === "POST") {
        commentBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ ok: true, id: "act-3" }) } as Response);
      }
      return realFetch(u, init);
    }));

    renderApp(<App />, { route: "/cases?sel=case-1" });
    await screen.findByRole("heading", { name: "Investigate 203.0.113.44" });

    await userEvent.type(screen.getByLabelText("Case comment input"), "Verified IP is in known drop list.");
    await userEvent.click(screen.getByRole("button", { name: /post comment/i }));

    await waitFor(() => expect(commentBody).toMatchObject({ comment: "Verified IP is in known drop list." }));
  });

  it("adds observable and attachment via their respective tabs and forms", async () => {
    let obsBody: unknown = null;
    let attBody: unknown = null;
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/cases": { cases: [CASE_FULL] },
      "/api/copilot/runbooks": RUNBOOKS_MOCK,
    });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/cases/case-1/observables") && init?.method === "POST") {
        obsBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ ok: true }) } as Response);
      }
      if (String(u).includes("/api/cases/case-1/attachments") && init?.method === "POST") {
        attBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ ok: true }) } as Response);
      }
      return realFetch(u, init);
    }));

    renderApp(<App />, { route: "/cases?sel=case-1" });
    await screen.findByRole("heading", { name: "Investigate 203.0.113.44" });

    // Switch to Observables tab and add one
    await userEvent.click(screen.getByRole("tab", { name: "observables" }));
    expect(await screen.findByText("203.0.113.44")).toBeInTheDocument();
    expect(screen.getByText("evil-proxy.org")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Observable value"), "198.51.100.25");
    await userEvent.click(screen.getByRole("button", { name: "Add observable" }));
    await waitFor(() => expect(obsBody).toMatchObject({ value: "198.51.100.25", type: "ip" }));

    // Switch to Attachments tab and add one
    await userEvent.click(screen.getByRole("tab", { name: "attachments" }));
    expect(await screen.findByText("auth-traffic.pcap")).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Attachment name"), "syslog-export.csv");
    await userEvent.click(screen.getByRole("button", { name: "Add attachment" }));
    await waitFor(() => expect(attBody).toMatchObject({ name: "syslog-export.csv" }));
  });

  it("scopes Copilot rail to case with opening brief, chips, and Title+Description summary", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/cases": { cases: [CASE_FULL] },
      "/api/copilot/runbooks": RUNBOOKS_MOCK,
      "/api/copilot/suggest?caseId=case-1": {
        questions: [
          "Analyze 203.0.113.44",
          "Scan attachments",
          "Find related cases",
          "Summarize this case",
        ],
      },
    });

    renderApp(<App />, { route: "/cases?sel=case-1" });
    await screen.findByRole("heading", { name: "Investigate 203.0.113.44" });

    // Open Copilot drawer via floating launcher
    await userEvent.click(screen.getByTestId("copilot-fab"));

    // Copilot header & brief
    expect(await screen.findByTestId("copilot-case-brief")).toBeInTheDocument();
    expect(screen.getByTestId("copilot-case-opening-brief")).toHaveTextContent(/Brute-force auth attempts detected/i);

    // Copilot placeholder
    expect(screen.getByPlaceholderText("Ask me anything about this case…")).toBeInTheDocument();

    // Chips populated from case facts
    expect(screen.getAllByRole("button", { name: "Analyze 203.0.113.44" }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Scan attachments" }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Find related cases" }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Summarize this case" }).length).toBeGreaterThan(0);

    // Trigger "Summarize this case" -> must yield Title + Description from case facts
    await userEvent.click(screen.getAllByRole("button", { name: "Summarize this case" })[0]);
    expect(await screen.findByText(/Title: Investigate 203.0.113.44/i)).toBeInTheDocument();
    expect(screen.getByText(/Description:/i)).toBeInTheDocument();
    expect(screen.getAllByText(/High frequency SSH attempts on port 22/i).length).toBeGreaterThan(0);
  });
});

