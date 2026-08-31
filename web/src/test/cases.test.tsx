import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

const CASE = {
  id: "case-1", title: "Investigate 203.0.113.44", notes: "brute-force source",
  assignee: "sam", status: "new",
  activity: [{ at: "2026-08-19T09:00:00Z", actor: "system", kind: "system", text: "Case created" }],
  observables: [], attachments: [],
  links: { findings: ["detector-0"], incidents: [], cases: [] },
  createdAt: "2026-08-19T09:00:00Z", updatedAt: "2026-08-19T09:00:00Z",
};

const FILE_CASE = {
  ...CASE,
  summary: { what: "Investigate 203.0.113.44", impact: "No impact statement has been recorded on this case file.", when: "2026-08-19T09:00:00Z" },
  observables: [{ id: "observable-1", type: "url" as const, value: "https://walmart.com.mx", verdict: "Probably safe" }],
  attachments: [{ id: "attachment-1", name: "invoice.doc", kind: "other" as const, size: 12, stored: true, sha256: "abc" }],
  activity: [
    { at: "2026-08-19T09:00:00Z", actor: "system", kind: "system", text: "Case created" },
    { at: "2026-08-19T09:05:00Z", actor: "sam", kind: "observable", text: "Observable added: url https://walmart.com.mx" },
    { at: "2026-08-19T09:06:00Z", actor: "sam", kind: "comment", text: "Looks like a lookalike domain" },
  ],
  links: { findings: ["detector-0"], incidents: [], cases: ["case-2"] },
};

describe("Cases page (CRUD)", () => {
  it("renders real cases from /api/cases with their status", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [CASE] } });
    renderApp(<App />, { route: "/cases" });

    expect(await screen.findByText("Investigate 203.0.113.44")).toBeInTheDocument();
    expect(screen.getByText("case-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Status of case-1: new" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Status of case-1: closed" })).toBeEnabled();
    expect(screen.getByText("detector-0")).toBeInTheDocument();
  });

  it("shows an honest empty state when there are no cases", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [] } });
    renderApp(<App />, { route: "/cases" });
    expect(await screen.findByText("No cases yet.")).toBeInTheDocument();
    expect(screen.getByText(/nothing is invented/i)).toBeInTheDocument();
  });

  it("creates a case via POST /api/cases with the typed title", async () => {
    let postBody: unknown = null;
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [] } });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/cases") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 200, json: async () => CASE } as Response);
      }
      return realFetch(u, init);
    }));

    renderApp(<App />, { route: "/cases" });
    await screen.findByText("No cases yet.");

    await userEvent.click(screen.getByRole("button", { name: /new case/i }));
    await userEvent.type(screen.getByLabelText("Case title"), "Follow up on root logins");
    await userEvent.click(screen.getByRole("button", { name: /create case/i }));

    await waitFor(() => expect(postBody).toMatchObject({ title: "Follow up on root logins" }));
  });

  it("the CASE stepper posts NEW→CLOSED states", async () => {
    let patched: unknown = null;
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [CASE] } });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/cases/case-1") && init?.method === "PATCH") {
        patched = JSON.parse(String(init.body));
        return Promise.resolve({
          ok: true, status: 200,
          json: async () => ({ ...CASE, status: "escalated" }),
        } as Response);
      }
      return realFetch(u, init);
    }));
    renderApp(<App />, { route: "/cases" });
    await screen.findByText("Investigate 203.0.113.44");
    await userEvent.click(screen.getByRole("button", { name: "Status of case-1: escalated" }));
    await waitFor(() => expect(patched).toEqual({ status: "escalated" }));
  });

  it("opens the case file with summary, events, and linked cases", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [FILE_CASE, { ...CASE, id: "case-2", title: "Sister case",
                  links: { findings: [], incidents: [], cases: ["case-1"] } }] } });
    renderApp(<App />, { route: "/cases?sel=case-1" });
    expect(await screen.findByRole("heading", { name: "Investigate 203.0.113.44" })).toBeInTheDocument();
    expect(screen.getByTestId("copilot-case-overlay")).toBeInTheDocument();
    expect(screen.getByText(/advisory summary from objects on this file/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Regenerate" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: "Events" }));
    const events = document.querySelector(".is-case-tab-content") as HTMLElement;
    expect(within(events).getByText("Observable added: url https://walmart.com.mx")).toBeInTheDocument();
    expect(within(events).queryByText("Looks like a lookalike domain")).not.toBeInTheDocument();
    expect(screen.getByText("Looks like a lookalike domain")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: "Linked" }));
    expect(await screen.findByText(/Sister case/)).toBeInTheDocument();
  });

  it("uploads a real file on the attachments tab", async () => {
    let uploaded = "";
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS,
                "/api/cases": { cases: [FILE_CASE] } });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/attachments") && init?.method === "POST") {
        const body = init.body as FormData;
        const file = body.get("file") as File;
        uploaded = file?.name || "";
        return Promise.resolve({
          ok: true, status: 201,
          json: async () => ({
            ...FILE_CASE,
            attachments: [...FILE_CASE.attachments, { id: "attachment-2", name: file.name, kind: "note", size: 5, stored: true }],
          }),
        } as Response);
      }
      return realFetch(u, init);
    }));
    renderApp(<App />, { route: "/cases?sel=case-1" });
    await screen.findByRole("heading", { name: "Investigate 203.0.113.44" });
    await userEvent.click(screen.getByRole("tab", { name: "Attachments" }));
    expect(screen.getByRole("link", { name: "invoice.doc" })).toHaveAttribute(
      "href", "/api/cases/case-1/attachments/attachment-1");
    const file = new File(["hello"], "note.txt", { type: "text/plain" });
    await userEvent.upload(screen.getByLabelText("Upload attachment"), file);
    await waitFor(() => expect(uploaded).toBe("note.txt"));
  });
});
