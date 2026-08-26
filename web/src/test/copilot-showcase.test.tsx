import { screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, it, expect, vi } from "vitest";
import { CopilotRail } from "@/components/CopilotRail";
import { renderApp } from "./helpers";

/** Design-v2 P3 — AI copilot Showcase (§4). The rail asks the backend for a
 *  {view} directive and renders it as a REAL is-* card: rows are backend-
 *  selected real data (rule-owned severities), each card carries an 'advisory'
 *  chip + a 'cited: N findings' line and deep-links to the full page. An empty
 *  view is an honest "nothing matches", never invented rows. */

/** Route /api/ask by request body: view:true -> JSON {view}; stream:true -> a
 *  minimal SSE prose stream; everything else -> empty-ok. Other queries the
 *  rail makes return empty-ok so it renders. */
function stubAsk(view: unknown) {
  const enc = new TextEncoder();
  vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const u = String(url);
    if (u.includes("/api/ask")) {
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      if (body.view) {
        return { ok: true, status: 200, json: async () => ({ view }) } as Response;
      }
      if (body.stream) {
        const stream = new ReadableStream({
          start(c) {
            c.enqueue(enc.encode('data: {"delta":"Advisory summary."}\n\n'));
            c.enqueue(enc.encode('data: {"done":true}\n\n'));
            c.close();
          },
        });
        return { ok: true, status: 200, body: stream, json: async () => ({}) } as unknown as Response;
      }
    }
    return { ok: true, status: 200, json: async () => ({}) } as Response;
  }));
}

const INCIDENTS_VIEW = {
  type: "incidents",
  title: "Critical incidents",
  filter: "CRITICAL",
  items: [
    { id: "inc-1000", severity: "CRITICAL", entity: "203.0.113.44", findingCount: 3, deeplink: "/incidents?sel=inc-1000" },
  ],
  deeplink: "/incidents",
  citedFindings: 3,
};

describe("AI copilot Showcase (design-v2 §4)", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders a real is-* result card with advisory chip, cited count, and deep-link", async () => {
    stubAsk(INCIDENTS_VIEW);
    renderApp(<CopilotRail docked />);

    await userEvent.click(await screen.findByRole("button", { name: /show me the critical incidents/i }));

    const card = await screen.findByTestId("copilot-showcase-card");
    // Title + advisory chip (never a verdict).
    expect(within(card).getByText("Critical incidents")).toBeInTheDocument();
    expect(within(card).getByText("advisory")).toBeInTheDocument();
    // Real backend-selected row: rule-owned severity + entity, deep-linked.
    expect(within(card).getByText("CRITICAL")).toBeInTheDocument();
    expect(within(card).getByText("203.0.113.44")).toBeInTheDocument();
    const link = within(card).getAllByRole("link").find((a) => a.getAttribute("href") === "/incidents?sel=inc-1000");
    expect(link).toBeTruthy();
    // Honest citation line.
    expect(within(card).getByText(/cited: 3 finding\(s\)/i)).toBeInTheDocument();
  });

  it("shows an honest 'nothing matches' when the view has no rows — never invents", async () => {
    stubAsk({ type: "findings", title: "Top Medium findings", filter: "MEDIUM", items: [], deeplink: "/findings", citedFindings: 0 });
    renderApp(<CopilotRail docked />);

    await userEvent.click(await screen.findByRole("button", { name: /top 5 findings/i }));

    const card = await screen.findByTestId("copilot-showcase-card");
    expect(within(card).getByText(/nothing matches/i)).toBeInTheDocument();
    expect(within(card).queryAllByRole("row")).toHaveLength(0);
    expect(within(card).getByText(/cited: 0 finding\(s\)/i)).toBeInTheDocument();
  });

  it("renders prose-only (no card) when the backend returns no view", async () => {
    stubAsk(null);
    renderApp(<CopilotRail docked />);

    await userEvent.click(await screen.findByRole("button", { name: /summarize the dashboard/i }));
    await waitFor(() => expect(screen.getByText(/Advisory summary\./)).toBeInTheDocument());
    expect(screen.queryByTestId("copilot-showcase-card")).not.toBeInTheDocument();
  });
});
