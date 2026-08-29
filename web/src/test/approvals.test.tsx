import { describe, it, expect, vi, afterEach } from "vitest";
import { screen, fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp, mockFetch } from "./helpers";
import { Approvals } from "@/pages/Approvals";
import { CopilotRail } from "@/components/CopilotRail";
import type { Approval } from "@/lib/api";

/** C4-T1 — Approvals screen + is-approval-modal. Every invariant below is proven
 *  by a RUN, never by a visual claim:
 *   - the approve control exists in exactly ONE component (and the advisory
 *     Copilot rail has none) — selector-null both ways;
 *   - the accent-button budget holds (≤1 primary/accent per view);
 *   - Enter submits only when the passphrase field is non-empty; Esc closes;
 *     J/K navigate the queue;
 *   - the passphrase never leaves the field — never a URL, never a log, never
 *     echoed into rendered state or an error message. */

const PASS = "stepup-" + "d34db33fa11ce";   // runtime-only, never committed as a real secret

function approval(over: Partial<Approval> = {}): Approval {
  return {
    id: "appr-abc123",
    incidentId: "INC-4a7f",
    runbookId: "rb-block-ip",
    connector: "nftables-ssh",
    step: 0,
    state: "pending",
    eligibilityProof: { eligible: true, missing: [] },
    evidenceRefs: ["5", "6", "7"],
    requestRedacted: {
      command: "nft add element inet filter blocklist { [IP-1] }",
      description: "Block source IP at the edge",
      connector: "nftables-ssh",
      action: "block_ip",
      params: { ip: "[IP-1]" },
    },
    responseVerbatim: null,
    actor: null,
    failureReason: null,
    createdAt: "2026-08-29T12:00:00Z",
    updatedAt: "2026-08-29T12:00:00Z",
    ...over,
  };
}

/** A recording fetch stub: captures every (url, init) and answers the approvals
 *  routes. `approveStatus` lets a test force a step-up failure (401). */
function recordingFetch(
  approvals: Approval[],
  approveStatus = 200,
) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, init });
    const reply = (status: number, body: unknown) =>
      ({ ok: status >= 200 && status < 300, status, json: async () => body } as Response);
    if (u.includes("/api/approvals/") && u.endsWith("/approve")) {
      return reply(approveStatus,
        approveStatus === 200
          ? { ...approvals[0], state: "executed", actor: "analyst" }
          : { error: "step-up verification failed" });
    }
    if (u.includes("/api/approvals/") && u.endsWith("/reject")) {
      return reply(200, { ...approvals[0], state: "rejected", actor: "analyst" });
    }
    if (u.includes("/api/approvals")) return reply(200, { approvals });
    return reply(404, {});
  }));
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function openModal() {
  fireEvent.click(screen.getByTestId("approval-open-review"));
  return screen.findByTestId("approval-modal");
}

describe("Approvals — screen + queue", () => {
  it("shows the honest empty state with no illustration filler when nothing is pending", async () => {
    mockFetch({ "/api/approvals": { approvals: [] } });
    const { container } = renderApp(<Approvals />, { route: "/approvals" });
    const empty = await screen.findByTestId("approvals-empty");
    expect(empty).toHaveTextContent("No pending approvals");
    // No illustration filler: no <svg>/<img> decoration in the empty state.
    expect(container.querySelector("svg")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("renders only PENDING approvals in the queue (resolved ones never appear)", async () => {
    mockFetch({
      "/api/approvals": {
        approvals: [
          approval({ id: "p1", incidentId: "INC-pending" }),
          approval({ id: "x1", incidentId: "INC-executed", state: "executed" }),
        ],
      },
    });
    renderApp(<Approvals />, { route: "/approvals" });
    const rows = await screen.findAllByTestId("approval-row");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("INC-pending");
  });

  it("J/K navigate the queue", async () => {
    mockFetch({
      "/api/approvals": {
        approvals: [
          approval({ id: "p1", incidentId: "INC-first" }),
          approval({ id: "p2", incidentId: "INC-second" }),
        ],
      },
    });
    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    // First row selected by default.
    expect(screen.getByTestId("approval-detail")).toHaveTextContent("INC-first");
    fireEvent.keyDown(window, { key: "j" });
    await waitFor(() =>
      expect(screen.getByTestId("approval-detail")).toHaveTextContent("INC-second"));
    fireEvent.keyDown(window, { key: "k" });
    await waitFor(() =>
      expect(screen.getByTestId("approval-detail")).toHaveTextContent("INC-first"));
  });
});

describe("is-approval-modal — the single authoritative approve surface", () => {
  it("the approve control exists in exactly ONE component", async () => {
    mockFetch({ "/api/approvals": { approvals: [approval()] } });
    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    // Closed: no approve control anywhere yet.
    expect(screen.queryByTestId("approval-approve")).toBeNull();
    await openModal();
    expect(screen.getAllByTestId("approval-approve")).toHaveLength(1);
  });

  it("SELECTOR-NULL — the advisory Copilot rail carries NO approve control (vice versa)", () => {
    mockFetch({});
    const { container } = renderApp(<CopilotRail docked />, { route: "/approvals" });
    // The advisory surface must be structurally absent of the deterministic act.
    expect(screen.queryByTestId("approval-approve")).toBeNull();
    expect(screen.queryByTestId("approval-reject")).toBeNull();
    expect(container.querySelector('[data-testid="approval-approve"]')).toBeNull();
    // And it is the advisory surface (has its advisory chip) — so this is a real
    // advisory-vs-deterministic separation, not an empty render.
    expect(screen.getByTestId("copilot-advisory-chip")).toBeInTheDocument();
    expect(container.querySelectorAll("button").length).toBeGreaterThan(0);
  });

  it("SELECTOR-NULL — the authoritative (rule-owned) region contains NO advisory element", async () => {
    mockFetch({ "/api/approvals": { approvals: [approval()] } });
    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    await openModal();
    const auth = screen.getByTestId("approval-authoritative");
    // No model/advisory styling may leak into the rule-owned decision surface.
    expect(auth.querySelector(".is-adv")).toBeNull();
    expect(auth.querySelector(".is-chip--adv")).toBeNull();
    expect(within(auth).queryByText(/advisory/i)).toBeNull();
    // It IS the authoritative surface (eligible-by rule, marked authoritative).
    expect(within(auth).getByTestId("approval-eligibility")).toHaveTextContent(/ELIGIBLE · rb-block-ip/);
    expect(auth.querySelector(".cap.authoritative")).not.toBeNull();
  });

  it("renders the redacted request preview and the evidence chain (rule-owned refs)", async () => {
    mockFetch({ "/api/approvals": { approvals: [approval()] } });
    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    await openModal();
    // The command is the REDACTED preview — the token, never a raw IP.
    const redacted = screen.getByTestId("approval-redacted");
    expect(redacted).toHaveTextContent("[IP-1]");
    expect(redacted.textContent).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
    const evidence = screen.getByTestId("approval-evidence");
    expect(evidence).toHaveTextContent("record #5");
    expect(evidence).toHaveTextContent("record #7");
  });

  it("the accent-button budget holds — at most one primary/accent button per view", async () => {
    mockFetch({ "/api/approvals": { approvals: [approval()] } });
    const { container } = renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    // Closed: opening review is not an accent action.
    expect(container.querySelectorAll(".is-btn--primary")).toHaveLength(0);
    await openModal();
    // Open: exactly one accent button — Approve. Reject is secondary.
    expect(container.querySelectorAll(".is-btn--primary")).toHaveLength(1);
    expect(screen.getByTestId("approval-approve")).toHaveClass("is-btn--primary");
    expect(screen.getByTestId("approval-reject")).not.toHaveClass("is-btn--primary");
  });

  it("Esc closes the modal", async () => {
    mockFetch({ "/api/approvals": { approvals: [approval()] } });
    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    await openModal();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("approval-modal")).toBeNull());
  });
});

describe("is-approval-modal — step-up (D3) at the UI layer", () => {
  it("Enter submits ONLY when the passphrase field is non-empty", async () => {
    const calls = recordingFetch([approval()]);
    const user = userEvent.setup();
    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    await openModal();

    const field = screen.getByTestId("approval-passphrase");
    field.focus();
    // Empty field: Enter must not submit (button disabled + onSubmit guard).
    await user.keyboard("{Enter}");
    expect(screen.getByTestId("approval-approve")).toBeDisabled();
    expect(calls.some((c) => c.url.endsWith("/approve"))).toBe(false);

    // Non-empty: Enter submits exactly one approve.
    await user.type(field, PASS);
    await user.keyboard("{Enter}");
    await waitFor(() =>
      expect(calls.filter((c) => c.url.endsWith("/approve"))).toHaveLength(1));
  });

  it("the passphrase never leaves the field — not the URL, not a log, not any rendered state or error", async () => {
    const calls = recordingFetch([approval()], 401);   // force a step-up failure
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const user = userEvent.setup();

    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    await openModal();

    await user.type(screen.getByTestId("approval-passphrase"), PASS);
    await user.click(screen.getByTestId("approval-approve"));

    // The error surfaces, but with the backend's generic reason only.
    const err = await screen.findByTestId("approval-error");
    expect(err).toHaveTextContent(/step-up verification failed/i);
    expect(err.textContent).not.toContain(PASS);

    const approve = calls.find((c) => c.url.endsWith("/approve"))!;
    expect(approve).toBeTruthy();
    // Never in the URL / query string.
    expect(approve.url).not.toContain(PASS);
    // Sent in the request BODY (that is the only place it may travel).
    expect(String(approve.init?.body)).toContain(PASS);
    // Field is cleared after the attempt — the credential is not left in the DOM.
    expect((screen.getByTestId("approval-passphrase") as HTMLInputElement).value).toBe("");
    // Nowhere in the rendered document.
    expect(document.body.textContent ?? "").not.toContain(PASS);
    // Never logged.
    for (const spy of [logSpy, errSpy, warnSpy]) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(PASS);
      }
    }
  });

  it("a failed re-evaluation surfaces the engine's missing[] verbatim — still no passphrase", async () => {
    // 401 path already covered; here the connector-side stale re-eval (409) —
    // reuse the recording stub but answer approve with 409 + missing[].
    const calls: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url);
      calls.push({ url: u, init });
      const reply = (status: number, body: unknown) =>
        ({ ok: status >= 200 && status < 300, status, json: async () => body } as Response);
      if (u.endsWith("/approve")) {
        return reply(409, { error: "re-evaluation failed", missing: ["recent_bruteforce"] });
      }
      if (u.includes("/api/approvals")) return reply(200, { approvals: [approval()] });
      return reply(404, {});
    }));
    const user = userEvent.setup();
    renderApp(<Approvals />, { route: "/approvals" });
    await screen.findByTestId("approvals-screen");
    await openModal();
    await user.type(screen.getByTestId("approval-passphrase"), PASS);
    await user.click(screen.getByTestId("approval-approve"));
    const err = await screen.findByTestId("approval-error");
    expect(err).toHaveTextContent(/recent_bruteforce/);
    expect(err.textContent).not.toContain(PASS);
  });
});
