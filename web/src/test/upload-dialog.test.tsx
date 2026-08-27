import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { useJobs } from "@/store/jobs";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

/** The Upload button opens a two-mode dialog (local file OR a pasted URL).
 *  Both feed the same background job — only the source differs. */
describe("upload dialog: files and a link, side by side (v3)", () => {
  beforeEach(() => useJobs.getState()._reset());

  it("opens a dialog offering both ingest modes at once", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS });
    renderApp(<App />);
    await screen.findByTestId("chart-overtime");

    await userEvent.click(screen.getByRole("button", { name: /upload logs/i }));
    const dialog = screen.getByRole("dialog", { name: /upload logs/i });
    // v3 shows UPLOAD FILES and PASTE A LOG LINK side by side — no mode switch.
    expect(within(dialog).getByText("UPLOAD FILES")).toBeInTheDocument();
    expect(within(dialog).getByText("PASTE A LOG LINK")).toBeInTheDocument();
    expect(within(dialog).getByTestId("ingest-file")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Log file URL")).toBeInTheDocument();
  });

  it("submitting a URL starts a job via POST /api/analyze {url}", async () => {
    let postBody: unknown = null;
    let progressN = 0;
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS, "/api/runs": { current: null, runs: [] },
      "/api/progress": () => (progressN++ === 0
        ? { status: "running", phase: "rules", done: 0, total: 0 }
        : { status: "done", phase: "done", findings: 3 }),
    });
    const realFetch = globalThis.fetch as unknown as (u: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
    vi.stubGlobal("fetch", vi.fn((u: RequestInfo | URL, init?: RequestInit) => {
      if (String(u).includes("/api/analyze") && init?.method === "POST") {
        postBody = JSON.parse(String(init.body));
        return Promise.resolve({ ok: true, status: 202, json: async () => ({ status: "running" }) } as Response);
      }
      return realFetch(u, init);
    }));

    renderApp(<App />);
    await screen.findByTestId("chart-overtime");
    await userEvent.click(screen.getByRole("button", { name: /upload logs/i }));

    const url = "https://raw.githubusercontent.com/org/repo/main/app.log";
    await userEvent.type(screen.getByLabelText("Log file URL"), url);
    await userEvent.click(screen.getByRole("button", { name: /fetch & parse/i }));

    // The URL was posted as {url}, and the job completes via the notifier.
    await waitFor(() => expect(postBody).toEqual({ url }));
    expect(await screen.findByText(/app\.log analyzed — 3 finding\(s\)/, undefined,
      { timeout: 6000 })).toBeInTheDocument();
  }, 10000);

  it("surfaces the backend's honest rejection of an unsafe URL", async () => {
    mockFetch({
      "/api/overview": OVERVIEW, "/api/metrics": METRICS,
      "/api/analyze": { __status: 400, error: "that URL points at a private, loopback, or link-local address — only public log URLs can be fetched" },
    });
    renderApp(<App />);
    await screen.findByTestId("chart-overtime");
    await userEvent.click(screen.getByRole("button", { name: /upload logs/i }));
    await userEvent.type(screen.getByLabelText("Log file URL"), "http://localhost/x.log");
    await userEvent.click(screen.getByRole("button", { name: /fetch & parse/i }));

    expect(await screen.findByText(/private, loopback, or link-local address/)).toBeInTheDocument();
  });
});
