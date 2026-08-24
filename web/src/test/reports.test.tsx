import { screen, within } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch, consoleState, finding } from "./helpers";
import { EXPORT_FORMATS } from "@/lib/api";

describe("Reports page", () => {
  it("lists real saved reports from disk", async () => {
    mockFetch({ "/api/reports": { reports: [
      { name: "attack-2026-08-18-20260818T190301Z.html", bytes: 48213, createdAt: "2026-08-18T19:03:01+00:00" },
    ] } });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByText(/Saved reports \(1\)/)).toBeInTheDocument();
    expect(screen.getByTestId("report-row")).toBeInTheDocument();
    expect(screen.getByText(/attack-2026-08-18/)).toBeInTheDocument();
    expect(screen.getByText("47.1 KB")).toBeInTheDocument();
  });

  it("shows an honest empty state with no reports yet", async () => {
    mockFetch({ "/api/reports": { reports: [] } });
    renderApp(<App />, { route: "/reports" });
    expect(await screen.findByText(/No reports generated yet/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Generate report/ })).toBeInTheDocument();
  });

  it("offers a download control per format, each linking to /api/export?format=X, when a run is loaded", async () => {
    mockFetch({
      "/console_state.json": consoleState([finding(0)]),
      "/api/reports": { reports: [] },
    });
    renderApp(<App />, { route: "/reports" });

    // Wait for the run state to resolve — the controls become real links then.
    await screen.findByTestId("download-html");
    await within(screen.getByTestId("download-panel")).findByRole("link", { name: /HTML/ });
    const panel = screen.getByTestId("download-panel");
    // Phase 0 (spec §3): exports are trimmed to HTML + JSON only.
    expect(EXPORT_FORMATS.map((f) => f.format)).toEqual(["html", "json"]);
    for (const gone of ["csv", "xml", "md"]) {
      expect(within(panel).queryByTestId(`download-${gone}`)).not.toBeInTheDocument();
    }
    // One control per offered format, each a real download link.
    for (const { format } of EXPORT_FORMATS) {
      const control = within(panel).getByTestId(`download-${format}`);
      expect(control.tagName).toBe("A");
      expect(control).toHaveAttribute("href", `/api/export?format=${format}`);
      expect(control).toHaveAttribute("download");
    }
    expect(within(panel).getAllByRole("link").length).toBe(2);
  });

  it("disables the download controls honestly when no run is loaded", async () => {
    mockFetch({
      "/console_state.json": { idle: true },
      "/api/reports": { reports: [] },
    });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("download-panel");
    const panel = screen.getByTestId("download-panel");
    // No anchors: every control is a disabled span, not a working link.
    expect(within(panel).queryAllByRole("link").length).toBe(0);
    for (const { format } of EXPORT_FORMATS) {
      const control = within(panel).getByTestId(`download-${format}`);
      expect(control.tagName).toBe("SPAN");
      expect(control).toHaveAttribute("aria-disabled", "true");
    }
    expect(screen.getByText(/No run loaded — analyze a log/)).toBeInTheDocument();
  });
});
