import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, vi } from "vitest";
import App from "@/App";
import type { SyslogStatus } from "@/lib/api";
import { renderApp, mockFetch } from "./helpers";

afterEach(() => vi.restoreAllMocks());

const STOPPED: SyslogStatus = {
  running: false, bind: "127.0.0.1", port: 1514, protocols: ["udp", "tcp"],
  exposed: false, receivedCount: 0, storedCount: 0,
  startedAt: null, lastEventAt: null, error: "",
};
// The null path the honest bind display must survive — bind/port absent on the
// wire. The guard must render "not bound", never the literal "undefined".
const NO_BIND = {
  running: false, bind: null, port: null, protocols: ["udp", "tcp"],
  exposed: false, receivedCount: 0, storedCount: 0,
  startedAt: null, lastEventAt: null, error: "",
};
const EMPTY_EVENTS = { items: [], total: 0, limit: 15, offset: 0 };

describe("Sources — merged Uploads + Collectors (C1-T5)", () => {
  it("opens on the Uploads tab with the file drop and URL fetch (capability parity)", async () => {
    mockFetch({ "/api/syslog/status": STOPPED, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/sources" });

    expect(await screen.findByRole("tab", { name: "Uploads" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Collectors" })).toBeInTheDocument();
    // Uploads is the default tab: both intake affordances are present.
    expect(screen.getByTestId("sources-upload-file")).toBeInTheDocument();
    expect(screen.getByLabelText("Log file URL")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /fetch/i })).toBeInTheDocument();
    expect(screen.getByText(/nothing leaves this machine/i)).toBeInTheDocument();
  });

  it("switches to the Collectors tab and keeps the honest bind display (host:port)", async () => {
    mockFetch({ "/api/syslog/status": STOPPED, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/sources" });

    await userEvent.click(await screen.findByRole("tab", { name: "Collectors" }));
    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    expect(screen.getByText("127.0.0.1:1514")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start collector/i })).toBeInTheDocument();
    expect(screen.queryByText(/undefined/i)).toBeNull();
  });

  it("bind display shows 'not bound' and NEVER 'undefined' on the null path", async () => {
    mockFetch({ "/api/syslog/status": NO_BIND, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/collectors" });

    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    expect(screen.getByText("not bound")).toBeInTheDocument();
    // The hard-won fix: the literal "undefined" must appear nowhere.
    expect(screen.queryByText(/undefined/i)).toBeNull();
  });

  it("/collectors deep-links straight to the Collectors tab (bookmarks + parity preserved)", async () => {
    mockFetch({ "/api/syslog/status": STOPPED, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/collectors" });

    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start collector/i })).toBeInTheDocument();
    expect(screen.getByText(/No events received yet/)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Collectors" })).toHaveAttribute("aria-selected", "true");
  });
});
