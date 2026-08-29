import { screen, within } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import App from "@/App";
import type { SyslogStatus } from "@/lib/api";
import { renderApp, mockFetch } from "./helpers";

/**
 * C5-T2 — collector back-pressure is SURFACED, not merely recorded.
 *
 * The collector counts dropped datagrams when its bounded ingest queue
 * saturates (a drop nobody counts is indistinguishable from an event that never
 * happened). A counter nobody shows is the same defect one layer up, so the
 * Collectors panel must render the drop count AND, when it is non-zero, an
 * explicit honest banner — and must NOT raise that alarm when nothing dropped.
 */

const EMPTY_EVENTS = { items: [], total: 0, limit: 15, offset: 0 };

const SATURATED: SyslogStatus = {
  running: true, bind: "127.0.0.1", port: 1514, protocols: ["udp", "tcp"],
  exposed: false,
  receivedCount: 1000, storedCount: 600, ingestedCount: 600,
  droppedCount: 395, laggingCount: 5, queueCapacity: 5, queueUsed: 5,
  startedAt: "2026-08-19T15:00:00Z", lastEventAt: "2026-08-19T15:01:00Z", error: "",
};

const HEALTHY: SyslogStatus = {
  running: true, bind: "127.0.0.1", port: 1514, protocols: ["udp", "tcp"],
  exposed: false,
  receivedCount: 12, storedCount: 12, ingestedCount: 12,
  droppedCount: 0, laggingCount: 0, queueCapacity: 10000, queueUsed: 0,
  startedAt: "2026-08-19T15:00:00Z", lastEventAt: "2026-08-19T15:01:00Z", error: "",
};

afterEach(() => vi.restoreAllMocks());

describe("Collectors — back-pressure surfacing (C5-T2)", () => {
  it("SHOWS the dropped count and an honest saturation banner when the queue drops events", async () => {
    mockFetch({ "/api/syslog/status": SATURATED, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/collectors" });

    // Await the loaded state (the banner renders only once real drops are in).
    const warning = await screen.findByTestId("collector-drop-warning");

    // The drop count is rendered verbatim (not hidden behind an aggregate).
    expect(screen.getByTestId("collector-dropped")).toHaveTextContent("395");
    // The live backlog (lagging) is shown against the queue capacity.
    expect(screen.getByTestId("collector-lagging")).toHaveTextContent("5");

    // And a drop is SHOWN, not merely recorded: an explicit banner explains it.
    expect(within(warning).getByText("395")).toBeInTheDocument();
    expect(warning).toHaveTextContent(/dropped under back-pressure/i);
    expect(warning).toHaveTextContent(/counted, not\s+silently lost/i);
    expect(warning).toHaveTextContent(/quiet network, not a saturated collector/i);
  });

  it("does NOT raise the saturation alarm when nothing has been dropped (no false alarm)", async () => {
    mockFetch({ "/api/syslog/status": HEALTHY, "/api/store/events": EMPTY_EVENTS });
    renderApp(<App />, { route: "/collectors" });

    expect(await screen.findByTestId("collector-dropped")).toHaveTextContent("0");
    expect(screen.queryByTestId("collector-drop-warning")).toBeNull();
  });
});
