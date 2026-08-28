import "@testing-library/jest-dom";
import { afterEach, vi } from "vitest";
import { useJobs } from "@/store/jobs";
import { useUi } from "@/store/ui";

// Extend default test timeout to 15s so full parallel test runs on busy CPUs
// are not subject to artificial timer starvation timeouts.
vi.setConfig({ testTimeout: 15000 });

// The intake job store (useJobs) is a module singleton shared across every test
// file on a worker. A file that starts a job and does not reset it (e.g. the
// header-upload test) leaks `busy`/job state into whichever file runs next on
// the same worker, which surfaced as a scheduling-dependent flake in the
// upload-dialog URL-submit tests once the suite gained another file. Reset it
// after every test globally — the same `_reset()` upload-dialog/upload-persist
// already call per-file — so isolation no longer depends on worker layout.
//
// The UI store (useUi) is also a module singleton. Tests opening the command
// palette (commandPaletteOpen) or toggling experimental features (experimentalEnabled)
// or changing theme/search leaked state across files, causing multi-element
// button collisions (e.g. /refresh/i in CommandPalette vs AppShell top bar)
// and inverted initial states when tests ran in shuffled order.
afterEach(() => {
  useJobs.getState()._reset();
  useUi.getState().resetUi();
  try {
    localStorage.clear();
  } catch {
    // storage unavailable
  }
});

// jsdom has no matchMedia; default to a light-preferring stub.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}
