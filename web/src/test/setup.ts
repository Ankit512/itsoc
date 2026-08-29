import "@testing-library/jest-dom";
import { afterEach, vi } from "vitest";
import { configure } from "@testing-library/dom";
import { useJobs } from "@/store/jobs";
import { useUi } from "@/store/ui";

// OPEN-14 — contention head-room for the integrated C4 suite.
// Integrating F1 (Response panel) + F2 (advisory states) + F3 (priority chip)
// roughly tripled the number of tests that mount the full <App>/Incidents detail.
// On a high-core box vitest fans out ~one fork per core, so those heavy React
// renders run concurrently and starve each other's event loop; under that CPU
// contention an async `findBy` (default 1000ms) or a whole test (default 5000ms)
// can miss its window before React commits and reports "Unable to find element".
// This is a load-induced flake, NOT a cross-file state leak. The evidence that
// settles it: the SAME command (same tree, same seed, same fork count) produced
// 2 failures on one run and 184/184 on the next. Same seed means same order, so
// order is not the variable — it is timing. Note that reducing the fork count
// lowers the failure RATE but does not eliminate it: a single-worker run has
// been observed failing too, so do not treat serial execution as a clean room. Give the async waits real head-room so
// isolation no longer depends on scheduler latency. This changes only how long we
// WAIT for an inherently async condition — it weakens no assertion: every test
// still requires the exact same DOM and values, only with time to reach them.
configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20000, hookTimeout: 20000 });

// Global reset after every test across all test files:
// 1. useJobs intake store singleton (busy, jobs list, progress)
// 2. useUi singleton (theme, search, timeWindow, commandPaletteOpen, experimentalEnabled)
// 3. localStorage (itsoc-theme, itsoc_auth_token)
// 4. document.documentElement classes and data-theme attribute
// 5. OPEN-14 — spies (restoreAllMocks) AND vi.stubGlobal stubs (unstubAllGlobals).
//    unstubAllGlobals is NOT done by restoreAllMocks. 14 of the 19 files that call
//    vi.stubGlobal never unstub. Under the current config (vitest forks pool with
//    isolate:true) each FILE gets a fresh environment, so those stubs cannot
//    actually reach the next file today — this is defence in depth, not the fix,
//    and it stops the hole opening the day someone sets isolate:false for speed. Reverting both here makes isolation independent of a file
//    remembering to clean up; neither can break a correct test, since every test
//    installs its own stubs/spies in a beforeEach or the test body.
afterEach(() => {
  useJobs.getState()._reset();
  useUi.getState().resetUi();
  try {
    localStorage.clear();
  } catch {
    // storage unavailable
  }
  document.documentElement.className = "";
  document.documentElement.removeAttribute("data-theme");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
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
