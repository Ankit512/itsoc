import "@testing-library/jest-dom";
import { afterEach } from "vitest";
import { useJobs } from "@/store/jobs";
import { useUi } from "@/store/ui";

// Global reset after every test across all test files:
// 1. useJobs intake store singleton (busy, jobs list, progress)
// 2. useUi singleton (theme, search, timeWindow, commandPaletteOpen, experimentalEnabled)
// 3. localStorage (itsoc-theme, itsoc_auth_token)
// 4. document.documentElement classes and data-theme attribute
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
