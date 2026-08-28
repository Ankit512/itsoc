import "@testing-library/jest-dom";
import { afterEach } from "vitest";
import { useJobs } from "@/store/jobs";

// The intake job store (useJobs) is a module singleton shared across every test
// file on a worker. A file that starts a job and does not reset it (e.g. the
// header-upload test) leaks `busy`/job state into whichever file runs next on
// the same worker, which surfaced as a scheduling-dependent flake in the
// upload-dialog URL-submit tests once the suite gained another file. Reset it
// after every test globally — the same `_reset()` upload-dialog/upload-persist
// already call per-file — so isolation no longer depends on worker layout.
afterEach(() => {
  useJobs.getState()._reset();
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
