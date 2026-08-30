// @ts-expect-error node:fs type declarations not included in browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations not included in browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations not included in browser tsconfig
import { fileURLToPath } from "node:url";

import { screen, within, fireEvent } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch } from "./helpers";
import type { EfficacyResponse } from "@/lib/api";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SCOPE_SENTENCE = "measured against synthetic ground-truth scenarios; not a claim about production traffic.";
const CEILING_SENTENCE = "These scenarios are drawn from the same attack classes the rules were written for — the expected result is perfection, and its value is regression proof (any future score below 1.0 is a detected regression), not a general-efficacy claim.";

const MOCK_DONE_RUN: EfficacyResponse = {
  status: "done",
  run: {
    run_date: "2026-08-30T17:00:00Z",
    scope: SCOPE_SENTENCE,
    pipeline: "log_analyzer.py --rules-only (subprocess)",
    scenarios: [
      {
        scenario: "brute_force",
        format: "canonical",
        line_count: 50,
        totals: {
          true_positive_findings: 1,
          false_positive_findings: 0,
          malicious_lines: 5,
          malicious_lines_detected: 5,
          precision: 1.0,
          recall: 1.0,
          f1: 1.0,
          missed_lines: 0,
          findings: 1,
        },
        misses: [],
        scope: SCOPE_SENTENCE,
      },
      {
        scenario: "web_sqli",
        format: "combined",
        line_count: 80,
        totals: {
          true_positive_findings: 2,
          false_positive_findings: 1,
          malicious_lines: 4,
          malicious_lines_detected: 3,
          precision: 0.6667,
          recall: 0.75,
          f1: 0.7059,
          missed_lines: 1,
          findings: 3,
        },
        misses: [
          {
            line: 42,
            raw: "GET /item.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1",
            why: "Unusual hex encoded SQL injection bypass",
          },
        ],
        scope: SCOPE_SENTENCE,
      },
    ],
    total_misses: 1,
    total_false_positives: 1,
  },
  error: null,
};

const MOCK_CLEAN_RUN: EfficacyResponse = {
  status: "done",
  run: {
    run_date: "2026-08-30T17:00:00Z",
    scope: SCOPE_SENTENCE,
    pipeline: "log_analyzer.py --rules-only (subprocess)",
    scenarios: [
      {
        scenario: "brute_force",
        format: "canonical",
        line_count: 50,
        totals: {
          true_positive_findings: 1,
          false_positive_findings: 0,
          malicious_lines: 5,
          malicious_lines_detected: 5,
          precision: 1.0,
          recall: 1.0,
          f1: 1.0,
          missed_lines: 0,
          findings: 1,
        },
        misses: [],
        scope: SCOPE_SENTENCE,
      },
    ],
    total_misses: 0,
    total_false_positives: 0,
  },
  error: null,
};

describe("Efficacy surface on Reports", () => {
  it("idle: shows honest empty state when run is null with exact reason", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": { status: "idle", run: null, error: null },
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("efficacy-idle")).toHaveTextContent(
      "No efficacy harness run yet — run one to measure synthetic scenarios"
    );
    expect(screen.queryByTestId("efficacy-table")).not.toBeInTheDocument();
    expect(screen.queryByText("1.000")).not.toBeInTheDocument();
  });

  it("scope sentence is always present on the panel", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": { status: "idle", run: null, error: null },
    });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-idle");
    const scopeEls = screen.getAllByText(SCOPE_SENTENCE);
    expect(scopeEls.length).toBeGreaterThan(0);
    expect(screen.getByTestId("efficacy-ceiling")).toHaveTextContent(CEILING_SENTENCE);
  });

  it("running: shows honest running state with no fabricated scores", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": { status: "running", run: null, error: null },
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("efficacy-running")).toHaveTextContent("Running efficacy harness…");
    expect(screen.queryByTestId("efficacy-table")).not.toBeInTheDocument();
    expect(screen.getAllByText(SCOPE_SENTENCE).length).toBeGreaterThan(0);
  });

  it("error: shows honest backend error string and no table fill", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": {
        status: "error",
        run: null,
        error: "Subprocess execution failed: missing scenario definition",
      },
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("efficacy-error")).toHaveTextContent(
      "Subprocess execution failed: missing scenario definition"
    );
    expect(screen.queryByTestId("efficacy-table")).not.toBeInTheDocument();
    expect(screen.getAllByText(SCOPE_SENTENCE).length).toBeGreaterThan(0);
  });

  it("done: table rows match fixture JSON exactly and tabular-nums are applied", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_DONE_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("efficacy-table")).toBeInTheDocument();
    const rows = screen.getAllByTestId("efficacy-row");
    expect(rows).toHaveLength(2);

    // First row: brute_force
    const row1 = within(rows[0]);
    expect(row1.getByText("brute_force")).toBeInTheDocument();
    expect(row1.getByText("canonical")).toBeInTheDocument();
    expect(row1.getAllByText("1")).toHaveLength(3); // precision 1, recall 1, f1 1
    expect(row1.getByText("0")).toBeInTheDocument(); // miss count 0

    // Second row: web_sqli
    const row2 = within(rows[1]);
    expect(row2.getByText("web_sqli")).toBeInTheDocument();
    expect(row2.getByText("combined")).toBeInTheDocument();
    expect(row2.getByText("0.6667")).toBeInTheDocument();
    expect(row2.getByText("0.75")).toBeInTheDocument();
    expect(row2.getByText("0.7059")).toBeInTheDocument();
    expect(row2.getByText("1")).toBeInTheDocument(); // miss count 1
  });

  it("done: miss list shows the fixture miss raw, line, and why verbatim", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_DONE_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("efficacy-misses-section")).toBeInTheDocument();
    expect(screen.getByText("Line 42:")).toBeInTheDocument();
    expect(
      screen.getByText("GET /item.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1")
    ).toBeInTheDocument();
    expect(screen.getByText("Why: Unusual hex encoded SQL injection bypass")).toBeInTheDocument();
  });

  it("done: empty misses shows honest 'no missed malicious lines'", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_CLEAN_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("no-misses")).toHaveTextContent("no missed malicious lines");
    expect(screen.getAllByText(SCOPE_SENTENCE).length).toBeGreaterThan(0);
  });

  it("client does not compute f1 (no precision * recall in Reports.tsx)", () => {
    const reportsPath = path.resolve(__dirname, "../pages/Reports.tsx");
    const reportsContent = fs.readFileSync(reportsPath, "utf-8");
    expect(reportsContent).not.toMatch(/precision\s*\*\s*recall/i);
    expect(reportsContent).not.toMatch(/recall\s*\*\s*precision/i);
    expect(reportsContent).not.toMatch(/2\s*\*\s*precision/i);
  });

  it("run harness button triggers POST /api/efficacy and displays error if 404s", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": { status: "idle", run: null, error: null },
    });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-idle");
    const btn = screen.getByTestId("run-harness-btn");
    expect(btn).toBeInTheDocument();
    expect(btn).not.toBeDisabled();

    // Now mock POST /api/efficacy failing with 404
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": () => ({ __status: 404, error: "Not Found: /api/efficacy" }),
    });

    fireEvent.click(btn);

    expect(await screen.findByTestId("efficacy-mutation-error")).toHaveTextContent("Not Found: /api/efficacy");
  });
});
