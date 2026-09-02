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

const ADVISORY_SENTENCE = "the learned model is advisory; these numbers are why.";

const MODEL = {
  available: true,
  reason: null,
  name: "sklearn.ensemble.GradientBoostingClassifier",
  sha256: "0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765",
  trainedAt: "2026-09-02T09:46:51+00:00",
  trainingSeeds: [20260902, 20260903],
};

const RULE_TOTALS_CLEAN = {
  true_positive_findings: 1,
  false_positive_findings: 0,
  malicious_lines: 5,
  malicious_lines_detected: 5,
  precision: 1.0,
  recall: 1.0,
  f1: 1.0,
  precision_defined: true,
  recall_defined: true,
  missed_lines: 0,
  findings: 1,
};

const LEARNED_TOTALS_DROPPED = {
  true_positive_findings: 0,
  false_positive_findings: 0,
  malicious_lines: 5,
  malicious_lines_detected: 0,
  precision: 0.0,
  recall: 0.0,
  f1: 0.0,
  precision_defined: false,
  recall_defined: true,
  missed_lines: 5,
  findings: 0,
};

const LEARNED_MISS = {
  line: 7,
  raw: "2026-08-30T02:16:47Z WARN bnch-server-01 Failed password for bnch-admin from 198.18.36.96 port 33121 ssh2",
  why: "credential-guessing failure from the scenario source",
};

const RULE_MISS = {
  line: 42,
  raw: "GET /item.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1",
  why: "Unusual hex encoded SQL injection bypass",
};

const MOCK_DONE_RUN: EfficacyResponse = {
  status: "done",
  run: {
    run_id: "efficacy-33b0ad5f410f",
    run_date: "2026-08-30T17:00:00Z",
    scope: SCOPE_SENTENCE,
    ceiling: CEILING_SENTENCE,
    advisory: ADVISORY_SENTENCE,
    pipeline: "log_analyzer.py --rules-only (subprocess)",
    systems: ["rules", "learned"],
    provenance: { commit: "e46d974559f8cda1a513fe918f6d580b85633abf", tree: "39910ef", worktreeDirty: false },
    benchmark: { seeds: [20270302, 20270303], scenarios: ["brute_force"], formats: ["canonical"] },
    freshness: { asserted: true, assertedEntityOverlap: { ip: [], user: [], host: [], port: [], change_window: [] } },
    model: MODEL,
    scenarios: [
      {
        scenario: "brute_force",
        format: "canonical",
        seed: 20270302,
        line_count: 50,
        totals: RULE_TOTALS_CLEAN,
        misses: [],
        rules: {
          system: "rules",
          available: true,
          reason: null,
          findings: 1,
          totals: RULE_TOTALS_CLEAN,
          per_rule: null,
          misses: [],
          false_positives: [],
        },
        learned: {
          system: "learned",
          available: true,
          reason: null,
          findings: 0,
          totals: LEARNED_TOTALS_DROPPED,
          per_rule: null,
          misses: [LEARNED_MISS],
          false_positives: [],
        },
        scope: SCOPE_SENTENCE,
      },
      {
        scenario: "web_sqli",
        format: "combined",
        seed: 20270303,
        line_count: 80,
        totals: {
          true_positive_findings: 2,
          false_positive_findings: 1,
          malicious_lines: 4,
          malicious_lines_detected: 3,
          precision: 0.6667,
          recall: 0.75,
          f1: 0.7059,
          precision_defined: true,
          recall_defined: true,
          missed_lines: 1,
          findings: 3,
        },
        misses: [RULE_MISS],
        rules: {
          system: "rules",
          available: true,
          reason: null,
          findings: 3,
          totals: {
            true_positive_findings: 2,
            false_positive_findings: 1,
            malicious_lines: 4,
            malicious_lines_detected: 3,
            precision: 0.6667,
            recall: 0.75,
            f1: 0.7059,
            precision_defined: true,
            recall_defined: true,
            missed_lines: 1,
            findings: 3,
          },
          per_rule: null,
          misses: [RULE_MISS],
          false_positives: [],
        },
        learned: {
          system: "learned",
          available: true,
          reason: null,
          findings: 2,
          totals: {
            true_positive_findings: 2,
            false_positive_findings: 0,
            malicious_lines: 4,
            malicious_lines_detected: 3,
            precision: 1.0,
            recall: 0.75,
            f1: 0.8571,
            precision_defined: true,
            recall_defined: true,
            missed_lines: 1,
            findings: 2,
          },
          per_rule: null,
          misses: [RULE_MISS],
          false_positives: [],
        },
        scope: SCOPE_SENTENCE,
      },
    ],
    total_misses: 1,
    total_false_positives: 1,
    learned_total_misses: 6,
    learned_total_false_positives: 0,
  },
  error: null,
};

/** The same run with NO model on the machine: rules measured, learned honestly absent. */
const MOCK_MODEL_UNAVAILABLE_RUN: EfficacyResponse = {
  status: "done",
  run: {
    run_id: "efficacy-nomodel00000",
    run_date: "2026-08-30T17:00:00Z",
    scope: SCOPE_SENTENCE,
    advisory: ADVISORY_SENTENCE,
    pipeline: "log_analyzer.py --rules-only (subprocess)",
    systems: ["rules", "learned"],
    benchmark: { seeds: [20270302], scenarios: ["brute_force"], formats: ["canonical"] },
    freshness: { asserted: false, reason: "no model was loaded" },
    model: {
      available: false,
      reason: "scikit-learn is not installed — the learned second opinion is optional and this installation does not have it.",
    },
    scenarios: [
      {
        scenario: "brute_force",
        format: "canonical",
        seed: 20270302,
        line_count: 50,
        totals: RULE_TOTALS_CLEAN,
        misses: [],
        rules: {
          system: "rules",
          available: true,
          reason: null,
          findings: 1,
          totals: RULE_TOTALS_CLEAN,
          per_rule: null,
          misses: [],
          false_positives: [],
        },
        learned: {
          system: "learned",
          available: false,
          reason: "scikit-learn is not installed — the learned second opinion is optional and this installation does not have it.",
          findings: null,
          totals: null,
          per_rule: null,
          misses: null,
          false_positives: null,
        },
        scope: SCOPE_SENTENCE,
      },
    ],
    total_misses: 0,
    total_false_positives: 0,
    learned_total_misses: null,
    learned_total_false_positives: null,
  },
  error: null,
};

const MOCK_CLEAN_RUN: EfficacyResponse = {
  status: "done",
  run: {
    run_id: "efficacy-cleanrun0000",
    run_date: "2026-08-30T17:00:00Z",
    scope: SCOPE_SENTENCE,
    advisory: ADVISORY_SENTENCE,
    pipeline: "log_analyzer.py --rules-only (subprocess)",
    systems: ["rules", "learned"],
    benchmark: { seeds: [20270302], scenarios: ["brute_force"], formats: ["canonical"] },
    model: MODEL,
    scenarios: [
      {
        scenario: "brute_force",
        format: "canonical",
        seed: 20270302,
        line_count: 50,
        totals: RULE_TOTALS_CLEAN,
        misses: [],
        rules: {
          system: "rules",
          available: true,
          reason: null,
          findings: 1,
          totals: RULE_TOTALS_CLEAN,
          per_rule: null,
          misses: [],
          false_positives: [],
        },
        learned: {
          system: "learned",
          available: true,
          reason: null,
          findings: 1,
          totals: RULE_TOTALS_CLEAN,
          per_rule: null,
          misses: [],
          false_positives: [],
        },
        scope: SCOPE_SENTENCE,
      },
    ],
    total_misses: 0,
    total_false_positives: 0,
    learned_total_misses: 0,
    learned_total_false_positives: 0,
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

  it("the advisory sentence travels with the numbers, verbatim and beside the scope", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_DONE_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-table");
    expect(screen.getByTestId("efficacy-advisory")).toHaveTextContent(ADVISORY_SENTENCE);
    // the standing scope sentence is NOT replaced by it
    expect(screen.getAllByText(SCOPE_SENTENCE).length).toBeGreaterThan(0);
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

  it("done: paired Rule and Learned scores are both rendered, from the fixture verbatim", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_DONE_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("efficacy-table")).toBeInTheDocument();
    const rows = screen.getAllByTestId("efficacy-row");
    expect(rows).toHaveLength(2);

    // First row: rules were perfect; the learned model dropped the finding, so
    // its precision is UNDEFINED (no findings) and its recall a measured 0.
    const row1 = within(rows[0]);
    expect(row1.getByText("brute_force")).toBeInTheDocument();
    expect(row1.getByText("canonical")).toBeInTheDocument();
    expect(row1.getByText("20270302")).toBeInTheDocument();
    const cells1 = rows[0].querySelectorAll("td");
    expect(Array.from(cells1).map((c) => c.textContent)).toEqual([
      "brute_force", "canonical", "20270302",
      "1", "1", "1", "0",           // rules P / R / F1 / misses
      "n/a", "0", "n/a", "5",       // learned P (undefined) / R / F1 / misses
    ]);

    // Second row: the learned model dropped a false positive and gained precision.
    const cells2 = rows[1].querySelectorAll("td");
    expect(Array.from(cells2).map((c) => c.textContent)).toEqual([
      "web_sqli", "combined", "20270303",
      "0.6667", "0.75", "0.7059", "1",
      "1", "0.75", "0.8571", "1",
    ]);
  });

  it("done: BOTH systems' misses are listed verbatim, labelled by system", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_DONE_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    expect(await screen.findByTestId("efficacy-misses-section")).toBeInTheDocument();

    // the rule miss, verbatim (web_sqli: BOTH systems missed this line, so it
    // is listed once under each system — that is the paired report, not a dupe)
    expect(screen.getAllByText("Line 42:")).toHaveLength(2);
    expect(
      screen.getAllByText("GET /item.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1")
    ).toHaveLength(2);
    expect(screen.getAllByText("Why: Unusual hex encoded SQL injection bypass").length).toBeGreaterThan(0);

    // the learned miss, verbatim — a line the rules DID catch
    expect(screen.getByText("Line 7:")).toBeInTheDocument();
    expect(
      screen.getByText(
        "2026-08-30T02:16:47Z WARN bnch-server-01 Failed password for bnch-admin from 198.18.36.96 port 33121 ssh2"
      )
    ).toBeInTheDocument();
    expect(screen.getByText("Why: credential-guessing failure from the scenario source")).toBeInTheDocument();

    // and each list says which system it belongs to
    expect(screen.getByTestId("rule-misses-brute_force-none")).toHaveTextContent(
      "Rules: no missed malicious lines"
    );
    expect(screen.getByTestId("learned-misses-brute_force")).toHaveTextContent("Learned: 1 missed");
  });

  it("done: run id, commit, benchmark seeds and model provenance are all shown", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_DONE_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-table");
    expect(screen.getByTestId("efficacy-run-id")).toHaveTextContent("efficacy-33b0ad5f410f");
    expect(screen.getByTestId("efficacy-commit")).toHaveTextContent(
      "e46d974559f8cda1a513fe918f6d580b85633abf"
    );
    expect(screen.getByTestId("efficacy-seeds")).toHaveTextContent("20270302, 20270303");
    const provenance = screen.getByTestId("efficacy-model-provenance");
    expect(provenance).toHaveTextContent("sklearn.ensemble.GradientBoostingClassifier");
    expect(provenance).toHaveTextContent(
      "0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765"
    );
    expect(provenance).toHaveTextContent("2026-09-02T09:46:51+00:00");
    expect(provenance).toHaveTextContent("20260902, 20260903");
  });

  it("model unavailable: the rules half is measured and the learned half shows no score at all", async () => {
    mockFetch({
      "/api/reports": { reports: [] },
      "/api/efficacy": MOCK_MODEL_UNAVAILABLE_RUN,
    });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-table");
    expect(screen.getByTestId("efficacy-model-unavailable")).toHaveTextContent(
      "scikit-learn is not installed"
    );
    expect(screen.getByTestId("efficacy-row-learned-unavailable")).toHaveTextContent(
      "learned model unavailable — no score is shown"
    );
    // no fabricated learned totals anywhere
    expect(screen.getByTestId("efficacy-learned-total-misses")).toHaveTextContent("n/a");
    expect(screen.getByTestId("efficacy-learned-total-fps")).toHaveTextContent("n/a");
    // ...while the rules row is still fully scored
    const cells = screen.getAllByTestId("efficacy-row")[0].querySelectorAll("td");
    expect(Array.from(cells).map((c) => c.textContent)).toEqual([
      "brute_force", "canonical", "20270302", "1", "1", "1", "0",
      "learned model unavailable — no score is shown",
    ]);
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

  it("client picks no benchmark seed and never reads the model itself", () => {
    const reportsPath = path.resolve(__dirname, "../pages/Reports.tsx");
    const reportsContent = fs.readFileSync(reportsPath, "utf-8");
    // The frozen referee owns seed selection; the UI only renders what it is told.
    expect(reportsContent).not.toMatch(/2027\d{4}/);
    expect(reportsContent).not.toMatch(/BENCHMARK_SEEDS/);
    expect(reportsContent).not.toMatch(/triage_model/);
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
