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

/** E8m. The finding the learned system dropped WHILE it cited a malicious line —
 *  the loss line-level recall absorbs whenever a kept finding covers the same
 *  lines. Shaped after the real defect: an `ioc_observed` finding on the
 *  crown-jewel host, labelled benign-expected at high confidence. */
const DROPPED_TRUE_FINDING = {
  rule_id: "ioc_observed",
  severity: "MEDIUM",
  summary: "Threat-intel IOC observed on bnch-server-01",
  evidence: null,
  label: "benign-expected",
  confidence: 0.992,
  cited_malicious_lines: [
    {
      line: 2,
      raw: "2026-08-30T02:16:41Z WARN bnch-server-01 Connection to known-bad 198.18.36.96",
      why: "threat-intel indicator from the scenario source",
    },
  ],
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
    benchmark: {
      seeds: [20270302, 20270303],
      scenarios: ["brute_force"],
      // E8m2: the referee's frozen set, published beside what ran
      frozenScenarios: ["INC-4a7f", "failure-success", "error-burst",
                        "near-miss-auth", "near-miss-errors", "benign-maintenance"],
      scenarioSetIsFrozen: false,
      scenarioNote:
        "The benchmark's scenario set is frozen in the referee, not read from the generator.",
      formats: ["canonical"],
    },
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
          finding_recall: {
            true_findings_kept: 1, true_findings_total: 1, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          dropped_true_findings: [],
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
          finding_recall: {
            true_findings_kept: 0, true_findings_total: 1, recall: 0.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          dropped_true_findings: [DROPPED_TRUE_FINDING],
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
          finding_recall: {
            true_findings_kept: 2, true_findings_total: 2, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          dropped_true_findings: [],
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
          finding_recall: {
            true_findings_kept: 2, true_findings_total: 2, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          dropped_true_findings: [],
        },
        scope: SCOPE_SENTENCE,
      },
    ],
    total_misses: 1,
    total_false_positives: 1,
    learned_total_misses: 6,
    learned_total_false_positives: 0,
    // --- E8m: additive publication ---
    recall_note:
      "Recall is published with its denominator, always. LINE-LEVEL recall is over the manifest's malicious LINES; FINDING-LEVEL recall is over the FINDINGS that cite at least one malicious line.",
    format_scope_note:
      "Every false-positive total is scoped to the formats it was measured over.",
    line_level_recall_denominator: "manifest malicious lines",
    finding_level_recall: {
      denominator: "findings that cite at least one malicious line",
      true_findings_total: 3,
      rules: {
        true_findings_kept: 3, true_findings_total: 3, recall: 1.0,
        recall_defined: true,
        denominator: "findings that cite at least one malicious line",
      },
      learned: {
        true_findings_kept: 2, true_findings_total: 3, recall: 0.6667,
        recall_defined: true,
        denominator: "findings that cite at least one malicious line",
      },
      learned_dropped_true_findings: [DROPPED_TRUE_FINDING],
      // --- E8m2: the same recall, per rule class ---
      by_rule_note:
        "Finding-level recall is also published PER RULE CLASS, each with its own denominator. A rule that produced no finding citing a malicious line is absent from the breakdown rather than published as a 0/0. This is a reading aid over `dropped_true_findings`, which stays published verbatim.",
      by_rule: {
        ioc_observed: {
          denominator: "findings this rule produced that cite at least one malicious line",
          true_findings_total: 1,
          rules: {
            true_findings_kept: 1, true_findings_total: 1, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          learned: {
            true_findings_kept: 0, true_findings_total: 1, recall: 0.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          learned_dropped_true_findings: 1,
        },
        auth_bruteforce: {
          denominator: "findings this rule produced that cite at least one malicious line",
          true_findings_total: 2,
          rules: {
            true_findings_kept: 2, true_findings_total: 2, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          learned: {
            true_findings_kept: 2, true_findings_total: 2, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          learned_dropped_true_findings: 0,
        },
      },
    },
    false_positive_totals: {
      formats: ["canonical", "combined"],
      scope: "all formats measured in this run: canonical, combined",
      rules: 1,
      learned: 0,
      by_format: {
        canonical: { rules: 0, learned: 0 },
        combined: { rules: 1, learned: 0 },
      },
    },
    learned_total_dropped_true_findings: 1,
    criticality_sensitivity: {
      available: true,
      reason: null,
      kind: "counterfactual",
      note: "COUNTERFACTUAL, measured live on this run. The model is MORE willing to dismiss a finding on a MORE critical asset. These are counterfactuals only — every published number above stands exactly as measured.",
      feature: "criticality_rank",
      domain: ["low", "standard", "crown-jewel"],
      feature_importance: {
        available: true,
        reason: null,
        by_feature: { criticality_rank: 0.4146, rule_family_auth: 0.1476 },
        criticality_rank: 0.4146,
      },
      populations: {
        true_detections: {
          total: 85, robust: 57, flipping: 28,
          kept_at: { low: 85, standard: 85, "crown-jewel": 57 },
        },
        suppressions: {
          total: 84, robust: 51, flipping: 33,
          kept_at: { low: 33, standard: 33, "crown-jewel": 0 },
        },
      },
    },
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
          finding_recall: {
            true_findings_kept: 1, true_findings_total: 1, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          dropped_true_findings: [],
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
    line_level_recall_denominator: "manifest malicious lines",
    finding_level_recall: {
      denominator: "findings that cite at least one malicious line",
      true_findings_total: 1,
      rules: {
        true_findings_kept: 1, true_findings_total: 1, recall: 1.0,
        recall_defined: true,
        denominator: "findings that cite at least one malicious line",
      },
      learned: null,
      learned_dropped_true_findings: null,
      by_rule_note:
        "Finding-level recall is also published PER RULE CLASS, each with its own denominator.",
      by_rule: {
        auth_bruteforce: {
          denominator: "findings this rule produced that cite at least one malicious line",
          true_findings_total: 1,
          rules: {
            true_findings_kept: 1, true_findings_total: 1, recall: 1.0,
            recall_defined: true,
            denominator: "findings that cite at least one malicious line",
          },
          learned: null,
          learned_dropped_true_findings: null,
        },
      },
    },
    false_positive_totals: {
      formats: ["canonical"],
      scope: "all formats measured in this run: canonical",
      rules: 0,
      learned: null,
      by_format: { canonical: { rules: 0, learned: null } },
    },
    learned_total_dropped_true_findings: null,
    criticality_sensitivity: {
      available: false,
      reason: "no learned model was loaded, so there is nothing to re-score",
      kind: "counterfactual",
      note: "COUNTERFACTUAL.",
      feature: "criticality_rank",
      domain: ["low", "standard", "crown-jewel"],
      feature_importance: null,
      populations: null,
    },
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
      // rules P / R(lines) / R(findings) / F1 / misses
      "1", "1", "1", "1", "0",
      // learned P (undefined) / R(lines) / R(findings) / F1 / misses / dropped
      "n/a", "0", "0", "n/a", "5", "1",
    ]);

    // Second row: the learned model dropped a false positive and gained precision.
    const cells2 = rows[1].querySelectorAll("td");
    expect(Array.from(cells2).map((c) => c.textContent)).toEqual([
      "web_sqli", "combined", "20270303",
      "0.6667", "0.75", "1", "0.7059", "1",
      "1", "0.75", "1", "0.8571", "1", "0",
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
      "brute_force", "canonical", "20270302", "1", "1", "1", "1", "0",
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

  // --- E8m: the amendment's three publications -----------------------------

  it("E8m: both recalls are published, each labelled with its own denominator", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    const block = await screen.findByTestId("efficacy-recall-denominators");
    expect(within(block).getByTestId("efficacy-line-recall-denominator")).toHaveTextContent(
      "Line-level recall is over manifest malicious lines",
    );
    expect(within(block).getByTestId("efficacy-finding-recall-denominator")).toHaveTextContent(
      "Finding-level recall is over findings that cite at least one malicious line",
    );
    // both systems, from the fixture verbatim — nothing recomputed here
    expect(within(block).getByTestId("efficacy-finding-recall-rules")).toHaveTextContent("1 (3/3)");
    expect(within(block).getByTestId("efficacy-finding-recall-learned")).toHaveTextContent("0.6667 (2/3)");
    expect(screen.getByTestId("efficacy-recall-note")).toHaveTextContent("FINDING-LEVEL recall");
  });

  it("E8m: a finding dropped while citing a malicious line is listed VERBATIM, like a miss", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-misses-section");
    const dropped = screen.getByTestId("learned-dropped-brute_force");
    expect(dropped).toHaveTextContent("ioc_observed");
    expect(dropped).toHaveTextContent("benign-expected");
    expect(dropped).toHaveTextContent("0.992");
    expect(dropped).toHaveTextContent(DROPPED_TRUE_FINDING.cited_malicious_lines[0].raw);
    expect(dropped).toHaveTextContent(DROPPED_TRUE_FINDING.cited_malicious_lines[0].why);
    // and it is counted on the run header and in its own table column
    expect(screen.getByTestId("efficacy-learned-dropped-total")).toHaveTextContent("1");
    expect(screen.getAllByTestId("efficacy-row-learned-dropped")[0]).toHaveTextContent("1");
  });

  it("E8m: a scenario that dropped nothing says so, rather than omitting the line", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-misses-section");
    expect(screen.getByTestId("learned-dropped-web_sqli-none")).toHaveTextContent(
      "no findings dropped while citing a malicious line",
    );
  });

  it("E8m: no false-positive total is rendered without its format scope", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    const totals = await screen.findByTestId("efficacy-fp-totals");
    expect(totals).toHaveTextContent("all formats measured in this run: canonical, combined");
    expect(within(totals).getByTestId("efficacy-fp-headline")).toHaveTextContent("rules 1");
    // each single format is an EXPLICITLY LABELLED subset, never the headline
    expect(within(totals).getByTestId("efficacy-fp-subset-canonical")).toHaveTextContent("subset");
    expect(within(totals).getByTestId("efficacy-fp-subset-combined")).toHaveTextContent("subset");
    // and the header count carries the scope too
    expect(screen.getByTestId("efficacy-fp-scope")).toHaveTextContent(
      "all formats measured in this run: canonical, combined",
    );
  });

  it("E8m: the criticality sensitivity is a first-class finding, labelled a counterfactual", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    const block = await screen.findByTestId("efficacy-criticality-sensitivity");
    expect(within(block).getByTestId("efficacy-criticality-kind")).toHaveTextContent("counterfactual");
    expect(within(block).getByTestId("efficacy-criticality-importance")).toHaveTextContent("0.4146");
    // direction, read straight off the bands
    expect(within(block).getByTestId("efficacy-criticality-true_detections")).toHaveTextContent(
      "85 total — 57 robust, 28 flip",
    );
    expect(within(block).getByTestId("efficacy-criticality-true_detections")).toHaveTextContent(
      "low 85 · standard 85 · crown-jewel 57",
    );
    expect(within(block).getByTestId("efficacy-criticality-suppressions")).toHaveTextContent(
      "84 total — 51 robust, 33 flip",
    );
    expect(within(block).getByTestId("efficacy-criticality-note")).toHaveTextContent(
      "stands exactly as measured",
    );
  });

  it("E8m: with no model, the amendment renders honest gaps and never a zero", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_MODEL_UNAVAILABLE_RUN });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-table");
    expect(screen.getByTestId("efficacy-finding-recall-learned")).toHaveTextContent(
      "unavailable — no number is invented",
    );
    expect(screen.getByTestId("efficacy-learned-dropped-total")).toHaveTextContent("n/a");
    expect(screen.getByTestId("efficacy-criticality-unavailable")).toHaveTextContent(
      "no learned model was loaded",
    );
    expect(screen.queryByTestId("efficacy-criticality-sensitivity")).not.toBeInTheDocument();
  });

  it("E8m: a run body with no finding-level recall renders n/a, never a fabricated 1.0", async () => {
    const legacy = JSON.parse(JSON.stringify(MOCK_DONE_RUN));
    delete legacy.run.finding_level_recall;
    delete legacy.run.false_positive_totals;
    delete legacy.run.criticality_sensitivity;
    for (const sc of legacy.run.scenarios) {
      delete sc.rules.finding_recall;
      delete sc.learned.finding_recall;
    }
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": legacy });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-table");
    expect(screen.getAllByTestId("efficacy-row-rule-finding-recall")[0]).toHaveTextContent("n/a");
    expect(screen.getAllByTestId("efficacy-row-learned-finding-recall")[0]).toHaveTextContent("n/a");
    expect(screen.queryByTestId("efficacy-recall-denominators")).not.toBeInTheDocument();
    expect(screen.queryByTestId("efficacy-fp-totals")).not.toBeInTheDocument();
    expect(screen.queryByTestId("efficacy-criticality-sensitivity")).not.toBeInTheDocument();
  });

  // --- E8m2: the per-rule breakdown and the frozen scenario pin ------------

  it("E8m2: finding-level recall is broken down by rule class, each with its own denominator", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    const table = await screen.findByTestId("efficacy-finding-recall-by-rule");
    // the class the learned system LOST is readable on its own row — this is
    // exactly what an aggregate 0.9111 hid
    const lost = within(table).getByTestId("efficacy-by-rule-ioc_observed");
    expect(within(lost).getByTestId("efficacy-by-rule-ioc_observed-rules")).toHaveTextContent("1 (1/1)");
    expect(within(lost).getByTestId("efficacy-by-rule-ioc_observed-learned")).toHaveTextContent("0 (0/1)");
    expect(within(lost).getByTestId("efficacy-by-rule-ioc_observed-dropped")).toHaveTextContent("1");
    // ... beside a class it kept in full
    const kept = within(table).getByTestId("efficacy-by-rule-auth_bruteforce");
    expect(within(kept).getByTestId("efficacy-by-rule-auth_bruteforce-learned")).toHaveTextContent("1 (2/2)");
    expect(within(table).getByTestId("efficacy-by-rule-note")).toHaveTextContent(
      "PER RULE CLASS",
    );
  });

  it("E8m2: the breakdown ADDS to the verbatim dropped list, it does not replace it", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-finding-recall-by-rule");
    // the same drop, still listed verbatim with its real evidence
    const dropped = screen.getByTestId("learned-dropped-brute_force");
    expect(dropped).toHaveTextContent(DROPPED_TRUE_FINDING.cited_malicious_lines[0].raw);
    // and the aggregate is still published, unreplaced
    expect(screen.getByTestId("efficacy-finding-recall-learned")).toHaveTextContent("0.6667 (2/3)");
  });

  it("E8m2: with no learned model every per-rule learned cell is an honest gap", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_MODEL_UNAVAILABLE_RUN });
    renderApp(<App />, { route: "/reports" });

    const table = await screen.findByTestId("efficacy-finding-recall-by-rule");
    const row = within(table).getByTestId("efficacy-by-rule-auth_bruteforce");
    expect(within(row).getByTestId("efficacy-by-rule-auth_bruteforce-learned")).toHaveTextContent(
      "unavailable",
    );
    expect(within(row).getByTestId("efficacy-by-rule-auth_bruteforce-dropped")).toHaveTextContent("n/a");
    expect(within(row).getByTestId("efficacy-by-rule-auth_bruteforce-learned")).not.toHaveTextContent("0 (0/");
  });

  it("E8m2: a run body with no per-rule breakdown renders no table, never a fabricated one", async () => {
    const legacy = JSON.parse(JSON.stringify(MOCK_DONE_RUN));
    delete legacy.run.finding_level_recall.by_rule;
    delete legacy.run.finding_level_recall.by_rule_note;
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": legacy });
    renderApp(<App />, { route: "/reports" });

    await screen.findByTestId("efficacy-recall-denominators");
    expect(screen.queryByTestId("efficacy-finding-recall-by-rule")).not.toBeInTheDocument();
    // the aggregate it sits beside is untouched
    expect(screen.getByTestId("efficacy-finding-recall-learned")).toHaveTextContent("0.6667 (2/3)");
  });

  it("E8m2: the benchmark's frozen scenario set is shown beside what actually ran", async () => {
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": MOCK_DONE_RUN });
    renderApp(<App />, { route: "/reports" });

    const pin = await screen.findByTestId("efficacy-scenario-pin");
    expect(within(pin).getByTestId("efficacy-scenarios")).toHaveTextContent("brute_force");
    // this fixture deliberately did NOT run the frozen set, and says so
    expect(within(pin).getByTestId("efficacy-scenario-pin-off")).toHaveTextContent(
      "NOT the frozen set",
    );
    expect(pin).toHaveTextContent("INC-4a7f");
    expect(screen.queryByTestId("efficacy-scenario-pin-on")).not.toBeInTheDocument();
  });

  it("E8m2: a run of the frozen set says so, and a run body without the pin shows nothing", async () => {
    const pinned = JSON.parse(JSON.stringify(MOCK_DONE_RUN));
    pinned.run.benchmark.scenarioSetIsFrozen = true;
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": pinned });
    const { unmount } = renderApp(<App />, { route: "/reports" });
    expect(await screen.findByTestId("efficacy-scenario-pin-on")).toHaveTextContent(
      "the frozen benchmark set",
    );
    unmount();

    const legacy = JSON.parse(JSON.stringify(MOCK_DONE_RUN));
    delete legacy.run.benchmark.frozenScenarios;
    mockFetch({ "/api/reports": { reports: [] }, "/api/efficacy": legacy });
    renderApp(<App />, { route: "/reports" });
    await screen.findByTestId("efficacy-table");
    expect(screen.queryByTestId("efficacy-scenario-pin")).not.toBeInTheDocument();
  });

  it("E8m: the client still computes nothing — the amendment added no arithmetic", () => {
    const reportsPath = path.resolve(__dirname, "../pages/Reports.tsx");
    const reportsContent = fs.readFileSync(reportsPath, "utf-8");
    // no recall of any kind is derived here
    expect(reportsContent).not.toMatch(/true_findings_kept\s*\/\s*/);
    expect(reportsContent).not.toMatch(/criticality_rank\s*[=:]\s*\d/);
    // and no false-positive total is summed client-side
    expect(reportsContent).not.toMatch(/reduce\(\s*\(.*fals/i);
  });
});
