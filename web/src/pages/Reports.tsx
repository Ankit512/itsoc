import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, EXPORT_FORMATS } from "@/lib/api";
import type { EfficacyRun, EfficacySystem, EfficacyTotals } from "@/lib/api";

/** Reports — real files only, in the itsoc. design system (mirrors prototype
 *  #p-reports / handoff §3). Downloads are real <a href download> to
 *  GET /api/export?format=X (HTML + JSON primary; CSV/XML/MD secondary) — with
 *  no run loaded the controls are honestly disabled, never offering an empty
 *  file. The saved-reports table lists only files that exist on disk. */
function kb(bytes: number) {
  return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
}

/** HTML + JSON are the primary export formats per the handoff; the rest are
 *  secondary. Purely a visual weighting — every format is a real export. */
const PRIMARY = new Set(["html", "json"]);

function DownloadPanel({ hasRun }: { hasRun: boolean }) {
  return (
    <div className="is-panel">
      <div className="is-panel__h">
        <h3>Download the current run</h3>
        <span className="is-panel__sub">real findings, severities &amp; MITRE tags — no fabricated rows</span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }} data-testid="download-panel">
        {EXPORT_FORMATS.map(({ format, label }) => {
          const cls = "is-btn" + (PRIMARY.has(format) ? " is-btn--primary" : "");
          return hasRun ? (
            <a key={format} href={api.exportUrl(format)} download data-testid={`download-${format}`}
               className={cls} title={`Download this run as ${label} (${format})`}>{label}</a>
          ) : (
            <span key={format} data-testid={`download-${format}`} aria-disabled="true"
                  className={cls} style={{ opacity: 0.5, cursor: "not-allowed" }}
                  title="No run loaded — analyze a log first, then export">{label}</span>
          );
        })}
      </div>
      <p className="is-mut" style={{ marginTop: 10, fontSize: 11.5, lineHeight: 1.5 }}>
        DORA-ready action trail — every action carries approver, rule eligibility, evidence, and connector response.
      </p>
      {!hasRun && (
        <p className="is-mut" style={{ marginTop: 6, fontSize: 11.5 }}>
          No run loaded — analyze a log from the Overview, then download it here.
        </p>
      )}
    </div>
  );
}

const EFFICACY_SCOPE = "measured against synthetic ground-truth scenarios; not a claim about production traffic.";
const EFFICACY_CEILING = "These scenarios are drawn from the same attack classes the rules were written for — the expected result is perfection, and its value is regression proof (any future score below 1.0 is a detected regression), not a general-efficacy claim.";
/** E8. Travels with the paired numbers, beside the scope sentence — it does not replace it. */
const EFFICACY_ADVISORY = "the learned model is advisory; these numbers are why.";

/** A ratio with no denominator is undefined, not a measured zero. The backend
 *  says which is which; this only renders what it was told. */
function ratio(totals: EfficacyTotals | null | undefined, key: "precision" | "recall" | "f1") {
  if (!totals) return "n/a";
  const precisionOk = totals.precision_defined !== false;
  const recallOk = totals.recall_defined !== false;
  const defined = key === "precision" ? precisionOk : key === "recall" ? recallOk : precisionOk && recallOk;
  return defined ? String(totals[key]) : "n/a";
}

/** E8m. Finding-level recall, rendered from what the backend measured — never
 *  recomputed here. An undefined ratio (no findings cited a malicious line at
 *  all) renders n/a, the same rule line-level recall already follows. */
function findingRatio(system: EfficacySystem | null | undefined) {
  const fr = system?.finding_recall;
  if (!fr) return "n/a";
  return fr.recall_defined ? String(fr.recall) : "n/a";
}

/** E8m. Findings a system dropped WHILE they cited malicious lines — the loss
 *  line-level recall absorbs. Listed verbatim, with the same weight as a miss. */
function DroppedFindingList({ label, system, testid }: { label: string; system?: EfficacySystem; testid: string }) {
  if (!system || !system.available) return null;
  const dropped = system.dropped_true_findings ?? [];
  if (!dropped.length) {
    return (
      <div data-testid={`${testid}-none`} className="is-mut" style={{ fontSize: 11.5 }}>
        {label}: no findings dropped while citing a malicious line
      </div>
    );
  }
  return (
    <div data-testid={testid}>
      <div style={{ fontSize: 11.5, fontWeight: 600, color: "var(--ink)", marginBottom: 4 }}>
        {label}: {dropped.length} finding(s) dropped while citing a malicious line
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {dropped.map((d, dIdx) => (
          <div
            key={dIdx}
            data-testid="efficacy-dropped-item"
            style={{
              padding: "6px 10px",
              background: "var(--bg, #fff)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              fontSize: 11.5,
              lineHeight: 1.4,
            }}
          >
            <div>
              <span style={{ fontWeight: 600, color: "var(--high)", marginRight: 6 }}>{d.rule_id}</span>
              <span className="is-mut">
                severity {d.severity ?? "n/a"} · advisory label {d.label ?? "n/a"}
                {d.confidence != null ? ` · confidence ${d.confidence}` : ""}
              </span>
            </div>
            {d.summary && <div style={{ marginTop: 2 }}>{d.summary}</div>}
            {d.cited_malicious_lines.map((c, cIdx) => (
              <div key={cIdx} style={{ marginTop: 2 }}>
                <span style={{ fontWeight: 600, color: "var(--crit)", marginRight: 6 }}>Cited line {c.line}:</span>
                <code className="is-mono" style={{ wordBreak: "break-all" }}>{c.raw}</code>
                <div style={{ color: "var(--mut)", fontSize: 11 }}>Why: {c.why}</div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

/** The misses one system reported, verbatim, or the honest reason there are none to show. */
function MissList({ label, system, testid }: { label: string; system?: EfficacySystem; testid: string }) {
  if (!system) return null;
  if (!system.available) {
    return (
      <div data-testid={`${testid}-unavailable`} className="is-mut" style={{ fontSize: 11.5 }}>
        {label}: unavailable — {system.reason}
      </div>
    );
  }
  const misses = system.misses ?? [];
  if (!misses.length) {
    return (
      <div data-testid={`${testid}-none`} className="is-mut" style={{ fontSize: 11.5 }}>
        {label}: no missed malicious lines
      </div>
    );
  }
  return (
    <div data-testid={testid}>
      <div style={{ fontSize: 11.5, fontWeight: 600, color: "var(--ink)", marginBottom: 4 }}>
        {label}: {misses.length} missed
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {misses.map((m, mIdx) => (
          <div
            key={mIdx}
            data-testid="efficacy-miss-item"
            style={{
              padding: "6px 10px",
              background: "var(--bg, #fff)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              fontSize: 11.5,
              lineHeight: 1.4,
            }}
          >
            <div>
              <span style={{ fontWeight: 600, color: "var(--crit)", marginRight: 6 }}>Line {m.line}:</span>
              <code className="is-mono" style={{ wordBreak: "break-all" }}>{m.raw}</code>
            </div>
            <div style={{ color: "var(--mut)", marginTop: 2, fontSize: 11 }}>
              Why: {m.why}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Run id, commit, benchmark seeds and the model's own provenance. Every
 *  published number carries these; an unavailable model says so and shows no
 *  score at all. */
function EfficacyProvenanceBlock({ run }: { run: EfficacyRun }) {
  const model = run.model;
  const seeds = run.benchmark?.seeds ?? [];
  // E8m: a false-positive count is never rendered without its format scope.
  const formatScope = run.false_positive_totals?.scope ?? null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 16, fontSize: 12, color: "var(--mut)" }}>
      {run.run_id && (
        <div>
          Run ID: <span className="is-mono" style={{ color: "var(--ink)" }} data-testid="efficacy-run-id">{run.run_id}</span>
        </div>
      )}
      {run.run_date && (
        <div>
          Run Date: <span className="col-mono" style={{ color: "var(--ink)" }}>{run.run_date}</span>
        </div>
      )}
      {run.provenance?.commit && (
        <div>
          Commit: <span className="is-mono" style={{ color: "var(--ink)" }} data-testid="efficacy-commit">{run.provenance.commit}</span>
        </div>
      )}
      {seeds.length > 0 && (
        <div>
          Benchmark seeds: <span className="is-mono" style={{ color: "var(--ink)" }} data-testid="efficacy-seeds">{seeds.join(", ")}</span>
        </div>
      )}
      {run.pipeline && (
        <div>
          Pipeline: <span className="is-mono" style={{ color: "var(--ink)" }}>{run.pipeline}</span>
        </div>
      )}
      {model && (
        model.available ? (
          <div data-testid="efficacy-model-provenance">
            Model: <span className="is-mono" style={{ color: "var(--ink)" }}>{model.name}</span>
            {" · "}sha256 <span className="is-mono" style={{ color: "var(--ink)" }}>{model.sha256}</span>
            {" · "}trained <span className="is-mono" style={{ color: "var(--ink)" }}>{model.trainedAt}</span>
            {model.trainingSeeds?.length ? (
              <> · training seeds <span className="is-mono" style={{ color: "var(--ink)" }}>{model.trainingSeeds.join(", ")}</span></>
            ) : null}
          </div>
        ) : (
          <div data-testid="efficacy-model-unavailable" style={{ color: "var(--high)" }}>
            Learned model unavailable — {model.reason}
          </div>
        )
      )}
      <div>
        Rule misses: <span className="is-tnum" style={{ color: run.total_misses > 0 ? "var(--high)" : "var(--ink)", fontWeight: 500 }}>{run.total_misses}</span>
      </div>
      <div>
        Learned misses:{" "}
        <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }} data-testid="efficacy-learned-total-misses">
          {run.learned_total_misses ?? "n/a"}
        </span>
      </div>
      <div>
        Rule false positives: <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }}>{run.total_false_positives}</span>
        {formatScope && <span className="is-mut" data-testid="efficacy-fp-scope"> ({formatScope})</span>}
      </div>
      <div>
        Learned false positives:{" "}
        <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }} data-testid="efficacy-learned-total-fps">
          {run.learned_total_false_positives ?? "n/a"}
        </span>
        {formatScope && <span className="is-mut"> ({formatScope})</span>}
      </div>
      <div>
        Learned findings dropped while citing a malicious line:{" "}
        <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }} data-testid="efficacy-learned-dropped-total">
          {run.learned_total_dropped_true_findings ?? "n/a"}
        </span>
      </div>
    </div>
  );
}

/** E8m (b). A false-positive count is never published bare: the headline is
 *  every format the run measured, and each single format is an explicitly
 *  labelled subset beneath it. */
function FalsePositiveScopeBlock({ run }: { run: EfficacyRun }) {
  const totals = run.false_positive_totals;
  if (!totals) return null;
  const subsets = Object.entries(totals.by_format);
  return (
    <div className="is-note" style={{ margin: 0 }} data-testid="efficacy-fp-totals">
      <div style={{ fontWeight: 600 }}>
        False positives — {totals.scope}:{" "}
        <span className="is-tnum" data-testid="efficacy-fp-headline">rules {totals.rules}</span>
        {", "}
        <span className="is-tnum">learned {totals.learned ?? "n/a"}</span>
      </div>
      <div className="is-mut" style={{ fontSize: 11.5, marginTop: 4 }}>
        {subsets.map(([format, bucket]) => (
          <div key={format} data-testid={`efficacy-fp-subset-${format}`}>
            subset — <span className="is-mono">{format}</span> only: rules{" "}
            <span className="is-tnum">{bucket.rules}</span>, learned{" "}
            <span className="is-tnum">{bucket.learned ?? "n/a"}</span>
          </div>
        ))}
      </div>
      {run.format_scope_note && (
        <p className="is-mut" style={{ fontSize: 11.5, margin: "6px 0 0", lineHeight: 1.5 }} data-testid="efficacy-format-scope-note">
          {run.format_scope_note}
        </p>
      )}
    </div>
  );
}

/** E8m (a). Both recalls, side by side, each labelled with its denominator. */
function RecallDenominatorBlock({ run }: { run: EfficacyRun }) {
  const flr = run.finding_level_recall;
  if (!flr) return null;
  const learned = flr.learned;
  return (
    <div className="is-note" style={{ margin: 0 }} data-testid="efficacy-recall-denominators">
      <div style={{ fontWeight: 600 }}>Recall, with its denominator — both are published</div>
      <div className="is-mut" style={{ fontSize: 11.5, marginTop: 4, lineHeight: 1.6 }}>
        <div data-testid="efficacy-line-recall-denominator">
          Line-level recall is over <b>{run.line_level_recall_denominator ?? "manifest malicious lines"}</b>.
        </div>
        <div data-testid="efficacy-finding-recall-denominator">
          Finding-level recall is over <b>{flr.denominator}</b> —{" "}
          <span className="is-tnum">{flr.true_findings_total}</span> of them in this run.
        </div>
        <div style={{ marginTop: 4 }} data-testid="efficacy-finding-recall-rules">
          RULES finding-level recall:{" "}
          <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }}>
            {flr.rules.recall_defined ? flr.rules.recall : "n/a"}
          </span>{" "}
          ({flr.rules.true_findings_kept}/{flr.rules.true_findings_total})
        </div>
        <div data-testid="efficacy-finding-recall-learned">
          LEARNED finding-level recall:{" "}
          {learned ? (
            <>
              <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }}>
                {learned.recall_defined ? learned.recall : "n/a"}
              </span>{" "}
              ({learned.true_findings_kept}/{learned.true_findings_total})
            </>
          ) : (
            <span>unavailable — no number is invented</span>
          )}
        </div>
      </div>
      {run.recall_note && (
        <p className="is-mut" style={{ fontSize: 11.5, margin: "6px 0 0", lineHeight: 1.5 }} data-testid="efficacy-recall-note">
          {run.recall_note}
        </p>
      )}
    </div>
  );
}

/** E8m (c). The criticality counterfactual, as a named first-class finding —
 *  not a footnote. `kept_at` is the direction, read straight off the bands. */
function CriticalitySensitivityBlock({ run }: { run: EfficacyRun }) {
  const sens = run.criticality_sensitivity;
  if (!sens) return null;
  if (!sens.available) {
    return (
      <div className="is-note" style={{ margin: 0 }} data-testid="efficacy-criticality-unavailable">
        <b>Criticality sensitivity</b> — unavailable: {sens.reason}
      </div>
    );
  }
  const importance = sens.feature_importance?.criticality_rank ?? null;
  const populations = sens.populations ?? null;
  return (
    <div className="is-note" style={{ margin: 0, borderColor: "var(--high)" }} data-testid="efficacy-criticality-sensitivity">
      <div style={{ fontWeight: 600 }}>
        Criticality sensitivity — a <span data-testid="efficacy-criticality-kind">counterfactual</span>, not a measurement
      </div>
      <div className="is-mut" style={{ fontSize: 11.5, marginTop: 4, lineHeight: 1.6 }}>
        <div data-testid="efficacy-criticality-importance">
          <span className="is-mono">{sens.feature}</span> feature importance:{" "}
          <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }}>{importance ?? "n/a"}</span>
          {" · "}forced across <span className="is-mono">{sens.domain.join(", ")}</span>
        </div>
        {populations &&
          (Object.keys(populations) as Array<keyof typeof populations>).map((name) => {
            const bucket = populations[name];
            return (
              <div key={String(name)} data-testid={`efficacy-criticality-${String(name)}`} style={{ marginTop: 4 }}>
                <b>{String(name).replace("_", " ")}</b>: <span className="is-tnum">{bucket.total}</span> total —{" "}
                <span className="is-tnum">{bucket.robust}</span> robust,{" "}
                <span className="is-tnum">{bucket.flipping}</span> flip in at least one band. Kept at{" "}
                {Object.entries(bucket.kept_at)
                  .map(([band, kept]) => `${band} ${kept}`)
                  .join(" · ")}
              </div>
            );
          })}
      </div>
      <p className="is-mut" style={{ fontSize: 11.5, margin: "6px 0 0", lineHeight: 1.5 }} data-testid="efficacy-criticality-note">
        {sens.note}
      </p>
    </div>
  );
}

function EfficacyPanel() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["efficacy"],
    queryFn: api.efficacy,
    refetchInterval: (query) => (query.state.data?.status === "running" ? 1000 : false),
  });

  const runMutation = useMutation({
    mutationFn: api.runEfficacy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["efficacy"] }),
  });

  const status = data?.status ?? (isLoading ? "running" : isError ? "error" : "idle");
  const run = data?.run ?? null;
  const backendError = data?.error ?? (isError ? (error as Error).message : null);
  const isRunning = status === "running" || runMutation.isPending;

  return (
    <div className="is-panel" data-testid="efficacy-panel">
      <div className="is-panel__h" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
        <div>
          <h3>Detection Efficacy</h3>
          <span className="is-panel__sub">synthetic scenario evaluation · log_analyzer rules-only</span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
          <button
            className="is-btn is-btn--primary"
            onClick={() => runMutation.mutate()}
            disabled={isRunning}
            data-testid="run-harness-btn"
            title="Execute the efficacy harness against synthetic ground-truth scenarios"
          >
            {isRunning ? "Running harness…" : "Run harness"}
          </button>
          {runMutation.isError && (
            <span style={{ color: "var(--crit)", fontSize: 11.5 }} data-testid="efficacy-mutation-error">
              {(runMutation.error as Error).message}
            </span>
          )}
        </div>
      </div>

      <p className="is-mut" style={{ marginTop: 6, marginBottom: 6, fontSize: 11.5, lineHeight: 1.5 }} data-testid="efficacy-scope">
        {EFFICACY_SCOPE}
      </p>
      <p className="is-mut" style={{ marginTop: 0, marginBottom: 6, fontSize: 11.5, lineHeight: 1.5 }} data-testid="efficacy-ceiling">
        {EFFICACY_CEILING}
      </p>
      <p className="is-mut" style={{ marginTop: 0, marginBottom: 12, fontSize: 11.5, lineHeight: 1.5 }} data-testid="efficacy-advisory">
        {EFFICACY_ADVISORY}
      </p>

      {status === "error" || (isError && !run) ? (
        <div className="is-note" style={{ borderColor: "var(--crit)", color: "var(--crit)", margin: 0 }} data-testid="efficacy-error">
          <b>Efficacy harness error:</b> {backendError || "Failed to load efficacy data"}
        </div>
      ) : isRunning && !run ? (
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }} data-testid="efficacy-running">
          Running efficacy harness…
        </p>
      ) : !run || status === "idle" ? (
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }} data-testid="efficacy-idle">
          No efficacy harness run yet — run one to measure synthetic scenarios
        </p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }} data-testid="efficacy-results">
          <EfficacyProvenanceBlock run={run} />
          <RecallDenominatorBlock run={run} />
          <FalsePositiveScopeBlock run={run} />
          <CriticalitySensitivityBlock run={run} />

          <div style={{ overflowX: "auto" }}>
            <table className="is-table" data-testid="efficacy-table">
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Format</th>
                  <th>Seed</th>
                  <th>Rule P</th>
                  <th title="over manifest malicious lines">Rule R (lines)</th>
                  <th title="over findings that cite at least one malicious line">Rule R (findings)</th>
                  <th>Rule F1</th>
                  <th>Rule misses</th>
                  <th>Learned P</th>
                  <th title="over manifest malicious lines">Learned R (lines)</th>
                  <th title="over findings that cite at least one malicious line">Learned R (findings)</th>
                  <th>Learned F1</th>
                  <th>Learned misses</th>
                  <th title="dropped by the system while citing a malicious line">Learned dropped</th>
                </tr>
              </thead>
              <tbody>
                {run.scenarios.map((sc, idx) => {
                  const rules = sc.rules;
                  const learned = sc.learned;
                  const ruleTotals = rules?.totals ?? sc.totals;
                  const ruleMisses = rules?.misses ?? sc.misses;
                  const learnedOff = !learned || !learned.available;
                  return (
                    <tr key={`${sc.scenario}-${sc.format}-${sc.seed ?? idx}`} data-testid="efficacy-row" style={{ cursor: "default" }}>
                      <td className="is-mono" style={{ fontSize: 11.5, color: "var(--ink)", fontWeight: 500 }}>
                        {sc.scenario}
                      </td>
                      <td className="is-mono" style={{ fontSize: 11.5 }}>
                        {sc.format}
                      </td>
                      <td className="is-tnum" data-testid="efficacy-row-seed">{sc.seed ?? "n/a"}</td>
                      <td className="is-tnum">{ratio(ruleTotals, "precision")}</td>
                      <td className="is-tnum">{ratio(ruleTotals, "recall")}</td>
                      <td className="is-tnum" data-testid="efficacy-row-rule-finding-recall">{findingRatio(rules)}</td>
                      <td className="is-tnum">{ratio(ruleTotals, "f1")}</td>
                      <td className="is-tnum">{ruleTotals.missed_lines ?? ruleMisses.length}</td>
                      {learnedOff ? (
                        <td className="is-mut" colSpan={6} data-testid="efficacy-row-learned-unavailable" style={{ fontSize: 11.5 }}>
                          learned model unavailable — no score is shown
                        </td>
                      ) : (
                        <>
                          <td className="is-tnum">{ratio(learned.totals, "precision")}</td>
                          <td className="is-tnum">{ratio(learned.totals, "recall")}</td>
                          <td className="is-tnum" data-testid="efficacy-row-learned-finding-recall">{findingRatio(learned)}</td>
                          <td className="is-tnum">{ratio(learned.totals, "f1")}</td>
                          <td className="is-tnum">{learned.totals?.missed_lines ?? learned.misses?.length ?? 0}</td>
                          <td className="is-tnum" data-testid="efficacy-row-learned-dropped">{learned.dropped_true_findings?.length ?? 0}</td>
                        </>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="is-panel" style={{ background: "var(--bg-subtle, rgba(0, 0, 0, 0.02))", border: "1px solid var(--border)", padding: 12, borderRadius: 6 }} data-testid="efficacy-misses-section">
            <h4 style={{ margin: "0 0 8px", fontSize: 13, fontWeight: 600 }}>
              Missed Malicious Lines, and Findings Dropped While Citing One — both systems, verbatim
            </h4>
            {run.scenarios.some(
              (s) =>
                (s.rules?.misses ?? s.misses).length > 0 ||
                (s.learned?.misses ?? []).length > 0 ||
                (s.learned?.dropped_true_findings ?? []).length > 0,
            ) ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {run.scenarios.map((sc, scIdx) => {
                  const rules: EfficacySystem = sc.rules ?? {
                    system: "rules", available: true, reason: null, findings: null,
                    totals: sc.totals, per_rule: null, misses: sc.misses, false_positives: null,
                  };
                  const hasAny =
                    (rules.misses ?? []).length > 0 ||
                    (sc.learned?.misses ?? []).length > 0 ||
                    (sc.learned?.dropped_true_findings ?? []).length > 0;
                  if (!hasAny) return null;
                  return (
                    <div key={`${sc.scenario}-${sc.format}-${sc.seed ?? scIdx}`} data-testid={`scenario-misses-${sc.scenario}`}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: "var(--ink)", marginBottom: 4 }}>
                        [{sc.scenario} / {sc.format}{sc.seed != null ? ` / seed ${sc.seed}` : ""}]
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        <MissList label="Rules" system={rules} testid={`rule-misses-${sc.scenario}`} />
                        <MissList label="Learned" system={sc.learned} testid={`learned-misses-${sc.scenario}`} />
                        <DroppedFindingList label="Learned" system={sc.learned} testid={`learned-dropped-${sc.scenario}`} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="is-mut" style={{ margin: 0, fontSize: 12 }} data-testid="no-misses">
                no missed malicious lines, and no findings dropped while citing one
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function Reports() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({ queryKey: ["reports"], queryFn: api.reports });
  const { data: state } = useQuery({ queryKey: ["console-state"], queryFn: api.consoleState });
  const hasRun = !!state && !state.idle;

  const generate = useMutation({
    mutationFn: api.generateReport,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });

  const reports = data?.reports ?? [];

  return (
    <>
      <div className="is-note" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12 }}>
        <span style={{ maxWidth: 640, lineHeight: 1.5 }}>
          <b>Real files only — a report exists when it is on disk.</b> Every row lives in{" "}
          <span className="is-mono" style={{ color: "var(--acc)" }}>console/.soc/reports/</span>. Generating renders
          the <b>current run</b> through the standalone exporter — nothing is listed that wasn't produced.
        </span>
        <span style={{ marginLeft: "auto", display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
          <button className="is-btn is-btn--primary" onClick={() => generate.mutate()} disabled={generate.isPending}
                  title="Render the currently loaded run into a saved HTML report">
            {generate.isPending ? "Generating…" : "Generate report"}
          </button>
          {generate.isError && (
            <span style={{ color: "var(--crit)", fontSize: 11.5 }}>
              {(generate.error as Error).message === "no run to report on yet"
                ? "No run loaded — analyze a log first, then generate."
                : (generate.error as Error).message}
            </span>
          )}
          {generate.isSuccess && <span style={{ color: "var(--low)", fontSize: 11.5 }}>Saved {generate.data.name}</span>}
        </span>
      </div>

      <DownloadPanel hasRun={hasRun} />

      <div className="is-panel">
        <div className="is-panel__h"><h3>Saved reports ({reports.length})</h3></div>
        {isLoading ? (
          <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>Loading reports…</p>
        ) : isError ? (
          <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>Couldn't load reports — {(error as Error).message}</p>
        ) : reports.length === 0 ? (
          <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
            No saved reports — generate one to see it here.
          </p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="is-table">
              <thead><tr><th>Report</th><th>Size</th><th>Created</th></tr></thead>
              <tbody>
                {reports.map((r) => (
                  <tr key={r.name} data-testid="report-row" style={{ cursor: "default" }}>
                    <td className="is-mono" style={{ fontSize: 11.5, color: "var(--ink)", fontWeight: 500, wordBreak: "break-all" }}>{r.name}</td>
                    <td className="is-tnum">{kb(r.bytes)}</td>
                    <td className="col-mono">{r.createdAt}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <EfficacyPanel />
    </>
  );
}
