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
      </div>
      <div>
        Learned false positives:{" "}
        <span className="is-tnum" style={{ color: "var(--ink)", fontWeight: 500 }} data-testid="efficacy-learned-total-fps">
          {run.learned_total_false_positives ?? "n/a"}
        </span>
      </div>
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

          <div style={{ overflowX: "auto" }}>
            <table className="is-table" data-testid="efficacy-table">
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Format</th>
                  <th>Seed</th>
                  <th>Rule P</th>
                  <th>Rule R</th>
                  <th>Rule F1</th>
                  <th>Rule misses</th>
                  <th>Learned P</th>
                  <th>Learned R</th>
                  <th>Learned F1</th>
                  <th>Learned misses</th>
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
                      <td className="is-tnum">{ratio(ruleTotals, "f1")}</td>
                      <td className="is-tnum">{ruleTotals.missed_lines ?? ruleMisses.length}</td>
                      {learnedOff ? (
                        <td className="is-mut" colSpan={4} data-testid="efficacy-row-learned-unavailable" style={{ fontSize: 11.5 }}>
                          learned model unavailable — no score is shown
                        </td>
                      ) : (
                        <>
                          <td className="is-tnum">{ratio(learned.totals, "precision")}</td>
                          <td className="is-tnum">{ratio(learned.totals, "recall")}</td>
                          <td className="is-tnum">{ratio(learned.totals, "f1")}</td>
                          <td className="is-tnum">{learned.totals?.missed_lines ?? learned.misses?.length ?? 0}</td>
                        </>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="is-panel" style={{ background: "var(--bg-subtle, rgba(0, 0, 0, 0.02))", border: "1px solid var(--border)", padding: 12, borderRadius: 6 }} data-testid="efficacy-misses-section">
            <h4 style={{ margin: "0 0 8px", fontSize: 13, fontWeight: 600 }}>Missed Malicious Lines — both systems, verbatim</h4>
            {run.scenarios.some((s) => (s.rules?.misses ?? s.misses).length > 0 || (s.learned?.misses ?? []).length > 0) ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {run.scenarios.map((sc, scIdx) => {
                  const rules: EfficacySystem = sc.rules ?? {
                    system: "rules", available: true, reason: null, findings: null,
                    totals: sc.totals, per_rule: null, misses: sc.misses, false_positives: null,
                  };
                  const hasAny = (rules.misses ?? []).length > 0 || (sc.learned?.misses ?? []).length > 0;
                  if (!hasAny) return null;
                  return (
                    <div key={`${sc.scenario}-${sc.format}-${sc.seed ?? scIdx}`} data-testid={`scenario-misses-${sc.scenario}`}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: "var(--ink)", marginBottom: 4 }}>
                        [{sc.scenario} / {sc.format}{sc.seed != null ? ` / seed ${sc.seed}` : ""}]
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        <MissList label="Rules" system={rules} testid={`rule-misses-${sc.scenario}`} />
                        <MissList label="Learned" system={sc.learned} testid={`learned-misses-${sc.scenario}`} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="is-mut" style={{ margin: 0, fontSize: 12 }} data-testid="no-misses">
                no missed malicious lines
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
