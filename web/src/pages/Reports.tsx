import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, EXPORT_FORMATS } from "@/lib/api";

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
      {!hasRun && (
        <p className="is-mut" style={{ marginTop: 10, fontSize: 11.5 }}>
          No run loaded — analyze a log from the Overview, then download it here.
        </p>
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
    </>
  );
}
