import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, EXPORT_FORMATS } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { Download, FileText } from "lucide-react";

const th = "border-b border-border px-3 py-2.5 text-left text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground";
const td = "border-b border-border px-3 py-2.5 align-middle text-[12.5px]";

function kb(bytes: number) {
  return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
}

/** One control per export format. When a run is loaded each is a real
 *  <a href download> that hits GET /api/export?format=X — the backend answers
 *  with Content-Disposition: attachment, so the browser saves <runId>.<ext>.
 *  With no run loaded the controls are honestly disabled (the endpoint would
 *  409); we never offer a download that would produce an empty file. */
function DownloadPanel({ hasRun }: { hasRun: boolean }) {
  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="text-[14px] font-semibold">Download the current run</CardTitle>
        <p className="text-[11.5px] text-muted-foreground">
          The real findings, severities and MITRE tags this run produced — no fabricated rows.
        </p>
      </CardHeader>
      <CardContent className="p-4 pt-3">
        <div className="flex flex-wrap items-center gap-2" data-testid="download-panel">
          {EXPORT_FORMATS.map(({ format, label }) =>
            hasRun ? (
              <a
                key={format}
                href={api.exportUrl(format)}
                download
                data-testid={`download-${format}`}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2",
                  "text-[12px] font-medium text-foreground hover:bg-muted transition-colors shadow-xs",
                )}
                title={`Download this run as ${label} (${format})`}
              >
                <Download className="h-3.5 w-3.5 text-muted-foreground" strokeWidth={1.8} aria-hidden />
                {label}
              </a>
            ) : (
              <span
                key={format}
                data-testid={`download-${format}`}
                aria-disabled="true"
                className={cn(
                  "inline-flex cursor-not-allowed items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2",
                  "text-[12px] font-medium text-muted-foreground opacity-50",
                )}
                title="No run loaded — analyze a log first, then export"
              >
                <Download className="h-3.5 w-3.5" strokeWidth={1.8} aria-hidden />
                {label}
              </span>
            ),
          )}
        </div>
        {!hasRun && (
          <p className="mt-2.5 text-[11.5px] text-muted-foreground">
            No run loaded — analyze a log from the Overview, then download it here.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export function Reports() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["reports"],
    queryFn: api.reports,
  });
  const { data: state } = useQuery({ queryKey: ["console-state"], queryFn: api.consoleState });
  const hasRun = !!state && !state.idle;

  const generate = useMutation({
    mutationFn: api.generateReport,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });

  const reports = data?.reports ?? [];

  return (
    <div className="space-y-4">
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="flex flex-wrap items-center gap-3 p-4 text-[12.5px] text-muted-foreground">
          <span className="max-w-2xl leading-relaxed">
            <b className="text-foreground">Real files only.</b>{" "}
            Every row is a report that exists on disk in <code className="font-mono text-primary text-[11.5px]">console/.soc/reports/</code>.
            Generating renders the <b>current run</b> through the standalone exporter — nothing is listed that wasn't produced.
          </span>
          <div className="ml-auto flex flex-col items-end gap-1">
            <Button
              onClick={() => generate.mutate()}
              disabled={generate.isPending}
              title="Render the currently loaded run into a saved HTML report"
              className="text-xs h-8.5 rounded-lg"
            >
              <FileText className="h-3.5 w-3.5" strokeWidth={1.8} aria-hidden />
              {generate.isPending ? "Generating…" : "Generate report"}
            </Button>
            {generate.isError && (
              <span className="text-[11.5px]" style={{ color: "var(--sev-critical)" }}>
                {(generate.error as Error).message === "no run to report on yet"
                  ? "No run loaded — analyze a log first, then generate."
                  : (generate.error as Error).message}
              </span>
            )}
            {generate.isSuccess && (
              <span className="text-[11.5px]" style={{ color: "var(--sev-low)" }}>
                Saved {generate.data.name}
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      <DownloadPanel hasRun={hasRun} />

      <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        <CardHeader className="p-4 pb-3 border-b border-border">
          <CardTitle className="text-[14px] font-semibold">Saved reports ({reports.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-3">
          {isLoading ? (
            <p className="text-[12.5px] text-muted-foreground">Loading reports…</p>
          ) : isError ? (
            <p className="text-[12.5px] text-muted-foreground">
              Couldn't load reports — {(error as Error).message}
            </p>
          ) : reports.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              No reports generated yet — use “Generate report” above to render the current run.
            </p>
          ) : (
            <div className="overflow-auto rounded-lg border border-border">
              <table className="w-full border-collapse text-[12.5px]">
                <thead className="sticky top-0 z-10 bg-card border-b border-border">
                  <tr>
                    <th className={th}>Report</th>
                    <th className={th}>Size</th>
                    <th className={th}>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.name} data-testid="report-row" className="hover:bg-muted/40 transition-colors">
                      <td className={`${td} font-mono text-[11.5px] break-all font-medium text-foreground`}>{r.name}</td>
                      <td className={`${td} tabular-nums`}>{kb(r.bytes)}</td>
                      <td className={`${td} font-mono text-[11px] tabular-nums text-muted-foreground`}>{r.createdAt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
