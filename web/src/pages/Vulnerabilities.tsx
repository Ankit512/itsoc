import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { api, type StoreVuln } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { sevVar } from "@/lib/severity";

/** Vulnerabilities — every finding nmap's NSE vuln scripts recorded in the
 *  persistent store, newest first. Severity is derived from the CVSS score NSE
 *  reported (standard band); when NSE gives no score the severity is shown as
 *  "unknown" rather than guessed. An empty store is an honest empty state — we
 *  never seed a sample vulnerability. */

function SevBadge({ sev }: { sev: string }) {
  const label = sev ? sev.toUpperCase() : "UNKNOWN";
  return (
    <span className="inline-flex items-center gap-1.5 text-[11.5px] font-semibold">
      <span className="inline-block h-2 w-2 rounded-full"
            style={{ backgroundColor: sev ? sevVar(sev) : "hsl(var(--muted-foreground))" }} aria-hidden />
      {sev ? label : <span className="font-normal text-muted-foreground">unknown</span>}
    </span>
  );
}

export function Vulnerabilities() {
  const { data, error } = useQuery({
    queryKey: ["vulns"], queryFn: () => api.vulns(200),
    refetchInterval: 5000,
  });
  const items: StoreVuln[] = data?.items ?? [];

  return (
    <div className="flex flex-col gap-4">
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground leading-relaxed">
          <b className="text-foreground">Discovered vulnerabilities.</b> Vulnerabilities discovered by nmap NSE <span className="font-mono text-primary text-[11.5px]">vuln</span> scripts
          during a scan. Severity is the CVSS band NSE reported — an empty severity means NSE gave
          no score, shown honestly as “unknown” rather than guessed.
        </CardContent>
      </Card>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to view stored vulnerabilities.
        </p>
      )}
      <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        <CardHeader className="p-4 pb-3 border-b border-border">
          <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
            <ShieldAlert className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
            Vulnerabilities
            {items.length > 0 && (
              <span className="text-[12px] font-normal text-muted-foreground">
                · {data?.total ?? items.length} total
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-3">
          {items.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              No vulnerabilities recorded yet. Run a “Service + vulnerability scan”
              from the Discovery page against a private target — real NSE findings
              appear here.
            </p>
          ) : (
            <div className="overflow-auto rounded-lg border border-border">
              <table className="w-full border-collapse text-left text-[12.5px]">
                <thead className="sticky top-0 z-10 bg-card border-b border-border text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="border-b border-border px-3 py-2.5">Found</th>
                    <th className="border-b border-border px-3 py-2.5">Asset</th>
                    <th className="border-b border-border px-3 py-2.5">Severity</th>
                    <th className="border-b border-border px-3 py-2.5">CVSS</th>
                    <th className="border-b border-border px-3 py-2.5">CVE</th>
                    <th className="border-b border-border px-3 py-2.5">Script</th>
                    <th className="border-b border-border px-3 py-2.5">Status</th>
                    <th className="border-b border-border px-3 py-2.5">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((v) => (
                    <tr key={v.id} className="hover:bg-muted/40 transition-colors">
                      <td className="border-b border-border px-3 py-2 tabular-nums text-muted-foreground whitespace-nowrap text-[11px]">
                        {new Date(v.ts).toLocaleString()}
                      </td>
                      <td className="border-b border-border px-3 py-2 font-mono text-xs font-medium text-foreground">{v.asset_ip || "—"}</td>
                      <td className="border-b border-border px-3 py-2"><SevBadge sev={v.severity} /></td>
                      <td className="border-b border-border px-3 py-2 tabular-nums font-semibold">
                        {v.cvss > 0 ? v.cvss.toFixed(1) : <span className="text-muted-foreground font-normal">—</span>}
                      </td>
                      <td className="border-b border-border px-3 py-2 font-mono text-xs text-primary">{v.cve || <span className="text-muted-foreground">—</span>}</td>
                      <td className="border-b border-border px-3 py-2 font-mono text-xs">{v.name || "—"}</td>
                      <td className="border-b border-border px-3 py-2 text-xs font-medium">{v.status || "OPEN"}</td>
                      <td className="border-b border-border px-3 py-2 font-mono break-all text-[11px] text-muted-foreground leading-relaxed">
                        {v.details ? (v.details.length > 240 ? v.details.slice(0, 240) + "…" : v.details) : "—"}
                      </td>
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
