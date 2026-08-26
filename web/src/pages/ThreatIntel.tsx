import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const th = "border-b border-border px-3 py-2.5 text-left text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground";
const td = "border-b border-border px-3 py-2.5 align-middle text-[12.5px]";

export function ThreatIntel() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["threat-intel"],
    queryFn: api.threatIntel,
  });

  if (isLoading) return <p className="text-muted-foreground">Loading threat intel…</p>;

  if (isError || !data) {
    return (
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          Couldn't load threat intel — {(error as Error)?.message ?? "no data"}
        </CardContent>
      </Card>
    );
  }

  const ruleEntries = Object.entries(data.ruleTechniques);

  return (
    <div className="space-y-4">
      {/* Honest provenance line: this page surfaces what threat_intel/ already
          holds and what the rules statically map — no new intel is created. */}
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground">
          <b className="text-foreground">Surfaced, not generated.</b>{" "}
          Indicators come from an offline STIX bundle; the technique rollups are the
          static MITRE mapping each rule carries. These are <b>derived tags — not verdicts</b>,
          and nothing here changes a finding's severity.
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
          <CardHeader className="p-4 pb-3 border-b border-border">
            <CardTitle className="text-[14px] font-semibold">Indicators of Compromise</CardTitle>
            <p className="text-[11.5px] text-muted-foreground">
              {data.indicatorSource}
            </p>
          </CardHeader>
          <CardContent className="p-4 pt-3">
            {data.indicators.length === 0 ? (
              <p className="text-[12.5px] text-muted-foreground">
                The bundle holds no indicators.
              </p>
            ) : (
              <div className="overflow-auto rounded-lg border border-border">
                <table className="w-full border-collapse text-[12.5px]">
                  <thead className="sticky top-0 z-10 bg-card border-b border-border">
                    <tr>
                      <th className={th}>Name</th>
                      <th className={th}>Pattern</th>
                      <th className={th}>Types</th>
                      <th className={th}>Valid from</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.indicators.map((ind) => (
                      <tr key={ind.id} data-testid="ioc-row" className="hover:bg-muted/40 transition-colors">
                        <td className={`${td} font-medium`}>{ind.name}</td>
                        <td className={`${td} font-mono text-[11px] text-primary break-all`}>
                          {ind.pattern}
                        </td>
                        <td className={`${td} text-[11px] text-muted-foreground`}>
                          {ind.types.join(", ") || "—"}
                        </td>
                        <td className={`${td} font-mono text-[11px] tabular-nums text-muted-foreground`}>
                          {ind.validFrom || "n/a"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
          <CardHeader className="p-4 pb-3 border-b border-border">
            <CardTitle className="text-[14px] font-semibold">Rule → MITRE technique map</CardTitle>
            <p className="text-[11.5px] text-muted-foreground">
              static mapping each detector rule carries — derived, not verdicts
            </p>
          </CardHeader>
          <CardContent className="p-4 pt-3 space-y-2.5">
            {ruleEntries.length === 0 ? (
              <p className="text-[12.5px] text-muted-foreground">No rule mappings available.</p>
            ) : (
              ruleEntries.map(([rule, techniques]) => (
                <div key={rule} className="rounded-lg border border-border bg-muted/20 p-3">
                  <div className="font-mono text-[12px] font-semibold text-foreground">{rule}</div>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {techniques.map((t) => (
                      <span key={t.id}
                        className="rounded bg-accent px-1.5 py-0.5 text-[10.5px] font-mono text-accent-foreground"
                        title={`${t.id} · ${t.name} · ${t.tactic}`}>
                        {t.id} · {t.name}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="rounded-xl border border-border bg-card shadow-sm">
        <CardContent className="flex flex-wrap items-center gap-2.5 p-4 text-[12.5px]">
          <span className="text-muted-foreground font-medium">MITRE ATT&amp;CK offline cache:</span>
          <span
            className="rounded-full border px-2.5 py-0.5 text-[11px] font-semibold"
            style={{
              borderColor: data.attackCacheWarm ? "var(--sev-low)" : "var(--sev-medium)",
              color: data.attackCacheWarm ? "var(--sev-low)" : "var(--sev-medium)",
              background: data.attackCacheWarm ? "color-mix(in srgb, var(--sev-low) 10%, transparent)" : "color-mix(in srgb, var(--sev-medium) 10%, transparent)",
            }}
            title="~/.cache/mitre_attack — populated once the ATT&CK dataset has been fetched"
          >
            {data.attackCacheWarm ? "warm" : "cold — technique names come from the static map only"}
          </span>
        </CardContent>
      </Card>
    </div>
  );
}
