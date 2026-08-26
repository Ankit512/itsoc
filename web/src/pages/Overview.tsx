import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowDown, ArrowUp, Bell, CircleAlert, CircleArrowDown, Database, ExternalLink,
  Eye, MoreVertical, Monitor, OctagonAlert, Shield, ShieldCheck, Users,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { api, type Delta, type Metrics, type OverviewData } from "@/lib/api";
import { sevVar } from "@/lib/severity";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { AlertsOverTime } from "@/components/charts/AlertsOverTime";
import { TacticBars } from "@/components/charts/TacticBars";
import { AiAnalyst } from "@/components/AiAnalyst";
import { UnrecognizedBanner } from "@/components/UnrecognizedBanner";
import { useUi } from "@/store/ui";

/** Grafana × Vercel KPI card: clean panel, colored label, tabular-nums count,
 *  and a delta line that is either the real prior-run delta or the honest
 *  "no prior run — no delta". */
function KpiCard({ label, count, delta, icon: Icon, color }:
  { label: string; count: number; delta: Delta | null; icon: LucideIcon; color?: string }) {
  return (
    <div className="flex flex-col justify-between rounded-xl border border-border bg-card p-3.5 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        <Icon className="h-4 w-4 flex-none opacity-80" strokeWidth={1.8} aria-hidden
              style={{ color: color ?? "hsl(var(--muted-foreground))" }} />
      </div>
      <div className="mt-2 text-2xl font-bold leading-tight tabular-nums tracking-tight"
           style={color ? { color } : undefined}>
        {count.toLocaleString()}
      </div>
      <div className="mt-1.5">
        {delta ? (
          <div className="flex items-center gap-1 text-[10px] font-semibold"
               style={{ color: delta.dir === "up" ? "var(--sev-critical)" : "var(--sev-low)" }}>
            {delta.dir === "up" ? <ArrowUp className="h-2.5 w-2.5" /> : <ArrowDown className="h-2.5 w-2.5" />}
            {delta.pct}% vs previous
          </div>
        ) : (
          <div className="text-[10px] text-muted-foreground">no prior run — no delta</div>
        )}
      </div>
    </div>
  );
}

function fmtDuration(seconds: number | null): string {
  if (seconds == null) return "n/a";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

/** The ops footer, wired to /api/metrics (soc.metrics aggregates incidents,
 *  assets, users and run history). null values render as n/a or a dash with
 *  the reason in the title — never an invented number. */
function OpsFooter() {
  const { data: m } = useQuery<Metrics>({ queryKey: ["metrics"], queryFn: api.metrics });

  const entries: { label: string; value: string; icon?: LucideIcon; title?: string }[] = m ? [
    { label: "Open Incidents", value: String(m.openIncidents), icon: Shield,
      title: "Incidents not yet resolved, from the incident subsystem" },
    { label: "MTTD", value: fmtDuration(m.mttdSeconds),
      title: m.mttdSeconds == null
        ? "Mean time to detect needs acknowledged incidents — no lifecycle basis yet"
        : `Mean of created→acknowledged over ${m.mttdBasis} incident(s)` },
    { label: "MTTR", value: fmtDuration(m.mttrSeconds),
      title: m.mttrSeconds == null
        ? "Mean time to resolve needs resolved incidents — no lifecycle basis yet"
        : `Mean of created→resolved over ${m.mttrBasis} incident(s)` },
    { label: "Assets at Risk", value: m.assetsAtRisk == null ? "—" : String(m.assetsAtRisk),
      icon: Monitor, title: "Hosts in the current run with a HIGH or CRITICAL finding" },
    { label: "Users at Risk", value: m.usersAtRisk == null ? "—" : String(m.usersAtRisk),
      icon: Users, title: "Accounts targeted by findings in the current run" },
    { label: "Data Sources", value: String(m.dataSources), icon: Database,
      title: "Distinct analyzed sources across the run history" },
  ] : [];

  return (
    <div className="rounded-xl border border-border bg-card p-4 md:p-5 shadow-sm">
      {m ? (
        <>
          <div className="grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-4">
            {entries.map(({ label, value, icon: Icon, title }) => (
              <div key={label} className="flex items-center gap-3" title={title}>
                {Icon && <Icon className="h-6 w-6 flex-none text-muted-foreground opacity-75" strokeWidth={1.6} aria-hidden />}
                <div>
                  <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">{label}</div>
                  <div className="text-xl font-bold leading-tight tabular-nums">{value}</div>
                </div>
              </div>
            ))}
          </div>
          <p className="mt-3.5 border-t border-border pt-3 text-xs leading-normal text-muted-foreground">
            <b className="text-foreground">Operational metrics — derived, never invented.</b>{" "}
            Incident counts and MTTD/MTTR come from the incident subsystem's real
            lifecycle stamps (n/a until incidents are acknowledged or resolved);
            asset and user risk are derived from the current run's findings.
          </p>
        </>
      ) : (
        <p className="text-xs text-muted-foreground">
          Operational metrics are unavailable — the backend's /api/metrics did
          not answer. Nothing is shown rather than an invented number.
        </p>
      )}
    </div>
  );
}

const th = "border-b border-border px-3 py-2.5 text-left text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground";
const td = "border-b border-border px-3 py-2.5 align-middle text-[12.5px]";

export function Overview() {
  const { data, isLoading, error } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  // The current run's parse facts (unrecognized / empty / line counts) live in
  // console_state, not in /api/overview — needed to tell "nothing parsed" from
  // "nothing found" honestly.
  const { data: state } = useQuery({ queryKey: ["consoleState"], queryFn: api.consoleState });
  const setTimeWindow = useUi((s) => s.setTimeWindow);

  const overview = data && !("error" in data) ? (data as OverviewData) : null;
  const unparsed = !!state && !state.idle && (!!state.unrecognized || !!state.emptyInput);
  useEffect(() => {
    if (overview?.timeWindowLabel) setTimeWindow(overview.timeWindowLabel);
  }, [overview?.timeWindowLabel, setTimeWindow]);

  if (isLoading) return <p className="text-muted-foreground">Loading the current run…</p>;
  if (error) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          The console backend is not reachable. Start it with
          <code className="mx-1 rounded bg-muted px-1.5 py-0.5 font-mono">python3 console/serve.py</code>
          — nothing is shown here rather than sample numbers.
        </CardContent>
      </Card>
    );
  }
  if (!overview) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          {(data as { error: string } | undefined)?.error ?? "No run yet"} — upload a
          log above or open <Link className="text-primary underline" to="/alerts">Alerts</Link>.
          No sample data is shown in its place.
        </CardContent>
      </Card>
    );
  }

  const k = overview.kpis;
  return (
    <div className="flex flex-col gap-4">
      {/* Honesty guardrail: an unrecognized / empty run must not read as an
          all-clear. Show the banner FIRST, above the zero KPIs. */}
      {unparsed && state && <UnrecognizedBanner state={state} />}
      {unparsed && (
        <p className="text-[12px] text-muted-foreground" style={{ color: "var(--sev-medium)" }}>
          The counts below are all zero because <b>nothing was parsed</b>, not
          because nothing was found. Open <Link className="underline" to="/alerts">Alerts</Link>{" "}
          for the run details.
        </p>
      )}
      <div className="grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-2.5">
        <KpiCard label="Total Alerts" count={k.total} delta={k.deltas.total} icon={Bell} />
        <KpiCard label="Critical" count={k.critical} delta={k.deltas.critical} icon={OctagonAlert} color={sevVar("CRITICAL")} />
        <KpiCard label="High" count={k.high} delta={k.deltas.high} icon={CircleAlert} color={sevVar("HIGH")} />
        <KpiCard label="Medium" count={k.medium} delta={k.deltas.medium} icon={CircleArrowDown} color={sevVar("MEDIUM")} />
        <KpiCard label="Low" count={k.low} delta={k.deltas.low} icon={ShieldCheck} color={sevVar("LOW")} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 items-stretch gap-4">
        <div className="min-w-0 rounded-xl border border-border bg-card p-4 shadow-sm">
          <h3 className="mb-3.5 text-[13.5px] font-semibold">Alerts by Severity</h3>
          <SeverityDonut data={overview.severityDonut} />
        </div>
        <div className="min-w-0 rounded-xl border border-border bg-card p-4 shadow-sm">
          <h3 className="mb-3.5 text-[13.5px] font-semibold">Alerts Over Time</h3>
          <AlertsOverTime data={overview.alertsOverTime} />
        </div>
        <div className="min-w-0 rounded-xl border border-border bg-card p-4 shadow-sm">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-[13.5px] font-semibold">Top Attack Tactics (MITRE)</h3>
            <span className="rounded-full border border-border px-2 py-0.5 text-[9.5px] text-muted-foreground">
              derived tags — not verdicts
            </span>
          </div>
          <TacticBars data={overview.mitreTactics} />
        </div>
      </div>

      <div className="min-w-0 rounded-xl border border-border bg-card p-4 shadow-sm">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="text-[13.5px] font-semibold">Latest Alerts</h3>
          <span className="text-[11.5px] text-muted-foreground">
            {overview.latestAlerts.length} most recent of {k.total} · drill into Alerts for evidence
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[920px] border-collapse text-[12.5px]">
            <thead>
              <tr>
                <th className={th}>Time</th>
                <th className={th}>Severity</th>
                <th className={th}>Attacker Status</th>
                <th className={th}>Primary MITRE Tactics</th>
                <th className={`${th} min-w-[300px]`}>Alert Name / Description</th>
                <th className={th}>Source</th>
                <th className={th}>Action</th>
              </tr>
            </thead>
            <tbody>
              {overview.latestAlerts.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-3 py-4 text-center text-muted-foreground">
                    No alerts in this window.
                  </td>
                </tr>
              )}
              {overview.latestAlerts.map((a) => (
                <tr key={a.id} data-testid="latest-alert-row" className="hover:bg-muted/40 transition-colors">
                  <td className={`${td} whitespace-nowrap font-mono text-[11.5px] tabular-nums text-muted-foreground`}>
                    {a.time}
                  </td>
                  <td className={td}>
                    <span className="inline-flex items-center gap-1.5 whitespace-nowrap font-semibold"
                          style={{ color: sevVar(a.severity) }}>
                      <i className="h-2 w-2 flex-none rounded-full"
                         style={{ background: sevVar(a.severity) }} />
                      {a.severity.charAt(0) + a.severity.slice(1).toLowerCase()}
                    </span>
                  </td>
                  <td className={td}>
                    <span className="whitespace-nowrap"
                          title="Derived kill-chain grouping of this alert's MITRE tactics — a display aid, not a verdict">
                      {a.attackerStatus || "—"}
                    </span>
                  </td>
                  <td className={td}>
                    <span title="derived, does not affect severity" className="text-muted-foreground">
                      {a.tactics.length ? a.tactics.join(", ") : "—"}
                    </span>
                  </td>
                  <td className={`${td} font-medium`}>{a.name}</td>
                  <td className={td}>
                    {a.source
                      ? <span title={a.source} className="cursor-help border-b border-dotted font-mono text-[11px] text-muted-foreground">
                          {a.source.split("/").pop()}
                        </span>
                      : "—"}
                  </td>
                  <td className={td}>
                    <span className="inline-flex items-center gap-2.5 text-muted-foreground">
                      <Link to={`/alerts?sel=${encodeURIComponent(a.id)}`}
                            title="View this finding's evidence in Alerts" aria-label="View finding"
                            className="inline-flex hover:text-foreground">
                        <Eye className="h-4 w-4" strokeWidth={1.8} aria-hidden />
                      </Link>
                      <a href={`/alerts?sel=${encodeURIComponent(a.id)}`} target="_blank" rel="noreferrer"
                         title="Open this finding in a new tab" aria-label="Open finding"
                         className="inline-flex hover:text-foreground">
                        <ExternalLink className="h-4 w-4" strokeWidth={1.8} aria-hidden />
                      </a>
                      <button disabled title="Row actions need case management — a later phase"
                              aria-label="More actions"
                              className="inline-flex cursor-not-allowed opacity-40">
                        <MoreVertical className="h-4 w-4" strokeWidth={1.8} aria-hidden />
                      </button>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <OpsFooter />

      <AiAnalyst model={overview.model} />
    </div>
  );
}
