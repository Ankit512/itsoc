import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, INCIDENT_STATES, type Incident, type IncidentState, type Rca } from "@/lib/api";
import { SeverityBadge, Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** The lifecycle order is fixed (docs/soc_subsystems.md): new → acknowledged →
 *  investigating → resolved. Moving backwards is allowed (a mistaken resolve
 *  can be reopened); the backend never erases a timestamp already earned. */
const STATE_STYLE: Record<IncidentState, string> = {
  new: "border-border text-muted-foreground",
  acknowledged: "border-[color:var(--sev-medium)] text-[color:var(--sev-medium)]",
  investigating: "border-[color:var(--sev-high)] text-[color:var(--sev-high)]",
  resolved: "border-[color:var(--sev-low)] text-[color:var(--sev-low)]",
};

function StateBadge({ state }: { state: IncidentState }) {
  return <Badge className={cn("capitalize", STATE_STYLE[state])}>{state}</Badge>;
}

const th = "border-b border-border px-3 py-2.5 text-left text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground";

/** Layered RCA (soc.derive_rca), rendered BELOW and apart from the rule-owned
 *  verdict: a dashed advisory container so it can never read as part of the
 *  verdict. Facts are deterministic; runbook + hypothesis each render their
 *  honest absence note when the server withheld or couldn't produce them. */
function RcaPanel({ incidentId }: { incidentId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["rca", incidentId],
    queryFn: () => api.incidentRca(incidentId),
  });

  if (isLoading) {
    return <p className="text-[11.5px] text-muted-foreground">Loading root-cause analysis…</p>;
  }
  // Off-shape data is treated the same as an error: an honest absence,
  // never a crash and never an invented panel.
  if (isError || !data || "error" in data || !("facts" in data)) {
    return (
      <p className="text-[11.5px] text-muted-foreground">
        Root-cause analysis unavailable for this incident.
      </p>
    );
  }
  const rca = data as Rca;

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-border bg-muted/20 p-3" data-testid="rca-facts">
        <div className="mb-1 text-[9.5px] uppercase font-semibold tracking-wider text-muted-foreground">
          Cluster facts · deterministic
        </div>
        <div className="flex flex-wrap gap-1.5">
          {rca.facts.rules.length ? rca.facts.rules.map((r) => (
            <span key={r} className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[10.5px]">{r}</span>
          )) : (
            <span className="text-[11.5px] text-muted-foreground">
              Member findings are not in the loaded run.
            </span>
          )}
        </div>
        <div className="mt-2 text-[11.5px]">
          <span className="text-muted-foreground">Span: </span>
          <span className="font-mono text-[11px]">
            {rca.facts.firstSeen ?? "n/a"} → {rca.facts.lastSeen ?? "n/a"}
          </span>
        </div>
        {rca.facts.timeline.length > 0 && (
          <ol className="mt-2 space-y-1">
            {rca.facts.timeline.map((e, i) => (
              <li key={i} className="text-[11.5px]">
                <span className="font-mono text-[11px] tabular-nums text-muted-foreground">{e.t || "—"}</span>
                {" "}<span className="text-foreground">{e.label}</span>
                {e.rule && <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">[{e.rule}]</span>}
              </li>
            ))}
          </ol>
        )}
        {rca.facts.note && (
          <p className="mt-1.5 text-[11px] text-muted-foreground">{rca.facts.note}</p>
        )}
      </div>

      <div className="rounded-lg border border-border bg-muted/20 p-3" data-testid="rca-runbook">
        <div className="mb-1 text-[9.5px] uppercase font-semibold tracking-wider text-muted-foreground">
          Runbook citation · retrieved, never forced
        </div>
        {rca.runbook.matched ? (
          <div>
            <div className="text-[12px] font-semibold text-foreground">{rca.runbook.title}</div>
            <div className="font-mono text-[10.5px] text-muted-foreground mt-0.5">
              {rca.runbook.file} · score {rca.runbook.score} · rule coverage{" "}
              {Math.round((rca.runbook.coverage ?? 0) * 100)}%
            </div>
            <blockquote className="mt-2 whitespace-pre-wrap border-l-2 border-primary pl-2.5 text-[11.5px] text-muted-foreground leading-relaxed">
              {rca.runbook.passage}
            </blockquote>
          </div>
        ) : (
          <p className="text-[11.5px] text-muted-foreground">{rca.runbook.note}</p>
        )}
      </div>

      <div className="rounded-lg border border-border bg-muted/20 p-3" data-testid="rca-hypothesis">
        <div className="mb-1.5 flex items-center gap-2">
          <span className="text-[9.5px] uppercase font-semibold tracking-wider text-muted-foreground">
            Root-cause hypothesis
          </span>
          <Badge className="border-border text-[9.5px] text-muted-foreground">
            {rca.hypothesis.label}
          </Badge>
        </div>
        {rca.hypothesis.text ? (
          <p className="text-[12px] leading-relaxed text-foreground">{rca.hypothesis.text}</p>
        ) : (
          <div className="text-[11.5px] text-muted-foreground">
            <p>{rca.hypothesis.note}</p>
            {rca.hypothesis.reasons?.map((r, i) => <p key={i} className="mt-0.5">— {r}</p>)}
          </div>
        )}
      </div>
    </div>
  );
}

function IncidentDetail({ inc }: { inc: Incident }) {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: (state: IncidentState) => api.setIncidentState(inc.id, state),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });

  const facts: [string, string | null][] = [
    ["Detected (earliest finding)", inc.createdAt],
    ["First seen", inc.firstSeen],
    ["Last seen", inc.lastSeen],
    ["Acknowledged", inc.acknowledgedAt],
    ["Resolved", inc.resolvedAt],
  ];

  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden sticky top-4">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={inc.severity} />
          <StateBadge state={inc.state} />
          <span className="font-mono text-[11px] text-muted-foreground">{inc.entityKind}</span>
          <span className="ml-auto font-mono text-[11px] text-muted-foreground">{inc.id}</span>
        </div>
        <CardTitle className="text-[15px] font-bold leading-snug mt-1.5">{inc.title}</CardTitle>
        <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          <span>{inc.entity}</span>
          <span>·</span>
          <span>detected {inc.createdAt ? inc.createdAt.slice(11, 19) : "n/a"}</span>
          <span>·</span>
          <span>{inc.findingCount} correlated finding(s)</span>
          <span className="ml-auto rounded-full border border-border px-2 py-0.5 text-[9.5px]">
            severity is rule-owned
          </span>
        </div>
      </CardHeader>
      <CardContent className="p-4 space-y-4">
        <div className="rounded-lg border border-border bg-muted/20 p-3">
          <div className="text-[9.5px] uppercase font-semibold tracking-wider text-muted-foreground">
            Lifecycle · analyst-owned
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {INCIDENT_STATES.map((s) => (
              <Button
                key={s}
                size="sm"
                variant={s === inc.state ? "default" : "outline"}
                disabled={s === inc.state || mutation.isPending}
                onClick={() => mutation.mutate(s)}
                className="capitalize text-xs h-8"
                title={s === inc.state ? "Current state" : `Move to ${s}`}
              >
                {s}
              </Button>
            ))}
          </div>
          {mutation.isError && (
            <p className="mt-2 text-[11.5px]" style={{ color: "var(--sev-critical)" }}>
              {(mutation.error as Error).message}
            </p>
          )}
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-border bg-muted/20 p-3">
            <div className="mb-1.5 text-[9.5px] uppercase font-semibold tracking-wider text-muted-foreground">
              Timestamps · from the log, not wall-clock
            </div>
            <div className="space-y-1">
              {facts.map(([label, val]) => (
                <div key={label} className="flex justify-between gap-3 py-0.5 text-xs">
                  <span className="text-muted-foreground">{label}</span>
                  <span className="font-mono text-[11px] tabular-nums text-foreground">{val ?? "n/a"}</span>
                </div>
              ))}
            </div>
            {inc.timeUncertain && (
              <p className="mt-2 text-[11px] text-muted-foreground">
                A member finding had no timestamp — it joined this cluster's first group.
              </p>
            )}
          </div>

          <div className="rounded-lg border border-border bg-muted/20 p-3">
            <div className="mb-1.5 text-[9.5px] uppercase font-semibold tracking-wider text-muted-foreground">
              MITRE techniques · derived tags, not verdicts
            </div>
            {inc.techniques.length ? (
              <div className="flex flex-wrap gap-1.5">
                {inc.techniques.map((t) => (
                  <span key={t.id}
                    className="rounded bg-accent px-1.5 py-0.5 text-[10.5px] font-mono text-accent-foreground"
                    title={`${t.id} · ${t.name} · ${t.tactic} — derived, does not affect severity`}>
                    {t.id}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-[11.5px] text-muted-foreground">No techniques mapped.</p>
            )}
            {inc.attackerStatus && (
              <div className="mt-2.5 text-[11.5px]">
                <span className="text-muted-foreground">Kill-chain phase: </span>
                <span title="Derived grouping of member tactics — a display aid, not a verdict" className="font-medium text-foreground">
                  {inc.attackerStatus}
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-muted/20 p-3">
          <div className="mb-1.5 text-[9.5px] uppercase font-semibold tracking-wider text-muted-foreground">
            {inc.findingCount} correlated finding(s)
          </div>
          <div className="flex flex-wrap gap-1.5">
            {inc.findingIds.map((fid) => (
              <a key={fid} href={`/alerts?sel=${encodeURIComponent(fid)}`}
                className="rounded border border-border bg-card px-2 py-0.5 font-mono text-[10.5px] hover:bg-muted transition-colors"
                title="Open this finding in Findings">
                {fid}
              </a>
            ))}
          </div>
        </div>

        {/* Advisory territory starts here — dashed frame + explicit banner so
            nothing below can be mistaken for the rule-owned verdict above. */}
        <div className="rounded-xl border border-dashed border-border bg-card p-4 space-y-3" data-testid="rca-panel">
          <div className="flex items-center justify-between">
            <h3 className="text-[12.5px] font-semibold text-foreground">Root cause</h3>
            <span className="rounded-full border border-primary/40 px-2 py-0.5 text-[9.5px] text-primary">
              advisory · hypothesis · not a verdict
            </span>
          </div>
          <RcaPanel incidentId={inc.id} />
        </div>
      </CardContent>
    </Card>
  );
}

export function Incidents() {
  const [params, setParams] = useSearchParams();
  const [stateFilter, setStateFilter] = useState<IncidentState | "">("");
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["incidents", stateFilter],
    queryFn: () => api.incidents(stateFilter || undefined),
    refetchInterval: 5000,
  });

  const incidents = data?.incidents ?? [];
  const selId = params.get("sel");
  const selected = incidents.find((i) => i.id === selId) ?? null;

  if (isLoading) return <p className="text-muted-foreground">Loading incidents…</p>;

  if (isError) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          Couldn't load incidents — {(error as Error).message}
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select
          className="h-9 rounded-lg border border-border bg-card px-2.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          aria-label="Lifecycle filter"
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value as IncidentState | "")}
        >
          <option value="">All states</option>
          {INCIDENT_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="text-xs text-muted-foreground">
          {incidents.length} incident(s){stateFilter && ` · ${stateFilter}`} · correlated clusters of real findings
        </span>
      </div>

      {incidents.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="p-6 text-[12.5px] text-muted-foreground">
            {stateFilter
              ? `No incidents in the "${stateFilter}" state.`
              : "No incidents yet — an incident is a correlated cluster of the current run's findings. Analyze a log with findings and they'll appear here."}
          </CardContent>
        </Card>
      ) : (
        <div className={cn("grid gap-4 items-start", selected ? "grid-cols-1 lg:grid-cols-12" : "grid-cols-1")}>
          <div className={selected ? "lg:col-span-5" : "w-full"}>
            <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
              <div className="overflow-auto max-h-[60vh]">
                <table className="w-full border-collapse text-[12.5px]">
                  <thead className="sticky top-0 z-10 bg-card border-b border-border">
                    <tr className="text-left text-[10.5px] uppercase font-semibold tracking-wider text-muted-foreground">
                      <th className={th}>Severity</th>
                      <th className={th}>State</th>
                      <th className={th}>Entity</th>
                      <th className={th}>Findings</th>
                      <th className={th}>Detected</th>
                      <th className={th}>Phase</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.map((inc) => (
                      <tr
                        key={inc.id}
                        data-testid="incident-row"
                        onClick={() => setParams({ sel: inc.id })}
                        className={cn(
                          "cursor-pointer border-b border-border last:border-0 align-top hover:bg-muted/40 transition-colors",
                          selected?.id === inc.id && "bg-accent/50",
                        )}
                      >
                        <td className="px-3 py-2.5"><SeverityBadge severity={inc.severity} /></td>
                        <td className="px-3 py-2.5"><StateBadge state={inc.state} /></td>
                        <td className="px-3 py-2.5 font-mono text-[11.5px] font-medium">
                          {inc.entity}
                          {inc.isRollup && (
                            <span className="ml-1.5 rounded border px-1 py-0.5 text-[9.5px] uppercase tracking-wide text-muted-foreground">
                              rollup
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 tabular-nums text-[12.5px] font-medium">{inc.findingCount}</td>
                        <td className="px-3 py-2.5 font-mono text-[11px] tabular-nums text-muted-foreground">
                          {inc.createdAt ?? "n/a"}
                        </td>
                        <td className="px-3 py-2.5 text-[12px] text-muted-foreground">
                          {inc.attackerStatus || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>

          {selected && (
            <div className="lg:col-span-7">
              <IncidentDetail inc={selected} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
