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

const th = "px-2 py-2 text-left text-[10.5px] uppercase tracking-wide text-muted-foreground";

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
      <div className="rounded-md border p-3">
        <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
          Cluster facts · deterministic
        </div>
        <div className="flex flex-wrap gap-1.5">
          {rca.facts.rules.length ? rca.facts.rules.map((r) => (
            <span key={r} className="rounded border px-1.5 py-0.5 font-mono text-[10.5px]">{r}</span>
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
          <ol className="mt-2 space-y-0.5">
            {rca.facts.timeline.map((e, i) => (
              <li key={i} className="text-[11.5px]">
                <span className="font-mono text-[11px] text-muted-foreground">{e.t || "—"}</span>
                {" "}{e.label}
                {e.rule && <span className="ml-1 font-mono text-[10px] text-muted-foreground">[{e.rule}]</span>}
              </li>
            ))}
          </ol>
        )}
        {rca.facts.note && (
          <p className="mt-1.5 text-[11px] text-muted-foreground">{rca.facts.note}</p>
        )}
      </div>

      <div className="rounded-md border p-3">
        <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
          Runbook citation · retrieved, never forced
        </div>
        {rca.runbook.matched ? (
          <div>
            <div className="text-[12px] font-medium">{rca.runbook.title}</div>
            <div className="font-mono text-[10.5px] text-muted-foreground">
              {rca.runbook.file} · score {rca.runbook.score} · rule coverage{" "}
              {Math.round(rca.runbook.coverage * 100)}%
            </div>
            <blockquote className="mt-1.5 whitespace-pre-wrap border-l-2 pl-2 text-[11.5px]">
              {rca.runbook.passage}
            </blockquote>
          </div>
        ) : (
          <p className="text-[11.5px] text-muted-foreground">{rca.runbook.note}</p>
        )}
      </div>

      <div className="rounded-md border p-3">
        <div className="mb-1 flex items-center gap-2">
          <span className="text-[9.5px] uppercase tracking-wide text-muted-foreground">
            Root-cause hypothesis
          </span>
          <Badge className="border-border text-[9.5px] text-muted-foreground">
            {rca.hypothesis.label}
          </Badge>
        </div>
        {rca.hypothesis.text ? (
          <p className="text-[12px]">{rca.hypothesis.text}</p>
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
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={inc.severity} />
          <StateBadge state={inc.state} />
          <span className="font-mono text-[11px] text-muted-foreground">{inc.entityKind}</span>
          <span className="ml-auto font-mono text-[11px] text-muted-foreground">{inc.id}</span>
        </div>
        <CardTitle className="text-[16px] leading-snug">{inc.title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border p-3">
          <div className="text-[9.5px] uppercase tracking-wide text-muted-foreground">
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
                className="capitalize"
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
          <div className="rounded-md border p-3">
            <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
              Timestamps · from the log, not wall-clock
            </div>
            {facts.map(([label, val]) => (
              <div key={label} className="flex justify-between gap-3 py-0.5 text-xs">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-mono text-[11px]">{val ?? "n/a"}</span>
              </div>
            ))}
            {inc.timeUncertain && (
              <p className="mt-1.5 text-[11px] text-muted-foreground">
                A member finding had no timestamp — it joined this cluster's first group.
              </p>
            )}
          </div>

          <div className="rounded-md border p-3">
            <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
              MITRE techniques · derived tags, not verdicts
            </div>
            {inc.techniques.length ? (
              <div className="flex flex-wrap gap-1.5">
                {inc.techniques.map((t) => (
                  <span key={t.id}
                    className="rounded bg-accent px-1.5 py-0.5 text-[10.5px] text-accent-foreground"
                    title={`${t.id} · ${t.name} · ${t.tactic} — derived, does not affect severity`}>
                    {t.id}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-[11.5px] text-muted-foreground">No techniques mapped.</p>
            )}
            {inc.attackerStatus && (
              <div className="mt-2 text-[11.5px]">
                <span className="text-muted-foreground">Kill-chain phase: </span>
                <span title="Derived grouping of member tactics — a display aid, not a verdict">
                  {inc.attackerStatus}
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="rounded-md border p-3">
          <div className="mb-1 text-[9.5px] uppercase tracking-wide text-muted-foreground">
            {inc.findingCount} correlated finding(s)
          </div>
          <div className="flex flex-wrap gap-1.5">
            {inc.findingIds.map((fid) => (
              <a key={fid} href={`/alerts?sel=${encodeURIComponent(fid)}`}
                className="rounded border px-1.5 py-0.5 font-mono text-[10.5px] hover:bg-muted"
                title="Open this finding in Alerts">
                {fid}
              </a>
            ))}
          </div>
        </div>

        {/* Advisory territory starts here — dashed frame + explicit banner so
            nothing below can be mistaken for the rule-owned verdict above. */}
        <div className="rounded-md border border-dashed p-3" data-testid="rca-panel">
          <div className="mb-2 text-[9.5px] uppercase tracking-wide text-muted-foreground">
            Root-cause analysis · advisory — severity above is rule-owned and unaffected
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
          className="h-9 rounded-md border border-input bg-card px-2 text-sm"
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
        <Card>
          <div className="overflow-auto">
            <table className="w-full">
              <thead className="bg-card">
                <tr className="border-b">
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
                      "cursor-pointer border-b last:border-0 align-top hover:bg-muted/60",
                      selected?.id === inc.id && "bg-accent/60",
                    )}
                  >
                    <td className="px-2 py-2"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-2 py-2"><StateBadge state={inc.state} /></td>
                    <td className="px-2 py-2 font-mono text-[11.5px]">{inc.entity}</td>
                    <td className="px-2 py-2 tabular-nums text-[12.5px]">{inc.findingCount}</td>
                    <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">
                      {inc.createdAt ?? "n/a"}
                    </td>
                    <td className="px-2 py-2 text-[12.5px] text-muted-foreground">
                      {inc.attackerStatus || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {selected && <IncidentDetail inc={selected} />}
    </div>
  );
}
