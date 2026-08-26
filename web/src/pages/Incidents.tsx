import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, INCIDENT_STATES, type Incident, type IncidentState, type Rca } from "@/lib/api";
import { cn } from "@/lib/utils";

function sevShort(sev: string): "crit" | "high" | "med" | "low" {
  const s = (sev || "").toUpperCase();
  if (s.startsWith("CRIT")) return "crit";
  if (s.startsWith("HIGH")) return "high";
  if (s.startsWith("MED")) return "med";
  return "low";
}
function SevTag({ sev }: { sev: string }) {
  return <span className={`is-tag is-tag--${sevShort(sev)}`}>{(sev || "").toUpperCase()}</span>;
}
function StateChip({ state }: { state: IncidentState }) {
  return <span className="is-state" style={{ textTransform: "capitalize" }}>{state}</span>;
}

/** Layered RCA (soc.derive_rca): deterministic facts + runbook citation +
 *  hypothesis, each rendering its honest absence note when withheld. Advisory,
 *  never a verdict. Testids preserved for the honesty checks. */
function RcaPanel({ incidentId }: { incidentId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["rca", incidentId],
    queryFn: () => api.incidentRca(incidentId),
  });

  if (isLoading) return <p className="is-mut" style={{ fontSize: "11.5px" }}>Loading root-cause analysis…</p>;
  if (isError || !data || "error" in data || !("facts" in data)) {
    return <p className="is-mut" style={{ fontSize: "11.5px" }}>Root-cause analysis unavailable for this incident.</p>;
  }
  const rca = data as Rca;

  return (
    <div className="flex flex-col gap-2.5">
      <div className="is-rca" data-testid="rca-facts">
        <div className="cap" style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--mut)", marginBottom: 7 }}>
          Cluster facts · deterministic
        </div>
        <div className="flex flex-wrap gap-1.5">
          {rca.facts.rules.length ? rca.facts.rules.map((r) => (
            <span key={r} className="is-tag is-tag--info is-mono">{r}</span>
          )) : (
            <span className="is-mut" style={{ fontSize: "11.5px" }}>Member findings are not in the loaded run.</span>
          )}
        </div>
        <div style={{ marginTop: 8, fontSize: "11.5px" }}>
          <span className="is-mut">Span: </span>
          <span className="is-mono">{rca.facts.firstSeen ?? "n/a"} → {rca.facts.lastSeen ?? "n/a"}</span>
        </div>
        {rca.facts.timeline.length > 0 && (
          <ol style={{ marginTop: 8, paddingLeft: 0, listStyle: "none" }}>
            {rca.facts.timeline.map((e, i) => (
              <li key={i} style={{ fontSize: "11.5px", padding: "1px 0" }}>
                <span className="is-mono is-mut is-tnum">{e.t || "—"}</span>{" "}
                <span>{e.label}</span>
                {e.rule && <span className="is-mono is-mut" style={{ marginLeft: 6, fontSize: 10 }}>[{e.rule}]</span>}
              </li>
            ))}
          </ol>
        )}
        {rca.facts.note && <p className="is-mut" style={{ marginTop: 6, fontSize: 11 }}>{rca.facts.note}</p>}
      </div>

      <div className="is-rca" data-testid="rca-runbook">
        <div className="cap" style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--mut)", marginBottom: 7 }}>
          Runbook citation · retrieved, never forced
        </div>
        {rca.runbook.matched ? (
          <div>
            <div style={{ fontSize: 12, fontWeight: 600 }}>{rca.runbook.title}</div>
            <div className="is-mono is-mut" style={{ fontSize: "10.5px", marginTop: 2 }}>
              {rca.runbook.file} · score {rca.runbook.score} · rule coverage {Math.round((rca.runbook.coverage ?? 0) * 100)}%
            </div>
            <blockquote className="is-mut" style={{ margin: "8px 0 0", whiteSpace: "pre-wrap", borderLeft: "2px solid var(--acc)", paddingLeft: 10, fontSize: "11.5px", lineHeight: 1.55 }}>
              {rca.runbook.passage}
            </blockquote>
          </div>
        ) : (
          <p className="is-mut" style={{ fontSize: "11.5px" }}>{rca.runbook.note}</p>
        )}
      </div>

      <div className="is-rca" data-testid="rca-hypothesis">
        <div className="flex items-center gap-2" style={{ marginBottom: 6 }}>
          <span className="cap" style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--mut)" }}>
            Root-cause hypothesis
          </span>
          <span className="is-chip">{rca.hypothesis.label}</span>
        </div>
        {rca.hypothesis.text ? (
          <p style={{ fontSize: 12, lineHeight: 1.55 }}>{rca.hypothesis.text}</p>
        ) : (
          <div className="is-mut" style={{ fontSize: "11.5px" }}>
            <p>{rca.hypothesis.note}</p>
            {rca.hypothesis.reasons?.map((r, i) => <p key={i} style={{ marginTop: 2 }}>— {r}</p>)}
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
    <div className="is-md__detail">
      <div className="is-detail-head">
        <SevTag sev={inc.severity} />
        <StateChip state={inc.state} />
        <span className="id">{inc.id}</span>
      </div>
      <h2>{inc.entity} — {inc.findingCount} correlated finding(s)</h2>
      <div className="is-detail-meta">
        {inc.title} · detected {inc.createdAt ? inc.createdAt.slice(11, 19) : "n/a"}
        <span className="is-ro">severity is rule-owned</span>
      </div>

      {/* Lifecycle — analyst-owned, real stamps */}
      <div className="is-lifecycle">
        <div className="cap">Lifecycle · analyst-owned</div>
        <div className="steps">
          {INCIDENT_STATES.map((s) => (
            <button
              key={s}
              className={cn("step", s === inc.state && "on")}
              style={{ textTransform: "capitalize" }}
              disabled={s === inc.state || mutation.isPending}
              onClick={() => mutation.mutate(s)}
              title={s === inc.state ? "Current state" : `Move to ${s}`}
            >
              {s}
            </button>
          ))}
        </div>
        {mutation.isError && (
          <p style={{ marginTop: 8, fontSize: "11.5px", color: "var(--crit)" }}>{(mutation.error as Error).message}</p>
        )}
      </div>

      <div className="is-vgrid">
        <div className="is-facts">
          <div className="cap">Timestamps · from the log, not wall-clock</div>
          {facts.map(([label, val]) => (
            <div key={label} className="is-facts-row">
              <span>{label}</span>
              <b className={val ? "is-mono" : "na"}>{val ?? "n/a"}</b>
            </div>
          ))}
          {inc.timeUncertain && (
            <p className="is-mut" style={{ marginTop: 8, fontSize: 11 }}>
              A member finding had no timestamp — it joined this cluster's first group.
            </p>
          )}
        </div>

        <div className="is-facts">
          <div className="cap">MITRE techniques · derived tags, not verdicts</div>
          {inc.techniques.length ? (
            <div className="flex flex-wrap gap-1.5">
              {inc.techniques.map((t) => (
                <span key={t.id} className="is-tid" title={`${t.id} · ${t.name} · ${t.tactic} — derived, does not affect severity`}>
                  {t.id}
                </span>
              ))}
            </div>
          ) : (
            <p className="is-mut" style={{ fontSize: "11.5px" }}>No techniques mapped.</p>
          )}
          {inc.attackerStatus && (
            <div style={{ marginTop: 10, fontSize: "11.5px" }}>
              <span className="is-mut">Kill-chain phase: </span>
              <span title="Derived grouping of member tactics — a display aid, not a verdict" style={{ fontWeight: 500 }}>
                {inc.attackerStatus}
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="is-facts">
        <div className="cap">{inc.findingCount} correlated finding(s)</div>
        <div className="flex flex-wrap gap-1.5">
          {inc.findingIds.map((fid) => (
            <a key={fid} href={`/alerts?sel=${encodeURIComponent(fid)}`}
              className="is-tag is-tag--info is-mono" title="Open this finding in Findings">
              {fid}
            </a>
          ))}
        </div>
      </div>

      {/* Root cause — advisory territory (§3) */}
      <div className="is-rca" data-testid="rca-panel" style={{ borderStyle: "dashed" }}>
        <div className="h">
          <b>Root cause</b>
          <span className="is-chip is-chip--adv">advisory · hypothesis · not a verdict</span>
        </div>
        <RcaPanel incidentId={inc.id} />
      </div>
    </div>
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

  if (isLoading) return <p className="is-mut">Loading incidents…</p>;
  if (isError) {
    return <div className="is-note">Couldn't load incidents — {(error as Error).message}</div>;
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2.5">
        <select
          className="is-select"
          style={{ maxWidth: 150 }}
          aria-label="Lifecycle filter"
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value as IncidentState | "")}
        >
          <option value="">All states</option>
          {INCIDENT_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="is-panel__sub">
          {incidents.length} incident(s){stateFilter && ` · ${stateFilter}`} · correlated clusters of real findings
        </span>
      </div>

      {incidents.length === 0 ? (
        <div className="is-note">
          {stateFilter
            ? `No incidents in the "${stateFilter}" state.`
            : "No incidents yet — an incident is a correlated cluster of the current run's findings. Analyze a log with findings and they'll appear here."}
        </div>
      ) : (
        <div className={cn("is-md", !selected && "!grid-cols-1")}>
          <div className="is-md__list">
            <div className="overflow-auto max-h-[60vh]">
              <table className="is-table">
                <thead>
                  <tr>
                    <th>Sev</th>
                    <th>State</th>
                    <th>Entity</th>
                    <th>Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr
                      key={inc.id}
                      data-testid="incident-row"
                      onClick={() => setParams({ sel: inc.id })}
                      className={cn(selected?.id === inc.id && "active")}
                    >
                      <td><SevTag sev={inc.severity} /></td>
                      <td><StateChip state={inc.state} /></td>
                      <td className="col-mono" style={{ color: "var(--ink)" }}>
                        {inc.entity}
                        {inc.isRollup && <span className="is-tag is-tag--info" style={{ marginLeft: 6 }}>rollup</span>}
                      </td>
                      <td className="is-tnum">{inc.findingCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {selected && <IncidentDetail inc={selected} />}
        </div>
      )}
    </>
  );
}
