import { useQuery } from "@tanstack/react-query";
import { api, type Metrics } from "@/lib/api";

/** Human duration, or an honest "n/a" when the lifecycle basis does not exist
 *  yet (mtta/mttr are null until incidents carry acknowledge/resolve stamps). */
function fmtDuration(seconds: number | null): string {
  if (seconds == null) return "n/a";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

/** The ops-metrics panel, wired to /api/metrics (soc.metrics aggregates
 *  incidents, assets, users and run history). Every value is derived or null —
 *  a null renders as n/a or a dash with the reason in its title and note, never an
 *  invented number; an unreachable backend says so rather than showing zeros. */
export function OpsMetrics() {
  const { data: m, isLoading, error } =
    useQuery<Metrics>({ queryKey: ["metrics"], queryFn: api.metrics });

  const tiles: { label: string; value: string; note?: string; title: string }[] = m ? [
    { label: "Open Incidents", value: String(m.openIncidents),
      title: "Incidents not yet resolved, from the incident subsystem" },
    { label: "MTTA", value: fmtDuration(m.mttaSeconds),
      note: m.mttaSeconds == null ? "no lifecycle basis yet" : `${m.mttaBasis} incident(s)`,
      title: m.mttaSeconds == null
        ? "Mean time to acknowledge needs acknowledged incidents — no lifecycle basis yet"
        : `Mean of created→acknowledged over ${m.mttaBasis} incident(s)` },
    { label: "MTTR", value: fmtDuration(m.mttrSeconds),
      note: m.mttrSeconds == null ? "no lifecycle basis yet" : `${m.mttrBasis} incident(s)`,
      title: m.mttrSeconds == null
        ? "Mean time to resolve needs resolved incidents — no lifecycle basis yet"
        : `Mean of created→resolved over ${m.mttrBasis} incident(s)` },
    { label: "Assets at Risk", value: m.assetsAtRisk == null ? "—" : String(m.assetsAtRisk),
      note: m.assetsAtRisk == null ? "no active run" : undefined,
      title: "Assets with a HIGH or CRITICAL finding — LOW/MEDIUM excluded to avoid dilution" },
    { label: "Users at Risk", value: m.usersAtRisk == null ? "—" : String(m.usersAtRisk),
      note: m.usersAtRisk == null ? "no active run" : undefined,
      title: "Accounts targeted by findings in the current run" },
    { label: "Data Sources", value: String(m.dataSources),
      title: "Distinct analyzed sources across the run history" },
  ] : [];

  return (
    <div className="is-panel">
      <div className="is-panel__h">
        <h3>Operational metrics</h3>
        <span className="is-chip" title="Derived from the incident subsystem and the current run's findings — never invented">derived</span>
      </div>

      {isLoading && <p className="is-mut" style={{ fontSize: "12px" }}>Loading operational metrics…</p>}

      {!isLoading && (error || !m) && (
        <div className="is-note" style={{ fontSize: "12px" }}>
          Operational metrics are unavailable — the backend's <code>/api/metrics</code> did
          not answer. Nothing is shown rather than an invented number.
        </div>
      )}

      {m && (
        <>
          <div className="is-kpis" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}>
            {tiles.map(({ label, value, note, title }) => (
              <div key={label} className="is-kpi" title={title} data-testid={`kpi-${label.toLowerCase().replace(/\s+/g, "-")}`}>
                <div className="lbl">{label}</div>
                <div className="val is-tnum">{value}</div>
                {note && <div className="delta na">{note}</div>}
              </div>
            ))}
          </div>
          <p className="is-mut" style={{ fontSize: "11px", marginTop: "10px", lineHeight: 1.5 }}>
            <b style={{ color: "var(--ink)" }}>Operational metrics — derived, never invented.</b>{" "}
            Incident counts and MTTA/MTTR come from the incident subsystem's real lifecycle
            stamps (n/a until incidents are acknowledged or resolved); asset and user risk are
            derived from the current run's findings.
          </p>
        </>
      )}
    </div>
  );
}
