import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

/** Threat Intel — surfaced, not generated, in the itsoc. design system (mirrors
 *  prototype #p-threat). Indicators come from an offline STIX bundle; technique
 *  rollups are the static MITRE mapping each rule carries — derived tags, never
 *  verdicts, and nothing here changes a finding's severity. */
export function ThreatIntel() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["threat-intel"], queryFn: api.threatIntel,
  });

  if (isLoading) return <p className="is-mut">Loading threat intel…</p>;
  if (isError || !data) {
    return <div className="is-note">Couldn't load threat intel — {(error as Error)?.message ?? "no data"}</div>;
  }

  const ruleEntries = Object.entries(data.ruleTechniques);

  return (
    <>
      <div className="is-note">
        <b>Surfaced, not generated — derived tags, not verdicts.</b> Indicators come from an offline
        STIX bundle; the technique rollups are the static MITRE mapping each rule carries. Nothing here
        changes a finding's severity.
      </div>

      <div className="is-grid-2">
        <div className="is-panel">
          <div className="is-panel__h">
            <h3>Indicators of Compromise</h3>
            <span className="is-panel__sub">{data.indicatorSource}</span>
          </div>
          {data.indicators.length === 0 ? (
            <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>The bundle holds no indicators.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="is-table">
                <thead>
                  <tr><th>Name</th><th>Pattern</th><th>Types</th><th>Valid from</th></tr>
                </thead>
                <tbody>
                  {data.indicators.map((ind) => (
                    <tr key={ind.id} data-testid="ioc-row" style={{ cursor: "default" }}>
                      <td style={{ fontWeight: 500 }}>{ind.name}</td>
                      <td className="is-mono" style={{ fontSize: 11, color: "var(--acc)", wordBreak: "break-all" }}>{ind.pattern}</td>
                      <td style={{ fontSize: 11, color: "var(--mut)" }}>{ind.types.join(", ") || "—"}</td>
                      <td className="col-mono">{ind.validFrom || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="is-panel">
          <div className="is-panel__h">
            <h3>Rule → MITRE map</h3>
            <span className="is-panel__sub">static per-rule mapping — derived, not verdicts</span>
          </div>
          {ruleEntries.length === 0 ? (
            <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>No rule mappings available.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {ruleEntries.map(([rule, techniques]) => (
                <div key={rule} style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span className="is-mono" style={{ fontSize: 12, fontWeight: 600 }}>{rule}</span>
                  {techniques.map((t) => (
                    <span key={t.id} className="is-tid" title={`${t.id} · ${t.name} · ${t.tactic}`}>{t.id}</span>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="is-panel">
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10, fontSize: 12.5 }}>
          <span className="is-mut" style={{ fontWeight: 500 }}>MITRE ATT&amp;CK offline cache:</span>
          <span className={data.attackCacheWarm ? "is-chip is-chip--ok" : "is-chip"}
                title="~/.cache/mitre_attack — populated once the ATT&CK dataset has been fetched">
            {data.attackCacheWarm ? "warm" : "cold — technique names come from the static map only"}
          </span>
        </div>
      </div>
    </>
  );
}
