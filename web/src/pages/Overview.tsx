import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ArrowDown, ArrowUp } from "lucide-react";
import { api, type Delta, type OverviewData } from "@/lib/api";
import { sevVar } from "@/lib/severity";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { AlertsOverTime } from "@/components/charts/AlertsOverTime";
import { TacticBars } from "@/components/charts/TacticBars";
import { UnrecognizedBanner } from "@/components/UnrecognizedBanner";
import { useUi } from "@/store/ui";

/** Delta line: the real prior-run delta, or the honest "no prior run — no
 *  delta". Colors follow the design system (.delta.up green / .dn red). */
function DeltaLine({ delta }: { delta: Delta | null }) {
  if (!delta) return <div className="delta na">no prior run — no delta</div>;
  const up = delta.dir === "up";
  return (
    <div className={`delta ${up ? "up" : "dn"}`} style={{ display: "inline-flex", alignItems: "center", gap: 3 }}>
      {up ? <ArrowUp size={11} aria-hidden /> : <ArrowDown size={11} aria-hidden />} {delta.pct}% vs previous
    </div>
  );
}

export function Overview() {
  const { data, isLoading, error } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  // Parse facts (unrecognized / empty / line counts) live in console_state, not
  // in /api/overview — needed to tell "nothing parsed" from "nothing found".
  const { data: state } = useQuery({ queryKey: ["consoleState"], queryFn: api.consoleState });
  const setTimeWindow = useUi((s) => s.setTimeWindow);

  const overview = data && !("error" in data) ? (data as OverviewData) : null;
  const unparsed = !!state && !state.idle && (!!state.unrecognized || !!state.emptyInput);
  useEffect(() => {
    if (overview?.timeWindowLabel) setTimeWindow(overview.timeWindowLabel);
  }, [overview?.timeWindowLabel, setTimeWindow]);

  if (isLoading) return <p className="is-mut">Loading the current run…</p>;
  if (error) {
    return (
      <div className="is-note">
        The console backend is not reachable. Start it with{" "}
        <code>python3 console/serve.py</code> — nothing is shown here rather than sample numbers.
      </div>
    );
  }
  if (!overview) {
    return (
      <div className="is-note">
        {(data as { error: string } | undefined)?.error ?? "No run yet"} — upload a log above or open{" "}
        <Link to="/findings" style={{ color: "var(--acc)" }}>Findings</Link>. No sample data is shown in its place.
      </div>
    );
  }

  const k = overview.kpis;

  // Run-provenance mono strip (DESIGN_HANDOFF §3): every value from the real run.
  const sha = state?.manifest?.detector_sha256;
  const tail = [
    state?.runHosts && `host ${state.runHosts}`,
    state?.runParsed,
    state?.manifest?.ruleset && `ruleset ${state.manifest.ruleset}`,
    overview.model,
    sha && `detector ${sha.slice(0, 8)}…${sha.slice(-6)}`,
  ].filter(Boolean).join(" · ");
  const hasProvenance = !!(state && !state.idle && state.findings);

  return (
    <>
      {/* Honesty guardrail: an unrecognized / empty run must not read as an
          all-clear. Show the banner FIRST, above the zero KPIs. */}
      {unparsed && state && <UnrecognizedBanner state={state} />}
      {unparsed && (
        <p className="text-[12px]" style={{ color: "var(--high)" }}>
          The counts below are all zero because <b>nothing was parsed</b>, not because nothing was
          found. Open <Link to="/findings" style={{ color: "var(--acc)" }}>Findings</Link> for the run details.
        </p>
      )}

      {hasProvenance && (
        <div className="is-note is-mono" style={{ fontSize: "10.5px" }}>
          {state?.sourceLabel && (
            <span title={state.sourceLabel}>{state.sourceLabel.split("/").pop()}</span>
          )}
          {tail && ` · ${tail}`}
          {state?.llmNote && (
            <span title={state.llmNote}> · rules-only run — explanations skipped (model offline)</span>
          )}
        </div>
      )}

      <div className="is-kpis">
        <div className="is-kpi">
          <div className="lbl">Total</div>
          <div className="val is-tnum">{k.total.toLocaleString()}</div>
          <DeltaLine delta={k.deltas.total} />
        </div>
        <div className="is-kpi val-crit">
          <div className="lbl">Critical</div>
          <div className="val is-tnum">{k.critical.toLocaleString()}</div>
          <DeltaLine delta={k.deltas.critical} />
        </div>
        <div className="is-kpi val-high">
          <div className="lbl">High</div>
          <div className="val is-tnum">{k.high.toLocaleString()}</div>
          <DeltaLine delta={k.deltas.high} />
        </div>
        <div className="is-kpi val-med">
          <div className="lbl">Medium</div>
          <div className="val is-tnum">{k.medium.toLocaleString()}</div>
          <DeltaLine delta={k.deltas.medium} />
        </div>
        <div className="is-kpi val-low">
          <div className="lbl">Low</div>
          <div className="val is-tnum">{k.low.toLocaleString()}</div>
          <DeltaLine delta={k.deltas.low} />
        </div>
      </div>

      <div className="is-grid-3">
        <div className="is-panel">
          <div className="is-panel__h"><h3>Alerts by severity</h3></div>
          <SeverityDonut data={overview.severityDonut} />
        </div>
        <div className="is-panel">
          <div className="is-panel__h"><h3>Alerts over time</h3></div>
          <AlertsOverTime data={overview.alertsOverTime} />
        </div>
        <div className="is-panel">
          <div className="is-panel__h">
            <h3>Top ATT&amp;CK tactics</h3>
            <span className="is-chip">derived · not a verdict</span>
          </div>
          <TacticBars data={overview.mitreTactics} />
        </div>
      </div>

      <div className="is-panel">
        <div className="is-panel__h">
          <h3>Latest alerts</h3>
          <span className="is-panel__sub">
            {overview.latestAlerts.length} most recent of {k.total} · drill into Findings for evidence
          </span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="is-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Sev</th>
                <th>Attacker status</th>
                <th>Alert</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {overview.latestAlerts.length === 0 && (
                <tr>
                  <td colSpan={5} className="is-mut" style={{ textAlign: "center", padding: "16px" }}>
                    No findings in this window.
                  </td>
                </tr>
              )}
              {overview.latestAlerts.map((a) => (
                <tr
                  key={a.id}
                  data-testid="latest-alert-row"
                  onClick={() => { window.location.href = `/alerts?sel=${encodeURIComponent(a.id)}`; }}
                >
                  <td className="col-mono">{a.time}</td>
                  <td>
                    <span
                      className="is-tag"
                      style={{ background: `color-mix(in srgb, ${sevVar(a.severity)} 17%, transparent)`, color: sevVar(a.severity) }}
                    >
                      {a.severity.toUpperCase()}
                    </span>
                  </td>
                  <td title="Derived kill-chain grouping of this alert's MITRE tactics — a display aid, not a verdict">
                    {a.attackerStatus || "—"}
                  </td>
                  <td>
                    {a.name}
                    <Link
                      to={`/alerts?sel=${encodeURIComponent(a.id)}`}
                      aria-label="View finding"
                      title="View this finding's evidence in Findings"
                      style={{ marginLeft: 8, color: "var(--acc)", fontSize: "11px" }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      view →
                    </Link>
                  </td>
                  <td className="col-mono">
                    {a.source ? <span title={a.source}>{a.source.split("/").pop()}</span> : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
