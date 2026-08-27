import { useState, type ReactNode } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { Check, Sparkles } from "lucide-react";
import { api, INCIDENT_STATES, type AttemptPoint, type Incident, type IncidentState, type Rca } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Open the shell's real (streaming) analyst — the inline card is a grounded
 *  summary; its chips + ask-box hand off to the shell copilot via its existing
 *  launcher, so we never duplicate the CopilotRail or touch shell chrome. */
function openCopilot() {
  const fab = document.querySelector<HTMLButtonElement>('[data-testid="copilot-fab"]');
  fab?.click();
}

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

/** Parse "HH:MM:SS" or an ISO stamp to a comparable ms value; null if neither. */
function toMs(t?: string | null): number | null {
  if (!t) return null;
  const iso = Date.parse(t);
  if (!Number.isNaN(iso)) return iso;
  const m = /^(\d{1,2}):(\d{2}):(\d{2})/.exec(t);
  if (m) return ((+m[1]) * 3600 + (+m[2]) * 60 + (+m[3])) * 1000;
  return null;
}
type TickKind = "fail" | "ok" | "c2" | "other";
function kindOf(rule?: string, label?: string): TickKind {
  const s = `${rule ?? ""} ${label ?? ""}`.toLowerCase();
  if (/c2|outbound|beacon|block|exfil|callback/.test(s)) return "c2";
  if (/success|accepted|login ok|logged in|granted/.test(s)) return "ok";
  if (/fail|invalid|brute|denied|refused|bad/.test(s)) return "fail";
  return "other";
}
const KIND_VAR: Record<TickKind, string> = {
  fail: "var(--crit)", ok: "var(--low)", c2: "var(--high)", other: "var(--mut)",
};

/** Attack-timeline card (v3): a hairline axis with the cluster's real sub-events
 *  positioned by time — failed-login ticks, and OK/C2 marker dots when such an
 *  event actually occurred. Positions are derived from the events' own stamps;
 *  honest empty when the cluster has no sub-event timeline. */
function AttackTimeline({ incidentId }: { incidentId: string }) {
  const { data } = useQuery({ queryKey: ["rca", incidentId], queryFn: () => api.incidentRca(incidentId) });
  const rca = data && !("error" in data) && "facts" in data ? (data as Rca) : null;
  const events = rca?.facts.timeline ?? [];

  const card = (body: ReactNode) => (
    <section className="is-panel is-tl">
      <div className="is-panel__h"><h3>Attack timeline</h3></div>
      {body}
    </section>
  );

  if (!events.length) {
    return card(
      <p className="is-mut" style={{ fontSize: "11.5px" }}>
        No sub-event timeline for this cluster — the correlated findings carry no ordered events.
      </p>,
    );
  }

  const stamps = events.map((e) => toMs(e.t));
  const known = stamps.filter((v): v is number => v != null);
  const min = known.length ? Math.min(...known) : 0;
  const max = known.length ? Math.max(...known) : 0;
  const span = max - min;
  const pctFor = (i: number) => {
    const v = stamps[i];
    if (v == null || span <= 0) return events.length > 1 ? 8 + (i / (events.length - 1)) * 80 : 48;
    return 8 + ((v - min) / span) * 80;
  };

  const first = events.find((e) => e.t)?.t;
  const last = [...events].reverse().find((e) => e.t)?.t;

  return card(
    <>
      <div className="is-tl__axis" role="img" aria-label="attack timeline">
        <div className="is-tl__line" />
        {events.map((e, i) => {
          const kind = kindOf(e.rule, e.label);
          const left = `${pctFor(i)}%`;
          const title = `${e.t || "—"} · ${e.label}${e.rule ? ` [${e.rule}]` : ""}`;
          if (kind === "ok" || kind === "c2") {
            return (
              <span key={i} className="is-tl__dot" style={{ left, background: KIND_VAR[kind] }} title={title}>
                <span className="is-tl__dotlabel" style={{ color: KIND_VAR[kind] }}>
                  {kind === "ok" ? "login OK" : "C2 blocked"}
                </span>
              </span>
            );
          }
          return <span key={i} className="is-tl__tick" style={{ left, background: KIND_VAR[kind] }} title={title} />;
        })}
        {first && <span className="is-tl__t" style={{ left: "8%" }}>{first.slice(-8)}</span>}
        {last && last !== first && <span className="is-tl__t" style={{ left: "88%" }}>{last.slice(-8)}</span>}
      </div>
      <div className="is-tl__legend">
        <span><i className="tk" style={{ background: "var(--crit)" }} />failed login</span>
        <span><i className="dt" style={{ background: "var(--low)" }} />login OK</span>
        <span><i className="dt" style={{ background: "var(--high)" }} />C2 blocked</span>
      </div>
    </>,
  );
}

/** Verbatim evidence — the real log lines from the incident's member findings
 *  (console_state), never generated. Honest note when the members aren't in the
 *  loaded run. */
function EvidenceCard({ inc }: { inc: Incident }) {
  const { data, isError } = useQuery({ queryKey: ["console-state"], queryFn: api.consoleState });
  const byId = new Map((data?.findings ?? []).map((f) => [f.id, f]));
  const members = inc.findingIds.map((id) => byId.get(id)).filter((f): f is NonNullable<typeof f> => !!f);
  const lines = members.flatMap((f) => f.lines ?? []);

  return (
    <section className="is-panel">
      <div className="is-panel__h"><h3>Evidence — verbatim log lines</h3></div>
      {lines.length ? (
        <>
          <pre className="is-evidence" data-testid="incident-evidence">
            {lines.map((l, i) => (
              <div key={i} className={l.crit ? "eline crit" : "eline"}>
                <span className="ln">{l.n}</span>
                {l.a}
                {l.hit && <mark>{l.hit}</mark>}
                {l.b}
              </div>
            ))}
          </pre>
          <div className="is-mono is-mut2" style={{ fontSize: "10.5px", marginTop: 8 }}>
            verbatim from the source log — nothing generated
          </div>
        </>
      ) : (
        <p className="is-mut" style={{ fontSize: "11.5px" }}>
          {isError || !data
            ? "The member findings for this cluster aren't in the loaded run — no verbatim evidence to show."
            : "No stored evidence lines on this cluster's member findings."}
        </p>
      )}
    </section>
  );
}

/** Build the sparkline area+line path over the attempt points. */
function sparkGeometry(points: AttemptPoint[], w: number, h: number, pad = 4) {
  const vals = points.map((p) => p.attempts);
  const max = Math.max(...vals, 1);
  const min = Math.min(...vals, 0);
  const span = max - min || 1;
  const n = points.length;
  const x = (i: number) => (n === 1 ? w / 2 : pad + (i / (n - 1)) * (w - 2 * pad));
  const y = (v: number) => h - pad - ((v - min) / span) * (h - 2 * pad);
  const line = points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p.attempts).toFixed(1)}`).join(" ");
  const area = `${line} L${x(n - 1).toFixed(1)} ${(h - pad).toFixed(1)} L${x(0).toFixed(1)} ${(h - pad).toFixed(1)} Z`;
  return { line, area, x, y };
}

/** Brute-force attempt sparkline — the entity's failed-login attempts across
 *  the last N saved runs, from GET /api/incidents/<id>/bruteforce (a DERIVED
 *  run-history aggregation, never a verdict). Honest 'n/a — needs ≥2 runs'
 *  when fewer than two real runs carry brute-force activity for the entity. */
function BruteforceSparkline({ inc }: { inc: Incident }) {
  const { data, isLoading } = useQuery({
    queryKey: ["bruteforce", inc.id],
    queryFn: () => api.incidentBruteforce(inc.id),
  });

  const card = (body: ReactNode) => (
    <section className="is-panel" data-testid="bruteforce-card">
      <div className="is-panel__h">
        <h3>Brute-force on {inc.entity} <span className="is-mut2" style={{ fontWeight: 400 }}>· last 7 runs</span></h3>
      </div>
      {body}
    </section>
  );

  if (isLoading) return card(<p className="is-mut" style={{ fontSize: "11.5px" }}>Loading run history…</p>);
  if (!data || !data.available) {
    return card(
      <div className="is-spark-na">
        <div className="is-mono na" style={{ fontSize: 13 }}>n/a — needs ≥2 runs</div>
        <p className="is-mut2" style={{ fontSize: "10.5px", marginTop: 6, lineHeight: 1.5 }}>
          {data?.note ?? "A cross-run trend needs ≥2 runs with brute-force activity for this entity."}
          {" · "}derived from run history, not a verdict
        </p>
      </div>,
    );
  }

  const W = 252, H = 60;
  const { line, area, x, y } = sparkGeometry(data.points, W, H);
  const last = data.points.length - 1;
  const mid = Math.floor(last / 2);
  const up = data.changePct != null && data.changePct > 0;
  const arrow = data.direction === "up" ? "↑" : data.direction === "down" ? "↓" : "→";
  const change = data.changePct == null ? "n/a" : `${data.changePct > 0 ? "+" : ""}${data.changePct}%`;

  return card(
    <div className="is-spark">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none"
        className="is-spark__svg" role="img" aria-label={`brute-force attempts across ${data.runs} runs`}>
        <path d={area} className="is-spark__area" />
        <path d={line} className="is-spark__line" />
        <circle cx={x(last)} cy={y(data.points[last].attempts)} r="3" className="is-spark__dot" />
      </svg>
      <div className="is-spark__x">
        <span>{data.points[0].label}</span>
        {last > 1 && <span>{data.points[mid].label}</span>}
        <span>{data.points[last].label}</span>
      </div>
      <div className="is-spark__stats">
        <div><div className="k">THIS RUN</div><div className="v">{data.thisRun} <span>attempts</span></div></div>
        <div><div className="k">7-RUN AVG</div><div className="v">{data.avg} <span>attempts</span></div></div>
        <div><div className="k">CHANGE</div><div className={cn("v", up ? "up" : "dn")}>{change} <span>vs prior run</span></div></div>
      </div>
      <p className="is-spark__trend">
        {arrow} trending {data.direction} across {data.runs} runs · forecast: {data.forecast} — {data.caption}
      </p>
    </div>,
  );
}

/** Inline itsoc-analyst card (advisory) — a grounded interpretation of THIS
 *  incident from its real RCA (hypothesis + runbook citation); the chips and
 *  ask-box hand off to the shell's real streaming analyst. It never states a
 *  verdict. Distinct testids so it never collides with the shell CopilotRail. */
function IncidentAnalyst({ inc }: { inc: Incident }) {
  const { data } = useQuery({ queryKey: ["rca", inc.id], queryFn: () => api.incidentRca(inc.id) });
  const rca = data && !("error" in data) && "facts" in data ? (data as Rca) : null;
  const runbook = rca?.runbook.matched ? rca.runbook.file : null;
  const chain = inc.techniques.map((t) => t.id).join(" → ");
  const answer = rca?.hypothesis.text
    ?? `${inc.entity} carries ${inc.findingCount} correlated finding(s)${chain ? ` spanning ${chain}` : ""}. The rules set the severity (${(inc.severity || "").toUpperCase()}) — I only interpret what they found, I don't decide it.`;
  const cite = `from ${inc.findingCount} finding(s)${runbook ? ` + ${runbook}` : ""}`;
  const chips = ["Summarize the dashboard", `What's on ${inc.entity}?`, "Recommend next steps"];

  return (
    <section className="is-analyst" data-testid="incident-analyst">
      <div className="is-analyst__h">
        <b><Sparkles className="ic" size={13} aria-hidden /> itsoc analyst</b>
        <span className="adv">advisory</span>
      </div>
      <div className="is-analyst__q">What's the root cause here?</div>
      <div className="is-analyst__a">
        {answer}
        <div className="cite">cited: {cite}</div>
      </div>
      <div className="is-analyst__chips">
        {chips.map((c) => (
          <button key={c} type="button" className="chip" onClick={openCopilot} title="Continue in the analyst">{c}</button>
        ))}
      </div>
      <input
        className="is-analyst__ask"
        placeholder="Ask about this run…"
        aria-label="Ask about this run"
        onKeyDown={(e) => { if (e.key === "Enter") openCopilot(); }}
      />
      <div className="is-analyst__foot" data-testid="incident-analyst-footer">
        Rules set severity. I interpret &amp; explain — I don't decide.
      </div>
    </section>
  );
}

/** Response checklist (v3 dc rail). Items are the cited runbook's OWN list
 *  lines, quoted verbatim — never generated advice. When no runbook clears the
 *  citation bar the card shows the backend's honest no-match note instead of
 *  inventing steps. Ticks are local analyst state; they change nothing. */
function ResponseChecklist({ inc }: { inc: Incident }) {
  const { data } = useQuery({ queryKey: ["rca", inc.id], queryFn: () => api.incidentRca(inc.id) });
  const [done, setDone] = useState<Record<number, boolean>>({});
  const rca = data && !("error" in data) ? (data as Rca) : null;
  const rb = rca?.runbook;

  // A runbook passage is markdown: its "- "/"* "/"1. " lines are the steps.
  const steps: string[] = (rb?.matched ? rb.passage ?? "" : "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => /^([-*]|\d+\.)\s+/.test(l))
    .map((l) => l.replace(/^([-*]|\d+\.)\s+/, ""));

  return (
    <section className="is-panel" data-testid="response-checklist">
      <div className="is-panel__h">
        <h3>Response checklist</h3>
        <span className="is-chip">from runbook</span>
      </div>
      {steps.length === 0 ? (
        <p className="is-mut" style={{ fontSize: "11.5px", margin: 0, lineHeight: 1.5 }}>
          {rb?.matched
            ? `${rb.file} was cited but lists no discrete steps — read the passage above.`
            : rb?.note ?? "No runbook match — no checklist to show."}
        </p>
      ) : (
        <>
          <div className="is-check">
            {steps.map((t, i) => (
              <button key={i} type="button" className={cn("is-check__row", done[i] && "on")}
                      aria-pressed={!!done[i]}
                      onClick={() => setDone((d) => ({ ...d, [i]: !d[i] }))}>
                <span className="box">{done[i] && <Check size={9} strokeWidth={3} aria-hidden />}</span>
                <span className="txt">{t}</span>
              </button>
            ))}
          </div>
          <div className="is-mono is-mut2" style={{ fontSize: 10, marginTop: 8 }}>
            {Object.values(done).filter(Boolean).length}/{steps.length} done · {rb?.file}
          </div>
        </>
      )}
    </section>
  );
}

/** Right rail for the selected incident: real Properties + the real cross-run
 *  brute-force sparkline + the inline itsoc-analyst card (v3 renders). */
function IncidentRail({ inc }: { inc: Incident }) {
  const rows: [string, ReactNode][] = [
    ["Severity", <SevTag key="s" sev={inc.severity} />],
    ["State", <StateChip key="st" state={inc.state} />],
    ["Entity", <span key="e" className="is-mono">{inc.entity}</span>],
    ["Findings", <span key="f" className="is-tnum">{inc.findingCount}</span>],
    ["First seen", <span key="fs" className={inc.firstSeen ? "is-mono" : "na"}>{inc.firstSeen ?? "n/a"}</span>],
    ["Last seen", <span key="ls" className={inc.lastSeen ? "is-mono" : "na"}>{inc.lastSeen ?? "n/a"}</span>],
  ];
  return (
    <aside className="is-rca-rail">
      <section className="is-panel">
        <div className="is-panel__h"><h3>Properties</h3></div>
        <div className="is-facts">
          {rows.map(([label, val]) => (
            <div key={label} className="is-facts-row">
              <span>{label}</span>
              <b>{val}</b>
            </div>
          ))}
          <div className="is-facts-row">
            <span>Techniques</span>
            <b>
              {inc.techniques.length ? (
                <span className="flex flex-wrap gap-1" style={{ justifyContent: "flex-end" }}>
                  {inc.techniques.map((t) => (
                    <span key={t.id} className="is-chip--tech" title={`${t.id} · ${t.name} · ${t.tactic}`}>{t.id}</span>
                  ))}
                </span>
              ) : (
                <span className="na">n/a</span>
              )}
            </b>
          </div>
        </div>
      </section>

      <BruteforceSparkline inc={inc} />
      <ResponseChecklist inc={inc} />
      <IncidentAnalyst inc={inc} />
    </aside>
  );
}

function IncidentDetail({ inc, onBack }: { inc: Incident; onBack: () => void }) {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: (state: IncidentState) => api.setIncidentState(inc.id, state),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });

  const spanLabel = (() => {
    const a = toMs(inc.firstSeen), b = toMs(inc.lastSeen);
    if (a == null || b == null || b < a) return null;
    const s = Math.round((b - a) / 1000);
    return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
  })();

  return (
    <div className="is-rca-layout">
      <div className="is-rca-center">
        {/* Breadcrumb — 'Incidents / <id>' */}
        <div className="is-crumb">
          <button className="is-crumb__link" onClick={onBack}>Incidents</button>
          <span className="sep">/</span>
          <span className="is-mono is-mut">{inc.id}</span>
        </div>

        {/* Header: severity pill + title + state */}
        <div className="is-rca-head">
          <SevTag sev={inc.severity} />
          <h2 className="ttl">{inc.title || `${inc.entity} — ${inc.findingCount} correlated finding(s)`}</h2>
          <StateChip state={inc.state} />
        </div>
        <div className="is-detail-meta">
          <span className="is-mono">{inc.entity}</span>
          {" · "}detected {inc.createdAt ? inc.createdAt.slice(11, 19) : "n/a"}
          {spanLabel && <> · span {spanLabel}</>}
          {" · "}{inc.findingCount} correlated finding(s)
          <span className="is-ro">severity is rule-owned</span>
        </div>

        {/* Attack timeline (real sub-events, positioned by time) */}
        <AttackTimeline incidentId={inc.id} />

        {/* Root cause — advisory territory (§3) */}
        <section className="is-panel" data-testid="rca-panel">
          <div className="is-panel__h" style={{ justifyContent: "space-between" }}>
            <h3>Root cause</h3>
            <span className="is-chip is-chip--adv">advisory · hypothesis · not a verdict</span>
          </div>
          <RcaPanel incidentId={inc.id} />
          {/* Chain — MITRE technique pills (derived tags, not verdicts) */}
          <div className="is-chain">
            <span className="lbl">CHAIN</span>
            {inc.techniques.length ? (
              <span className="pills">
                {inc.techniques.map((t, i) => (
                  <span key={t.id} className="flex items-center gap-1.5">
                    {i > 0 && <span className="is-mut2">→</span>}
                    <span className="is-chip--tech" title={`${t.id} · ${t.name} · ${t.tactic} — derived, does not affect severity`}>{t.id}</span>
                  </span>
                ))}
              </span>
            ) : (
              <span className="is-mut" style={{ fontSize: "11.5px" }}>no techniques mapped</span>
            )}
          </div>
          {inc.attackerStatus && (
            <div style={{ fontSize: "11.5px" }}>
              <span className="is-mut">Kill-chain phase: </span>
              <span title="Derived grouping of member tactics — a display aid, not a verdict">{inc.attackerStatus}</span>
            </div>
          )}
        </section>

        {/* Verbatim evidence */}
        <EvidenceCard inc={inc} />

        {/* Correlated findings + lifecycle (analyst-owned, real stamps) */}
        <section className="is-panel">
          <div className="is-panel__h"><h3>{inc.findingCount} correlated finding(s)</h3></div>
          <div className="flex flex-wrap gap-1.5">
            {inc.findingIds.map((fid) => (
              <a key={fid} href={`/alerts?sel=${encodeURIComponent(fid)}`}
                className="is-tag is-tag--info is-mono" title="Open this finding in Findings">
                {fid}
              </a>
            ))}
          </div>
        </section>

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
          {inc.timeUncertain && (
            <p className="is-mut" style={{ marginTop: 8, fontSize: 11 }}>
              A member finding had no timestamp — it joined this cluster's first group.
            </p>
          )}
        </div>
      </div>

      <IncidentRail inc={inc} />
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
  const clearSel = () => setParams({});

  if (isLoading) return <p className="is-mut">Loading incidents…</p>;
  if (isError) {
    return <div className="is-note">Couldn't load incidents — {(error as Error).message}</div>;
  }

  // Selected → the v3 single-incident RCA composition (center + right rail).
  if (selected) return <IncidentDetail inc={selected} onBack={clearSel} />;

  // Otherwise → the incident index: filter + list, honest empty state.
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
        <div className="is-md !grid-cols-1">
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
                      className="cursor-pointer"
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
        </div>
      )}
    </>
  );
}
