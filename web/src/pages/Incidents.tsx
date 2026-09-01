import { useState, useEffect, type ReactNode } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams, Link, useNavigate } from "react-router-dom";
import { Check, Sparkles, Pencil, X, Shield, ShieldCheck, FolderKanban, Search } from "lucide-react";
import { api, INCIDENT_STATES, CASE_STATUSES, type AttemptPoint, type CaseStatus, type EmbeddedCase, type Incident, type IncidentState, type Rca, type InvestigationEvent, type AdvisoryBlock, type AdvisoryReport } from "@/lib/api";
import { RunbookCard, type RunbookCardData } from "@/components/RunbookCard";
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

const MANUAL_BADGE_FALLBACK = "MANUAL — analyst-created, no rule verdict";
const CASE_STATUS_LABEL: Record<CaseStatus, string> = {
  new: "New", triaged: "Triaged", investigating: "Investigating",
  escalated: "Escalated", resolved: "Resolved", closed: "Closed",
};

/** A manual incident (origin "manual") is an analyst-created case with no rule
 *  verdict. The owner's core C1 honesty constraint: it must be visually
 *  unmistakable and NEVER read as a rule-detected one. */
function isManual(inc: Incident): boolean {
  return inc.origin === "manual";
}

function PriorityChip({ priority }: { priority?: string }) {
  if (!priority) return null;
  const p = priority.toUpperCase();
  const cls = p.toLowerCase();
  return (
    <span
      className={`is-chip is-chip--priority is-chip--${cls}`}
      data-testid="priority-chip"
      title="priority is rule-owned, weighted by asset criticality"
    >
      {p}
    </span>
  );
}

/** Severity presentation that can never misrepresent a manual incident. Rule
 *  incidents show their rule-owned severity tag; manual incidents show a MANUAL
 *  badge and, ONLY when the case actually carried one, an explicitly
 *  analyst-assigned severity — rendered so it can never pass as a rule verdict.
 *  `full` renders the whole badge sentence (detail header); otherwise a compact
 *  MANUAL tag (list rows). */
function IncidentSeverity({ inc, full = false }: { inc: Incident; full?: boolean }) {
  if (!isManual(inc)) return <SevTag sev={inc.severity} />;
  return (
    <span className="is-manual-sev" data-testid="manual-badge">
      <span className="is-tag is-tag--manual" title={inc.manualBadge || MANUAL_BADGE_FALLBACK}>
        {full ? (inc.manualBadge || MANUAL_BADGE_FALLBACK) : "MANUAL"}
      </span>
      {inc.analystSeverity && (
        <span className="is-anasev" data-testid="analyst-severity"
              title="Assigned by an analyst — not a rule verdict">
          analyst-assigned: {inc.analystSeverity.toUpperCase()}
        </span>
      )}
    </span>
  );
}

/** One analyst case absorbed onto an incident (C1-T1 migration). Surfaces the
 *  full pre-merge Cases capability on the merged screen: title, notes, assignee,
 *  case status, and the analyst-chosen linked findings/incidents — kept SEPARATE
 *  from the incident's derived findings. Notes/assignee/status stay editable and
 *  persist through the real PATCH /api/cases/<id>. */
function EmbeddedCaseCard({ c }: { c: EmbeddedCase }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [notes, setNotes] = useState(c.notes);
  const [assignee, setAssignee] = useState(c.assignee);
  const [err, setErr] = useState("");
  const patch = useMutation({
    mutationFn: (p: Parameters<typeof api.patchCase>[1]) => api.patchCase(c.caseId, p),
    onSuccess: (out) => {
      if (!out.ok) { setErr(out.error ?? "Could not save."); return; }
      setErr(""); setEditing(false); qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  return (
    <div className="is-case" data-testid="embedded-case">
      <div className="is-case__h">
        <div style={{ minWidth: 0 }}>
          <div className="is-case__ttl">{c.title || "(untitled case)"}</div>
          <div className="is-mono is-mut2" style={{ fontSize: 10.5 }}>{c.caseId}</div>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span className="is-visually-hidden">Case status of {c.caseId}</span>
          <select className="is-select" style={{ width: "auto", padding: "5px 8px" }}
                  aria-label={`Case status of ${c.caseId}`} value={c.caseStatus} disabled={patch.isPending}
                  onChange={(e) => patch.mutate({ status: e.target.value as CaseStatus })}>
            {CASE_STATUSES.map((s) => <option key={s} value={s}>{CASE_STATUS_LABEL[s]}</option>)}
          </select>
        </label>
        {!editing && (
          <button className="is-icobtn" style={{ width: 26, height: 26 }} aria-label={`Edit ${c.caseId}`}
                  onClick={() => setEditing(true)}><Pencil size={12} aria-hidden /></button>
        )}
      </div>

      {editing ? (
        <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 8 }}>
          <label className="is-field"><span>Assignee</span>
            <input className="is-input" value={assignee} onChange={(e) => setAssignee(e.target.value)}
                   aria-label={`Edit assignee of ${c.caseId}`} /></label>
          <label className="is-field"><span>Notes</span>
            <textarea className="is-input" style={{ minHeight: 60, resize: "vertical" }} value={notes}
                      onChange={(e) => setNotes(e.target.value)} aria-label={`Edit notes of ${c.caseId}`} /></label>
          {err && <p style={{ color: "var(--crit)", fontSize: 11.5, margin: 0 }}>{err}</p>}
          <div style={{ display: "flex", gap: 8 }}>
            <button className="is-btn is-btn--primary" disabled={patch.isPending}
                    onClick={() => patch.mutate({ notes, assignee })}>{patch.isPending ? "Saving…" : "Save"}</button>
            <button className="is-btn" onClick={() => { setEditing(false); setNotes(c.notes); setAssignee(c.assignee); setErr(""); }}>Cancel</button>
          </div>
        </div>
      ) : (
        <>
          {c.notes
            ? <p className="is-mut" style={{ marginTop: 8, whiteSpace: "pre-wrap", fontSize: 12.5, lineHeight: 1.55 }}>{c.notes}</p>
            : <p className="is-mut2" style={{ marginTop: 8, fontSize: 11.5 }}>No notes on this case.</p>}
          <div className="is-case__meta">
            {c.assignee
              ? <span>Assignee: <b style={{ color: "var(--ink)" }}>{c.assignee}</b></span>
              : <span className="na">Unassigned</span>}
            {c.caseCreatedAt && <span>Created {c.caseCreatedAt.slice(0, 16).replace("T", " ")}</span>}
            {c.caseUpdatedAt && <span>Updated {c.caseUpdatedAt.slice(0, 16).replace("T", " ")}</span>}
            {c.linkedFindings.length > 0 && (
              <span className="is-case__links">Findings (analyst-linked):
                {c.linkedFindings.map((f) => (
                  <a key={f} href={`/alerts?sel=${encodeURIComponent(f)}`} className="is-mono lk"
                     title="Open this analyst-linked finding">{f}</a>
                ))}
              </span>
            )}
            {c.linkedIncidents.length > 0 && (
              <span className="is-case__links">Incidents:
                {c.linkedIncidents.map((i) => <span key={i} className="is-mono lk">{i}</span>)}
              </span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/** The absorbed Cases surface on an incident. For a manual incident this is the
 *  incident's own case; for a rule incident it lists any analyst cases linked to
 *  it (many-to-many is fine). Honest empty when nothing is linked. */
function CasesPanel({ inc }: { inc: Incident }) {
  const cases = inc.cases ?? [];
  const navigate = useNavigate();
  const qc = useQueryClient();
  const openCase = useMutation({
    mutationFn: () => api.openIncidentCase(inc.id),
    onSuccess: (out) => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["cases"] });
      if (out.ok && out.case) navigate(`/cases?sel=${encodeURIComponent(out.case.id)}`);
    },
  });
  return (
    <section className="is-panel" data-testid="incident-cases">
      <div className="is-panel__h" style={{ justifyContent: "space-between" }}>
        <h3>Linked analyst cases</h3>
        <button className="is-btn" type="button" disabled={openCase.isPending} onClick={() => openCase.mutate()}>
          {openCase.isPending ? "Opening…" : cases.length ? "Open case file" : "Open case"}
        </button>
      </div>
      {cases.length === 0 ? (
        <p className="is-mut2" style={{ fontSize: 11.5 }}>No analyst case is linked yet. Open case creates one from this incident — not a new verdict.</p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {cases.map((c) => <EmbeddedCaseCard key={c.caseId} c={c} />)}
        </div>
      )}
    </section>
  );
}

/** Create a new analyst case from the merged Incidents screen (create parity
 *  with the pre-merge Cases page). It posts the real POST /api/cases; the
 *  backend migration then surfaces it here as a manual incident (incident-less)
 *  or as an embedded case on the incident it links. */
function NewCase() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [assignee, setAssignee] = useState("");
  const [notes, setNotes] = useState("");
  const [err, setErr] = useState("");
  const create = useMutation({
    mutationFn: () => api.createCase({ title, assignee, notes }),
    onSuccess: (out) => {
      if (!out.ok) { setErr(out.error ?? "Could not create the case."); return; }
      setTitle(""); setAssignee(""); setNotes(""); setErr(""); setOpen(false);
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  if (!open) return <button className="is-btn is-btn--primary" onClick={() => setOpen(true)}>+ New case</button>;

  return (
    <div className="is-panel" style={{ width: "100%" }}>
      <form style={{ display: "flex", flexDirection: "column", gap: 12 }}
            onSubmit={(e) => { e.preventDefault(); if (title.trim()) create.mutate(); }}>
        <div className="is-panel__h">
          <h3>New case</h3>
          <button type="button" className="is-icobtn" aria-label="Cancel new case" style={{ width: 26, height: 26 }}
                  onClick={() => { setOpen(false); setErr(""); }}><X size={14} aria-hidden /></button>
        </div>
        <label className="is-field"><span>Title (required)</span>
          <input className="is-input" value={title} onChange={(e) => setTitle(e.target.value)}
                 aria-label="Case title" placeholder="e.g. Investigate brute-force from 203.0.113.44" /></label>
        <label className="is-field"><span>Assignee</span>
          <input className="is-input" value={assignee} onChange={(e) => setAssignee(e.target.value)}
                 aria-label="Case assignee" placeholder="who is looking at this" /></label>
        <label className="is-field"><span>Notes</span>
          <textarea className="is-input" style={{ minHeight: 64, resize: "vertical" }} value={notes}
                    onChange={(e) => setNotes(e.target.value)} aria-label="Case notes" /></label>
        {err && <p style={{ color: "var(--crit)", fontSize: 11.5, margin: 0 }}>{err}</p>}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button className="is-btn is-btn--primary" type="submit" disabled={!title.trim() || create.isPending}>
            {create.isPending ? "Creating…" : "Create case"}
          </button>
          <span className="is-mut" style={{ fontSize: 11 }}>Status starts as “open”. An unlinked case appears as a manual incident.</span>
        </div>
      </form>
    </div>
  );
}

/** A manual incident's detail: analyst-created, no rule verdict, so it gets a
 *  deliberately DIFFERENT, honest composition from a rule incident — the case
 *  is the content; there is no RCA/evidence/timeline to fabricate. The lifecycle
 *  stepper is the same analyst-owned control. */
function ManualIncidentDetail({ inc, onBack }: { inc: Incident; onBack: () => void }) {
  return (
    <div className="is-rca-layout is-single">
      <div className="is-rca-center">
        <div className="is-crumb">
          <button className="is-crumb__link" onClick={onBack}>Incidents</button>
          <span className="sep">/</span>
          <span className="is-mono is-mut">{inc.id}</span>
        </div>

        <div className="is-rca-head">
          <IncidentSeverity inc={inc} full />
          <PriorityChip priority={(inc as { priority?: string }).priority} />
          <h2 className="ttl">{inc.title || `Manual case ${inc.id}`}</h2>
          <StateChip state={inc.state} />
        </div>
        <div className="is-detail-meta" data-testid="manual-meta">
          {inc.entity && inc.entity !== "—" && <><span className="is-mono">{inc.entity}</span>{" · "}</>}
          created {inc.createdAt ? inc.createdAt.slice(0, 16).replace("T", " ") : "n/a"}
          <span className="is-ro">analyst-created — no rule verdict</span>
        </div>

        <CasesPanel inc={inc} />
        <LifecycleStepper inc={inc} />
      </div>
    </div>
  );
}

/** The analyst-owned lifecycle stepper. NEW → TRIAGED → INVESTIGATING →
 *  ESCALATED → RESOLVED → CLOSED. Shared by rule and manual incidents. */
function LifecycleStepper({ inc }: { inc: Incident }) {
  const qc = useQueryClient();
  const mutation = useMutation({
    mutationFn: (state: IncidentState) => api.setIncidentState(inc.id, state),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
  return (
    <div className="is-lifecycle">
      <div className="cap">Lifecycle · analyst-owned</div>
      <div className="steps">
        {INCIDENT_STATES.map((s) => (
          <button key={s} className={cn("step", s === inc.state && "on")}
                  style={{ textTransform: "capitalize" }}
                  disabled={s === inc.state || mutation.isPending}
                  onClick={() => mutation.mutate(s)}
                  title={s === inc.state ? "Current state" : `Move to ${s}`}>
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
  );
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
          <ol className="is-logpane" data-testid="rca-facts-timeline"
              style={{ marginTop: 8, paddingLeft: 0, listStyle: "none", maxHeight: 180, overflow: "auto" }}>
            {rca.facts.timeline.map((e, i) => (
              <li key={i} style={{ fontSize: "11.5px", padding: "1px 0", overflowWrap: "anywhere" }}>
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

  const dense = events.length > 48;
  const plotted = events
    .map((e, i) => ({ e, i }))
    .filter(({ e }) => !dense || kindOf(e.rule, e.label) === "ok" || kindOf(e.rule, e.label) === "c2");

  return card(
    <>
      {dense && (
        <p className="is-mut" style={{ fontSize: "11.5px", margin: "0 0 8px" }}>
          {events.length.toLocaleString()} sub-events — too dense for one tick each.
          Plotting login-OK / C2 markers only; the reconstructed log is in the pane below.
        </p>
      )}
      <div className="is-tl__axis" role="img" aria-label="attack timeline">
        <div className="is-tl__line" />
        {plotted.map(({ e, i }) => {
          const kind = kindOf(e.rule, e.label);
          const left = `${pctFor(i)}%`;
          const title = `${e.t || "—"} · ${e.label}${e.rule ? ` [${e.rule}]` : ""}`;
          if (kind === "ok" || kind === "c2") {
            return (
              <span key={`${e.t}-${i}`} className="is-tl__dot" style={{ left, background: KIND_VAR[kind] }} title={title}>
                <span className="is-tl__dotlabel" style={{ color: KIND_VAR[kind] }}>
                  {kind === "ok" ? "login OK" : "C2 blocked"}
                </span>
              </span>
            );
          }
          return <span key={`${e.t}-${i}`} className="is-tl__tick" style={{ left, background: KIND_VAR[kind] }} title={title} />;
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
    <details className="is-panel" data-testid="incident-evidence-wrap">
      <summary className="is-panel__h" style={{ cursor: "pointer", listStyle: "revert" }}>
        <h3>Evidence — {lines.length ? `${lines.length.toLocaleString()} verbatim line(s)` : "verbatim log lines"}</h3>
        <span className="is-mut2" style={{ fontSize: 10, fontFamily: "var(--mono)" }}>collapsed · click to expand</span>
      </summary>
      {lines.length ? (
        <div className="is-logpane" style={{ marginTop: 8 }}>
          <div className="is-logpane__meta">
            Scroll inside this pane. Same source lines as the findings — nothing generated.
          </div>
          <pre className="is-evidence" data-testid="incident-evidence">
            {lines.map((l, i) => (
              <div key={i} className={l.crit ? "eline crit" : "eline"}>
                <span className="ln">{l.n}</span>
                <span style={{ minWidth: 0 }}>
                  {l.a}
                  {l.hit && <mark>{l.hit}</mark>}
                  {l.b}
                </span>
              </div>
            ))}
          </pre>
        </div>
      ) : (
        <div className="space-y-2 pt-2">
          <p className="is-mut" style={{ fontSize: "11.5px", margin: 0 }}>
            {isError || !data
              ? "The member findings for this cluster aren't in the loaded run — no verbatim evidence to show."
              : "No stored evidence lines on this cluster's member findings."}
          </p>
          <div className="p-3 rounded border bg-muted/20 flex items-center justify-between text-xs text-muted-foreground">
            <span>
              Member finding(s) <code className="font-mono text-foreground font-semibold">{inc.findingIds.join(", ")}</code> can be reviewed in Findings.
            </span>
            <Link to={`/alerts?sel=${encodeURIComponent(inc.findingIds[0] || "")}`} className="is-btn is-btn--ghost text-xs py-0.5 h-auto">
              Inspect Finding
            </Link>
          </div>
        </div>
      )}
    </details>
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

/** Response panel (C4-F1): the rule-ELIGIBLE runbooks for this incident, each an
 *  is-runbook-card, with a single Request-approval action.
 *
 *  Rule-owned only. The eligible list and every `missing` come straight from the
 *  engine (/runbook-recommendation → runbooks.eligible()); the advisory model
 *  ranking the same endpoint also returns is deliberately NOT surfaced here, so
 *  this panel can never let advice widen eligibility. NO approve control lives
 *  here: Request approval CREATES a pending approval record — approving happens
 *  only in the Approvals screen, behind step-up. A Request that comes back 409
 *  (eligibility drifted since load) flips that card to ineligible with the
 *  engine's own `missing`, verbatim — the same discipline as the 409 body. */
export function ResponsePanel({ inc }: { inc: Incident }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["runbook-recommendation", inc.id],
    queryFn: () => api.incidentRunbookRecommendation(inc.id),
  });
  const reco = data && !("error" in data) ? data : null;
  const eligible = reco?.eligible ?? [];

  const [selId, setSelId] = useState<string | null>(null);
  const selected = eligible.find((e) => e.runbookId === selId) ?? eligible[0] ?? null;

  const [driftMissing, setDriftMissing] = useState<Record<string, string[]>>({});
  const [created, setCreated] = useState<{ runbookId: string; id: string } | null>(null);

  const request = useMutation({
    mutationFn: (rid: string) => api.createApproval({ incidentId: inc.id, runbookId: rid }),
    onSuccess: (res, rid) => {
      if (res.ok && res.approval) setCreated({ runbookId: rid, id: res.approval.id });
      else if (res.missing) setDriftMissing((m) => ({ ...m, [rid]: res.missing! }));
    },
  });

  return (
    <section className="is-panel" data-testid="response-panel">
      <div className="is-panel__h" style={{ justifyContent: "space-between" }}>
        <h3>Response</h3>
        <span className="is-chip">rule-eligible runbooks</span>
      </div>

      {isLoading ? (
        <p className="is-mut" style={{ fontSize: 11.5, margin: 0 }}>Loading eligible runbooks…</p>
      ) : isError ? (
        <p className="is-mut" style={{ fontSize: 11.5, margin: 0, lineHeight: 1.5 }}>
          The runbook engine is unreachable — no runbooks shown. Nothing is invented.
        </p>
      ) : eligible.length === 0 ? (
        // Ineligibility is information, not alarm: no eligible runbook is a
        // normal state, stated plainly and muted — never an error surface.
        <p className="is-mut" data-testid="response-empty" style={{ fontSize: 11.5, margin: 0, lineHeight: 1.5 }}>
          No runbook is eligible for this incident yet — the rules cleared none of their requirements.
          This is information, not a failure.
        </p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {eligible.map((e) => {
            const drift = driftMissing[e.runbookId];
            const rb: RunbookCardData = drift
              ? { runbookId: e.runbookId, name: e.name, severityFloor: e.severityFloor,
                  triggerRules: e.triggerRules, eligible: false, missing: drift }
              : { runbookId: e.runbookId, name: e.name, severityFloor: e.severityFloor,
                  triggerRules: e.triggerRules, eligible: true };
            return (
              <RunbookCard
                key={e.runbookId}
                rb={rb}
                selected={selected?.runbookId === e.runbookId}
                onSelect={() => setSelId(e.runbookId)}
              />
            );
          })}

          <div className="is-response-actions">
            {/* The SINGLE accent action in the Incidents view. It CREATES a
                pending approval — it is not an approve control. */}
            <button
              type="button"
              className="is-btn is-btn--primary"
              data-testid="request-approval"
              disabled={!selected || request.isPending
                || Boolean(driftMissing[selected?.runbookId ?? ""])}
              onClick={() => selected && request.mutate(selected.runbookId)}
            >
              {request.isPending ? "Requesting…" : "Request approval"}
            </button>
          </div>

          {created && (
            <div className="is-response-created" data-testid="approval-created">
              <span>Pending approval created for <span className="is-mono">{created.runbookId}</span>.</span>{" "}
              <Link
                to={`/approvals?sel=${encodeURIComponent(created.id)}`}
                data-testid="open-in-approvals"
                className="is-response-link"
              >
                Open in Approvals →
              </Link>
            </div>
          )}
        </div>
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

      {/* Rapid SOC Actions & Pivots */}
      <section className="is-panel">
        <div className="is-panel__h"><h3>Analyst Actions</h3></div>
        <div className="flex flex-col gap-2">
          <button
            type="button"
            onClick={openCopilot}
            className="is-btn w-full justify-center text-xs gap-1.5 cursor-pointer"
          >
            <Sparkles size={12} className="text-primary" />
            Analyze with AI Copilot
          </button>
          <Link
            to="/intel"
            className="is-btn is-btn--ghost w-full justify-center text-xs gap-1.5"
          >
            <Shield size={12} className="text-blue-400" />
            Search in Threat Intel
          </Link>
          <Link
            to="/approvals"
            className="is-btn is-btn--ghost w-full justify-center text-xs gap-1.5"
          >
            <ShieldCheck size={12} className="text-amber-500" />
            Remediation Approvals
          </Link>
          <Link
            to="/history"
            className="is-btn is-btn--ghost w-full justify-center text-xs gap-1.5"
          >
            <Search size={12} className="text-muted-foreground" />
            Look Up in Run History
          </Link>
        </div>
      </section>

      <BruteforceSparkline inc={inc} />
      <ResponsePanel inc={inc} />
      <ResponseChecklist inc={inc} />
      <IncidentAnalyst inc={inc} />
    </aside>
  );
}

/** A resolvable record {n} citation. Deterministic facts cite records; a cite
 *  resolves when its `n` maps to a real event in the loaded case, and its verbatim
 *  source line is shown on hover. A citation that does NOT resolve is marked
 *  honestly (`.miss`) rather than shown as if it were grounded. */
function RecordCite({ n, byN }: { n: number; byN: Map<number, InvestigationEvent> }) {
  const ev = byN.get(n);
  return (
    <span
      className={cn("is-cite", !ev && "miss")}
      data-testid={`cite-${n}`}
      data-resolves={ev ? "true" : "false"}
      title={ev ? `record ${n}: ${ev.raw}` : `record ${n} is not in the loaded run`}
    >
      {`{${n}}`}
    </span>
  );
}

const CITE_PREVIEW = 8;

/** Cap a long {n} chip list so hundreds of citations cannot leak off-screen.
 *  Hidden ids stay in the DOM once expanded — tests with a handful of records
 *  still see every chip without clicking. */
function CiteList({ ns, byN }: { ns: number[]; byN: Map<number, InvestigationEvent> }) {
  const [open, setOpen] = useState(false);
  const extra = ns.length - CITE_PREVIEW;
  const shown = open || extra <= 0 ? ns : ns.slice(0, CITE_PREVIEW);
  return (
    <span className="is-cite-row">
      {shown.map((n) => <RecordCite key={n} n={n} byN={byN} />)}
      {extra > 0 && (
        <button type="button" className="is-cite-more"
                aria-expanded={open}
                onClick={() => setOpen((v) => !v)}>
          {open ? "show fewer" : `+${extra} more`}
        </button>
      )}
    </span>
  );
}

/** One grounded advisory agent's block (narrative / ATT&CK / pivots). Model
 *  output, never a verdict — so it renders inside the advisory family (dashed
 *  accent + ADVISORY chip) and shows its three honest states: filled prose,
 *  withheld ("rejected"), or a VISIBLE timeout that never becomes prose. */
function AdvisoryBlockView({ block, byN }: { block: AdvisoryBlock; byN: Map<number, InvestigationEvent> }) {
  const timedOut = block.status === "timed_out";
  const pending = (block.status as string) === "pending";
  return (
    <div
      className={cn(
        "is-block is-adv",
        pending && "is-advisory-pending",
        timedOut && "is-advisory-timeout"
      )}
      data-testid={`investigation-adv-${block.kind}`}
      data-adv-status={block.status}
    >
      <div className="flex items-center gap-2" style={{ marginBottom: 6 }}>
        <span className="cap" style={{ marginBottom: 0 }}>{block.kind}</span>
        <span className="is-chip is-chip--adv">{block.label}</span>
      </div>
      {block.status === "complete" && block.sentences.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          {block.sentences.map((s, i) => (
            <p key={i} style={{ fontSize: 12, lineHeight: 1.5 }}>
              {s.text}{" "}
              <CiteList ns={s.records} byN={byN} />
            </p>
          ))}
        </div>
      ) : timedOut ? (
        <div className="note-timeout" data-testid={`advisory-timeout-${block.kind}`}>
          {block.note || "ADVISORY · timed out — retry"}
        </div>
      ) : pending ? (
        <p className="is-mut" style={{ fontSize: "11.5px" }}>
          {block.note || "ADVISORY · pending — agent dispatched"}
        </p>
      ) : (
        <p className="is-mut" style={{ fontSize: "11.5px" }}>
          {block.note || "ADVISORY · unverified — model prose was withheld by the grounding guard"}
        </p>
      )}
    </div>
  );
}

/** The Investigation file (build-doc C2 item 4). The DETERMINISTIC case — timeline
 *  reconstruction, entity/asset correlation, IOCs and blast radius — comes from
 *  /rca and renders immediately, every fact carrying a resolvable record {n}. The
 *  ADVISORY agents are dispatched on a SEPARATE query so the file never waits on
 *  the model; they render pending → filled → visible-timeout, always distinct from
 *  the deterministic blocks so a reader can tell fact from hypothesis at a glance. */
function InvestigationFile({ incidentId }: { incidentId: string }) {
  const { data: rcaData, isLoading } = useQuery({
    queryKey: ["rca", incidentId],
    queryFn: () => api.incidentRca(incidentId),
  });
  const rca = rcaData && !("error" in rcaData) && "facts" in rcaData ? (rcaData as Rca) : null;
  const inv = rca?.investigation;

  // A SEPARATE query — the deterministic file above never blocks on this. Advisory
  // failure is data, not an exception, so keep it out of retry/suspense storms.
  const advisory = useQuery({
    queryKey: ["advisory", incidentId],
    queryFn: () => api.incidentAdvisory(incidentId),
    retry: false,
    staleTime: 30_000,
  });
  const advReport = advisory.data && !("error" in advisory.data) ? (advisory.data as AdvisoryReport) : null;

  // A huge indicator list (hundreds of distinct IPs/hashes) must not stretch the
  // incident ruler out of sight — preview the head, keep the rest one click away.
  const [showAllIocs, setShowAllIocs] = useState(false);

  if (isLoading) {
    return (
      <section className="is-panel" data-testid="investigation-file">
        <div className="is-panel__h"><h3>Investigation file</h3></div>
        <p className="is-mut" style={{ fontSize: "11.5px" }}>Assembling the deterministic case…</p>
      </section>
    );
  }
  if (!inv) {
    return (
      <section className="is-panel" data-testid="investigation-file">
        <div className="is-panel__h"><h3>Investigation file</h3></div>
        <p className="is-mut" style={{ fontSize: "11.5px" }}>
          No investigation file for this incident — its member records are not in the loaded run.
        </p>
      </section>
    );
  }

  const byN = new Map(inv.timeline.map((e) => [e.n, e]));
  const c = inv.correlation;

  return (
    <section className="is-panel" data-testid="investigation-file">
      <div className="is-panel__h" style={{ justifyContent: "space-between" }}>
        <h3>Investigation file</h3>
        <span className="is-chip is-chip--ok" title="Rule-derived and cited — not a model output">
          deterministic · rule-derived
        </span>
      </div>

      <div className="is-invfile">
        {/* ---- DETERMINISTIC: timeline reconstruction (resolvable {n} = the line) */}
        <div className="is-block is-det" data-testid="investigation-deterministic">
          <div className="cap authoritative">Timeline · reconstructed from the events store · every line cited</div>
          {inv.timeline.length ? (
            <details className="is-logpane">
              <summary className="is-logpane__meta" data-testid="investigation-log-count">
                {inv.timeline.length.toLocaleString()} reconstructed line(s) · every line cited · collapsed, click to expand
              </summary>
              <pre className="is-evidence" data-testid="investigation-timeline">
                {inv.timeline.map((e) => (
                  <div key={e.n} className={e.isFinding ? "eline crit" : "eline"} data-testid={`tl-${e.n}`}>
                    <span className="ln">{`{${e.n}}`}</span>
                    <span style={{ minWidth: 0 }}>{e.raw}</span>
                  </div>
                ))}
              </pre>
            </details>
          ) : (
            <div className="space-y-2 py-1">
              <p className="is-mut" style={{ fontSize: "11.5px", margin: 0 }}>No records reconstructed for this entity in the loaded run.</p>
              <div className="flex items-center justify-between text-xs text-muted-foreground bg-muted/20 p-2.5 rounded border border-border/50">
                <span>Timeline reconstruction is active for live runs and analyzed log files.</span>
                <Link to="/history" className="is-btn is-btn--ghost text-xs py-0.5 h-auto">View Run History</Link>
              </div>
            </div>
          )}
        </div>

        {/* ---- DETERMINISTIC: entity / asset correlation */}
        <div className="is-block is-det" data-testid="investigation-correlation">
          <div className="cap authoritative">Correlation · {c.entity ?? "—"} → assets it touched</div>
          {c.assets.length ? c.assets.map((a) => (
            <div key={a.name} className="is-facts-row">
              <span><span className="is-mono">{a.name}</span> <span className="is-mut">· {a.role} · {a.eventCount} record(s)</span></span>
              <b><CiteList ns={a.records} byN={byN} /></b>
            </div>
          )) : (
            <div className="space-y-2 py-1">
              <p className="is-mut" style={{ fontSize: "11.5px", margin: 0 }}>No correlated assets — the entity acted only on itself.</p>
              <div className="flex items-center justify-between text-xs text-muted-foreground bg-muted/20 p-2.5 rounded border border-border/50">
                <span>Scope isolated to entity <code className="font-mono text-foreground font-semibold">{c.entity ?? "—"}</code>. No lateral movement observed.</span>
                <Link to="/assets" className="is-btn is-btn--ghost text-xs py-0.5 h-auto">Asset Inventory</Link>
              </div>
            </div>
          )}
        </div>

        {/* ---- DETERMINISTIC: IOC extraction */}
        <div className="is-block is-det" data-testid="investigation-iocs">
          <div className="cap authoritative">Indicators · extracted from the records, not inferred</div>
          {inv.iocs.length ? (() => {
            const preview = 24;
            const iocs = showAllIocs ? inv.iocs : inv.iocs.slice(0, preview);
            const extra = inv.iocs.length - preview;
            return (
              <>
                {iocs.map((i) => (
                  <div key={`${i.type}:${i.value}`} className="is-facts-row">
                    <span><span className="is-tag is-tag--info is-mono">{i.type}</span> <span className="is-mono">{i.value}</span> <span className="is-mut">· ×{i.count}</span></span>
                    <b><CiteList ns={i.records} byN={byN} /></b>
                  </div>
                ))}
                {extra > 0 && (
                  <button
                    type="button"
                    className="is-cite-more"
                    style={{ marginTop: 6 }}
                    aria-expanded={showAllIocs}
                    data-testid="ioc-show-more"
                    onClick={() => setShowAllIocs((v) => !v)}
                  >
                    {showAllIocs ? `show fewer · ${inv.iocs.length} total` : `+${extra} more indicators (${inv.iocs.length} total)`}
                  </button>
                )}
              </>
            );
          })() : (
            <div className="space-y-2 py-1">
              <p className="is-mut" style={{ fontSize: "11.5px", margin: 0 }}>No indicators extracted from the reconstructed records.</p>
              <div className="flex items-center justify-between text-xs text-muted-foreground bg-muted/20 p-2.5 rounded border border-border/50">
                <span>Primary Observable: <code className="font-mono text-foreground font-semibold">{inv.entity}</code> ({(inv.entityKind || "entity").toUpperCase()})</span>
                <Link to="/intel" className="is-btn is-btn--ghost text-xs py-0.5 h-auto">Threat Intel</Link>
              </div>
            </div>
          )}
        </div>

        {/* ---- DETERMINISTIC: blast radius */}
        <div className="is-block is-det" data-testid="investigation-blast">
          <div className="cap authoritative">Blast radius · everything in scope, each traceable to a record</div>
          <div className="is-facts-row">
            <span className="is-mut">Source</span>
            <b><span className="is-mono">{inv.blastRadius.sourceEntity ?? "—"}</span></b>
          </div>
          <div className="is-facts-row">
            <span className="is-mut">Assets ({inv.blastRadius.assetCount})</span>
            <b className={inv.blastRadius.assets.length ? undefined : "na"}>
              {inv.blastRadius.assets.length ? inv.blastRadius.assets.map((h) => <span key={h} className="is-mono" style={{ marginRight: 8 }}>{h}</span>) : "none"}
            </b>
          </div>
          <div className="is-facts-row">
            <span className="is-mut">Accounts ({inv.blastRadius.accountCount})</span>
            <b className={inv.blastRadius.accounts.length ? undefined : "na"}>
              {inv.blastRadius.accounts.length ? inv.blastRadius.accounts.map((u) => <span key={u} className="is-mono" style={{ marginRight: 8 }}>{u}</span>) : "none"}
            </b>
          </div>
          <div style={{ marginTop: 4 }}><CiteList ns={inv.blastRadius.records} byN={byN} /></div>
        </div>

        {inv.note && <p className="is-mut" style={{ fontSize: 11 }}>{inv.note}</p>}

        {/* ---- ADVISORY: dispatched separately, visually distinct, honest states */}
        <div className="is-adv-head" data-testid="investigation-advisory">
          <span className="cap" style={{ marginBottom: 0 }}>Advisory · model output</span>
          <span className="is-chip is-chip--adv">ADVISORY · hypothesis · not a verdict</span>
          {advReport?.status === "timed_out" && (
            <button className="is-btn is-btn--ghost" style={{ marginLeft: "auto", fontSize: 11 }}
                    data-testid="advisory-retry" onClick={() => advisory.refetch()}>
              retry
            </button>
          )}
        </div>

        {advisory.isLoading || advisory.isFetching ? (
          // PENDING — dispatched, not yet returned. The file above is already complete.
          <div className="is-block is-adv is-advisory-pending" data-testid="advisory-pending">
            <p className="is-mut" style={{ fontSize: "11.5px" }}>
              ADVISORY · pending — three grounded agents dispatched; the deterministic case above does not wait on them.
            </p>
          </div>
        ) : !advReport ? (
          // Route unreachable — a VISIBLE degrade, never a silent omission.
          <div className="is-block is-adv is-advisory-timeout" data-testid="advisory-unavailable">
            <div className="note-timeout">ADVISORY · timed out — retry</div>
            <button className="is-btn is-btn--ghost" style={{ marginTop: 6, fontSize: 11 }}
                    data-testid="advisory-retry" onClick={() => advisory.refetch()}>retry</button>
          </div>
        ) : advReport.blocks.length === 0 && advReport.status === "timed_out" ? (
          // Entire report timed out with no sub-blocks
          <div className="is-block is-adv is-advisory-timeout" data-testid="advisory-timeout-empty">
            <div className="note-timeout">{advReport.note || "ADVISORY · timed out — the eligible list above is complete without it"}</div>
            <button className="is-btn is-btn--ghost" style={{ marginTop: 6, fontSize: 11 }}
                    data-testid="advisory-retry" onClick={() => advisory.refetch()}>retry</button>
          </div>
        ) : (
          advReport.blocks.map((b) => <AdvisoryBlockView key={b.kind} block={b} byN={byN} />)
        )}
      </div>
    </section>
  );
}

function IncidentDetail({ inc, onBack }: { inc: Incident; onBack: () => void }) {
  const qc = useQueryClient();
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const runs = runsQuery.data?.runs ?? [];
  const currentRun = runsQuery.data?.current;

  // Find matching run file for this incident
  const matchingRun = runs.find((r) => r.runId === inc.runId);
  const isDifferentRun = Boolean(matchingRun?.file && currentRun !== matchingRun.file && currentRun !== inc.runId);

  const openRun = useMutation({
    mutationFn: (file: string) => api.openRun(file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rca", inc.id] });
      qc.invalidateQueries({ queryKey: ["advisory", inc.id] });
      qc.invalidateQueries({ queryKey: ["console-state"] });
      qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });

  // Auto-switch run on mount so memory evidence, timeline & correlations load immediately
  useEffect(() => {
    if (matchingRun?.file && isDifferentRun && !openRun.isPending) {
      openRun.mutate(matchingRun.file);
    }
  }, [matchingRun?.file, isDifferentRun]);

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

        {/* Header: severity pill + priority chip + title + state */}
        <div className="is-rca-head">
          <IncidentSeverity inc={inc} full />
          <PriorityChip priority={(inc as { priority?: string }).priority} />
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

        {/* Quick Investigation Action Bar */}
        <div className="flex items-center gap-1.5 py-1 px-1 overflow-x-auto border-b border-border/50 text-[11px]" style={{ marginBottom: 12 }}>
          <span className="text-muted-foreground mr-1 text-[10.5px] font-medium uppercase tracking-wider">Quick Actions:</span>
          <button
            type="button"
            onClick={openCopilot}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors font-medium cursor-pointer"
          >
            <Sparkles size={11} className="text-primary" />
            Ask Incident Copilot
          </button>
          <Link
            to="/intel"
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors font-medium"
          >
            <Shield size={11} className="text-blue-400" />
            Threat Intel Lookup
          </Link>
          <Link
            to="/approvals"
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors font-medium"
          >
            <ShieldCheck size={11} className="text-amber-500" />
            Remediation Approvals
          </Link>
          <Link
            to="/cases"
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors font-medium"
          >
            <FolderKanban size={11} className="text-purple-400" />
            Case Board
          </Link>
        </div>

        <LifecycleStepper inc={inc} />

        {/* Attack timeline (real sub-events, positioned by time) */}
        <AttackTimeline incidentId={inc.id} />

        {/* Investigation file — deterministic case (cited) + separate advisory */}
        <InvestigationFile incidentId={inc.id} />

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

        {/* Correlated findings (rule-derived — kept SEPARATE from analyst-linked) */}
        <section className="is-panel">
          <div className="is-panel__h">
            <h3>{inc.findingCount} correlated finding(s)</h3>
            <span className="is-mut text-[11px]">Rule-derived detection members</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(inc.findingIds || []).map((fid) => (
              <a key={fid} href={`/alerts?sel=${encodeURIComponent(fid)}`}
                className="is-tag is-tag--info is-mono" title="Open this finding in Findings">
                {fid}
              </a>
            ))}
          </div>
        </section>

        {/* Absorbed Cases surface — any analyst case(s) linked to this incident */}
        <CasesPanel inc={inc} />

        {/* Incident History & Audit Log */}
        <section className="is-panel" data-testid="incident-audit">
          <div className="is-panel__h">
            <h3>Incident History & Audit Log</h3>
            <span className="is-mut text-[11px]">Tamper-evident system log</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex items-start justify-between border-b border-border/40 pb-2">
              <div>
                <span className="font-semibold text-foreground">Detection Cluster Created</span>
                <p className="text-muted-foreground text-[11px] mt-0.5">
                  Cluster initialized from correlated findings on entity <code className="font-mono">{inc.entity}</code> ({inc.findingCount} detections).
                </p>
              </div>
              <span className="is-mono text-muted-foreground text-[11px] whitespace-nowrap">
                {inc.createdAt ? inc.createdAt.slice(0, 19).replace("T", " ") : "Initial run"}
              </span>
            </div>
            <div className="flex items-start justify-between border-b border-border/40 pb-2">
              <div>
                <span className="font-semibold text-foreground">Rule Engine Verdict Assigned</span>
                <p className="text-muted-foreground text-[11px] mt-0.5">
                  Severity set to <span className={`font-semibold ${inc.severity === 'CRITICAL' ? 'text-red-500' : 'text-amber-500'}`}>{inc.severity}</span> with Priority <span className="font-semibold">{(inc as { priority?: string }).priority || 'P2'}</span>.
                </p>
              </div>
              <span className="is-mono text-muted-foreground text-[11px] whitespace-nowrap">
                {inc.firstSeen ? inc.firstSeen.slice(0, 19).replace("T", " ") : "Rule engine"}
              </span>
            </div>
            <div className="flex items-start justify-between pb-2">
              <div>
                <span className="font-semibold text-foreground">Lifecycle State: <span className="capitalize text-foreground font-bold">{inc.state}</span></span>
                <p className="text-muted-foreground text-[11px] mt-0.5">
                  Current status in SOC triage workflow. All transitions are recorded in the audit store.
                </p>
              </div>
              <span className="is-mono text-muted-foreground text-[11px] whitespace-nowrap">
                {inc.acknowledgedAt ? inc.acknowledgedAt.slice(0, 19).replace("T", " ") : "Active"}
              </span>
            </div>
          </div>
        </section>
      </div>

      <IncidentRail inc={inc} />
    </div>
  );
}

export function Incidents() {
  const [params, setParams] = useSearchParams();
  const [stateFilter, setStateFilter] = useState<IncidentState | "">("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  // Keeping the index to a viewport-sized slice avoids turning a large run into
  // a long, repetitive scroll. The full filtered result remains reachable.
  const pageSize = 12;
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["incidents", stateFilter],
    queryFn: () => api.incidents(stateFilter || undefined),
    refetchInterval: 5000,
  });

  const incidents = data?.incidents ?? [];
  const selId = params.get("sel");
  const selected = incidents.find((i) => i.id === selId) ?? null;
  const clearSel = () => setParams({});

  const filteredIncidents = incidents.filter((inc) => {
    if (!search.trim()) return true;
    const s = search.toLowerCase();
    return (
      inc.id.toLowerCase().includes(s) ||
      inc.entity.toLowerCase().includes(s) ||
      (inc.title || "").toLowerCase().includes(s) ||
      inc.findingIds.some((f) => f.toLowerCase().includes(s))
    );
  });
  const pageCount = Math.max(1, Math.ceil(filteredIncidents.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const pageStart = currentPage * pageSize;
  const visibleIncidents = filteredIncidents.slice(pageStart, pageStart + pageSize);

  if (isLoading) return <p className="is-mut">Loading incidents…</p>;
  if (isError) {
    return <div className="is-note">Couldn't load incidents — {(error as Error).message}</div>;
  }

  // Selected → the v3 single-incident composition. Manual incidents get a
  // deliberately different, honest layout so they can never read as rule ones.
  if (selected) {
    return isManual(selected)
      ? <ManualIncidentDetail inc={selected} onBack={clearSel} />
      : <IncidentDetail inc={selected} onBack={clearSel} />;
  }

  // Otherwise → the incident index: filter + list + case creation, honest empty.
  return (
    <div className="space-y-4">
      {/* Incident Summary KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border bg-card p-3">
          <div className="text-[10.5px] font-medium text-muted-foreground uppercase tracking-wider">Total Incidents</div>
          <div className="text-xl font-bold font-mono mt-0.5">{incidents.length}</div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Correlated finding clusters</div>
        </div>
        <div className="rounded-lg border bg-card p-3">
          <div className="text-[10.5px] font-medium text-muted-foreground uppercase tracking-wider">Critical / High</div>
          <div className="text-xl font-bold font-mono mt-0.5 text-red-500">
            {incidents.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Rule-owned severity</div>
        </div>
        <div className="rounded-lg border bg-card p-3">
          <div className="text-[10.5px] font-medium text-muted-foreground uppercase tracking-wider">In Progress</div>
          <div className="text-xl font-bold font-mono mt-0.5 text-amber-500">
            {incidents.filter((i) => i.state === "investigating" || i.state === "triaged").length}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Under active review</div>
        </div>
        <div className="rounded-lg border bg-card p-3">
          <div className="text-[10.5px] font-medium text-muted-foreground uppercase tracking-wider">Resolved / Closed</div>
          <div className="text-xl font-bold font-mono mt-0.5 text-emerald-500">
            {incidents.filter((i) => i.state === "resolved" || i.state === "closed").length}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">Lifecycle completed</div>
        </div>
      </div>

      <div className="is-incidents-toolbar">
        <div className="is-incidents-toolbar__filters">
          <select
            className="is-select"
            style={{ maxWidth: 150 }}
            aria-label="Lifecycle filter"
            value={stateFilter}
            onChange={(e) => {
              setStateFilter(e.target.value as IncidentState | "");
              setPage(0);
            }}
          >
            <option value="">All states</option>
            {INCIDENT_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <span className="is-panel__sub is-incidents-toolbar__summary" title={`${incidents.length} incident(s)${stateFilter ? ` · ${stateFilter}` : ""} · rule-detected clusters + analyst-created cases`}>
            {incidents.length} incident(s){stateFilter && ` · ${stateFilter}`} · rule-detected clusters + analyst-created cases
          </span>
        </div>

        <div className="is-incidents-toolbar__actions">
          <div className="relative is-incidents-toolbar__search">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              className="is-input pl-8 py-1 text-xs"
              placeholder="Search incidents…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              aria-label="Search incidents"
            />
          </div>
          <Link to="/cases" className="is-btn">Case board</Link>
          <NewCase />
        </div>
      </div>

      {incidents.length === 0 ? (
        <div className="is-note">
          {stateFilter
            ? `No incidents in the "${stateFilter}" state.`
            : "No incidents yet — an incident is a correlated cluster of the current run's findings, or an analyst-created case. Analyze a log with findings, or add a case, and they'll appear here."}
        </div>
      ) : filteredIncidents.length === 0 ? (
        <div className="is-note">
          No incidents match <b>{search}</b>{stateFilter && ` in the ${stateFilter} state`}.
        </div>
      ) : (
        <div className="is-md !grid-cols-1">
          <div className="is-md__list">
            <div className="overflow-auto">
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
                  {visibleIncidents.map((inc) => (
                    <tr
                      key={inc.id}
                      data-testid="incident-row"
                      onClick={() => setParams({ sel: inc.id })}
                      className="cursor-pointer"
                    >
                      <td>
                        <div style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                          <IncidentSeverity inc={inc} />
                          <PriorityChip priority={(inc as { priority?: string }).priority} />
                        </div>
                      </td>
                      <td><StateChip state={inc.state} /></td>
                      <td className="col-mono" style={{ color: "var(--ink)" }}>
                        {inc.entity}
                        {inc.isRollup && <span className="is-tag is-tag--info" style={{ marginLeft: 6 }}>rollup</span>}
                        {(inc.cases?.length ?? 0) > 0 && !isManual(inc) && (
                          <span className="is-chip" style={{ marginLeft: 6 }} title="This incident has analyst case(s) linked">
                            {inc.cases!.length} case{inc.cases!.length > 1 ? "s" : ""}
                          </span>
                        )}
                      </td>
                      <td className="is-tnum">{inc.findingCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <nav className="is-incidents-pager" aria-label="Incident list pagination">
              <span className="is-panel__sub is-incidents-pager__range">
                Showing {pageStart + 1}–{Math.min(pageStart + pageSize, filteredIncidents.length)} of {filteredIncidents.length}
              </span>
              <div className="is-incidents-pager__controls">
                <button
                  className="is-btn"
                  onClick={() => setPage((value) => Math.max(0, value - 1))}
                  disabled={currentPage === 0}
                >
                  Previous
                </button>
                <span className="is-tnum is-mut" aria-live="polite">Page {currentPage + 1} of {pageCount}</span>
                <button
                  className="is-btn"
                  onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}
                  disabled={currentPage === pageCount - 1}
                >
                  Next
                </button>
              </div>
            </nav>
          </div>
        </div>
      )}
    </div>
  );
}
