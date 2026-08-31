import { useState } from "react";
import { useSearchParams, useParams, Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, X, ArrowLeft, Send, Sparkles, Paperclip } from "lucide-react";
import {
  api,
  CASE_STATUSES,
  type Case,
  type CaseStatus,
  type CaseActivity,
  type CopilotRunbookRow,
} from "@/lib/api";

const STATUS_COLOR: Record<CaseStatus, string> = {
  new: "var(--acc)",
  triaged: "var(--med)",
  investigating: "var(--high)",
  escalated: "var(--crit)",
  resolved: "var(--low)",
  closed: "var(--mut)",
};

const STATUS_LABEL: Record<CaseStatus, string> = {
  new: "New",
  triaged: "Triaged",
  investigating: "Investigating",
  escalated: "Escalated",
  resolved: "Resolved",
  closed: "Closed",
};

export function StatusPill({ status }: { status: CaseStatus }) {
  const c = STATUS_COLOR[status] || "var(--mut)";
  return (
    <span
      className="is-state"
      style={{ color: c, borderColor: "color-mix(in srgb, " + c + " 45%, transparent)" }}
    >
      <i style={{ display: "inline-block", width: 6, height: 6, borderRadius: "50%", background: c }} />
      {STATUS_LABEL[status] || status}
    </span>
  );
}

function CreateCase() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [assignee, setAssignee] = useState("");
  const [category, setCategory] = useState("");
  const [notes, setNotes] = useState("");
  const [err, setErr] = useState("");

  const create = useMutation({
    mutationFn: () => api.createCase({ title, assignee, category, notes }),
    onSuccess: (out) => {
      if (!out.ok) {
        setErr(out.error ?? "Could not create the case.");
        return;
      }
      setTitle("");
      setAssignee("");
      setCategory("");
      setNotes("");
      setErr("");
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  if (!open) {
    return (
      <button className="is-btn is-btn--primary" onClick={() => setOpen(true)}>
        + New case
      </button>
    );
  }

  return (
    <div className="is-panel" style={{ width: "100%" }}>
      <form
        style={{ display: "flex", flexDirection: "column", gap: 12 }}
        onSubmit={(e) => {
          e.preventDefault();
          if (title.trim()) create.mutate();
        }}
      >
        <div className="is-panel__h">
          <h3>New case</h3>
          <button
            type="button"
            className="is-icobtn"
            aria-label="Cancel new case"
            onClick={() => {
              setOpen(false);
              setErr("");
            }}
            style={{ width: 26, height: 26 }}
          >
            <X size={14} aria-hidden />
          </button>
        </div>
        <label className="is-field">
          <span>Title (required)</span>
          <input
            className="is-input"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            aria-label="Case title"
            placeholder="e.g. Investigate brute-force from 203.0.113.44"
          />
        </label>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <label className="is-field">
            <span>Assignee</span>
            <input
              className="is-input"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              aria-label="Case assignee"
              placeholder="who is looking at this"
            />
          </label>
          <label className="is-field">
            <span>Category</span>
            <input
              className="is-input"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              aria-label="Case category"
              placeholder="e.g. Authentication, Malware, Phishing"
            />
          </label>
        </div>
        <label className="is-field">
          <span>Notes</span>
          <textarea
            className="is-input"
            style={{ minHeight: 64, resize: "vertical" }}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            aria-label="Case notes"
          />
        </label>
        {err && <p style={{ color: "var(--crit)", fontSize: 11.5, margin: 0 }}>{err}</p>}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            className="is-btn is-btn--primary"
            type="submit"
            disabled={!title.trim() || create.isPending}
          >
            {create.isPending ? "Creating…" : "Create case"}
          </button>
          <span className="is-mut" style={{ fontSize: 11 }}>
            Status starts as NEW.
          </span>
        </div>
      </form>
    </div>
  );
}

function KanbanCard({ c }: { c: Case }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const links = [...(c.links?.findings ?? []), ...(c.links?.incidents ?? [])];

  const patch = useMutation({
    mutationFn: (p: Parameters<typeof api.patchCase>[1]) => api.patchCase(c.id, p),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  return (
    <div
      className="is-kanban-card"
      data-testid={`case-card-${c.id}`}
      onClick={() => navigate(`/cases?sel=${encodeURIComponent(c.id)}`)}
    >
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
        <div className="is-kanban-card__title">{c.title}</div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
        <span className="is-mono is-mut" style={{ fontSize: 10.5 }}>
          {c.id}
        </span>
        {c.category && (
          <span
            className="is-tag"
            style={{
              fontSize: 9,
              background: "var(--inset)",
              color: "var(--ink2)",
              border: "1px solid var(--bd)",
            }}
          >
            {c.category}
          </span>
        )}
      </div>
      <div className="is-kanban-card__meta">
        <span>
          Assignee: <b style={{ color: "var(--ink)" }}>{c.assignee || "Unassigned"}</b>
        </span>
      </div>
      {links.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 4, marginTop: 2 }}>
          {links.map((l) => (
            <span
              key={l}
              className="is-mono is-mut2"
              style={{
                border: "1px solid var(--bd)",
                borderRadius: 4,
                padding: "0 4px",
                fontSize: 9.5,
              }}
            >
              {l}
            </span>
          ))}
        </div>
      )}
      {/* State transition buttons */}
      <div
        className="is-lifecycle"
        data-testid={`case-lifecycle-${c.id}`}
        style={{ margin: "4px 0 0", borderTop: "1px solid var(--bd)", paddingTop: 6 }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="steps" style={{ gap: 4 }}>
          {CASE_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              className={s === c.status ? "step on" : "step"}
              style={{ textTransform: "capitalize", fontSize: 10, padding: "3px 7px" }}
              aria-label={`Status of ${c.id}: ${s}`}
              disabled={s === c.status || patch.isPending}
              onClick={(e) => {
                e.stopPropagation();
                patch.mutate({ status: s });
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

type RightTab = "overview" | "observables" | "notes" | "attachments" | "linked" | "events";

function CaseFileView({ caseItem }: { caseItem: Case }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<RightTab>("overview");
  const [editingTitle, setEditingTitle] = useState(false);
  const [title, setTitle] = useState(caseItem.title);
  const [assignee, setAssignee] = useState(caseItem.assignee);
  const [category, setCategory] = useState(caseItem.category || "");
  const [notes, setNotes] = useState(caseItem.notes);
  const [comment, setComment] = useState("");
  const [obsType, setObsType] = useState("ip");
  const [obsValue, setObsValue] = useState("");
  const [attName, setAttName] = useState("");
  const [attType, setAttType] = useState("log");
  const [summaryDraft, setSummaryDraft] = useState<typeof caseItem.summary | null>(null);
  const [statusErr, setStatusErr] = useState("");
  const [wfMessage, setWfMessage] = useState("");

  const { data: runbooksData } = useQuery({
    queryKey: ["copilot-runbooks"],
    queryFn: api.copilotRunbooks,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["cases"] });

  const patch = useMutation({
    mutationFn: (p: Parameters<typeof api.patchCase>[1]) => api.patchCase(caseItem.id, p),
    onSuccess: (out) => {
      if (!out.ok) {
        setStatusErr(out.error ?? "Could not save.");
        return;
      }
      setStatusErr("");
      setEditingTitle(false);
      invalidate();
    },
  });

  const postComment = useMutation({
    mutationFn: () => api.caseComment(caseItem.id, comment),
    onSuccess: (out) => {
      if (out.ok) {
        setComment("");
        invalidate();
      }
    },
  });

  const addObservable = useMutation({
    mutationFn: () => api.addCaseObservable(caseItem.id, { type: obsType, value: obsValue }),
    onSuccess: (out) => {
      if (out.ok) {
        setObsValue("");
        invalidate();
      }
    },
  });

  const addAttachment = useMutation({
    mutationFn: () => api.addCaseAttachment(caseItem.id, { name: attName, type: attType }),
    onSuccess: (out) => {
      if (out.ok) {
        setAttName("");
        invalidate();
      }
    },
  });

  const runWorkflow = useMutation({
    mutationFn: (runbookId: string) => api.runCaseWorkflow(caseItem.id, runbookId),
    onSuccess: (out) => {
      if (out.ok) {
        setWfMessage("Workflow dispatched successfully.");
        invalidate();
      } else {
        setWfMessage(out.error ?? "Workflow execution failed.");
      }
    },
  });

  const activityList: CaseActivity[] = [
    ...(caseItem.activity ?? []),
    ...(caseItem.history?.map((h, i) => ({
      id: `hist-${i}`,
      ts: h.at,
      actor: "system",
      action: `Status changed to ${h.status}`,
      kind: "system" as const,
    })) ?? []),
  ].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

  const summary = summaryDraft ?? caseItem.summary;
  const runbooks: CopilotRunbookRow[] = runbooksData?.runbooks ?? [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Header bar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            type="button"
            className="is-btn is-btn--ghost"
            onClick={() => navigate("/cases")}
            style={{ padding: "4px 8px", fontSize: 12 }}
          >
            <ArrowLeft size={14} aria-hidden /> Back to cases
          </button>
          <span className="is-mono is-mut" style={{ fontSize: 12 }}>
            {caseItem.id}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <StatusPill status={caseItem.status} />
        </div>
      </div>

      {/* Title area */}
      <div className="is-panel" style={{ padding: "14px 16px" }}>
        {editingTitle ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input
              className="is-input"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              aria-label={`Edit title of ${caseItem.id}`}
              style={{ fontSize: 16, fontWeight: 600 }}
            />
            <button
              className="is-btn is-btn--primary"
              onClick={() => title.trim() && patch.mutate({ title })}
              disabled={!title.trim() || patch.isPending}
            >
              Save
            </button>
            <button
              className="is-btn"
              onClick={() => {
                setEditingTitle(false);
                setTitle(caseItem.title);
              }}
            >
              Cancel
            </button>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
            <h2 style={{ fontSize: 18, fontWeight: 650, margin: 0, color: "var(--ink)" }}>{caseItem.title}</h2>
            <button
              className="is-icobtn"
              style={{ width: 28, height: 28 }}
              onClick={() => setEditingTitle(true)}
              aria-label={`Edit title of ${caseItem.id}`}
            >
              <Pencil size={13} aria-hidden />
            </button>
          </div>
        )}
        <div className="is-mut" style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: "4px 16px", fontSize: 11 }}>
          <span>Created: {caseItem.createdAt?.slice(0, 16).replace("T", " ") || "n/a"}</span>
          <span>Updated: {caseItem.updatedAt?.slice(0, 16).replace("T", " ") || "n/a"}</span>
          {caseItem.category && <span>Category: <b style={{ color: "var(--ink)" }}>{caseItem.category}</b></span>}
        </div>
      </div>

      {/* 2-Column Split: Left Controls/Timeline & Right Tabs */}
      <div className="is-casefile">
        {/* Left Column */}
        <div className="is-casefile__left">
          {/* Status Machine / Stepper */}
          <div>
            <div className="is-approval-lbl" style={{ marginBottom: 6 }}>
              Status lifecycle · analyst-owned
            </div>
            <div className="is-lifecycle" data-testid={`case-file-lifecycle-${caseItem.id}`} style={{ margin: 0 }}>
              <div className="steps">
                {CASE_STATUSES.map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={s === caseItem.status ? "step on" : "step"}
                    style={{ textTransform: "capitalize" }}
                    aria-label={`Status of ${caseItem.id}: ${s}`}
                    disabled={s === caseItem.status || patch.isPending}
                    onClick={() => patch.mutate({ status: s })}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
            {statusErr && <p style={{ color: "var(--crit)", fontSize: 11, margin: "4px 0 0" }}>{statusErr}</p>}
          </div>

          {/* Assignee & Category Fields */}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <label className="is-field">
              <span>Assignee</span>
              <div style={{ display: "flex", gap: 6 }}>
                <input
                  className="is-input"
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  aria-label="Assignee"
                  placeholder="Unassigned"
                />
                <button
                  className="is-btn"
                  type="button"
                  disabled={assignee === caseItem.assignee || patch.isPending}
                  onClick={() => patch.mutate({ assignee })}
                >
                  Update
                </button>
              </div>
            </label>

            <label className="is-field">
              <span>Category</span>
              <div style={{ display: "flex", gap: 6 }}>
                <input
                  className="is-input"
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  aria-label="Category"
                  placeholder="e.g. Authentication"
                />
                <button
                  className="is-btn"
                  type="button"
                  disabled={category === (caseItem.category || "") || patch.isPending}
                  onClick={() => patch.mutate({ category })}
                >
                  Update
                </button>
              </div>
            </label>
          </div>

          {/* Workflow Picker: only eligible shipped runbooks */}
          <div style={{ borderTop: "1px solid var(--bd)", paddingTop: 12 }}>
            <div className="is-approval-lbl" style={{ marginBottom: 4 }}>
              Run a workflow · shipped runbooks
            </div>
            <p className="is-mut2" style={{ fontSize: 11, margin: "0 0 8px" }}>
              Eligibility is rule-owned. No ungated quarantine actions.
            </p>
            {runbooks.length === 0 ? (
              <div className="is-note" style={{ fontSize: 11, padding: 8 }}>
                No shipped runbooks loaded.
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {runbooks.map((rb) => (
                  <div
                    key={rb.id}
                    className="is-block"
                    style={{ padding: "8px 10px", display: "flex", flexDirection: "column", gap: 4 }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6 }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: "var(--ink)" }}>
                        {rb.name || rb.id}
                      </span>
                      <span
                        className="is-tag"
                        style={{
                          fontSize: 9,
                          border: "1px solid var(--bd)",
                          color: rb.eligible ? "var(--acc)" : "var(--mut)",
                          background: "transparent",
                        }}
                      >
                        {rb.eligible ? "eligible" : "ineligible"}
                      </span>
                    </div>
                    {!rb.eligible && rb.missing?.[0] && (
                      <div className="is-mut2" style={{ fontSize: 10.5 }}>
                        Reason: {rb.missing[0]}
                      </div>
                    )}
                    <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 2 }}>
                      <button
                        className="is-btn is-btn--primary"
                        style={{ padding: "3px 8px", fontSize: 11, height: 26 }}
                        disabled={!rb.eligible || runWorkflow.isPending}
                        onClick={() => runWorkflow.mutate(rb.id)}
                      >
                        {rb.eligible ? "Run workflow" : "Ineligible"}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {wfMessage && (
              <p className="is-mut" style={{ fontSize: 11, marginTop: 6 }}>
                {wfMessage}
              </p>
            )}
          </div>

          {/* Activity Timeline */}
          <div style={{ borderTop: "1px solid var(--bd)", paddingTop: 12 }}>
            <div className="is-approval-lbl" style={{ marginBottom: 6 }}>
              Activity timeline · human &amp; system actions
            </div>
            {activityList.length === 0 ? (
              <div className="is-mut2" style={{ fontSize: 11 }}>
                No activity recorded yet.
              </div>
            ) : (
              <div className="is-timeline" data-testid="case-activity-timeline">
                {activityList.map((act, idx) => (
                  <div key={act.id || idx} className="is-timeline__item">
                    <div className="is-timeline__h">
                      <span className="is-timeline__actor">{act.actor}</span>
                      <span className="is-timeline__ts">
                        {act.ts ? act.ts.slice(0, 16).replace("T", " ") : ""}
                      </span>
                    </div>
                    <div className="is-timeline__body">
                      {act.action}
                      {act.message ? `: ${act.message}` : ""}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Comment Composer */}
          <div style={{ borderTop: "1px solid var(--bd)", paddingTop: 12 }}>
            <label className="is-field">
              <span>Add comment</span>
              <textarea
                className="is-input"
                style={{ minHeight: 52, resize: "vertical", fontSize: 12 }}
                placeholder="Type a comment or investigation note…"
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                aria-label="Case comment input"
              />
            </label>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 6 }}>
              <button
                className="is-btn is-btn--primary"
                style={{ fontSize: 12, height: 28 }}
                disabled={!comment.trim() || postComment.isPending}
                onClick={() => postComment.mutate()}
              >
                <Send size={12} aria-hidden /> Post comment
              </button>
            </div>
          </div>
        </div>

        {/* Right Column (Tabs) */}
        <div className="is-casefile__right">
          {/* Tab Navigation Bar */}
          <div className="is-tabs" role="tablist">
            {(["overview", "observables", "notes", "attachments", "linked", "events"] as RightTab[]).map((tab) => (
              <button
                key={tab}
                role="tab"
                aria-selected={activeTab === tab}
                className={activeTab === tab ? "on" : ""}
                style={{ textTransform: "capitalize" }}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            ))}
          </div>

          {/* Tab 1: Overview */}
          {activeTab === "overview" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }} data-testid="tab-overview">
              <div className="is-block">
                <div className="cap authoritative">Case summary</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--ink)", marginBottom: 4 }}>
                  {caseItem.title}
                </div>
                {caseItem.notes ? (
                  <p style={{ fontSize: 12.5, color: "var(--ink2)", whiteSpace: "pre-wrap" }}>
                    {caseItem.notes}
                  </p>
                ) : (
                  <p className="is-mut2" style={{ fontSize: 12 }}>No notes provided yet.</p>
                )}
              </div>

              {/* Advisory Summary if present */}
              {summary ? (
                <div className="is-block is-adv" data-testid="case-advisory-summary">
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                    <div className="cap">Advisory summary</div>
                    <span className="is-chip is-chip--adv">advisory · summary · not a verdict</span>
                  </div>
                  {summary.what && (
                    <div style={{ marginBottom: 6 }}>
                      <div className="is-mut2" style={{ fontSize: 10.5, textTransform: "uppercase" }}>What happened</div>
                      <div style={{ fontSize: 12, color: "var(--ink)" }}>{summary.what}</div>
                    </div>
                  )}
                  {summary.impact && (
                    <div style={{ marginBottom: 6 }}>
                      <div className="is-mut2" style={{ fontSize: 10.5, textTransform: "uppercase" }}>Potential impact</div>
                      <div style={{ fontSize: 12, color: "var(--ink)" }}>{summary.impact}</div>
                    </div>
                  )}
                  {summary.when && (
                    <div>
                      <div className="is-mut2" style={{ fontSize: 10.5, textTransform: "uppercase" }}>Timeline / Window</div>
                      <div style={{ fontSize: 12, color: "var(--ink)" }}>{summary.when}</div>
                    </div>
                  )}
                </div>
              ) : null}

              {/* Regenerable Advisory Summary Button */}
              <div>
                <button
                  type="button"
                  className="is-btn"
                  style={{ fontSize: 11.5 }}
                  onClick={() => {
                    setSummaryDraft({
                      what: `${caseItem.title} — investigation initiated for category ${caseItem.category || "general"}.`,
                      impact: caseItem.links?.incidents?.length ? "Linked to active security incidents." : "No critical compromise identified so far.",
                      when: caseItem.createdAt ? `Observed since ${caseItem.createdAt.slice(0, 16).replace("T", " ")}` : "Current run window",
                    });
                  }}
                >
                  <Sparkles size={12} className="text-primary" aria-hidden /> Regenerate advisory summary
                </button>
                <span className="is-mut2" style={{ fontSize: 10.5, marginLeft: 8 }}>
                  Advisory only — never changes severity.
                </span>
              </div>

              {/* Linked Incident Facts */}
              <div className="is-block">
                <div className="cap authoritative">Linked Incident Facts</div>
                {caseItem.links?.incidents?.length ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {caseItem.links.incidents.map((incId) => (
                      <div key={incId} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 12 }}>
                        <span className="is-mono">{incId}</span>
                        <Link to={`/incidents?sel=${encodeURIComponent(incId)}`} style={{ color: "var(--acc)", fontSize: 11 }}>
                          view incident →
                        </Link>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="is-mut2" style={{ fontSize: 11.5 }}>
                    No linked incidents.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab 2: Observables */}
          {activeTab === "observables" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }} data-testid="tab-observables">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span className="is-approval-lbl">Real case observables</span>
                <span className="is-mut" style={{ fontSize: 11 }}>
                  {caseItem.observables?.length ?? 0} item(s)
                </span>
              </div>

              {(!caseItem.observables || caseItem.observables.length === 0) ? (
                <div className="is-note" style={{ textAlign: "center", padding: "20px 12px" }}>
                  <div style={{ fontWeight: 600, color: "var(--ink)" }}>No observables yet.</div>
                  <p className="is-mut2" style={{ fontSize: 11.5, margin: "4px 0 0" }}>
                    No real observables recorded for this case. Add one below.
                  </p>
                </div>
              ) : (
                <div className="is-table-wrap">
                  <table className="is-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Source</th>
                        <th>Added</th>
                      </tr>
                    </thead>
                    <tbody>
                      {caseItem.observables.map((o, idx) => (
                        <tr key={o.id || idx}>
                          <td>
                            <span className="is-tag is-tag--info" style={{ textTransform: "uppercase" }}>
                              {o.type}
                            </span>
                          </td>
                          <td>
                            <span className="is-mono" style={{ color: "var(--ink)", fontWeight: 500 }}>
                              {o.value}
                            </span>
                          </td>
                          <td className="is-mut">{o.source || "analyst"}</td>
                          <td className="col-mono">{o.addedAt ? o.addedAt.slice(0, 10) : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Add Observable Form */}
              <form
                className="is-panel"
                style={{ padding: 12, display: "flex", gap: 8, alignItems: "flex-end" }}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (obsValue.trim()) addObservable.mutate();
                }}
              >
                <label className="is-field" style={{ minWidth: 100 }}>
                  <span>Type</span>
                  <select
                    className="is-select"
                    value={obsType}
                    onChange={(e) => setObsType(e.target.value)}
                    aria-label="Observable type"
                  >
                    <option value="ip">IP</option>
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="hash">Hash</option>
                    <option value="account">Account</option>
                    <option value="host">Host</option>
                  </select>
                </label>
                <label className="is-field" style={{ flex: 1 }}>
                  <span>Value</span>
                  <input
                    className="is-input"
                    placeholder="e.g. 203.0.113.44 or https://evil.com"
                    value={obsValue}
                    onChange={(e) => setObsValue(e.target.value)}
                    aria-label="Observable value"
                  />
                </label>
                <button
                  className="is-btn is-btn--primary"
                  type="submit"
                  disabled={!obsValue.trim() || addObservable.isPending}
                >
                  Add observable
                </button>
              </form>
            </div>
          )}

          {/* Tab 3: Notes */}
          {activeTab === "notes" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }} data-testid="tab-notes">
              <label className="is-field">
                <span>Case notes</span>
                <textarea
                  className="is-input"
                  style={{ minHeight: 180, resize: "vertical", lineHeight: 1.55 }}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  aria-label="Detailed case notes"
                />
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <button
                  className="is-btn is-btn--primary"
                  disabled={notes === caseItem.notes || patch.isPending}
                  onClick={() => patch.mutate({ notes })}
                >
                  {patch.isPending ? "Saving…" : "Save notes"}
                </button>
                <button
                  className="is-btn"
                  onClick={() => setNotes(caseItem.notes)}
                  disabled={notes === caseItem.notes}
                >
                  Reset
                </button>
              </div>
            </div>
          )}

          {/* Tab 4: Attachments */}
          {activeTab === "attachments" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }} data-testid="tab-attachments">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span className="is-approval-lbl">Case attachments</span>
                <span className="is-mut" style={{ fontSize: 11 }}>
                  {caseItem.attachments?.length ?? 0} file(s)
                </span>
              </div>

              {(!caseItem.attachments || caseItem.attachments.length === 0) ? (
                <div className="is-note" style={{ textAlign: "center", padding: "20px 12px" }}>
                  <div style={{ fontWeight: 600, color: "var(--ink)" }}>No attachments on this case.</div>
                  <p className="is-mut2" style={{ fontSize: 11.5, margin: "4px 0 0" }}>
                    Attach logs, pcap exports, or evidence files.
                  </p>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {caseItem.attachments.map((att, idx) => (
                    <div
                      key={att.id || idx}
                      className="is-block"
                      style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 12px" }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <Paperclip size={14} className="text-primary" />
                        <span style={{ fontWeight: 500, color: "var(--ink)" }}>{att.name}</span>
                        {att.type && (
                          <span className="is-tag is-tag--info" style={{ fontSize: 9 }}>
                            {att.type}
                          </span>
                        )}
                      </div>
                      <div className="col-mono" style={{ fontSize: 11 }}>
                        {att.size ? `${Math.round(att.size / 1024)} KB` : ""}
                        {att.uploadedAt ? ` · ${att.uploadedAt.slice(0, 10)}` : ""}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Add Attachment form */}
              <form
                className="is-panel"
                style={{ padding: 12, display: "flex", gap: 8, alignItems: "flex-end" }}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (attName.trim()) addAttachment.mutate();
                }}
              >
                <label className="is-field" style={{ flex: 1 }}>
                  <span>Attachment name / file</span>
                  <input
                    className="is-input"
                    placeholder="e.g. auth-dump-2026-08.log"
                    value={attName}
                    onChange={(e) => setAttName(e.target.value)}
                    aria-label="Attachment name"
                  />
                </label>
                <label className="is-field" style={{ minWidth: 100 }}>
                  <span>Type</span>
                  <input
                    className="is-input"
                    placeholder="e.g. log, pcap, csv"
                    value={attType}
                    onChange={(e) => setAttType(e.target.value)}
                    aria-label="Attachment type"
                  />
                </label>
                <button
                  className="is-btn is-btn--primary"
                  type="submit"
                  disabled={!attName.trim() || addAttachment.isPending}
                >
                  Add attachment
                </button>
              </form>
            </div>
          )}

          {/* Tab 5: Linked */}
          {activeTab === "linked" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }} data-testid="tab-linked">
              <div className="is-block">
                <div className="cap authoritative">Linked Findings</div>
                {caseItem.links?.findings?.length ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {caseItem.links.findings.map((f) => (
                      <Link
                        key={f}
                        to={`/alerts?sel=${encodeURIComponent(f)}`}
                        className="is-mono is-btn"
                        style={{ fontSize: 11, height: 26, padding: "2px 8px" }}
                      >
                        {f} →
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="is-mut2" style={{ fontSize: 11.5 }}>
                    No linked findings.
                  </div>
                )}
              </div>

              <div className="is-block">
                <div className="cap authoritative">Linked Incidents</div>
                {caseItem.links?.incidents?.length ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {caseItem.links.incidents.map((inc) => (
                      <Link
                        key={inc}
                        to={`/incidents?sel=${encodeURIComponent(inc)}`}
                        className="is-mono is-btn"
                        style={{ fontSize: 11, height: 26, padding: "2px 8px" }}
                      >
                        {inc} →
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="is-mut2" style={{ fontSize: 11.5 }}>
                    No linked incidents.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab 6: Events */}
          {activeTab === "events" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }} data-testid="tab-events">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span className="is-approval-lbl">Real events</span>
                <span className="is-mut" style={{ fontSize: 11 }}>
                  {caseItem.events?.length ?? 0} event(s)
                </span>
              </div>

              {(!caseItem.events || caseItem.events.length === 0) ? (
                <div className="is-note" style={{ textAlign: "center", padding: "20px 12px" }}>
                  <div style={{ fontWeight: 600, color: "var(--ink)" }}>No events linked.</div>
                  <p className="is-mut2" style={{ fontSize: 11.5, margin: "4px 0 0" }}>
                    No raw events are attached to this case.
                  </p>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {caseItem.events.map((ev, idx) => (
                    <div
                      key={ev.id || idx}
                      className="is-block"
                      style={{ padding: "8px 10px", display: "flex", flexDirection: "column", gap: 2 }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10.5, color: "var(--mut)" }}>
                        <span className="is-mono">{ev.source || "log"}</span>
                        <span className="is-mono">{ev.ts}</span>
                      </div>
                      <div className="is-mono" style={{ fontSize: 11.5, color: "var(--ink)" }}>
                        {ev.message}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function Cases() {
  const [searchParams] = useSearchParams();
  const params = useParams();
  const selectedId = searchParams.get("sel") || params.id;

  const { data, isLoading, error } = useQuery({
    queryKey: ["cases"],
    queryFn: api.listCases,
  });

  const cases = data?.cases ?? [];
  const selectedCase = selectedId ? cases.find((c) => c.id === selectedId) : null;

  if (selectedId && selectedCase) {
    return <CaseFileView caseItem={selectedCase} />;
  }

  return (
    <>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12 }}>
        <div className="is-note" style={{ flex: 1, minWidth: 260 }}>
          <b>Analyst-entered CASE lifecycle NEW → CLOSED — no sample cases invented.</b> Investigation
          cases you create live in <span className="is-mono" style={{ color: "var(--ink)" }}>cases.json</span>.
        </div>
        <CreateCase />
      </div>

      {isLoading && <p className="is-mut">Loading cases…</p>}
      {error && (
        <div className="is-note">
          The console backend is not reachable — start it with{" "}
          <span className="is-mono">python3 console/serve.py</span>.
        </div>
      )}

      {!isLoading && !error && cases.length === 0 && (
        <div className="is-note" style={{ textAlign: "center", padding: "28px 14px" }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--ink)" }}>No cases yet.</div>
          <p className="is-mut" style={{ margin: "6px auto 0", maxWidth: 420, fontSize: 12 }}>
            Create a case to track an investigation. Nothing is shown here until you add one — no sample
            cases are invented.
          </p>
        </div>
      )}

      {/* Kanban 6-column board */}
      {!isLoading && !error && cases.length > 0 && (
        <div className="is-kanban" data-testid="cases-kanban-board">
          {CASE_STATUSES.map((status) => {
            const cardsInStatus = cases.filter((c) => c.status === status);
            return (
              <div key={status} className="is-kanban-col" data-testid={`kanban-column-${status}`}>
                <div className="is-kanban-col__h">
                  <span className="is-kanban-col__title">
                    <StatusPill status={status} />
                  </span>
                  <span className="is-kanban-col__count">{cardsInStatus.length}</span>
                </div>
                <div className="is-kanban-cards">
                  {cardsInStatus.length === 0 ? (
                    <div className="is-kanban-empty" data-testid={`empty-col-${status}`}>
                      No cases
                    </div>
                  ) : (
                    cardsInStatus.map((c) => <KanbanCard key={c.id} c={c} />)
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

