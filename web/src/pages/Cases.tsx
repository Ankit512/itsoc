import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, X } from "lucide-react";
import { api, CASE_STATUSES, type Case, type CaseStatus } from "@/lib/api";

/** Cases — analyst-entered investigation records (cases.json), in the itsoc.
 *  design system (mirrors handoff §3). Full CRUD over the real /api/cases
 *  endpoints: this is the one subsystem whose data is honestly stored because
 *  the analyst types it. No derivation, no invented rows — an empty store shows
 *  an honest empty state. */

const STATUS_COLOR: Record<CaseStatus, string> = {
  open: "var(--acc)",
  investigating: "var(--med)",
  closed: "var(--mut)",
};
const STATUS_LABEL: Record<CaseStatus, string> = {
  open: "Open", investigating: "Investigating", closed: "Closed",
};

function StatusPill({ status }: { status: CaseStatus }) {
  const c = STATUS_COLOR[status];
  return (
    <span className="is-state" style={{ color: c, borderColor: "color-mix(in srgb, " + c + " 45%, transparent)" }}>
      <i style={{ display: "inline-block", width: 6, height: 6, borderRadius: "50%", background: c }} />
      {STATUS_LABEL[status]}
    </span>
  );
}

function CreateCase() {
  const queryClient = useQueryClient();
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
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  if (!open) {
    return <button className="is-btn is-btn--primary" onClick={() => setOpen(true)}>+ New case</button>;
  }

  return (
    <div className="is-panel" style={{ width: "100%" }}>
      <form style={{ display: "flex", flexDirection: "column", gap: 12 }}
            onSubmit={(e) => { e.preventDefault(); if (title.trim()) create.mutate(); }}>
        <div className="is-panel__h">
          <h3>New case</h3>
          <button type="button" className="is-icobtn" aria-label="Cancel new case"
                  onClick={() => { setOpen(false); setErr(""); }} style={{ width: 26, height: 26 }}><X size={14} aria-hidden /></button>
        </div>
        <label className="is-field"><span>Title (required)</span>
          <input className="is-input" value={title} onChange={(e) => setTitle(e.target.value)}
                 aria-label="Case title" placeholder="e.g. Investigate brute-force from 203.0.113.44" />
        </label>
        <label className="is-field"><span>Assignee</span>
          <input className="is-input" value={assignee} onChange={(e) => setAssignee(e.target.value)}
                 aria-label="Case assignee" placeholder="who is looking at this" />
        </label>
        <label className="is-field"><span>Notes</span>
          <textarea className="is-input" style={{ minHeight: 64, resize: "vertical" }} value={notes}
                    onChange={(e) => setNotes(e.target.value)} aria-label="Case notes" />
        </label>
        {err && <p style={{ color: "var(--crit)", fontSize: 11.5, margin: 0 }}>{err}</p>}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button className="is-btn is-btn--primary" type="submit" disabled={!title.trim() || create.isPending}>
            {create.isPending ? "Creating…" : "Create case"}
          </button>
          <span className="is-mut" style={{ fontSize: 11 }}>Status starts as “open”.</span>
        </div>
      </form>
    </div>
  );
}

function CaseRow({ c }: { c: Case }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(c.title);
  const [assignee, setAssignee] = useState(c.assignee);
  const [notes, setNotes] = useState(c.notes);
  const [err, setErr] = useState("");

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["cases"] });
  const patch = useMutation({
    mutationFn: (p: Parameters<typeof api.patchCase>[1]) => api.patchCase(c.id, p),
    onSuccess: (out) => {
      if (!out.ok) { setErr(out.error ?? "Could not save."); return; }
      setErr(""); setEditing(false); invalidate();
    },
  });

  const links = [...c.links.findings, ...c.links.incidents];

  return (
    <div className="is-panel">
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          {editing ? (
            <input className="is-input" value={title} onChange={(e) => setTitle(e.target.value)} aria-label={`Edit title of ${c.id}`} />
          ) : (
            <div style={{ fontSize: 14, fontWeight: 650 }}>{c.title}</div>
          )}
          <div className="is-mono" style={{ marginTop: 2, fontSize: 10.5, color: "var(--mut)" }}>{c.id}</div>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="is-visually-hidden">Status of {c.id}</span>
          <StatusPill status={c.status} />
          <select className="is-select" style={{ width: "auto", padding: "6px 8px" }}
                  aria-label={`Status of ${c.id}`} value={c.status} disabled={patch.isPending}
                  onChange={(e) => patch.mutate({ status: e.target.value as CaseStatus })}>
            {CASE_STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </label>
        {!editing && (
          <button className="is-icobtn" style={{ width: 28, height: 28 }} onClick={() => setEditing(true)} aria-label={`Edit ${c.id}`}><Pencil size={13} aria-hidden /></button>
        )}
      </div>

      {editing ? (
        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 10 }}>
          <label className="is-field"><span>Assignee</span>
            <input className="is-input" value={assignee} onChange={(e) => setAssignee(e.target.value)} aria-label={`Edit assignee of ${c.id}`} />
          </label>
          <label className="is-field"><span>Notes</span>
            <textarea className="is-input" style={{ minHeight: 64, resize: "vertical" }} value={notes}
                      onChange={(e) => setNotes(e.target.value)} aria-label={`Edit notes of ${c.id}`} />
          </label>
          {err && <p style={{ color: "var(--crit)", fontSize: 11.5, margin: 0 }}>{err}</p>}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button className="is-btn is-btn--primary" disabled={!title.trim() || patch.isPending}
                    onClick={() => title.trim() && patch.mutate({ title, assignee, notes })}>
              {patch.isPending ? "Saving…" : "Save"}
            </button>
            <button className="is-btn" onClick={() => { setEditing(false); setTitle(c.title); setAssignee(c.assignee); setNotes(c.notes); setErr(""); }}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <>
          {c.notes && <p className="is-mut" style={{ marginTop: 10, whiteSpace: "pre-wrap", fontSize: 12.5, lineHeight: 1.55 }}>{c.notes}</p>}
          <div className="is-mut" style={{ marginTop: 12, display: "flex", flexWrap: "wrap", alignItems: "center", gap: "4px 16px", borderTop: "1px solid var(--bd)", paddingTop: 10, fontSize: 11 }}>
            {c.assignee && <span>Assignee: <b style={{ color: "var(--ink)" }}>{c.assignee}</b></span>}
            <span>Created {c.createdAt.slice(0, 16).replace("T", " ")}</span>
            <span>Updated {c.updatedAt.slice(0, 16).replace("T", " ")}</span>
            {links.length > 0 && (
              <span style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 4 }}>
                Linked:
                {links.map((l) => <span key={l} className="is-mono" style={{ border: "1px solid var(--bd)", borderRadius: 4, padding: "0 5px", fontSize: 10 }}>{l}</span>)}
              </span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export function Cases() {
  const { data, isLoading, error } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const cases = data?.cases ?? [];

  return (
    <>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12 }}>
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
          Analyst-entered — no sample invented. Investigation cases you create, stored locally in{" "}
          <span className="is-mono" style={{ color: "var(--ink)" }}>cases.json</span>. This is analyst-entered
          data, not derived from findings.
        </p>
        <div style={{ marginLeft: "auto" }}><CreateCase /></div>
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
          <div style={{ fontSize: 14, fontWeight: 650, color: "var(--ink)" }}>No cases yet</div>
          <p className="is-mut" style={{ margin: "6px auto 0", maxWidth: 420, fontSize: 12 }}>
            Create a case to track an investigation. Nothing is shown here until you add one — no sample
            cases are invented.
          </p>
        </div>
      )}

      {cases.map((c) => <CaseRow key={c.id} c={c} />)}
    </>
  );
}
