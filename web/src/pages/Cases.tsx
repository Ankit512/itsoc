import { useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  ChevronLeft, Paperclip, Play, Plus, Send, X, AlertTriangle, CheckCircle2,
  Sparkles, Image, FileCode, Search, Shield
} from "lucide-react";
import { CopilotRail } from "@/components/CopilotRail";
import { api, CASE_STATUSES, type Case, type CaseObservableInput, type CaseStatus, type CopilotRunbookRow } from "@/lib/api";

const LABEL: Record<CaseStatus, string> = { new: "New", triaged: "Triaged", investigating: "Investigating", escalated: "Escalated", resolved: "Resolved", closed: "Closed" };
const COLOR: Record<CaseStatus, string> = { new: "var(--acc)", triaged: "var(--med)", investigating: "var(--high)", escalated: "var(--crit)", resolved: "var(--low)", closed: "var(--mut)" };
const TABS = ["Overview", "Observables", "Notes", "Attachments", "Linked", "Events"] as const;
type DetailTab = typeof TABS[number];

function StatusPill({ status }: { status: CaseStatus }) { const color = COLOR[status]; return <span className="is-state" style={{ color, borderColor: `color-mix(in srgb, ${color} 45%, transparent)` }}><i style={{ display: "inline-block", width: 6, height: 6, borderRadius: "50%", background: color }} />{LABEL[status]}</span>; }

function CreateCase() {
  const qc = useQueryClient(); const [open, setOpen] = useState(false); const [title, setTitle] = useState(""); const [assignee, setAssignee] = useState(""); const [category, setCategory] = useState(""); const [notes, setNotes] = useState(""); const [error, setError] = useState("");
  const create = useMutation({ mutationFn: () => api.createCase({ title, assignee, category, notes }), onSuccess: (out) => { if (!out.ok) return setError(out.error ?? "Could not create the case."); setTitle(""); setAssignee(""); setCategory(""); setNotes(""); setError(""); setOpen(false); qc.invalidateQueries({ queryKey: ["cases"] }); } });
  if (!open) return <button className="is-btn is-btn--primary" onClick={() => setOpen(true)}><Plus size={14} />New case</button>;
  return <section className="is-panel is-case-create"><div className="is-panel__h"><h3>New case</h3><button className="is-icobtn" aria-label="Cancel new case" onClick={() => setOpen(false)}><X size={14} /></button></div><form className="is-case-form" onSubmit={(e) => { e.preventDefault(); if (title.trim()) create.mutate(); }}><label className="is-field"><span>Title (required)</span><input className="is-input" value={title} onChange={(e) => setTitle(e.target.value)} aria-label="Case title" placeholder="What needs investigation?" /></label><label className="is-field"><span>Category</span><input className="is-input" value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Case category" placeholder="e.g. identity" /></label><label className="is-field"><span>Assignee</span><input className="is-input" value={assignee} onChange={(e) => setAssignee(e.target.value)} aria-label="Case assignee" /></label><label className="is-field"><span>Notes</span><textarea className="is-input" value={notes} onChange={(e) => setNotes(e.target.value)} aria-label="Case notes" /></label>{error && <p className="is-case-error">{error}</p>}<button className="is-btn is-btn--primary" disabled={!title.trim() || create.isPending}>{create.isPending ? "Creating…" : "Create case"}</button></form></section>;
}

function CaseCard({ item }: { item: Case }) {
  const navigate = useNavigate(); const qc = useQueryClient(); const update = useMutation({ mutationFn: (status: CaseStatus) => api.patchCase(item.id, { status }), onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }) });
  const visibleFindings = item.links.findings.slice(0, 2);
  const remainingFindings = item.links.findings.length - visibleFindings.length;
  return <article className="is-case-card" onClick={() => navigate(`/cases?sel=${encodeURIComponent(item.id)}`)}><button className="is-case-card__title">{item.title}</button><div className="is-case-card__meta"><span className="is-mono">{item.id}</span><span>{item.assignee || "Unassigned"} · {item.category || "Uncategorized"}</span>{visibleFindings.length > 0 && <span className="is-case-card__findings">{visibleFindings.map((id) => <code key={id}>{id}</code>)}{remainingFindings > 0 && <span>+{remainingFindings} more</span>}</span>}</div><div className="is-case-card__foot"><StatusPill status={item.status} /><div className="is-case-card__steps" aria-label={`Move ${item.id}`} onClick={(e) => e.stopPropagation()}>{CASE_STATUSES.map((status) => <button key={status} type="button" aria-label={`Status of ${item.id}: ${status}`} disabled={status === item.status || update.isPending} onClick={() => update.mutate(status)}>{LABEL[status]}</button>)}</div></div></article>;
}

function Board({ cases }: { cases: Case[] }) {
  if (!cases.length) return null;
  return <div className="is-case-board is-case-board--bounded" aria-label="Case board">{CASE_STATUSES.map((status) => {
    const items = cases.filter((item) => item.status === status).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return <section key={status} className="is-case-column" aria-label={LABEL[status]}><header><span>{LABEL[status]}</span><span className="is-mono" title={`${items.length} case${items.length === 1 ? "" : "s"}`}>{items.length}</span></header><div className="is-case-column__cards is-case-column__cards--scrollable">{items.length ? items.map((item) => <CaseCard key={item.id} item={item} />) : <p className="is-case-empty">No cases</p>}</div></section>;
  })}</div>;
}

function Activity({ item }: { item: Case }) { const activity = item.activity ?? []; if (!activity.length) return <p className="is-case-empty">No human or system actions have been recorded.</p>; return <ol className="is-case-activity">{activity.slice().reverse().map((entry, index) => <li key={`${entry.at}-${index}`}><span className="is-mono">{entry.at.slice(0, 16).replace("T", " ")}</span><b>{entry.actor}</b><span className="is-chip">{entry.kind}</span><p>{entry.text}</p></li>)}</ol>; }

function CommentComposer({ item }: { item: Case }) { const qc = useQueryClient(); const [text, setText] = useState(""); const [error, setError] = useState(""); const comment = useMutation({ mutationFn: () => api.addCaseComment(item.id, { text }), onSuccess: (out) => { if (!out.ok) return setError(out.error ?? "Could not add comment."); setText(""); setError(""); qc.invalidateQueries({ queryKey: ["cases"] }); } }); return <form className="is-case-comment" onSubmit={(e) => { e.preventDefault(); if (text.trim()) comment.mutate(); }}><textarea className="is-input" value={text} onChange={(e) => setText(e.target.value)} aria-label="Add a comment" placeholder="Add a case comment…" />{error && <p className="is-case-error">{error}</p>}<button className="is-btn is-btn--primary" disabled={!text.trim() || comment.isPending}><Send size={13} />{comment.isPending ? "Posting…" : "Comment"}</button></form>; }

function ObservableTab({ item }: { item: Case }) {
  const qc = useQueryClient();
  const [type, setType] = useState<CaseObservableInput["type"]>("url");
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const add = useMutation({
    mutationFn: () => api.addCaseObservable(item.id, { type, value }),
    onSuccess: (out) => { if (!out.ok) return setError(out.error ?? "Could not add observable."); setValue(""); setError(""); qc.invalidateQueries({ queryKey: ["cases"] }); },
  });
  const enrich = useMutation({
    mutationFn: (oid: string) => api.enrichCaseObservable(item.id, oid),
    onSuccess: (out) => { if (!out.ok) setError(out.error ?? "Could not enrich."); else qc.invalidateQueries({ queryKey: ["cases"] }); },
  });

  const getVerdictChip = (verdict?: string) => {
    if (!verdict) return <span className="is-mut text-[11px]">Unreviewed</span>;
    const v = verdict.toLowerCase();
    if (v.includes("malicious") || v.includes("bad") || v.includes("threat")) {
      return <span className="is-chip is-chip--crit inline-flex items-center gap-1 font-semibold"><AlertTriangle size={11} />{verdict}</span>;
    }
    if (v.includes("safe") || v.includes("clean")) {
      return <span className="is-chip is-chip--low inline-flex items-center gap-1"><CheckCircle2 size={11} />{verdict}</span>;
    }
    return <span className="is-chip is-chip--med inline-flex items-center gap-1"><Sparkles size={11} />{verdict}</span>;
  };

  return <>
    <div className="is-case-list">{item.observables.length ? item.observables.map((observable) => <div key={observable.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "6px 8px", borderRadius: 6, border: "1px solid var(--bd)", background: "var(--pan)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
        <span className="is-chip is-mono" style={{ textTransform: "uppercase", fontSize: 9.5 }}>{observable.type}</span>
        <code className="is-mono" style={{ wordBreak: "break-all" }}>{observable.value}</code>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
        {getVerdictChip(observable.verdict)}
        <button className="is-btn is-btn--xs" type="button" disabled={enrich.isPending} onClick={() => enrich.mutate(observable.id)}>{enrich.isPending ? "Enriching…" : "Enrich"}</button>
      </div>
    </div>) : <p className="is-case-empty">No observables are attached to this case.</p>}</div>
    <form className="is-case-inline-form" onSubmit={(e) => { e.preventDefault(); if (value.trim()) add.mutate(); }}>
      <select className="is-select" value={type} onChange={(e) => setType(e.target.value as CaseObservableInput["type"])} aria-label="Observable type">{["url", "ip", "hash", "domain", "email"].map((kind) => <option key={kind}>{kind}</option>)}</select>
      <input className="is-input" value={value} onChange={(e) => setValue(e.target.value)} aria-label="Observable value" placeholder="Value (e.g. 192.168.1.1 or https://...)" />
      <button className="is-btn" disabled={!value.trim() || add.isPending}>Add</button>
    </form>
    {error && <p className="is-case-error">{error}</p>}
    <p className="is-mut" style={{ fontSize: 11, margin: "8px 0 0" }}>Enrichment is advisory. Offline STIX always; live OTX/AbuseIPDB for IPs only when ITSOC_OEM=1. Never a rule severity. VirusTotal is not called.</p>
  </>;
}

function AttachmentTab({ item }: { item: Case }) {
  const qc = useQueryClient();
  const [error, setError] = useState("");
  const add = useMutation({
    mutationFn: (file: File) => api.addCaseAttachment(item.id, file),
    onSuccess: (out) => {
      if (!out.ok) return setError(out.error ?? "Could not add the file.");
      setError("");
      qc.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  const getFileIcon = (kind: string, name: string) => {
    if (kind === "image" || /\.(png|jpe?g|gif|svg)$/i.test(name)) return <Image size={14} className="text-purple-400 shrink-0" />;
    if (/\.(json|xml|csv|log|txt)$/i.test(name)) return <FileCode size={14} className="text-emerald-400 shrink-0" />;
    return <Paperclip size={14} className="text-muted-foreground shrink-0" />;
  };

  return <>
    <div className="is-case-list">{item.attachments.length ? item.attachments.map((attachment) => {
      const href = api.caseAttachmentUrl(item.id, attachment.id);
      return <div key={attachment.id} style={{ display: "flex", flexDirection: "column", gap: 6, padding: "8px 10px", borderRadius: 6, border: "1px solid var(--bd)", background: "var(--pan)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
            {getFileIcon(attachment.kind, attachment.name)}
            <a href={href} className="font-medium hover:underline text-[12px]">{attachment.name}</a>
          </div>
          <span className="is-mut is-mono text-[10.5px]">{attachment.kind}{typeof attachment.size === "number" ? ` · ${attachment.size} bytes` : ""}{attachment.stored ? " · stored" : ""}</span>
        </div>
        {attachment.kind === "image" && <img className="is-case-thumb" src={href} alt={attachment.name} style={{ maxHeight: 180, objectFit: "contain", borderRadius: 4, border: "1px solid var(--bd)" }} />}
      </div>;
    }) : <p className="is-case-empty">No files are stored on this case.</p>}</div>
    <label className="is-field"><span>Upload a file</span>
      <input className="is-input" type="file" aria-label="Upload attachment" disabled={add.isPending}
             onChange={(e) => { const file = e.target.files?.[0]; e.target.value = ""; if (file) add.mutate(file); }} />
    </label>
    {error && <p className="is-case-error">{error}</p>}
  </>;
}

function LinkedTab({ item, cases }: { item: Case; cases: Case[] }) {
  const qc = useQueryClient();
  const [caseId, setCaseId] = useState("");
  const [error, setError] = useState("");
  const add = useMutation({
    mutationFn: () => api.addCaseLink(item.id, caseId.trim()),
    onSuccess: (out) => {
      if (!out.ok) return setError(out.error ?? "Could not link the case.");
      setCaseId(""); setError("");
      qc.invalidateQueries({ queryKey: ["cases"] });
    },
  });
  const linkedCases = item.links.cases ?? [];
  const findings = item.links.findings ?? [];
  const incidents = item.links.incidents ?? [];
  return <>
    <div className="is-case-list">
      {linkedCases.length ? linkedCases.map((id) => {
        const linked = cases.find((entry) => entry.id === id);
        return <Link key={id} to={`/cases?sel=${encodeURIComponent(id)}`} style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 8px", borderRadius: 6, border: "1px solid var(--bd)", background: "var(--pan)" }}>
          <span className="is-chip is-chip--adv">Case</span>
          <span className="font-medium">{linked?.title || id}</span>
          <span className="is-mono is-mut ml-auto">{id}</span>
        </Link>;
      }) : <p className="is-case-empty">No other cases are linked.</p>}
      {findings.map((id) => <Link key={id} to={`/alerts?sel=${encodeURIComponent(id)}`} style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 8px", borderRadius: 6, border: "1px solid var(--bd)", background: "var(--pan)" }}>
        <span className="is-chip">Finding</span>
        <span className="is-mono">{id}</span>
      </Link>)}
      {incidents.map((id) => <Link key={id} to={`/incidents?sel=${encodeURIComponent(id)}`} style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 8px", borderRadius: 6, border: "1px solid var(--bd)", background: "var(--pan)" }}>
        <span className="is-chip is-chip--crit">Incident</span>
        <span className="is-mono">{id}</span>
      </Link>)}
    </div>
    <form className="is-case-inline-form is-case-link-form" onSubmit={(e) => { e.preventDefault(); if (caseId.trim()) add.mutate(); }}>
      <input className="is-input" value={caseId} onChange={(e) => setCaseId(e.target.value)} aria-label="Linked case id" placeholder="case-2" />
      <button className="is-btn" disabled={!caseId.trim() || add.isPending}>Link case</button>
    </form>
    {error && <p className="is-case-error">{error}</p>}
  </>;
}

function EventsTab({ item }: { item: Case }) {
  const events = (item.activity ?? []).filter((entry) => entry.kind !== "comment");
  if (!events.length) return <p className="is-case-empty">No case events are recorded. Host logs are not shown here.</p>;
  return <ol className="is-case-activity">{events.slice().reverse().map((entry, index) => <li key={`${entry.at}-${index}`}><span className="is-mono">{entry.at.slice(0, 16).replace("T", " ")}</span><b>{entry.actor}</b><span className="is-chip">{entry.kind}</span><p>{entry.text}</p></li>)}</ol>;
}

function Runbooks({ item }: { item: Case }) {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["copilot-runbooks"], queryFn: api.copilotRunbooks });
  const [notice, setNotice] = useState("");
  const run = useMutation({
    mutationFn: (row: CopilotRunbookRow) => api.addCaseRunbook(item.id, row.id),
    onSuccess: (out) => {
      setNotice(out.ok ? "Advisory runbook reference added. Nothing was executed." : out.reason ?? out.error ?? "Could not add runbook.");
      if (out.ok) qc.invalidateQueries({ queryKey: ["cases"] });
    },
  });
  const request = useMutation({
    mutationFn: (row: CopilotRunbookRow) => api.requestCaseApproval(item.id, row.id),
    onSuccess: (out) => {
      if (out.ok && out.approval) {
        setNotice(`Pending approval ${out.approval.id}. Nothing executed — approve on Approvals.`);
        qc.invalidateQueries({ queryKey: ["cases"] });
        qc.invalidateQueries({ queryKey: ["approvals"] });
      } else {
        setNotice(out.reason ?? out.error ?? "Could not request approval.");
      }
    },
  });
  const runbooks = data?.runbooks ?? [];
  return <section className="is-case-runbooks">
    <div className="is-panel__h"><div>
      <h3>Run a workflow</h3>
      <p className="is-panel__sub">Eligible shipped runbooks can be recorded here or sent to Approvals. They never execute on this page. Quarantine is never requested from a case file.</p>
    </div></div>
    {!runbooks.length ? <p className="is-case-empty">No shipped runbooks are available for this run.</p> : runbooks.map((row) => {
      const quarantine = /quarantine/i.test(`${row.id} ${row.name ?? ""}`);
      const canRun = row.eligible && !quarantine;
      return <div className="is-case-runbook" key={row.id}>
        <div>
          <b>{row.name || row.id}</b>
          <code>{row.id}</code>
          {row.triggerRules?.length ? <p className="is-mut">Triggers: {row.triggerRules.join(", ")}</p> : null}
        </div>
        {canRun ? <div className="is-case-runbook__actions">
          <button className="is-btn" disabled={run.isPending} onClick={() => run.mutate(row)}><Play size={12} />Add to case</button>
          <button className="is-btn is-btn--primary" disabled={request.isPending} onClick={() => request.mutate(row)}>Request approval</button>
        </div> : <span className="is-case-ineligible">{quarantine ? "Quarantine is never executed from case files." : row.missing?.join("; ") || "Not eligible for this case/run."}</span>}
      </div>;
    })}
    {notice && <p className="is-note">{notice}{notice.includes("Approvals") && <> <Link to="/approvals">Open Approvals</Link></>}</p>}
  </section>;
}

const PHISHING_STEPS = [
  ["Find", "Preserve the reported message, then capture sender, reply-to, subject, URLs, attachment names, and message headers as case observables."],
  ["Scout", "Search for the sender, domain, URLs, and hashes across approved sources. Record confirmed recipients and related findings; do not infer scope from one message."],
  ["Resolve", "Document the evidence and recommended remediation. Request an approval for any external response; this workflow never deletes mail, blocks an indicator, or contacts a user."],
] as const;

function PhishingWorkflow({ item }: { item: Case }) {
  const qc = useQueryClient();
  const [owner, setOwner] = useState(item.assignee || "");
  const [notice, setNotice] = useState("");
  const apply = useMutation({
    mutationFn: () => api.patchCase(item.id, {
      category: "email phishing",
      assignee: owner.trim(),
      notes: `${item.notes ? `${item.notes.trim()}\n\n` : ""}Email phishing workflow\n\n${PHISHING_STEPS.map(([name, detail], index) => `${index + 1}. ${name} — ${detail}`).join("\n")}`,
    }),
    onSuccess: (out) => {
      if (!out.ok) return setNotice(out.error ?? "Could not apply the workflow.");
      setNotice("Email phishing workflow added to this ticket. No response action was executed.");
      qc.invalidateQueries({ queryKey: ["cases"] });
    },
  });
  return <section className="is-phishing-workflow" data-testid="phishing-workflow">
    <div><span>Template</span><h3>Email phishing response</h3><p>Guided evidence collection and remediation planning for a reported phishing message.</p></div>
    <ol>{PHISHING_STEPS.map(([name, detail]) => <li key={name}><b>{name}</b><span>{detail}</span></li>)}</ol>
    <div className="is-phishing-workflow__actions">
      <label className="is-field"><span>Responsible analyst</span><input className="is-input" aria-label="Responsible analyst" value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Assign a person" /></label>
      <button type="button" className="is-btn is-btn--primary" disabled={apply.isPending} onClick={() => apply.mutate()}>{apply.isPending ? "Adding…" : "Add workflow to ticket"}</button>
    </div>
    {notice && <p className="is-mut">{notice}</p>}
  </section>;
}

function Detail({ item, cases }: { item: Case; cases: Case[] }) {
  const [tab, setTab] = useState<DetailTab>("Overview"); const [responsible, setResponsible] = useState(item.assignee || ""); const navigate = useNavigate(); const qc = useQueryClient(); const update = useMutation({ mutationFn: (status: CaseStatus) => api.patchCase(item.id, { status }), onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }) }); const assign = useMutation({ mutationFn: () => api.patchCase(item.id, { assignee: responsible.trim() }), onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }) });
  const regen = useMutation({ mutationFn: () => api.regenerateCaseSummary(item.id), onSuccess: () => qc.invalidateQueries({ queryKey: ["cases"] }) });
  
  const overview = <>
    <div className="is-case-summary-head">
      <p className="is-mut" style={{ margin: 0, fontSize: 11 }}>Advisory summary from objects on this file — not a verdict.</p>
      <button className="is-btn" type="button" onClick={() => regen.mutate()} disabled={regen.isPending}>{regen.isPending ? "Regenerating…" : "Regenerate"}</button>
    </div>
    <div className="is-case-summary">
      {(["what", "impact", "when"] as const).map((field) => item.summary?.[field] ? <div key={field}><span>{field}</span><p>{item.summary[field]}</p></div> : null)}
      {!item.summary?.what && !item.summary?.impact && !item.summary?.when && <p className="is-case-empty">No case summary has been recorded.</p>}
    </div>
    <Runbooks item={item} />
    <PhishingWorkflow item={item} />
  </>;
  
  const contents: Record<DetailTab, ReactNode> = {
    Overview: overview,
    Observables: <ObservableTab item={item} />,
    Notes: <div className="space-y-3">
      {item.notes ? <p className="is-case-notes">{item.notes}</p> : <p className="is-case-empty">No notes have been recorded for this case.</p>}
    </div>,
    Attachments: <AttachmentTab item={item} />,
    Linked: <LinkedTab item={item} cases={cases} />,
    Events: <EventsTab item={item} />
  };

  return <section className="is-case-file">
    <button className="is-case-back" onClick={() => navigate("/cases")}><ChevronLeft size={15} />All cases</button>
    <header className="is-case-file__head">
      <div>
        <div className="is-mono is-mut">{item.id}</div>
        <h2>{item.title}</h2>
        <div className="is-case-file__meta">
          <StatusPill status={item.status} />
          <span>{item.category || "Uncategorized"}</span>
          <span>{item.assignee || "Unassigned"}</span>
        </div>
      </div>
      <div className="is-case-file__controls"><label className="is-field"><span>Responsible person</span><input className="is-input" aria-label="Responsible person" value={responsible} onChange={(event) => setResponsible(event.target.value)} placeholder="Unassigned" /></label><button type="button" className="is-btn" disabled={assign.isPending || responsible.trim() === (item.assignee || "")} onClick={() => assign.mutate()}>{assign.isPending ? "Saving…" : "Assign"}</button><select className="is-select is-case-status-select" aria-label="Case status" value={item.status} disabled={update.isPending} onChange={(e) => update.mutate(e.target.value as CaseStatus)}>{CASE_STATUSES.map((status) => <option key={status} value={status}>{LABEL[status]}</option>)}</select></div>
    </header>

    {/* Quick Action Ribbon */}
    <div className="flex items-center gap-1.5 py-1 px-1 overflow-x-auto border-b border-border/50 text-[11px]" style={{ marginBottom: 12 }}>
      <span className="text-muted-foreground mr-1 text-[10.5px] font-medium uppercase tracking-wider">Quick Actions:</span>
      <button type="button" onClick={() => setTab("Overview")} className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors">
        <Sparkles size={11} className="text-primary" />
        Case Summary
      </button>
      <button type="button" onClick={() => setTab("Observables")} className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors">
        <Search size={11} className="text-primary" />
        Analyze Observables ({item.observables.length})
      </button>
      <button type="button" onClick={() => setTab("Attachments")} className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors">
        <Paperclip size={11} className="text-purple-400" />
        Attachments ({item.attachments.length})
      </button>
      <button type="button" onClick={() => setTab("Linked")} className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-border bg-background hover:bg-accent text-foreground transition-colors">
        <Shield size={11} className="text-blue-400" />
        Linked Findings ({item.links.findings.length})
      </button>
    </div>

    <div className="is-case-file__grid">
      <section className="is-case-file__left">
        <h3>Activity</h3>
        <Activity item={item} />
        <CommentComposer item={item} />
      </section>
      <section className="is-case-file__right">
        <div className="is-case-tabs" role="tablist">
          {TABS.map((next) => <button key={next} role="tab" aria-selected={tab === next} onClick={() => setTab(next)}>{next}</button>)}
        </div>
        <div className="is-case-tab-content">{contents[tab]}</div>
      </section>
    </div>
    <CopilotRail docked embedded defaultOpen />
  </section>;
}

export function Cases() { const { data, isLoading, error } = useQuery({ queryKey: ["cases"], queryFn: api.listCases }); const [params] = useSearchParams(); const selected = params.get("sel"); const cases = data?.cases ?? []; const item = useMemo(() => cases.find((entry) => entry.id === selected), [cases, selected]); if (isLoading) return <p className="is-mut">Loading cases…</p>; if (error) return <div className="is-note">The console backend is not reachable — start it with <code>python3 console/serve.py</code>.</div>; if (selected && item) return <Detail item={item} cases={cases} />; return <><div className="is-case-toolbar"><div className="is-note"><b>Analyst-entered case files.</b> No sample cases or host-log events are invented.</div><CreateCase /></div>{selected && <div className="is-note">This case is no longer available.</div>}{!cases.length && <div className="is-note"><b>No cases yet.</b> Cases open from derived incidents when a run is loaded, or an analyst creates one — nothing is invented.</div>}<Board cases={cases} /></>; }
