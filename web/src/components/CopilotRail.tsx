import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Bot, Send, Square, X, Compass, TrendingUp, Sparkles, BookOpen,
  ChevronRight, Activity, ShieldCheck, Download
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api, Finding, RunsSummaryEntry, AskView, ConsoleState, CopilotCitation, CopilotForecastPhase, CopilotPlaybook } from "@/lib/api";
import { cn } from "@/lib/utils";
import { sevVar } from "@/lib/severity";

interface Msg {
  who: "q" | "a" | "err";
  text: string;
  source?: string;
  view?: AskView | null;
  citations?: CopilotCitation[];
  followups?: string[];
}

/** Severity tag (is-tag) coloured by the rule-owned level. Never recomputes a
 *  severity — it renders the level the backend already put on the row. */
function SevTag({ sev }: { sev?: string }) {
  const s = (sev || "").toUpperCase();
  if (!s) return <span className="is-tag is-tag--info">n/a</span>;
  return (
    <span className="is-tag" style={{ background: `color-mix(in srgb, ${sevVar(s)} 17%, transparent)`, color: sevVar(s) }}>
      {s}
    </span>
  );
}

/** Showcase result card (design-v2 §4): renders the backend's {view} directive
 *  as REAL is-* cards inside the rail. The AI chose WHAT to surface; every row
 *  is real data and carries an advisory chip + a "cited: N findings" line.
 *  Empty items → honest "nothing matches", never invented rows. Each row/card
 *  deep-links to the full page. */
function ShowcaseCard({ view }: { view: AskView }) {
  const items = view.items ?? [];
  const kpis = view.kpis ?? [];
  const empty = view.type === "dashboard" ? kpis.length === 0 : items.length === 0;
  return (
    <div className="is-panel" data-testid="copilot-showcase-card" style={{ padding: "11px 12px", marginBottom: 6 }}>
      <div className="is-panel__h" style={{ marginBottom: 8 }}>
        <h3 style={{ fontSize: 12 }}>{view.title}</h3>
        <span className="is-chip is-chip--adv">advisory</span>
      </div>

      {empty ? (
        <p className="is-mut" style={{ fontSize: 11.5, margin: 0 }}>Nothing matches — no real data to surface for this request.</p>
      ) : view.type === "dashboard" ? (
        <div className="is-kpis" style={{ gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
          {kpis.map((k) => (
            <div key={k.label} className="is-kpi" style={{ padding: "8px 10px" }}>
              <div className="lbl" style={{ fontSize: 10 }}>{k.label}</div>
              <div className="val is-tnum" style={{ fontSize: 18 }}>{k.value ?? "n/a"}</div>
              {k.note && <div className="delta na">{k.note}</div>}
            </div>
          ))}
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="is-table">
            <tbody>
              {items.map((it, i) => (
                <tr key={it.id ?? i}>
                  <td style={{ padding: "7px 8px" }}><SevTag sev={it.severity} /></td>
                  <td style={{ padding: "7px 8px" }}>
                    {view.type === "incidents" ? (
                      <>
                        <span className="is-mono" style={{ color: "var(--ink)" }}>{it.entity || "—"}</span>
                        <span className="is-mut" style={{ marginLeft: 6 }}>{it.findingCount} finding(s)</span>
                      </>
                    ) : (
                      <>
                        <span style={{ color: "var(--ink)" }}>{it.title || it.rule || it.id}</span>
                        {it.host && <span className="is-mono is-mut" style={{ marginLeft: 6, fontSize: 10.5 }}>{it.host}</span>}
                      </>
                    )}
                  </td>
                  <td style={{ padding: "7px 8px", textAlign: "right" }}>
                    {it.deeplink && (
                      <Link to={it.deeplink} style={{ color: "var(--acc)", fontSize: 11 }} aria-label="Open in full view">view →</Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="is-mono is-mut" style={{ fontSize: 10.5, marginTop: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>cited: {view.citedFindings ?? 0} finding(s)</span>
        {view.deeplink && <Link to={view.deeplink} style={{ color: "var(--acc)" }}>open {view.type} →</Link>}
      </div>
    </div>
  );
}

const DEFAULT_EXAMPLES = [
  "Walk me through the highest-severity finding with source lines",
  "What did Overview group, and which matching lines are hidden?",
  "Are these findings a security incident or operational noise?",
];

/** Showcase triggers (design-v2 §4): each pulls a REAL is-* result card into
 *  the rail (incidents / dashboard / findings). Kept as the idle/empty fallback
 *  so showcase tests still have a stable click target. */
const SHOWCASE_CHIPS = [
  "Show me the critical incidents",
  "Summarize the dashboard",
  "Top 5 findings",
];

const SHOWCASE_NO_CRIT = [
  "What did Overview group, and which matching lines are hidden?",
  "Summarize the dashboard",
  "Top 5 findings",
];

function countSev(findings: Finding[], band: string): number {
  const want = band.toUpperCase();
  return findings.filter((f) => (f.sev || f.ruleSev || "").toUpperCase() === want).length;
}

/** One-line run context — never a new verdict. */
function RunBriefing({ state, loading }: { state?: ConsoleState; loading?: boolean }) {
  if (loading && !state) {
    return (
      <div className="text-[11px] text-muted-foreground" data-testid="copilot-run-brief">
        Loading current run…
      </div>
    );
  }
  if (!state || state.idle) {
    return (
      <div className="text-[11px] text-muted-foreground" data-testid="copilot-run-brief">
        No run loaded — analyze a log first. I only interpret findings that exist for the current run.
      </div>
    );
  }
  if (state.unrecognized || state.emptyInput) {
    return (
      <div className="text-[11px] text-muted-foreground" data-testid="copilot-run-brief">
        Run <span className="is-mono">{state.runId ?? "n/a"}</span> was not recognized
        {typeof state.linesUnparsed === "number" ? ` — ${state.linesUnparsed} unparsed` : ""}.
        Not an all-clear.
      </div>
    );
  }
  const findings = state.findings ?? [];
  const crit = countSev(findings, "CRITICAL");
  const high = countSev(findings, "HIGH");
  const matching = findings.reduce((n, f) => n + (f.occurrences || 1), 0);
  return (
    <div className="truncate text-[11px] text-muted-foreground" data-testid="copilot-run-brief">
      <span className="is-mono font-medium text-foreground">{state.runId}</span>
      {" · "}{findings.length} finding(s)
      {matching > findings.length ? ` · ${matching.toLocaleString()} lines` : ""}
      {" · "}{crit} critical · {high} high
    </div>
  );
}

function KillChain({ phases }: { phases: CopilotForecastPhase[] }) {
  if (!phases.length) {
    return <p className="text-[11px] text-muted-foreground">No kill-chain phases to draw.</p>;
  }
  return (
    <div data-testid="copilot-killchain" className="grid grid-cols-4 gap-1">
      {phases.map((p) => (
        <div
          key={p.name}
          className={cn(
            "rounded border px-1 py-1.5 text-center text-[10px] leading-tight",
            p.observed && "border-primary bg-primary/10 font-semibold text-foreground",
            p.watch && "border-dashed border-primary/50 text-muted-foreground",
            !p.observed && !p.watch && "text-muted-foreground opacity-50",
          )}
        >
          <div>{p.name}</div>
          <div className="mt-0.5 font-mono text-[9px]">
            {p.observed ? "seen in this file" : p.watch ? "watch — not in log" : "not in log"}
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingSparkline({ history }: { history: { runId: string; findingCount: number }[] }) {
  if (history.length < 2) {
    return (
      <p className="text-[11px] text-muted-foreground">
        Need ≥2 saved runs for a volume sparkline.
      </p>
    );
  }
  const w = 280;
  const h = 56;
  const pad = 4;
  const vals = history.map((p) => p.findingCount);
  const max = Math.max(...vals, 1);
  const min = Math.min(...vals, 0);
  const span = max - min || 1;
  const n = history.length;
  const x = (i: number) => pad + (i / (n - 1)) * (w - 2 * pad);
  const y = (v: number) => h - pad - ((v - min) / span) * (h - 2 * pad);
  const line = history.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p.findingCount).toFixed(1)}`).join(" ");
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className="w-full text-primary"
      data-testid="copilot-forecast-spark"
      role="img"
      aria-label="finding card counts across saved runs"
    >
      <path d={line} fill="none" stroke="currentColor" strokeWidth="1.6" />
      {history.map((p, i) => (
        <circle key={`${p.runId}-${i}`} cx={x(i)} cy={y(p.findingCount)} r="2.4" fill="currentColor">
          <title>{`${p.runId}: ${p.findingCount} findings`}</title>
        </circle>
      ))}
    </svg>
  );
}

function CitationsPanel({ citations }: { citations: CopilotCitation[] }) {
  const [open, setOpen] = useState(false);
  const extra = citations.length > 2;
  const shown = open ? citations.slice(0, 8) : citations.slice(0, 2);
  return (
    <div className="rounded border bg-background px-2 py-1.5" data-testid="copilot-citations">
      <button
        type="button"
        onClick={() => extra && setOpen((o) => !o)}
        className="is-mono is-mut mb-1 text-left"
        style={{ fontSize: 10 }}
      >
        {citations.length} cited line{citations.length === 1 ? "" : "s"}
        {extra ? (open ? " · hide" : " · show") : ""}
      </button>
      {shown.map((c, ci) => (
        <div key={ci} className="flex gap-2 text-[11px]" style={{ padding: "2px 0" }}>
          <span className="is-mono is-mut" style={{ minWidth: 36 }}>
            {c.findingId ? (
              <Link to={`/alerts?sel=${encodeURIComponent(c.findingId)}`} style={{ color: "var(--acc)" }}>
                {`{${c.n ?? "n"}}`}
              </Link>
            ) : `{${c.n ?? "n"}}`}
          </span>
          <span className="is-mono line-clamp-2" style={{ wordBreak: "break-all" }}>{c.raw}</span>
        </div>
      ))}
    </div>
  );
}

const FIRST_TOKEN_TIMEOUT_MS = 90_000;

export type CopilotTab = "ask" | "prioritize" | "trend" | "forecast" | "resolution";

export interface CopilotRailProps {
  model?: string;
  defaultOpen?: boolean;
  docked?: boolean;
  className?: string;
}

export function CopilotRail({
  model: propModel,
  defaultOpen = false,
  docked = false,
  className,
}: CopilotRailProps) {
  const { pathname, search } = useLocation();
  const [open, setOpen] = useState(defaultOpen);
  const [activeTab, setActiveTab] = useState<CopilotTab>("ask");
  const [log, setLog] = useState<Msg[]>([]);
  const [draft, setDraft] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [gotFirstToken, setGotFirstToken] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const startRef = useRef(0);

  // Same query keys as Overview / Alerts / Incidents so a run switch cannot
  // leave the rail on a stale cache while the dashboard has already moved.
  const { data: state, isLoading: stateLoading } = useQuery({ queryKey: ["console-state"], queryFn: api.consoleState });
  const { data: overview } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  const selectedCaseId = pathname === "/cases" ? new URLSearchParams(search).get("sel") : null;
  const { data: casesData } = useQuery({
    queryKey: ["cases"], queryFn: api.listCases, enabled: Boolean(selectedCaseId),
  });
  const selectedCase = selectedCaseId ? casesData?.cases.find((item) => item.id === selectedCaseId) : undefined;
  const { data: suggested } = useQuery({
    queryKey: ["copilot-suggest", selectedCaseId ?? state?.runId],
    queryFn: () => api.copilotSuggest(selectedCaseId ?? undefined),
    enabled: Boolean(selectedCaseId) || (!!state && !state.idle),
  });
  const { data: runbookScan } = useQuery({
    queryKey: ["copilot-runbooks", state?.runId],
    queryFn: api.copilotRunbooks,
    enabled: !!state && !state.idle,
  });
  const { data: forecast } = useQuery({
    queryKey: ["copilot-forecast", state?.runId],
    queryFn: api.copilotForecast,
    enabled: !!state && !state.idle && activeTab === "forecast",
  });
  const { data: angles } = useQuery({
    queryKey: ["copilot-angles", state?.runId],
    queryFn: api.copilotAngles,
    enabled: !!state && !state.idle,
  });
  const [playbook, setPlaybook] = useState<CopilotPlaybook | null>(null);
  const [playbookBusy, setPlaybookBusy] = useState(false);
  const { data: runsSummary } = useQuery({ queryKey: ["runs-summary"], queryFn: api.runsSummary });
  const selectedIncidentId = pathname === "/incidents" ? new URLSearchParams(search).get("sel") : null;
  const { data: selectedRca } = useQuery({
    queryKey: ["rca", selectedIncidentId],
    queryFn: () => api.incidentRca(selectedIncidentId!),
    enabled: Boolean(selectedIncidentId),
  });
  const { data: approvalsData } = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => api.approvals("pending"),
    refetchInterval: 5000,
  });
  const pendingApprovals = (approvalsData?.approvals ?? []).filter((a) => a.state === "pending");

  const effectiveModel =
    propModel ?? (overview && !("error" in overview) ? overview.model : null) ?? "not configured";

  // Active finding or incident from URL selection if any
  const selParam = new URLSearchParams(search).get("sel");
  const findings: Finding[] = state && !state.idle && state.findings ? state.findings : [];
  const matchingLines = findings.reduce((n, f) => n + (f.occurrences || 1), 0);
  const runId = state && !state.idle ? state.runId : null;
  const runReady = !!state && !state.idle && !state.unrecognized && !state.emptyInput;
  const caseScoped = Boolean(selectedCase);
  const blockAsk = !caseScoped && !!state && !runReady;
  const selectedFinding = selParam ? findings.find((f) => f.id === selParam) : null;

  // Chat is bound to one run. Switching runs (or going idle) drops the prior
  // thread so the pane cannot keep answering a log that is no longer current.
  useEffect(() => {
    setLog([]);
    setPlaybook(null);
    abortRef.current?.abort();
  }, [runId, selectedCaseId]);
  const topCriticalFinding = findings.find((f) => f.sev?.toUpperCase() === "CRITICAL" || f.ruleSev?.toUpperCase() === "CRITICAL")
    ?? findings.find((f) => f.sev?.toUpperCase() === "HIGH" || f.ruleSev?.toUpperCase() === "HIGH")
    ?? findings[0];

  // Role 4: Prioritize computation (Start Here)
  const priorityFinding = selectedFinding ?? topCriticalFinding;
  const priorityRule = priorityFinding?.type;
  const priorityHit = priorityFinding?.lines?.[0]?.hit;
  const priorityEntity = priorityHit || priorityFinding?.host || "Fleet target";
  const priorityFindingCount = findings.filter(
    (f) => (priorityHit && f.lines?.some((l) => l.hit === priorityHit))
      || (priorityRule && f.type === priorityRule)
  ).length || (priorityFinding ? 1 : 0);

  // Role 2: Trend Digest computation
  const runs: RunsSummaryEntry[] = runsSummary?.runs ?? [];
  const totalRunsCount = runsSummary?.totals?.runCount ?? runs.length;
  const hasMultipleRuns = totalRunsCount >= 2;
  const latestTechniques = new Map((runs[0]?.topTechniques ?? []).map((t) => [t.id, t]));
  const previousTechniques = new Map((runs[1]?.topTechniques ?? []).map((t) => [t.id, t]));
  const risingTechniques = [...latestTechniques.values()].filter(
    (t) => t.count > (previousTechniques.get(t.id)?.count ?? 0)
  );
  const hasComparableTechniqueHistory = Boolean(runs[0]?.topTechniques && runs[1]?.topTechniques);

  // Role 3: Forecast computation (based on real runs)
  const hasEnoughRunsForForecast = totalRunsCount >= 3;
  const avgFindingsPerRun = runs.length > 0
    ? Math.round(runs.reduce((acc, r) => acc + (r.findingCount ?? 0), 0) / runs.length)
    : findings.length;
  const projectedFindings = Math.round(avgFindingsPerRun);

  // Role 5: Resolution runbook match
  const matchedRunbook = selectedRca && !("error" in selectedRca) && selectedRca.runbook?.matched
    ? selectedRca.runbook : undefined;

  // Elapsed timer while streaming
  useEffect(() => {
    if (!streaming) return;
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - startRef.current) / 1000)), 250);
    return () => clearInterval(t);
  }, [streaming]);

  const stop = () => {
    abortRef.current?.abort();
  };

  const ask = async (q: string) => {
    const question = q.trim();
    if (!question || streaming) return;
    if (caseScoped && /^summarize this case$/i.test(question)) {
      const facts = selectedCase!;
      const description = [facts.summary?.what, facts.summary?.impact, facts.summary?.when, facts.notes]
        .filter(Boolean).join("\n\n") || "No description has been recorded for this case.";
      setActiveTab("ask"); setDraft("");
      setLog((l) => [...l, { who: "q", text: question }, { who: "a", text: `${facts.title}\n\n${description}` }]);
      return;
    }
    if (blockAsk) {
      setActiveTab("ask");
      setLog((l) => [...l, { who: "q", text: question }, {
        who: "err",
        text: state?.unrecognized
          ? "This run was not recognized — there are no findings to interpret."
          : "No run loaded — analyze a log first, then ask about its findings.",
      }]);
      setDraft("");
      return;
    }
    setActiveTab("ask");
    setDraft("");
    setLog((l) => [...l, { who: "q", text: question }, { who: "a", text: "" }]);
    const answerIndex = log.length + 1;
    const requestQuestion = caseScoped
      ? `Case ${selectedCase!.id}: ${selectedCase!.title}. Category: ${selectedCase!.category || "not recorded"}. Notes: ${selectedCase!.notes || "none"}. Observables: ${(selectedCase!.observables ?? []).map((item) => `${item.type} ${item.value}`).join(", ") || "none"}. User request: ${question}`
      : question;

    const controller = new AbortController();
    abortRef.current = controller;
    startRef.current = Date.now();
    setElapsed(0);
    setGotFirstToken(false);
    setStreaming(true);

    // Showcase (design-v2 §4): fetch the real {view} directive in parallel —
    // deterministic + model-free, so the card appears even if the LLM is slow
    // or offline. Attaching it to the answer message renders an is-* card.
    // A null view (not a showcase question) simply leaves prose-only.
    api.askView(requestQuestion).then((view) => {
      if (!view) return;
      setLog((l) => {
        const next = [...l];
        const cur = next[answerIndex];
        if (cur && cur.who === "a") next[answerIndex] = { ...cur, view };
        return next;
      });
    }).catch(() => { /* honest: no card rather than an invented one */ });

    let first = false;
    const timeout = setTimeout(() => {
      if (!first) controller.abort("timeout");
    }, FIRST_TOKEN_TIMEOUT_MS);

    try {
      await api.askStream(
        requestQuestion,
        (delta) => {
          if (!first) {
            first = true;
            setGotFirstToken(true);
          }
          setLog((l) => {
            const next = [...l];
            const cur = next[answerIndex];
            if (cur && cur.who === "a") {
              // Investigation already stamped this same rules answer.
              if (cur.text && delta === cur.text) return next;
              next[answerIndex] = { ...cur, who: "a", text: cur.text + delta };
            }
            return next;
          });
        },
        controller.signal,
        (inv) => {
          if (inv.answer) {
            first = true;
            setGotFirstToken(true);
          }
          setLog((l) => {
            const next = [...l];
            const cur = next[answerIndex];
            if (cur && cur.who === "a") {
              next[answerIndex] = {
                ...cur,
                text: inv.answer || cur.text,
                citations: inv.citations,
                followups: inv.followups,
                source: inv.source,
              };
            }
            return next;
          });
        },
      );
    } catch (e) {
      const aborted = controller.signal.aborted;
      const reason = controller.signal.reason;
      const msg = aborted
        ? reason === "timeout"
          ? "The model did not start answering in time — it may be loading or overloaded. Try again."
          : "Stopped."
        : `The analyst backend is not reachable — ${(e as Error).message}`;
      setLog((l) => {
        const next = [...l];
        const cur = next[answerIndex];
        if (cur && cur.who === "a" && !cur.text) next[answerIndex] = { who: "err", text: msg };
        else next.push({ who: "err", text: msg });
        return next;
      });
    } finally {
      clearTimeout(timeout);
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const casePrompts = selectedCase ? [
    ...(selectedCase.observables.some((item) => item.type === "url") ? ["Analyze this URL"] : []),
    ...(selectedCase.attachments.length ? ["Scan attachments"] : []),
    ...(selectedCase.links.findings.length || selectedCase.links.incidents.length ? ["Related cases"] : []),
    "Summarize this case",
  ] : [];
  const runPrompts = caseScoped ? casePrompts : (suggested && suggested.length > 0) ? suggested : DEFAULT_EXAMPLES;
  const critOnRun = countSev(findings, "CRITICAL");
  const showcaseChips = caseScoped ? casePrompts : runReady && findings.length > 0 && critOnRun === 0
    ? SHOWCASE_NO_CRIT
    : SHOWCASE_CHIPS;

  const composer = (
    <form
      data-testid="copilot-composer"
      className="flex shrink-0 items-end gap-1.5 border-t pt-2"
      onSubmit={(e) => { e.preventDefault(); ask(draft); }}
    >
      <textarea
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            ask(draft);
          }
        }}
        rows={2}
        placeholder={caseScoped ? "Ask me anything" : blockAsk ? "Analyze a log first…" : "Ask about this run…"}
        aria-label="Ask the AI analyst"
        disabled={streaming || blockAsk}
        className="min-h-[52px] min-w-0 flex-1 resize-none rounded-md border-2 border-primary/50 bg-background px-2.5 py-2 text-[13px] outline-none focus:border-primary disabled:opacity-60"
      />
      <button
        type="submit"
        aria-label="Send"
        disabled={streaming || !draft.trim() || blockAsk}
        className="mb-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-primary bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
      >
        <Send className="h-4 w-4" aria-hidden />
      </button>
    </form>
  );

  const content = (
    <section
      aria-label="AI Analyst"
      data-testid="copilot-rail"
      className={cn(
        "flex min-h-0 flex-col gap-2 overflow-hidden bg-card p-3 text-[13px]",
        docked ? "h-full w-full" : "max-h-[min(680px,calc(100vh-100px))] w-[380px] rounded-lg border shadow-[var(--shadow-pop)]",
        className,
      )}
    >
      {/* Copilot Header */}
      <div className="flex shrink-0 items-center justify-between">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" strokeWidth={2} aria-hidden />
          <span className="font-bold tracking-tight text-foreground">
            itsoc analyst
          </span>
          <span
            data-testid="copilot-advisory-chip"
            title={effectiveModel}
            className="rounded bg-accent px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-accent-foreground"
          >
            advisory
          </span>
        </div>
        {!docked && (
          <button
            onClick={() => setOpen(false)}
            aria-label="Close analyst"
            className="inline-flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-background"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        )}
      </div>
      <p className="shrink-0 text-[10.5px] leading-snug text-muted-foreground">
        Advisory only — severities come from rules and are never changed here.
      </p>

      {/* 5 Grounded Roles Tabs — single row so they never eat the composer */}
      <div className="flex shrink-0 flex-nowrap gap-1 overflow-x-auto rounded-md bg-background p-1 text-[11px] font-medium" role="tablist">
        <button
          role="tab"
          aria-selected={activeTab === "ask"}
          onClick={() => setActiveTab("ask")}
          className={cn(
            "flex items-center gap-1 rounded px-2 py-1 transition-colors",
            activeTab === "ask" ? "bg-card font-semibold text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <Compass className="h-3 w-3" />
          Interpret
        </button>
        <button
          role="tab"
          aria-selected={activeTab === "prioritize"}
          onClick={() => setActiveTab("prioritize")}
          className={cn(
            "flex items-center gap-1 rounded px-2 py-1 transition-colors",
            activeTab === "prioritize" ? "bg-card font-semibold text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <Sparkles className="h-3 w-3" />
          Start here
        </button>
        <button
          role="tab"
          aria-selected={activeTab === "trend"}
          onClick={() => setActiveTab("trend")}
          className={cn(
            "flex items-center gap-1 rounded px-2 py-1 transition-colors",
            activeTab === "trend" ? "bg-card font-semibold text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <TrendingUp className="h-3 w-3" />
          Trend
        </button>
        <button
          role="tab"
          aria-selected={activeTab === "forecast"}
          onClick={() => setActiveTab("forecast")}
          className={cn(
            "flex items-center gap-1 rounded px-2 py-1 transition-colors",
            activeTab === "forecast" ? "bg-card font-semibold text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <Activity className="h-3 w-3" />
          Forecast
        </button>
        <button
          role="tab"
          aria-selected={activeTab === "resolution"}
          onClick={() => setActiveTab("resolution")}
          className={cn(
            "flex items-center gap-1 rounded px-2 py-1 transition-colors",
            activeTab === "resolution" ? "bg-card font-semibold text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground",
          )}
        >
          <BookOpen className="h-3 w-3" />
          Runbook
        </button>
      </div>

      {/* Pending approvals read-only card (C4-F3) */}
      {pendingApprovals.length > 0 && (
        <div
          data-testid="copilot-pending-approvals-card"
          className="rounded-lg border border-primary/30 bg-primary/5 p-2.5 space-y-1.5"
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-foreground flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5 text-primary" aria-hidden />
              {pendingApprovals.length} pending approval{pendingApprovals.length > 1 ? "s" : ""}
            </span>
            <Link
              to="/approvals"
              className="text-[11px] font-medium text-primary hover:underline"
            >
              Open in Approvals →
            </Link>
          </div>
          <div className="space-y-1">
            {pendingApprovals.slice(0, 3).map((a) => (
              <div key={a.id} className="flex items-center justify-between text-[11px] bg-background/80 rounded px-2 py-1 border">
                <span className="font-mono">{a.runbookId} · {a.incidentId}</span>
                <Link
                  to={`/approvals?sel=${encodeURIComponent(a.id)}`}
                  className="text-primary hover:underline font-mono text-[10.5px]"
                >
                  review →
                </Link>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Role 1 & Q&A View: Interpret & Chat */}
      {activeTab === "ask" && (
        <div className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-hidden" data-testid="copilot-chat">
          {caseScoped ? <div className="text-[11px] text-muted-foreground" data-testid="copilot-case-brief">Scoped to case <span className="is-mono">{selectedCase?.id}</span> — advisory only.</div> : <RunBriefing state={state} loading={stateLoading} />}
          {!!angles && !state?.idle && Array.isArray((angles as { links?: unknown }).links) && (
            <div data-testid="copilot-angles" className="flex flex-wrap gap-x-2 gap-y-0.5 text-[10.5px] text-muted-foreground">
              {((angles as { links: { label: string; href: string; count?: number }[] }).links).map((l) => (
                <Link key={l.href} to={l.href} className="hover:text-primary">
                  {l.label} {typeof l.count === "number" ? l.count : ""}
                </Link>
              ))}
            </div>
          )}
          <div aria-live="polite" className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto pr-1 text-[12px]">
            {log.length === 0 && (
              <div className="flex flex-col gap-1.5">
                <p className="text-[12px] text-muted-foreground">
                  {caseScoped ? "Ask anything about this case. Type below or tap a starter." : "Ask anything about this run. Type below or tap a starter."}
                </p>
                {runPrompts.slice(0, 4).map((q) => (
                  <button
                    key={q}
                    onClick={() => ask(q)}
                    className="rounded border bg-card px-2.5 py-1.5 text-left text-xs text-muted-foreground hover:border-primary hover:text-foreground"
                    data-testid="copilot-suggested-q"
                  >
                    {q}
                  </button>
                ))}
              </div>
            )}
            {log.map((m, i) => {
              const isStreamingAnswer = streaming && m.who === "a" && i === log.length - 1;
              return (
                <div key={i} className="flex flex-col gap-1.5">
                  {m.who === "a" && m.view && <ShowcaseCard view={m.view} />}
                  {(m.text || m.who !== "a" || isStreamingAnswer) && (
                    <div
                      className={cn(
                        "max-w-[95%] whitespace-pre-wrap rounded-lg px-2.5 py-2",
                        m.who === "q" && "self-end bg-accent text-accent-foreground font-medium",
                        m.who === "a" && "bg-background text-foreground",
                        m.who === "err" && "border border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-300",
                      )}
                    >
                      {m.text}
                      {isStreamingAnswer && !m.text && (
                        <span className="text-muted-foreground">
                          {gotFirstToken ? "" : `investigating… ${elapsed}s`}
                        </span>
                      )}
                      {isStreamingAnswer && m.text && <span className="animate-pulse">▍</span>}
                    </div>
                  )}
                  {m.who === "a" && m.citations && m.citations.length > 0 && (
                    <CitationsPanel citations={m.citations} />
                  )}
                  {m.who === "a" && m.followups && m.followups.length > 0 && !isStreamingAnswer && (
                    <div className="flex flex-wrap gap-1.5" data-testid="copilot-followups">
                      {m.followups.map((fq) => (
                        <button
                          key={fq}
                          onClick={() => ask(fq)}
                          disabled={streaming}
                          className="rounded-full border bg-background px-2.5 py-1 text-[11px] text-muted-foreground hover:border-primary hover:text-foreground disabled:opacity-50"
                        >
                          {fq}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="flex shrink-0 flex-wrap gap-1" data-testid="copilot-showcase-chips">
            {showcaseChips.map((p) => (
              <button
                key={p}
                onClick={() => ask(p)}
                disabled={streaming}
                className="rounded-full border border-primary/40 bg-background px-2 py-0.5 text-[10.5px] font-medium text-primary hover:bg-accent disabled:opacity-50"
              >
                {p}
              </button>
            ))}
          </div>

          {streaming && (
            <div className="flex shrink-0 items-center gap-2 text-[11px] text-muted-foreground">
              <span className="tabular-nums">{elapsed}s</span>
              <button
                onClick={stop}
                className="ml-auto inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] hover:border-primary"
              >
                <Square className="h-3 w-3" aria-hidden /> Stop
              </button>
            </div>
          )}
        </div>
      )}

      {/* Role 4 View: Prioritize ("Start Here") */}
      {activeTab === "prioritize" && (
        <div data-testid="copilot-prioritize-card" className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto">
          <div className="rounded-lg border bg-background p-3">
            <div className="flex items-center gap-1.5 text-xs font-bold text-foreground">
              <Sparkles className="h-3.5 w-3.5 text-primary" />
              Start here
            </div>
            {priorityFinding ? (
              <div className="mt-2 space-y-2">
                <p className="text-[12px] leading-relaxed text-foreground">
                  <b className="font-semibold text-foreground">{priorityEntity}</b>
                  {priorityFinding.host && priorityFinding.host !== priorityEntity && ` → ${priorityFinding.host}`}.{" "}
                  {priorityRule === "auth_bruteforce_success"
                    ? "The only chain with a successful login after brute-force credential access (T1110 → T1078)."
                    : priorityFinding.title ?? "Highest severity active detection in current run."}
                </p>
                <div className="font-mono text-[11px] text-muted-foreground">
                  cited: {priorityFindingCount} finding(s) · rule <code className="rounded bg-muted px-1 py-0.5">{priorityRule}</code>
                </div>
                <div className="flex flex-wrap gap-2 pt-1">
                  <Link
                    to={`/alerts?sel=${priorityFinding.id}`}
                    className="inline-flex items-center gap-1 rounded bg-primary px-2.5 py-1 text-[11.5px] font-semibold text-primary-foreground hover:opacity-90"
                  >
                    View finding <ChevronRight className="h-3 w-3" />
                  </Link>
                  <button
                    onClick={() => ask(`Explain why ${priorityRule} on ${priorityEntity} is prioritized first`)}
                    className="inline-flex items-center gap-1 rounded border bg-card px-2.5 py-1 text-[11.5px] font-medium text-foreground hover:bg-accent"
                  >
                    Explain priority
                  </button>
                </div>
              </div>
            ) : (
              <p className="mt-2 text-[12px] text-muted-foreground">
                No active anomalies detected in current run.
              </p>
            )}
          </div>
          <div className="rounded border border-dashed p-2.5 text-[11.5px] text-muted-foreground">
            <b>Grounding rationale:</b> Priority ranking combines rule severity with confirmed compromise indicators (e.g. success post-failure) rather than raw volume.
          </div>
        </div>
      )}

      {/* Role 2 View: Trend Digest */}
      {activeTab === "trend" && (
        <div data-testid="copilot-trend-card" className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto">
          <div className="rounded-lg border bg-background p-3 space-y-2">
            <div className="flex items-center justify-between text-xs font-bold text-foreground">
              <span className="flex items-center gap-1.5">
                <TrendingUp className="h-3.5 w-3.5 text-primary" />
                Trend digest
              </span>
              <span className="font-mono text-[10.5px] text-muted-foreground">
                {totalRunsCount} saved run(s)
              </span>
            </div>

            {hasMultipleRuns ? (
              <div className="space-y-2 text-[12px]">
                <p className="text-muted-foreground">
                  Compared across recent analysis runs:
                </p>
                <ul className="space-y-1.5">
                  {runsSummary?.totals?.mitreFrequency?.slice(0, 3).map((t) => (
                    <li key={t.id} className="flex items-center justify-between rounded border bg-card px-2 py-1">
                      <span className="font-medium text-foreground">{t.name || t.id}</span>
                      <span className="font-mono text-[11px] text-primary">{t.count} hits</span>
                    </li>
                  ))}
                  {hasComparableTechniqueHistory ? risingTechniques.map((t) => (
                    <li key={`rising-${t.id}`} className="rounded bg-accent/50 p-1.5 text-[11px] text-accent-foreground">
                      <TrendingUp className="mr-1 inline h-3 w-3 align-middle" aria-hidden /><b>{t.name || t.id}:</b> {t.count - (previousTechniques.get(t.id)?.count ?? 0)} more hit(s) than the previous run.
                    </li>
                  )) : (
                    <li className="rounded bg-muted/40 p-1.5 text-[11px] text-muted-foreground">
                      Per-run technique history is unavailable — no direction is claimed.
                    </li>
                  )}
                  {hasComparableTechniqueHistory && risingTechniques.length === 0 && (
                    <li className="rounded bg-muted/40 p-1.5 text-[11px] text-muted-foreground">
                      No technique increased between the two latest runs.
                    </li>
                  )}
                </ul>
              </div>
            ) : (
              <div className="rounded bg-muted/40 p-2.5 text-[11.5px] text-muted-foreground">
                Single run recorded — trend comparison requires ≥2 saved runs.
              </div>
            )}
          </div>

          <button
            onClick={() => ask("What attack patterns are rising across runs?")}
            className="rounded border bg-card px-2.5 py-1.5 text-left text-xs text-muted-foreground hover:border-primary hover:text-foreground"
          >
            Ask copilot: &quot;What attack patterns are rising across runs?&quot;
          </button>
        </div>
      )}

      {/* Role 3 View: Honest Forecast — this-run facts first, never an invented attack */}
      {activeTab === "forecast" && (
        <div data-testid="copilot-forecast-card" className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto">
          <div className="rounded-lg border bg-background p-3 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                <Activity className="h-3.5 w-3.5 text-primary" />
                Honest forecast
              </span>
              <span
                data-testid="copilot-forecast-badge"
                className="rounded bg-accent px-1.5 py-0.5 font-mono text-[10px] text-accent-foreground"
              >
                {hasEnoughRunsForForecast
                  ? `forecast · based on ${totalRunsCount} runs`
                  : "forecast · not enough runs"}
              </span>
            </div>

            <div className="rounded border bg-card p-2 text-[12px]">
              <div className="text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">This run</div>
              <p className="mt-1 text-foreground">
                {findings.length} finding(s)
                {matchingLines > findings.length ? ` · ${matchingLines.toLocaleString()} matching lines` : ""}
                {priorityFinding ? ` · highest ${priorityFinding.sev || priorityFinding.ruleSev}: ${priorityFinding.title}` : " · no findings"}
              </p>
            </div>

            <div className="space-y-1">
              <div className="text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">
                What a continuation would look like
              </div>
              <KillChain phases={forecast?.phases ?? []} />
              <p className="text-[11px] text-muted-foreground">{forecast?.note}</p>
            </div>

            <div className="space-y-1">
              <div className="text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">
                Card count across saved runs
              </div>
              <FindingSparkline history={forecast?.history ?? []} />
            </div>

            {hasMultipleRuns && runs[0] && runs[1] && (
              <p className="text-[12px] text-muted-foreground">
                Previous saved run had {runs[1].findingCount ?? 0} finding(s); this one has {runs[0].findingCount ?? findings.length}.
                {((runs[0].findingCount ?? 0) === (runs[1].findingCount ?? 0))
                  ? " Flat card count."
                  : ((runs[0].findingCount ?? 0) > (runs[1].findingCount ?? 0)
                    ? " More cards than last time — that is volume, not a new tactic."
                    : " Fewer cards than last time.")}
              </p>
            )}

            {hasEnoughRunsForForecast ? (
              <div className="space-y-2 text-[12px]">
                <p className="text-foreground">
                  Extrapolating historical velocity from {totalRunsCount} recorded runs:
                </p>
                <div className="rounded border bg-card p-2">
                  <div className="flex justify-between text-[11.5px] font-medium">
                    <span className="text-muted-foreground">Expected next run:</span>
                    <span className="font-mono font-semibold text-primary">~{projectedFindings} findings</span>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    Historical average: {avgFindingsPerRun} findings/run
                  </div>
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Flat historical-average baseline; no acceleration or attack type is inferred.
                </p>
              </div>
            ) : (
              <div className="rounded bg-muted/40 p-2.5 text-[11.5px] text-muted-foreground">
                not enough runs (need ≥3 runs to project trend, currently {totalRunsCount}).
                I will not invent a next-run threat from this sample.
              </div>
            )}
          </div>
          <p className="text-[10.5px] text-muted-foreground">
            Forecasts are purely statistical extrapolations of real run counts — never conjured IOCs.
          </p>
        </div>
      )}

      {/* Role 5: shipped runbooks vs THIS run — eligibility only, never execute */}
      {activeTab === "resolution" && (
        <div data-testid="copilot-resolution-card" className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto">
          {matchedRunbook && (
            <div className="rounded-lg border bg-background p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                  <BookOpen className="h-3.5 w-3.5 text-primary" />
                  Cited for selected incident
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">
                  {matchedRunbook.file}
                </span>
              </div>
              <div className="text-xs font-semibold text-foreground">{matchedRunbook.title}</div>
              <p className="whitespace-pre-wrap text-[11.5px] text-muted-foreground">{matchedRunbook.passage}</p>
            </div>
          )}
          <div className="rounded-lg border bg-background p-3 space-y-2">
            <div className="text-xs font-bold text-foreground">Shipped runbooks on this run</div>
            <p className="text-[11px] text-muted-foreground">
              {runbookScan?.note
                || (state?.idle ? "No run loaded." : "Eligibility is rule-owned. Nothing is executed from here.")}
            </p>
            {(runbookScan?.runbooks ?? []).length === 0 ? (
              <p className="text-[12px] text-muted-foreground">
                {state?.idle
                  ? "Analyze a log first — there is no runbook to match."
                  : "No shipped runbook definitions loaded."}
              </p>
            ) : (
              <ul className="space-y-1.5">
                {(runbookScan?.runbooks ?? []).map((rb) => (
                  <li key={rb.id} className="rounded border bg-card px-2 py-1.5 text-[12px]">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-foreground">{rb.name || rb.id}</span>
                      <span className={cn(
                        "font-mono text-[10px]",
                        rb.eligible ? "text-primary" : "text-muted-foreground",
                      )}>
                        {rb.eligible ? "eligible" : "not eligible"}
                      </span>
                    </div>
                    {!rb.eligible && (rb.missing?.[0]) && (
                      <div className="mt-0.5 text-[10.5px] leading-snug text-muted-foreground">
                        {rb.missing[0]}
                      </div>
                    )}
                    {rb.eligible && rb.incidentId && (
                      <Link
                        to={`/incidents?sel=${encodeURIComponent(rb.incidentId)}`}
                        className="mt-1 inline-block text-[11px] text-primary"
                      >
                        Open incident →
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="rounded-lg border bg-background p-3 space-y-2">
            <div className="text-xs font-bold text-foreground">Draft a playbook</div>
            <p className="text-[11px] text-muted-foreground">
              Generates an advisory markdown playbook for this file — what fired, what to watch, which shipped books apply. It is not executed and is not saved into the executable runbook folder.
            </p>
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                disabled={playbookBusy || !!state?.idle}
                onClick={async () => {
                  setPlaybookBusy(true);
                  try {
                    setPlaybook(await api.copilotPlaybook());
                  } finally {
                    setPlaybookBusy(false);
                  }
                }}
                className="inline-flex items-center gap-1 rounded bg-primary px-2.5 py-1 text-[11.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                {playbookBusy ? "Drafting…" : "Draft playbook for this run"}
              </button>
              {playbook?.markdown && (
                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob([playbook.markdown || ""], { type: "text/markdown" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = playbook.filename || "playbook.md";
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="inline-flex items-center gap-1 rounded border px-2.5 py-1 text-[11.5px] font-medium hover:bg-accent"
                >
                  <Download className="h-3 w-3" aria-hidden /> Download .md
                </button>
              )}
            </div>
            {playbook?.markdown && (
              <pre
                data-testid="copilot-playbook"
                className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-card p-2 text-[11px] leading-relaxed text-foreground"
              >
                {playbook.markdown}
              </pre>
            )}
          </div>
          <p className="text-[10.5px] text-muted-foreground">
            These are references, not actions. Approvals live on the Approvals screen.
          </p>
        </div>
      )}

      {composer}

      {/* Verbatim Copilot Footer */}
      <div
        data-testid="copilot-footer"
        className="cop-f shrink-0 pt-1 text-[10.5px] font-medium text-muted-foreground"
      >
        Rules set severity. I interpret &amp; explain — I don&apos;t decide.
      </div>
    </section>
  );

  if (docked) {
    return content;
  }

  return (
    <div className="fixed bottom-[22px] right-[22px] z-50 flex flex-col items-end gap-2.5">
      {open && content}
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? "Close AI Analyst" : "Open AI Analyst"}
        className="inline-flex items-center gap-[9px] rounded-full border border-primary bg-card px-[18px] py-3 text-[13.5px] font-semibold shadow-card hover:bg-accent"
      >
        <Bot className="h-[17px] w-[17px] text-primary" strokeWidth={1.8} aria-hidden />
        AI Analyst
        <span className="text-[9.5px] font-medium uppercase tracking-[0.05em] text-muted-foreground">
          advisory
        </span>
      </button>
    </div>
  );
}

export { CopilotRail as AiAnalyst };
