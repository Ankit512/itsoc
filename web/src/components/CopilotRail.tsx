import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Bot, Send, Square, X, Compass, TrendingUp, Sparkles, BookOpen,
  ChevronRight, Activity, ShieldCheck
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api, Finding, RunsSummaryEntry, AskView, ConsoleState } from "@/lib/api";
import { cn } from "@/lib/utils";
import { sevVar } from "@/lib/severity";

interface Msg {
  who: "q" | "a" | "err";
  text: string;
  source?: string;
  view?: AskView | null;
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
  "Show me top 5 critical alerts",
  "What are the recent attack patterns?",
  "Summarize today's threats",
];

/** Showcase triggers (design-v2 §4): each pulls a REAL is-* result card into
 *  the rail (incidents / dashboard / findings). */
const SHOWCASE_CHIPS = [
  "Show me the critical incidents",
  "Summarize the dashboard",
  "Top 5 findings",
];

const CONTEXTUAL_PROMPTS: Record<string, string[]> = {
  "/": [
    "What changed since last run?",
    "Which host first?",
    "Is brute-force trending up?",
  ],
  "/alerts": [
    "Why is this critical?",
    "Explain the evidence lines",
    "What MITRE technique is this?",
  ],
  "/findings": [
    "Why is this critical?",
    "Explain the evidence lines",
    "What MITRE technique is this?",
  ],
  "/incidents": [
    "What's the root cause here?",
    "Summarize for handoff",
    "What is the attack chain?",
  ],
};

function countSev(findings: Finding[], band: string): number {
  const want = band.toUpperCase();
  return findings.filter((f) => (f.sev || f.ruleSev || "").toUpperCase() === want).length;
}

/** Deterministic briefing for the CURRENT run — display aggregation of
 *  rule-owned findings, never a new verdict. Bound to console-state so it
 *  cannot lag a run switch. */
function RunBriefing({ state, loading }: { state?: ConsoleState; loading?: boolean }) {
  if (loading && !state) {
    return (
      <div className="rounded border bg-background px-2.5 py-2 text-[11.5px] leading-relaxed text-muted-foreground" data-testid="copilot-run-brief">
        Loading current run…
      </div>
    );
  }
  if (!state || state.idle) {
    return (
      <div className="rounded border bg-background px-2.5 py-2 text-[11.5px] leading-relaxed text-muted-foreground" data-testid="copilot-run-brief">
        No run loaded — analyze a log first. I only interpret findings that exist for the current run.
      </div>
    );
  }
  if (state.unrecognized || state.emptyInput) {
    return (
      <div className="rounded border bg-background px-2.5 py-2 text-[11.5px] leading-relaxed text-muted-foreground" data-testid="copilot-run-brief">
        Run <span className="is-mono">{state.runId ?? "n/a"}</span> was not recognized
        {typeof state.linesUnparsed === "number" ? ` — ${state.linesUnparsed} unparsed line(s)` : ""}.
        That is not an all-clear.
      </div>
    );
  }
  const findings = state.findings ?? [];
  const crit = countSev(findings, "CRITICAL");
  const high = countSev(findings, "HIGH");
  return (
    <div className="rounded border bg-background px-2.5 py-2 text-[11.5px] leading-relaxed" data-testid="copilot-run-brief">
      <div className="font-semibold text-foreground">
        Interpreting <span className="is-mono">{state.runId}</span>
      </div>
      <div className="mt-0.5 text-muted-foreground">
        {state.sourceLabel || state.runHosts || "current log"}
        {state.runParsed ? ` · ${state.runParsed}` : ""}
      </div>
      <div className="mt-1 is-mono text-muted-foreground">
        {findings.length} finding(s) · {crit} critical · {high} high
        {state.llmNote ? ` · ${state.llmNote}` : ""}
      </div>
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
  const runId = state && !state.idle ? state.runId : null;
  const runReady = !!state && !state.idle && !state.unrecognized && !state.emptyInput;
  const blockAsk = !!state && !runReady;
  const selectedFinding = selParam ? findings.find((f) => f.id === selParam) : null;

  // Chat is bound to one run. Switching runs (or going idle) drops the prior
  // thread so the pane cannot keep answering a log that is no longer current.
  useEffect(() => {
    setLog([]);
    abortRef.current?.abort();
  }, [runId]);
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
    api.askView(question).then((view) => {
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
        question,
        (delta) => {
          if (!first) {
            first = true;
            setGotFirstToken(true);
          }
          setLog((l) => {
            const next = [...l];
            const cur = next[answerIndex];
            if (cur && cur.who === "a") next[answerIndex] = { who: "a", text: cur.text + delta };
            return next;
          });
        },
        controller.signal,
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

  const currentPrompts = CONTEXTUAL_PROMPTS[pathname] ?? DEFAULT_EXAMPLES;

  const content = (
    <section
      aria-label="AI Analyst"
      data-testid="copilot-rail"
      className={cn(
        "flex min-h-0 flex-col gap-2.5 bg-card p-3.5 text-[13px]",
        docked ? "h-full w-full" : "max-h-[min(680px,calc(100vh-100px))] w-[380px] rounded-lg border shadow-[var(--shadow-pop)]",
        className,
      )}
    >
      {/* Copilot Header */}
      <div className="flex items-center justify-between border-b pb-2.5">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" strokeWidth={2} aria-hidden />
          <span className="font-bold tracking-tight text-foreground">
            itsoc analyst{effectiveModel && effectiveModel !== "not configured" ? ` (${effectiveModel})` : ""}
          </span>
          <span
            data-testid="copilot-advisory-chip"
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

      {/* Advisory Disclaimer Notice */}
      <div className="rounded border bg-background px-3 py-2 text-[11.5px] leading-relaxed text-muted-foreground">
        Advisory only: the model explains findings in plain language. Severities and verdicts come from the deterministic rules and are never changed here.
      </div>

      {/* 5 Grounded Roles Tabs */}
      <div className="flex flex-wrap gap-1 rounded-md bg-background p-1 text-[11.5px] font-medium" role="tablist">
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
        <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-hidden" data-testid="copilot-chat">
          <RunBriefing state={state} loading={stateLoading} />
          <div aria-live="polite" className="flex min-h-[160px] flex-1 flex-col gap-2 overflow-y-auto pr-1 text-[12px]">
            {log.length === 0 && (
              <div className="flex flex-col gap-2">
                <p className="text-[12px] leading-normal text-muted-foreground">
                  Ask about this run in plain language. Answers are advisory — rules still own severity.
                </p>
                {DEFAULT_EXAMPLES.map((q) => (
                  <button
                    key={q}
                    onClick={() => ask(q)}
                    className="rounded border bg-card px-2.5 py-1.5 text-left text-xs text-muted-foreground hover:border-primary hover:text-foreground"
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
                          {gotFirstToken ? "" : `waiting for the model… ${elapsed}s`}
                        </span>
                      )}
                      {isStreamingAnswer && m.text && <span className="animate-pulse">▍</span>}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Showcase chips — pull a real is-* result card into the rail */}
          <div className="flex flex-wrap gap-1.5 pt-1" data-testid="copilot-showcase-chips">
            {SHOWCASE_CHIPS.map((p) => (
              <button
                key={p}
                onClick={() => ask(p)}
                disabled={streaming}
                className="rounded-full border border-primary/40 bg-background px-2.5 py-1 text-[11px] font-medium text-primary hover:bg-accent disabled:opacity-50"
              >
                {p}
              </button>
            ))}
          </div>

          {/* Contextual Chips */}
          <div className="flex flex-wrap gap-1.5 pt-1">
            {currentPrompts.map((p) => (
              <button
                key={p}
                onClick={() => ask(p)}
                disabled={streaming}
                className="rounded-full border bg-background px-2.5 py-1 text-[11px] text-muted-foreground hover:border-primary hover:text-foreground disabled:opacity-50"
              >
                {p}
              </button>
            ))}
          </div>

          {streaming && (
            <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
              <span className="tabular-nums">streaming · {elapsed}s</span>
              <button
                onClick={stop}
                className="ml-auto inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] hover:border-primary"
              >
                <Square className="h-3 w-3" aria-hidden /> Stop
              </button>
            </div>
          )}

          <form className="flex shrink-0 gap-1.5" onSubmit={(e) => { e.preventDefault(); ask(draft); }}>
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={blockAsk ? "Analyze a log first…" : "Ask about this run…"}
              aria-label="Ask the AI analyst"
              disabled={streaming || blockAsk}
              className="min-w-0 flex-1 rounded border bg-card px-2.5 py-1.5 text-[12.5px] outline-none focus:border-primary disabled:opacity-60"
            />
            <button
              type="submit"
              aria-label="Send"
              disabled={streaming || !draft.trim() || blockAsk}
              className="inline-flex w-8 items-center justify-center rounded border border-primary bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" aria-hidden />
            </button>
          </form>
        </div>
      )}

      {/* Role 4 View: Prioritize ("Start Here") */}
      {activeTab === "prioritize" && (
        <div data-testid="copilot-prioritize-card" className="flex flex-1 flex-col gap-2.5 overflow-y-auto">
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
        <div data-testid="copilot-trend-card" className="flex flex-1 flex-col gap-2.5 overflow-y-auto">
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

      {/* Role 3 View: Honest Forecast */}
      {activeTab === "forecast" && (
        <div data-testid="copilot-forecast-card" className="flex flex-1 flex-col gap-2.5 overflow-y-auto">
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
              </div>
            )}
          </div>
          <p className="text-[10.5px] text-muted-foreground">
            Forecasts are purely statistical extrapolations of real run counts — never conjured IOCs.
          </p>
        </div>
      )}

      {/* Role 5 View: Cited Resolution via Runbook Engine */}
      {activeTab === "resolution" && (
        <div data-testid="copilot-resolution-card" className="flex flex-1 flex-col gap-2.5 overflow-y-auto">
          {matchedRunbook ? (
            <div className="rounded-lg border bg-background p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-xs font-bold text-foreground">
                  <BookOpen className="h-3.5 w-3.5 text-primary" />
                  Cited resolution
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">
                  {matchedRunbook.file}
                </span>
              </div>
              <div className="text-xs font-semibold text-foreground">
                {matchedRunbook.title}
              </div>
              {typeof matchedRunbook.score === "number" && typeof matchedRunbook.coverage === "number" && (
                <div className="font-mono text-[10.5px] text-muted-foreground">
                  score {matchedRunbook.score} · rule coverage {(matchedRunbook.coverage * 100).toFixed(0)}%
                </div>
              )}
              <div className="space-y-1 rounded bg-card p-2 text-[11.5px]">
                <div className="font-semibold text-foreground">Immediate steps:</div>
                <p className="whitespace-pre-wrap text-muted-foreground">{matchedRunbook.passage}</p>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border bg-background p-3 text-[12px] text-muted-foreground">
              {selectedIncidentId
                ? "No runbook cleared the backend citation threshold for this incident."
                : "Select an incident to request its real derive_rca runbook result."}
            </div>
          )}
        </div>
      )}

      {/* Model footer line */}
      <div className="font-mono text-[11px] text-muted-foreground">
        Model: {effectiveModel}
      </div>

      {/* Verbatim Copilot Footer */}
      <div
        data-testid="copilot-footer"
        className="cop-f border-t pt-2 text-[11px] font-medium text-muted-foreground"
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
