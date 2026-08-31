import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Bot, Send, Square, X, Sparkles, BookOpen, Compass, House, Bell, TriangleAlert } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useUi } from "@/store/ui";
import { stepForRoute } from "@/lib/tour";

/** Ask AI — a separate, always-available helper bot (distinct from the run
 *  focused AI Analyst rail). It assists users with the app: quick actions
 *  (guided tour, explain this page, jump to a screen) plus grounded advisory
 *  chat over the same /api/ask stream. It never computes a verdict. */
interface AMsg {
  who: "q" | "a" | "err";
  text: string;
}

function TypeText({ text }: { text: string }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (shown >= text.length) return;
    const id = setInterval(() => {
      setShown((s) => {
        if (s >= text.length) return s;
        return s + 1;
      });
    }, 5);
    return () => clearInterval(id);
  }, [text, shown]);
  const animating = shown < text.length;
  return (
    <span data-testid="askai-typewriter">
      {text.slice(0, shown)}
      {animating && <span className="animate-pulse">▍</span>}
    </span>
  );
}

const HELP_ACTIONS = [
  { key: "tour", label: "Take the guided tour", icon: BookOpen },
  { key: "explain", label: "Explain this page", icon: Compass },
  { key: "start", label: "Where should I start?", icon: Sparkles },
] as const;

const NAV_ACTIONS = [
  { key: "/", label: "Overview", icon: House },
  { key: "/alerts", label: "Findings", icon: Bell },
  { key: "/incidents", label: "Incidents", icon: TriangleAlert },
] as const;

export function AskAiBot() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { startTour } = useUi();
  const [open, setOpen] = useState(false);
  const [log, setLog] = useState<AMsg[]>([]);
  const [draft, setDraft] = useState("");
  const [streaming, setStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const greeted = log.length > 0;

  const runAction = (key: string) => {
    if (key === "tour") {
      startTour();
      push("q", "Take the guided tour");
      push("a", "I've started the guided tour — it walks you through the main screens, starting at Overview. Use Next to move on, or Skip to leave. I'm here whenever you need help.");
      return;
    }
    if (key === "explain") {
      const page = stepForRoute(pathname)?.title ?? "this page";
      ask(`Explain what is on this screen (${page}) and how to use it.`);
      return;
    }
    if (key === "start") {
      push("q", "Where should I start?");
      const step = stepForRoute(pathname);
      push("a", step
        ? `You're on ${step.title}. A good first move is the guided tour (tap above) to see every screen, or open a finding if this run has one. Rules always set severity — I only interpret what's already there.`
        : "Start with the guided tour to see every screen. If a run is loaded, open Findings to review what the rules caught.");
      return;
    }
  };

  const go = (path: string) => {
    push("q", `Go to ${path === "/" ? "Overview" : path}`);
    navigate(path);
    push("a", `Opening ${path === "/" ? "Overview" : path}.`);
  };

  const push = (who: AMsg["who"], text: string) => setLog((l) => [...l, { who, text }]);

  const stop = () => abortRef.current?.abort();

  const ask = async (q: string) => {
    const question = q.trim();
    if (!question || streaming) return;
    setDraft("");
    push("q", question);
    push("a", "");
    const answerIndex = log.length + 1;

    const controller = new AbortController();
    abortRef.current = controller;
    setStreaming(true);

    try {
      await api.askStream(question, (delta) => {
        setLog((l) => {
          const next = [...l];
          const cur = next[answerIndex];
          if (cur && cur.who === "a") next[answerIndex] = { ...cur, text: cur.text + delta };
          return next;
        });
      }, controller.signal);
    } catch (e) {
      const aborted = controller.signal.aborted;
      const reason = controller.signal.reason;
      const msg = aborted
        ? reason === "timeout" ? "The model did not start answering in time — try again." : "Stopped."
        : `The assistant backend is not reachable — ${(e as Error).message}`;
      setLog((l) => {
        const next = [...l];
        const cur = next[answerIndex];
        if (cur && cur.who === "a" && !cur.text) next[answerIndex] = { who: "err", text: msg };
        else next.push({ who: "err", text: msg });
        return next;
      });
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  return (
    <div className="fixed bottom-[22px] left-[22px] z-50 flex flex-col items-start gap-2.5">
      {open && (
        <section
          aria-label="Ask AI assistant"
          data-testid="askai-panel"
          className="flex max-h-[min(600px,calc(100vh-100px))] w-[360px] flex-col gap-2 overflow-hidden rounded-lg border bg-card p-3 text-[13px] shadow-[var(--shadow-pop)]"
        >
          <div className="flex shrink-0 items-center justify-between">
            <div className="flex items-center gap-2">
              <Bot className="h-4 w-4 text-primary" strokeWidth={2} aria-hidden />
              <span className="font-bold tracking-tight text-foreground">Ask AI</span>
              <span
                data-testid="askai-advisory-chip"
                className="rounded bg-accent px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-accent-foreground"
              >
                advisory
              </span>
            </div>
            <button onClick={() => setOpen(false)} aria-label="Close Ask AI assistant" className="inline-flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-background">
              <X className="h-4 w-4" aria-hidden />
            </button>
          </div>
          <p className="shrink-0 text-[10.5px] leading-snug text-muted-foreground">
            I help you navigate &amp; understand the app. I never set or change a verdict — rules own severity.
          </p>

          <div aria-live="polite" className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto pr-1 text-[12px]">
            {!greeted && (
              <div className="flex flex-col gap-1.5">
                <p className="text-[12px] font-medium text-foreground" data-testid="askai-greeting">
                  Hi — what can I help you with?
                </p>
                <div className="flex flex-wrap gap-1" data-testid="askai-help-actions">
                  {HELP_ACTIONS.map((a) => {
                    const Icon = a.icon;
                    return (
                      <button
                        key={a.key}
                        onClick={() => runAction(a.key)}
                        data-testid={`askai-action-${a.key}`}
                        className="inline-flex items-center gap-1.5 rounded-full border border-primary/40 bg-background px-2.5 py-1 text-[11px] font-medium text-primary hover:bg-accent"
                      >
                        <Icon className="h-3 w-3" aria-hidden /> {a.label}
                      </button>
                    );
                  })}
                </div>
                <div className="flex flex-wrap gap-1 pt-0.5" data-testid="askai-nav-actions">
                  {NAV_ACTIONS.map((a) => {
                    const Icon = a.icon;
                    return (
                      <button
                        key={a.key}
                        onClick={() => go(a.key)}
                        className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-0.5 text-[10.5px] text-muted-foreground hover:border-primary hover:text-foreground"
                      >
                        <Icon className="h-3 w-3" aria-hidden /> {a.label}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
            {log.map((m, i) => (
              <div
                key={i}
                className={cn(
                  "max-w-[95%] whitespace-pre-wrap rounded-lg px-2.5 py-2",
                  m.who === "q" && "self-end bg-accent text-accent-foreground font-medium",
                  m.who === "a" && "bg-background text-foreground",
                  m.who === "err" && "border border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-300",
                )}
              >
                {m.who === "a" && m.text ? <TypeText text={m.text} /> : m.text}
                {streaming && i === log.length - 1 && m.who === "a" && !m.text && (
                  <span className="text-muted-foreground">thinking…</span>
                )}
              </div>
            ))}
          </div>

          {streaming && (
            <div className="flex shrink-0 items-center gap-2 text-[11px] text-muted-foreground">
              <button onClick={stop} className="inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] hover:border-primary">
                <Square className="h-3 w-3" aria-hidden /> Stop
              </button>
            </div>
          )}

          <form
            data-testid="askai-composer"
            className="flex shrink-0 items-end gap-1.5 border-t pt-2"
            onSubmit={(e) => { e.preventDefault(); ask(draft); }}
          >
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(draft); } }}
              rows={2}
              placeholder="Ask how to use the app…"
              aria-label="Ask the AI assistant a question"
              disabled={streaming}
              className="min-h-[52px] min-w-0 flex-1 resize-none rounded-md border-2 border-primary/50 bg-background px-2.5 py-2 text-[13px] outline-none focus:border-primary disabled:opacity-60"
            />
            <button
              type="submit"
              aria-label="Send"
              disabled={streaming || !draft.trim()}
              className="mb-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-primary bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              <Send className="h-4 w-4" aria-hidden />
            </button>
          </form>

          <div data-testid="askai-footer" className="shrink-0 pt-1 text-[10.5px] font-medium text-muted-foreground">
            I assist &amp; explain — I don&apos;t decide. Rules set severity.
          </div>
        </section>
      )}

      <button
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? "Close Ask AI assistant" : "Open Ask AI assistant"}
        data-testid="askai-fab"
        className="inline-flex items-center gap-[9px] rounded-full border border-primary bg-card px-[18px] py-3 text-[13.5px] font-semibold shadow-card hover:bg-accent"
      >
        {open ? <X className="h-[17px] w-[17px] text-primary" strokeWidth={1.8} aria-hidden />
          : <Sparkles className="h-[17px] w-[17px] text-primary" strokeWidth={1.8} aria-hidden />}
        Ask AI
        <span className="text-[9.5px] font-medium uppercase tracking-[0.05em] text-muted-foreground">help</span>
      </button>
    </div>
  );
}
