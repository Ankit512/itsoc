import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type ComputeConfig, type OverviewData } from "@/lib/api";
import { useUi } from "@/store/ui";

/** Settings — only the knobs that genuinely do something, in the itsoc. design
 *  system (mirrors prototype #p-settings). Compute location and its redaction
 *  consequence (the real /api/compute you can set), the analyst model/endpoint
 *  shown honestly, and theme. No invented switches: every value reflects real
 *  backend or client state. Cards cap at ~560px per the handoff. */

const CARD: React.CSSProperties = { maxWidth: 560 };

function ComputeSettings() {
  const queryClient = useQueryClient();
  const { data: compute, isLoading, error } = useQuery<ComputeConfig>({
    queryKey: ["compute"], queryFn: api.getCompute,
  });

  const [mode, setMode] = useState<"local" | "remote">("local");
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [msg, setMsg] = useState("");

  // Seed the form from the real current config once it loads.
  useEffect(() => {
    if (!compute) return;
    setMode(compute.mode);
    setBaseUrl(compute.baseUrl ?? "");
    setModel(compute.model ?? "");
  }, [compute]);

  const save = useMutation({
    mutationFn: () => api.setCompute(mode === "local" ? { mode } : { mode, baseUrl, model, apiKey }),
    onSuccess: (out) => {
      if (!out.ok) { setMsg(out.error ?? "Could not save."); return; }
      setMsg("Saved."); setApiKey("");
      queryClient.invalidateQueries({ queryKey: ["compute"] });
      queryClient.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  return (
    <div className="is-panel" style={CARD}>
      <div className="is-panel__h"><h3>⚙ Compute location</h3></div>
      {isLoading && <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>Loading current config…</p>}
      {error && <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>Backend not reachable — start the console server.</p>}
      {compute && (
        <>
          <p className="is-mut" style={{ fontSize: 12, lineHeight: 1.5, margin: "0 0 4px" }}>
            Detection ALWAYS runs locally — this only changes where the advisory LLM explanations
            compute. Currently: <b style={{ color: "var(--ink)" }}>{compute.mode}</b>.
          </p>
          {(["local", "remote"] as const).map((m) => (
            <label key={m} className={"is-radio" + (mode === m ? " on" : "")}>
              <input type="radio" name="compute-mode" value={m} className="is-visually-hidden"
                     checked={mode === m} onChange={() => setMode(m)} />
              <span className="dot" aria-hidden />
              <span style={{ color: "var(--ink)" }}>{m === "local" ? "Local" : "Remote"}</span>
              <small>
                {m === "local" ? "— nothing leaves this machine"
                  : "— explanations call an OpenAI-compatible endpoint (redacted first)"}
              </small>
            </label>
          ))}

          {mode === "remote" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
              <label className="is-field"><span>Base URL (must end in /v1)</span>
                <input className="is-input" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                       aria-label="Remote base URL" placeholder="https://host:port/v1" />
              </label>
              <label className="is-field"><span>Model</span>
                <input className="is-input" value={model} onChange={(e) => setModel(e.target.value)}
                       aria-label="Remote model" placeholder="model name" />
              </label>
              <label className="is-field">
                <span>API key {compute.hasKey && <span style={{ color: "var(--ink)" }}>(a key is currently set — leave blank to keep it)</span>}</span>
                <input className="is-input" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
                       aria-label="Remote API key" placeholder="sk-…" autoComplete="off" />
              </label>
              <p className="is-mut" style={{ fontSize: 10.5, margin: 0 }}>
                The key is sent to the backend but never returned to the browser.
              </p>
            </div>
          )}

          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10 }}>
            <button className="is-btn is-btn--primary" onClick={() => save.mutate()} disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save compute settings"}
            </button>
            {msg && <span className="is-mut" style={{ fontSize: 12 }}>{msg}</span>}
          </div>
        </>
      )}
    </div>
  );
}

function RedactionInfo({ compute }: { compute?: ComputeConfig }) {
  const remote = compute?.mode === "remote";
  return (
    <div className="is-panel" style={CARD}>
      <div className="is-panel__h"><h3>Outbound redaction</h3></div>
      <p className="is-mut" style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>
        Redaction is a consequence of compute location, not a separate toggle — so it is shown here
        honestly rather than as a switch that does nothing.
        {remote ? (
          <> It is <b style={{ color: "var(--ink)" }}>active</b>: with remote compute, finding summaries
          and your analyst questions pass through the redaction choke point{" "}
          <span className="is-mono" style={{ color: "var(--acc)" }}>console/redact.py</span> before leaving
          this machine. Raw log lines never leave at all.</>
        ) : (
          <> It is <b style={{ color: "var(--ink)" }}>not applicable</b> right now: compute is local, so
          nothing is sent anywhere and there is nothing to redact. Switch to remote above and redaction
          engages automatically.</>
        )}
      </p>
    </div>
  );
}

function AnalystModel() {
  const { data } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  const { data: compute } = useQuery<ComputeConfig>({ queryKey: ["compute"], queryFn: api.getCompute });
  const overview = data && !("error" in data) ? (data as OverviewData) : null;
  const model = compute?.mode === "remote" ? compute.model : overview?.model;

  return (
    <div className="is-panel" style={CARD}>
      <div className="is-panel__h"><h3>Analyst model</h3></div>
      <p style={{ fontSize: 12, margin: 0 }}>
        Model: <span className="is-mono" style={{ color: "var(--ink)", fontWeight: 500 }}>{model || "not reported (analyze a run first)"}</span>
        {compute?.mode === "remote"
          ? <> · Endpoint: <span className="is-mono" style={{ color: "var(--ink)", fontWeight: 500 }}>{compute.baseUrl || "—"}</span></>
          : <> · Endpoint: <b style={{ color: "var(--ink)" }}>local</b></>}
      </p>
      <p className="is-mut" style={{ fontSize: 12, margin: "6px 0 0", lineHeight: 1.5 }}>
        The model only explains findings in plain language. It never sets or changes a severity or
        verdict — those are the deterministic rules.
      </p>
    </div>
  );
}

function ThemeSetting() {
  const theme = useUi((s) => s.theme);
  const toggleTheme = useUi((s) => s.toggleTheme);
  const dark = theme === "dark";
  return (
    <div className="is-panel" style={CARD}>
      <div className="is-panel__h"><h3>Appearance</h3></div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 12 }}>
          Theme: <b style={{ color: "var(--ink)" }}>{dark ? "Dark" : "Light"}</b> — saved for your next visit.
        </span>
        <button className="is-btn" onClick={toggleTheme}
                aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}>
          {dark ? "☀ Switch" : "☾ Switch"}
        </button>
      </div>
    </div>
  );
}

export function Settings() {
  const { data: compute } = useQuery<ComputeConfig>({ queryKey: ["compute"], queryFn: api.getCompute });
  return (
    <>
      <div className="is-note" style={{ maxWidth: 560 }}>
        <b>System settings.</b> Only settings that genuinely do something are shown — each reflects real
        backend or client state, nothing decorative.
      </div>
      <ComputeSettings />
      <RedactionInfo compute={compute} />
      <AnalystModel />
      <ThemeSetting />
    </>
  );
}
