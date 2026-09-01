import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Antenna, Radio } from "lucide-react";
import { api, type SyslogStatus } from "@/lib/api";

type IngestSource = "edr" | "firewall" | "cloud" | "webhook";

/** Sources — the control panel for the live syslog listener (UDP + TCP), in the
 *  itsoc. design system (mirrors prototype #p-sources). Every value shown is the
 *  REAL listener state polled from /api/syslog/status; received messages land in
 *  the persistent store verbatim and their severity is the source's own syslog
 *  PRI level, never a guess. Binding 0.0.0.0 exposes the port to the network, so
 *  it is an explicit opt-in with a clear warning. */

/** One State/value row in the Listener status facts (is-facts-row). */
function Fact({ label, children, na }: { label: string; children: React.ReactNode; na?: boolean }) {
  return (
    <div className="is-facts-row">
      <span>{label}</span>
      <b className={na ? "na" : undefined}>{children}</b>
    </div>
  );
}

function LiveStatus({ status }: { status?: SyslogStatus }) {
  const running = !!status?.running;
  // Bind/port is only shown once BOTH are real — never the string "undefined".
  const bindPort = status?.bind && status?.port ? `${status.bind}:${status.port}` : null;
  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Listener status</h3></div>
      <Fact label="State">
        <span style={{ color: running ? "var(--low)" : "var(--mut)" }}>{running ? "Running" : "Stopped"}</span>
      </Fact>
      {bindPort
        ? <Fact label="Bind / port"><span className="is-mono">{bindPort}</span></Fact>
        : <Fact label="Bind / port" na>not bound</Fact>}
      <Fact label="Protocols">{status?.protocols?.join(" + ").toUpperCase() || "UDP + TCP"}</Fact>
      <Fact label="Messages received"><span className="is-tnum">{status?.receivedCount ?? 0}</span></Fact>
      <Fact label="Stored (new, deduped)"><span className="is-tnum">{status?.storedCount ?? 0}</span></Fact>
      <Fact label="Dropped (back-pressure)">
        <span className="is-tnum" data-testid="collector-dropped"
              style={{ color: (status?.droppedCount ?? 0) > 0 ? "var(--warn)" : "var(--mut)" }}>
          {status?.droppedCount ?? 0}
        </span>
      </Fact>
      <Fact label="Queue backlog (lagging)">
        <span className="is-tnum" data-testid="collector-lagging">{status?.laggingCount ?? 0}</span>
        <span className="is-mut"> / {status?.queueCapacity ?? 0}</span>
      </Fact>
      {running && status?.startedAt
        ? <Fact label="Started"><span className="is-mono">{new Date(status.startedAt).toLocaleString()}</span></Fact>
        : <Fact label="Started" na>—</Fact>}
      {status?.lastEventAt
        ? <Fact label="Last message"><span className="is-mono">{new Date(status.lastEventAt).toLocaleString()}</span></Fact>
        : <Fact label="Last message" na>none yet</Fact>}
      {status?.error && (
        <div className="is-facts-row" style={{ color: "var(--crit)" }}>{status.error}</div>
      )}
      {running && status?.exposed && (
        <div className="is-note" style={{ marginTop: 10, borderColor: "var(--crit)", color: "var(--crit)" }}>
          Bound to <span className="is-mono" style={{ fontWeight: 700 }}>0.0.0.0</span> — this port is
          reachable from the whole network. Anyone who can route to this host can send events into your
          store. Bind to <span className="is-mono" style={{ fontWeight: 700 }}>127.0.0.1</span> unless you
          intend to collect from other machines.
        </div>
      )}
      {(status?.droppedCount ?? 0) > 0 && (
        <div className="is-note" data-testid="collector-drop-warning"
             style={{ marginTop: 10, borderColor: "var(--warn)", color: "var(--warn)" }}>
          <b>{status?.droppedCount}</b> event(s) dropped under back-pressure — the ingest queue
          (capacity <span className="is-mono" style={{ fontWeight: 700 }}>{status?.queueCapacity}</span>)
          saturated faster than events could be written to the store. These drops are counted, not
          silently lost: a panel reporting zero drops means a quiet network, not a saturated collector.
        </div>
      )}
    </div>
  );
}

function Controls({ status }: { status?: SyslogStatus }) {
  const queryClient = useQueryClient();
  const [port, setPort] = useState("1514");
  const [bind, setBind] = useState<"127.0.0.1" | "0.0.0.0">("127.0.0.1");
  const [msg, setMsg] = useState("");

  // Seed the form from the last-used / current listener config when it first
  // arrives — but never once the user has touched the form, so neither the
  // first async load nor a later background poll clobbers what they typed.
  const touched = useRef(false);
  const seeded = useRef(false);
  useEffect(() => {
    if (!status || seeded.current || touched.current) return;
    seeded.current = true;
    setPort(String(status.port));
    setBind(status.bind === "0.0.0.0" ? "0.0.0.0" : "127.0.0.1");
  }, [status]);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["syslog"] });
  const start = useMutation({
    mutationFn: () => api.syslogStart({ port: Number(port), bind }),
    onSuccess: (out) => { setMsg(out.ok ? "Collector started." : (out.error ?? "Could not start.")); refresh(); },
  });
  const stop = useMutation({
    mutationFn: () => api.syslogStop(),
    onSuccess: () => { setMsg("Collector stopped."); refresh(); },
  });

  const running = !!status?.running;
  const portNum = Number(port);
  const portValid = Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535;

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3 style={{ display: "flex", alignItems: "center", gap: 7 }}><Antenna size={15} aria-hidden /> Syslog collector (UDP + TCP)</h3></div>
      <p className="is-mut" style={{ fontSize: 12, lineHeight: 1.5, margin: "0 0 8px" }}>
        Receives syslog messages on the port below and records each one in the persistent store,
        verbatim. Severity comes from the syslog PRI the sender chose — the collector never invents a level.
      </p>

      <label className="is-field" style={{ margin: "8px 0" }}>
        <span>Listen port</span>
        <input className="is-input" value={port} inputMode="numeric" aria-label="Listen port" placeholder="1514"
               onChange={(e) => { touched.current = true; setPort(e.target.value.replace(/[^0-9]/g, "")); }} />
      </label>
      {!portValid && <div style={{ color: "var(--crit)", fontSize: 11, marginTop: -4 }}>Port must be 1–65535.</div>}
      <div className="is-mut" style={{ fontSize: 11, lineHeight: 1.5 }}>
        1514 is unprivileged; port 514 (the syslog default) needs root — put a relay in front, or use
        1514 and point senders at it.
      </div>

      <label className={"is-radio" + (bind === "127.0.0.1" ? " on" : "")}>
        <input type="radio" name="syslog-bind" value="127.0.0.1" className="is-visually-hidden"
               checked={bind === "127.0.0.1"} onChange={() => { touched.current = true; setBind("127.0.0.1"); }} />
        <span className="dot" aria-hidden />
        <span style={{ color: "var(--ink)" }}>Loopback</span>
        <span className="is-mono">127.0.0.1</span>
        <small>— only this machine (safe default)</small>
      </label>
      <label className={"is-radio" + (bind === "0.0.0.0" ? " on" : "")}>
        <input type="radio" name="syslog-bind" value="0.0.0.0" className="is-visually-hidden"
               checked={bind === "0.0.0.0"} onChange={() => { touched.current = true; setBind("0.0.0.0"); }} />
        <span className="dot" aria-hidden />
        <span style={{ color: "var(--ink)" }}>All interfaces</span>
        <span className="is-mono">0.0.0.0</span>
        <small style={{ color: "var(--high)" }}>— exposes the port to the network</small>
      </label>

      {bind === "0.0.0.0" && (
        <div className="is-note" style={{ borderColor: "var(--high)", color: "var(--high)", marginTop: 4 }}>
          Binding to <span className="is-mono" style={{ fontWeight: 700 }}>0.0.0.0</span> exposes the
          listener to the network. Any host that can reach this machine could send events into your
          store — only do this on a trusted network, behind a firewall.
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginTop: 8, alignItems: "center" }}>
        <button className="is-btn is-btn--primary" onClick={() => start.mutate()} disabled={start.isPending || !portValid}>
          {start.isPending ? "Starting…" : running ? "Restart" : "Start collector"}
        </button>
        <button className="is-btn" onClick={() => stop.mutate()} disabled={stop.isPending || !running}>Stop</button>
        {msg && <span className="is-mut" style={{ fontSize: 12 }}>{msg}</span>}
      </div>

      <details className="is-mut" style={{ fontSize: 11.5, paddingTop: 8 }}>
        <summary style={{ cursor: "pointer", fontWeight: 500 }}>How to send it a test message</summary>
        <pre className="is-mono" style={{ marginTop: 8, overflowX: "auto", border: "1px solid var(--bd)", borderRadius: 8, padding: 10, fontSize: 11, lineHeight: 1.6, color: "var(--ink2)" }}>
{`# UDP
logger -n 127.0.0.1 -P ${portValid ? portNum : 1514} -d "test from logger"
echo '<13>hello syslog' | nc -u -w1 127.0.0.1 ${portValid ? portNum : 1514}

# TCP
echo '<11>disk error on host1' | nc -w1 127.0.0.1 ${portValid ? portNum : 1514}`}
        </pre>
      </details>
    </div>
  );
}

function RecentEvents({ running }: { running: boolean }) {
  const { data } = useQuery({
    queryKey: ["syslog", "events"], queryFn: () => api.syslogEvents(15),
    refetchInterval: running ? 3000 : false,
  });
  const items = data?.items ?? [];

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Recent received events</h3></div>
      {items.length === 0 ? (
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
          No events received yet — the listener reports real traffic only. Start the collector and
          send it a message; received lines appear here and in the events store.
        </p>
      ) : (
        <>
          <p className="is-mut" style={{ marginTop: 0, marginBottom: 10, fontSize: 11.5 }}>
            Severity shown is the sender's own syslog level (source-reported), not a verdict.{" "}
            <span className="is-mono" style={{ color: "var(--ink)" }}>raw</span> is the exact line received.
          </p>
          <div style={{ overflowX: "auto" }}>
            <table className="is-table">
              <thead>
                <tr><th>Time</th><th>From</th><th>Host</th><th>Severity</th><th>Raw</th></tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id} style={{ cursor: "default" }}>
                    <td className="col-mono" style={{ whiteSpace: "nowrap" }}>{new Date(e.ts).toLocaleTimeString()}</td>
                    <td className="col-mono">{e.src_ip || "—"}</td>
                    <td className="col-mono">{e.host || "—"}</td>
                    <td style={{ fontSize: 12 }}>{e.severity || <span className="is-mut">none</span>}</td>
                    <td className="is-mono" style={{ fontSize: 11, color: "var(--mut)", wordBreak: "break-all" }}>{e.raw}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function WebhookIngest() {
  const queryClient = useQueryClient();
  const [source, setSource] = useState<IngestSource>("webhook");
  const [body, setBody] = useState("{\n  \"message\": \"example event\",\n  \"host\": \"sensor-01\"\n}\n");
  const [result, setResult] = useState<string>("");
  const [err, setErr] = useState("");

  const send = useMutation({
    mutationFn: async () => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch {
        throw new Error("JSON is not valid — nothing was stored.");
      }
      const events = Array.isArray(parsed) ? parsed
        : (parsed && typeof parsed === "object" && "events" in (parsed as object))
          ? parsed
          : { event: parsed as Record<string, unknown> };
      const payload = Array.isArray(parsed)
        ? { source, events: parsed }
        : (parsed && typeof parsed === "object" && "source" in (parsed as object))
          ? parsed as { source: IngestSource; events?: unknown }
          : { source, ...(events as object) };
      return api.ingestWebhook(payload as Parameters<typeof api.ingestWebhook>[0]);
    },
    onSuccess: (out) => {
      if (!out.ok) { setErr(out.error ?? "Ingest failed."); setResult(""); return; }
      setErr("");
      const hits = (out.sigmaHits || []).map((h) => `${h.id}×${h.count}`).join(", ") || "none";
      setResult(`stored ${out.stored ?? 0} of ${out.accepted ?? 0} · Sigma hits: ${hits}`);
      queryClient.invalidateQueries({ queryKey: ["syslog", "events"] });
      queryClient.invalidateQueries({ queryKey: ["ingest"] });
    },
    onError: (e) => { setErr((e as Error).message); setResult(""); },
  });

  return (
    <div className="is-panel" data-testid="webhook-ingest">
      <div className="is-panel__h"><h3>Webhook / EDR / firewall / cloud</h3></div>
      <p className="is-mut" style={{ fontSize: 12, lineHeight: 1.5, margin: "0 0 8px" }}>
        POST JSON into the persistent store. Severity is whatever the event itself reported.
        Sigma may match after ingest — that is a rule hit, not an AI verdict.
      </p>
      <label className="is-field" style={{ margin: "8px 0" }}>
        <span>Source</span>
        <select className="is-select" aria-label="Ingest source" value={source}
                onChange={(e) => setSource(e.target.value as IngestSource)}>
          <option value="webhook">webhook</option>
          <option value="edr">edr</option>
          <option value="firewall">firewall</option>
          <option value="cloud">cloud</option>
        </select>
      </label>
      <label className="is-field">
        <span>JSON event or array</span>
        <textarea className="is-input" style={{ minHeight: 120, fontFamily: "var(--mono)", fontSize: 11 }}
                  aria-label="Ingest JSON" value={body} onChange={(e) => setBody(e.target.value)} />
      </label>
      {err && <p style={{ color: "var(--crit)", fontSize: 11.5, margin: "6px 0 0" }}>{err}</p>}
      {result && <p className="is-mut" data-testid="ingest-result" style={{ fontSize: 12, margin: "6px 0 0" }}>{result}</p>}
      <button className="is-btn is-btn--primary" style={{ marginTop: 10 }}
              disabled={send.isPending} onClick={() => send.mutate()}>
        {send.isPending ? "Sending…" : "POST to /api/ingest/webhook"}
      </button>
    </div>
  );
}

/** Splunk has no push tail endpoint in the local console. This connector polls
 * Splunk's export endpoint on a short, explicit interval and stores only real
 * returned events. Tokens are write-only and never come back to the browser. */
function SplunkLive() {
  const queryClient = useQueryClient();
  const [baseUrl, setBaseUrl] = useState("");
  const [token, setToken] = useState("");
  const [query, setQuery] = useState("search index=* earliest=-2m | head 200");
  const [notice, setNotice] = useState("");
  const { data } = useQuery({ queryKey: ["oem", "connectors"], queryFn: api.oemConnectors, refetchInterval: 5000 });
  const connector = data?.connectors.find((item) => item.name === "splunk-live");
  const start = useMutation({
    mutationFn: async () => {
      const out = await api.oemCreateConnector({
        name: "splunk-live", enabled: true, interval: 15, token,
        config: { vendor: "splunk", baseUrl, eventsPath: "/services/search/jobs/export", query },
      });
      if (!out.ok) throw new Error(out.error ?? "Could not save the Splunk connector.");
      return api.oemPoll("splunk-live");
    },
    onSuccess: (out) => {
      setToken("");
      setNotice(out.ok ? `Connected — ${out.stored} event(s) stored from the live poll.` : out.error || "Connector saved; the first poll did not complete.");
      queryClient.invalidateQueries({ queryKey: ["oem"] });
      queryClient.invalidateQueries({ queryKey: ["syslog", "events"] });
    },
    onError: (error) => setNotice((error as Error).message),
  });
  const poll = useMutation({ mutationFn: () => api.oemPoll("splunk-live"), onSuccess: (out) => setNotice(out.ok ? `Live poll stored ${out.stored} event(s).` : out.error || "Poll returned no event."), onError: (error) => setNotice((error as Error).message) });

  return <section className="is-panel" data-testid="splunk-live-collector">
    <div className="is-panel__h"><h3 style={{ display: "flex", alignItems: "center", gap: 7 }}><Radio size={15} aria-hidden /> Splunk live analysis</h3>{connector?.enabled && <span className="is-chip is-chip--ok">polling every {connector.interval ?? 15}s</span>}</div>
    <p className="is-mut" style={{ fontSize: 12, lineHeight: 1.5, margin: "0 0 8px" }}>Runs your SPL against Splunk&apos;s export endpoint and stores only returned events for rule analysis. This is outbound access to the Splunk endpoint; enable the console with <code>ITSOC_OEM=1</code> before starting it.</p>
    <div className="is-grid-2">
      <label className="is-field"><span>Splunk base URL</span><input className="is-input" aria-label="Splunk base URL" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://splunk.company.internal:8089" /></label>
      <label className="is-field"><span>API token</span><input className="is-input" aria-label="Splunk API token" type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder={connector?.hasToken ? "Token saved — enter a new value to replace" : "Write-only token"} /></label>
    </div>
    <label className="is-field" style={{ marginTop: 8 }}><span>SPL query</span><textarea className="is-input is-mono" aria-label="Splunk query" rows={2} value={query} onChange={(event) => setQuery(event.target.value)} /></label>
    <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 10 }}><button type="button" className="is-btn is-btn--primary" disabled={start.isPending || !baseUrl.trim() || (!token.trim() && !connector?.hasToken)} onClick={() => start.mutate()}>{start.isPending ? "Connecting…" : connector?.enabled ? "Update live poll" : "Connect live poll"}</button><button type="button" className="is-btn" disabled={poll.isPending || !connector?.enabled} onClick={() => poll.mutate()}>{poll.isPending ? "Polling…" : "Poll now"}</button>{connector?.lastError && <span style={{ color: "var(--crit)", fontSize: 11.5 }}>{connector.lastError}</span>}</div>
    {notice && <p className="is-mut" style={{ fontSize: 11.5, margin: "9px 0 0" }}>{notice}</p>}
  </section>;
}

export function Collectors() {
  const { data: status, error } = useQuery({
    queryKey: ["syslog", "status"], queryFn: api.syslogStatus, refetchInterval: 3000,
  });

  return (
    <>
      <div className="is-note">
        <b>Real listener state — never a fake running.</b> Point network devices, Linux/Windows
        agents, or a relay at this port and messages stream into the persistent store in real time.
      </div>
      {error && (
        <p className="is-mut" style={{ fontSize: 12.5 }}>
          Backend not reachable — start the console server to control the collector.
        </p>
      )}
      <div className="is-grid-2">
        <Controls status={status} />
        <LiveStatus status={status} />
      </div>
      <SplunkLive />
      <WebhookIngest />
      <RecentEvents running={!!status?.running} />
    </>
  );
}
