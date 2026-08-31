import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Cable, Plug, RefreshCw } from "lucide-react";
import { api, type OemConnector } from "@/lib/api";

/** OEM / API Engine — read-only connectors that poll a vendor's events API
 *  (Cisco Firepower, Ruckus SmartZone, ManageEngine Log360, or a generic
 *  endpoint) into the persistent store, in the itsoc. design system (mirrors v3
 *  dc "OEM Engine"). Vendor tokens are user-supplied and stored masked — the page
 *  only shows whether a token is set. `lastRun` / `lastError` are the REAL poll
 *  outcome; an event's severity is the level the vendor reported, never guessed.
 *  A placeholder base URL is never called. */

export const EGRESS_DISCLOSURE =
  "Enabling calls external services over HTTPS and transmits credentials, query parameters, and queried indicators — does not send logs wholesale.";

const TEMPLATES: Record<string, { vendor: string; baseUrl: string; eventsPath: string }> = {
  "Cisco Firepower": { vendor: "cisco", baseUrl: "https://FIREPOWER", eventsPath: "/api/fdm/v6/events" },
  "Ruckus SmartZone": { vendor: "ruckus", baseUrl: "https://SMARTZONE", eventsPath: "/wsg/api/public/v11_0/events" },
  "ManageEngine Log360": { vendor: "log360", baseUrl: "https://LOG360", eventsPath: "/api/v2/events" },
  "Generic API": { vendor: "generic", baseUrl: "", eventsPath: "/events" },
};

function AddConnector() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("Cisco Firepower");
  const [vendor, setVendor] = useState(TEMPLATES["Cisco Firepower"].vendor);
  const [baseUrl, setBaseUrl] = useState(TEMPLATES["Cisco Firepower"].baseUrl);
  const [eventsPath, setEventsPath] = useState(TEMPLATES["Cisco Firepower"].eventsPath);
  const [interval, setInterval] = useState("60");
  const [token, setToken] = useState("");
  const [msg, setMsg] = useState("");

  const applyTemplate = (t: string) => {
    setName(t);
    const tpl = TEMPLATES[t];
    if (tpl) { setVendor(tpl.vendor); setBaseUrl(tpl.baseUrl); setEventsPath(tpl.eventsPath); }
  };

  const create = useMutation({
    mutationFn: () => api.oemCreateConnector({
      name: name.trim(),
      config: { vendor, baseUrl: baseUrl.trim(), eventsPath: eventsPath.trim() },
      interval: Number(interval) || 60,
      token: token.trim() || undefined,
    }),
    onSuccess: (out) => {
      setMsg(out.ok ? "Connector saved." : (out.error ?? "Could not save."));
      setToken("");
      queryClient.invalidateQueries({ queryKey: ["oem"] });
    },
  });

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3 style={{ display: "flex", alignItems: "center", gap: 7 }}><Plug size={15} aria-hidden /> Add / update a connector</h3></div>

      <label className="is-field"><span>Template</span>
        <select className="is-select" value={name in TEMPLATES ? name : "Generic API"}
                onChange={(e) => applyTemplate(e.target.value)} aria-label="Template">
          {Object.keys(TEMPLATES).map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>

      <div className="is-grid-2" style={{ gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        <label className="is-field"><span>Connector name</span>
          <input className="is-input" value={name} onChange={(e) => setName(e.target.value)} aria-label="Connector name" placeholder="fw-core" />
        </label>
        <label className="is-field"><span>Poll interval (s)</span>
          <input className="is-input" value={interval} inputMode="numeric"
                 onChange={(e) => setInterval(e.target.value.replace(/[^0-9]/g, ""))} aria-label="Poll interval seconds" placeholder="300" />
        </label>
      </div>

      <label className="is-field"><span>Vendor</span>
        <input className="is-input" value={vendor} onChange={(e) => setVendor(e.target.value)} aria-label="Vendor" />
      </label>

      <label className="is-field"><span>Base URL</span>
        <input className="is-input" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
               aria-label="Base URL" placeholder="https://fmc.local/api" />
      </label>
      <p className="is-mut" style={{ fontSize: 11, margin: "-4px 0 0", lineHeight: 1.5 }}>
        Replace any placeholder host (e.g. <span className="is-mono" style={{ color: "var(--acc)" }}>FIREPOWER</span>) with your
        real appliance — a placeholder URL is never called.
      </p>

      <label className="is-field"><span>Events path</span>
        <input className="is-input" value={eventsPath} onChange={(e) => setEventsPath(e.target.value)} aria-label="Events path" />
      </label>

      <label className="is-field"><span>API token (stored masked, never returned)</span>
        <input className="is-input" type="password" value={token} autoComplete="off"
               onChange={(e) => setToken(e.target.value)} aria-label="API token" placeholder="Bearer token…" />
      </label>

      <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 4 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button className="is-btn is-btn--primary" onClick={() => create.mutate()} disabled={!name.trim() || create.isPending}>
            {create.isPending ? "Saving…" : "Save connector"}
          </button>
          {msg && <span className="is-mut" style={{ fontSize: 12 }}>{msg}</span>}
        </div>
        <p className="is-mut" style={{ fontSize: 11, margin: 0, lineHeight: 1.4 }}>
          {EGRESS_DISCLOSURE}
        </p>
      </div>
    </div>
  );
}

function ConnectorRow({ c }: { c: OemConnector }) {
  const queryClient = useQueryClient();
  const [msg, setMsg] = useState("");
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["oem"] });

  const toggle = useMutation({
    mutationFn: () => api.oemCreateConnector({ name: c.name, config: {}, enabled: !c.enabled }),
    onSuccess: refresh,
  });
  const poll = useMutation({
    mutationFn: () => api.oemPoll(c.name),
    onSuccess: (r) => { setMsg(r.ok ? `Polled — stored ${r.stored} event(s).` : `Poll failed: ${r.error}`); refresh(); },
    onError: (e: Error) => setMsg(e.message),
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6, borderBottom: "1px solid var(--bd)", padding: "12px 0" }}>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "2px 12px" }}>
        <span style={{ fontSize: 13.5, fontWeight: 600 }}>{c.name}</span>
        <span className="is-mut" style={{ fontSize: 11 }}>vendor {c.kind}</span>
        <span style={{ fontSize: 11, fontWeight: 600, color: c.enabled ? "var(--low)" : "var(--mut)" }}>
          {c.enabled ? "enabled" : "disabled"}
        </span>
        <span className="is-mut" style={{ fontSize: 11 }}>every {c.interval ?? 60}s</span>
        <span className="is-mut" style={{ fontSize: 11 }}>{c.hasToken ? "token set" : "no token"}</span>
      </div>
      <div className="is-mut" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "2px 16px", fontSize: 11 }}>
        <span>last run: <span style={{ color: "var(--ink)" }}>{c.lastRun ? new Date(c.lastRun).toLocaleString() : "never"}</span></span>
        {c.lastError && <span style={{ color: "var(--crit)" }}>last error: {c.lastError}</span>}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 2 }}>
        <button className="is-btn" onClick={() => toggle.mutate()} disabled={toggle.isPending}>
          {c.enabled ? "Disable" : "Enable"}
        </button>
        <button className="is-btn" onClick={() => poll.mutate()} disabled={poll.isPending}
                style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <RefreshCw size={12} aria-hidden />
          {poll.isPending ? "Polling…" : "Poll now"}
        </button>
        {msg && <span className="is-mut" style={{ fontSize: 11.5 }}>{msg}</span>}
      </div>
      <p className="is-mut" style={{ fontSize: 11, margin: 0, lineHeight: 1.4 }}>
        {EGRESS_DISCLOSURE}
      </p>
    </div>
  );
}

function ConnectorList() {
  const { data } = useQuery({ queryKey: ["oem", "connectors"], queryFn: api.oemConnectors, refetchInterval: 5000 });
  const items = data?.connectors ?? [];
  return (
    <div className="is-panel" style={{ alignSelf: "start" }}>
      <div className="is-panel__h"><h3 style={{ display: "flex", alignItems: "center", gap: 7 }}><Cable size={15} aria-hidden /> Connectors ({items.length})</h3></div>
      {items.length === 0 ? (
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
          No connectors yet — add one on the left. When enabled and pointed at a real vendor API, the
          engine polls it on its interval and records events in the store.
        </p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column" }}>
          {items.map((c) => <ConnectorRow key={c.name} c={c} />)}
        </div>
      )}
    </div>
  );
}

export function OemEngine() {
  const { error } = useQuery({ queryKey: ["oem", "connectors"], queryFn: api.oemConnectors });
  return (
    <>
      <div className="is-note" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <div>
          <b>Read-only OEM/API connectors · credentials stored masked · last-run is the real outcome.</b>{" "}
          They poll a vendor's events feed into the persistent store — never a fabricated “connected”.
        </div>
        <Link to="/integrations" className="is-btn is-btn--xs" style={{ textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 4 }}>
          <Plug size={12} />
          View Integrations Gallery
        </Link>
      </div>
      {error && (
        <p className="is-mut" style={{ fontSize: 12.5 }}>
          Backend not reachable — start the console server to manage connectors.
        </p>
      )}
      <div className="is-grid-2">
        <AddConnector />
        <ConnectorList />
      </div>
    </>
  );
}
