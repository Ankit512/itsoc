import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type StoreEvent, type HistoryQuery } from "@/lib/api";
import { sevVar } from "@/lib/severity";

/** History — the persistent store's event history, Command-Center KPIs, EVTX
 *  ingest, and retention controls, in the itsoc. design system (mirrors
 *  prototype #p-history + handoff §3). Every number is a real store count and
 *  every row is a stored event (raw verbatim, severity source-reported). An
 *  empty store shows an honest empty state; purge is destructive and gated
 *  behind a typed confirmation. */

const PAGE = 50;

function Kpis() {
  const { data } = useQuery({ queryKey: ["store", "metrics"], queryFn: api.storeMetrics, refetchInterval: 5000 });
  const tiles: { label: string; value: number | undefined; note?: string }[] = [
    { label: "Events", value: data?.events },
    { label: "Critical", value: data?.critical, note: "source-reported" },
    { label: "High", value: data?.high, note: "source-reported" },
    { label: "Assets", value: data?.assets },
    { label: "Open Vulns", value: data?.openVulns },
    { label: "IOC Hits", value: data?.iocHits },
  ];
  return (
    <div className="is-kpis" style={{ gridTemplateColumns: "repeat(6, 1fr)" }}>
      {tiles.map((t) => (
        <div key={t.label} className="is-kpi">
          <div className="lbl">{t.label}</div>
          <div className="val is-tnum">{t.value ?? "—"}</div>
          {t.note && <div className="delta na">{t.note}</div>}
        </div>
      ))}
    </div>
  );
}

function EvtxIngest() {
  const queryClient = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [msg, setMsg] = useState("");
  const [tone, setTone] = useState<string | undefined>(undefined);
  const { data: status } = useQuery({ queryKey: ["evtx", "status"], queryFn: api.evtxStatus });

  const ingest = useMutation({
    mutationFn: (file: File) => api.evtxIngest(file),
    onSuccess: (out) => {
      if (out.ok && out.result) {
        setTone("var(--low)");
        setMsg(`Ingested ${out.result.file ?? "file"} — stored ${out.result.stored} of ${out.result.parsed} record(s)`
          + (out.result.skipped ? ` (${out.result.skipped} unreadable)` : "") + ".");
        queryClient.invalidateQueries({ queryKey: ["store"] });
      } else {
        setTone("var(--crit)");
        setMsg(out.error ?? "Ingest failed.");
      }
    },
  });

  const unavailable = status && !status.available;

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Ingest Windows Event Log (.evtx)</h3></div>
      <p className="is-mut" style={{ fontSize: 12, lineHeight: 1.5, margin: "0 0 8px" }}>
        Parse an .evtx file into the persistent store. Each event's severity is the level Windows
        itself assigned (the EVTX{" "}
        <span className="is-mono" style={{ color: "var(--ink)" }}>Level</span>), and its raw is the verbatim record —
        never keyword-guessed or rewritten.
      </p>
      {unavailable && (
        <div className="is-note" style={{ borderColor: "var(--high)", color: "var(--high)" }}>{status?.message}</div>
      )}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
        <input ref={inputRef} type="file" accept=".evtx" className="is-visually-hidden" data-testid="evtx-file"
               aria-label="Choose an .evtx file"
               onChange={(e) => { const f = e.target.files?.[0]; if (f) ingest.mutate(f); e.target.value = ""; }} />
        <button className="is-btn is-btn--primary" onClick={() => inputRef.current?.click()} disabled={ingest.isPending || unavailable}>
          {ingest.isPending ? "Ingesting…" : "Choose .evtx"}
        </button>
        {msg && <span style={{ fontSize: 12, color: tone }}>{msg}</span>}
      </div>
    </div>
  );
}

function Retention() {
  const queryClient = useQueryClient();
  const { data: settings } = useQuery({ queryKey: ["store", "settings"], queryFn: api.storeSettings });
  const [days, setDays] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState("");
  const stored = settings?.settings?.retention_days ?? "90";
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["store"] });

  const save = useMutation({
    mutationFn: () => api.setRetentionDays(Number(days)),
    onSuccess: () => { setMsg(`Retention set to ${days} days.`); setDays(""); invalidate(); },
  });
  const cleanup = useMutation({
    mutationFn: () => api.storeCleanup(),
    onSuccess: (r) => {
      const n = Object.values(r.deleted).reduce((a, b) => a + b, 0);
      setMsg(`Cleanup removed ${n} row(s) older than ${r.retentionDays} days.`); invalidate();
    },
  });
  const purge = useMutation({
    mutationFn: () => api.storePurge(),
    onSuccess: (r) => {
      const n = Object.values(r.purged).reduce((a, b) => a + b, 0);
      setMsg(`History purged — 0 events retained (${n} row(s) removed).`); setConfirm(""); invalidate();
    },
  });

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Retention &amp; cleanup</h3></div>
      <label className="is-field">
        <span>Retention window (days) — history older than this is removed on cleanup</span>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input className="is-input" inputMode="numeric" value={days} aria-label="Retention days"
                 onChange={(e) => setDays(e.target.value.replace(/[^0-9]/g, ""))} placeholder={`current: ${stored}`} />
          <button className="is-btn" onClick={() => save.mutate()} disabled={!days || save.isPending}>Save</button>
        </div>
      </label>
      <div style={{ marginTop: 8 }}>
        <button className="is-btn" onClick={() => cleanup.mutate()} disabled={cleanup.isPending}>
          {cleanup.isPending ? "Cleaning…" : `Run cleanup (older than ${stored} days)`}
        </button>
      </div>

      <div className="is-note" style={{ borderColor: "var(--crit)", marginTop: 12 }}>
        <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: "var(--crit)" }}>
          Danger — purge all history
        </span>
        <p className="is-mut" style={{ fontSize: 11, lineHeight: 1.5, margin: "6px 0" }}>
          Permanently wipes ALL stored events, assets, vulnerabilities, IOCs and investigations. Type{" "}
          <span className="is-mono" style={{ fontWeight: 700, color: "var(--ink)" }}>PURGE</span> to confirm.
          This deletes every stored event.
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input className="is-input" value={confirm} onChange={(e) => setConfirm(e.target.value)}
                 aria-label="Type PURGE to confirm" placeholder="PURGE" />
          <button className="is-btn" onClick={() => purge.mutate()} disabled={confirm !== "PURGE" || purge.isPending}
                  style={{ whiteSpace: "nowrap", borderColor: "var(--crit)",
                           background: confirm === "PURGE" ? "var(--crit)" : "transparent",
                           color: confirm === "PURGE" ? "#fff" : "var(--crit)" }}>
            {purge.isPending ? "Purging…" : "Purge everything"}
          </button>
        </div>
      </div>
      {msg && <span className="is-mut" style={{ fontSize: 12, marginTop: 8, display: "inline-block" }}>{msg}</span>}
    </div>
  );
}

function EventsTable() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [offset, setOffset] = useState(0);
  const query: HistoryQuery = {
    q: q || undefined, severity: severity || undefined,
    source_type: sourceType || undefined, limit: PAGE, offset,
  };
  const { data } = useQuery({
    queryKey: ["store", "events", query], queryFn: () => api.historyEvents(query), refetchInterval: 5000,
  });
  const items: StoreEvent[] = data?.items ?? [];
  const total = data?.total ?? 0;
  const reset = () => setOffset(0);

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Events</h3><span className="is-panel__sub">{total} total</span></div>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <input className="is-input" style={{ width: 224 }} value={q} aria-label="Search events" placeholder="Search text…"
               onChange={(e) => { setQ(e.target.value); reset(); }} />
        <select className="is-select" style={{ width: "auto" }} value={severity} aria-label="Filter severity"
                onChange={(e) => { setSeverity(e.target.value); reset(); }}>
          <option value="">All severities</option>
          {["CRITICAL", "HIGH", "ERROR", "WARNING", "MEDIUM", "LOW", "INFORMATION", "NOTICE", "VERBOSE"].map((s) =>
            <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="is-select" style={{ width: "auto" }} value={sourceType} aria-label="Filter source type"
                onChange={(e) => { setSourceType(e.target.value); reset(); }}>
          <option value="">All sources</option>
          {["evtx", "syslog", "file", "oem:cisco", "oem:ruckus", "oem:log360"].map((s) =>
            <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {items.length === 0 ? (
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
          No events in the store yet — counts here are real totals only. Ingest an .evtx above, start
          the syslog collector, or add an OEM connector.
        </p>
      ) : (
        <>
          <p className="is-mut" style={{ fontSize: 11.5, marginTop: 0, marginBottom: 10 }}>
            Severity is the level the source reported (never a verdict).{" "}
            <span className="is-mono" style={{ color: "var(--ink)" }}>raw</span> is the exact stored record.
          </p>
          <div style={{ overflowX: "auto" }}>
            <table className="is-table">
              <thead>
                <tr><th>Time</th><th>Source type</th><th>Host</th><th>Event ID</th><th>Severity</th><th>Message</th></tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id} style={{ cursor: "default" }}>
                    <td className="col-mono" style={{ whiteSpace: "nowrap" }}>{new Date(e.ts).toLocaleString()}</td>
                    <td className="col-mono">{e.source_type || "—"}</td>
                    <td className="col-mono" style={{ color: "var(--ink)", fontWeight: 500 }}>{e.host || "—"}</td>
                    <td className="col-mono">{e.event_id || "—"}</td>
                    <td style={{ fontSize: 12, fontWeight: 600, color: e.severity ? sevVar(e.severity) : undefined }}>
                      {e.severity || <span className="is-mut" style={{ fontWeight: 400 }}>none</span>}
                    </td>
                    <td className="is-mono" style={{ fontSize: 11, color: "var(--mut)", wordBreak: "break-all" }} title={e.raw}>{e.message || e.raw}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 12, paddingTop: 10 }}>
            <button className="is-btn" onClick={() => setOffset(Math.max(0, offset - PAGE))} disabled={offset === 0}>Prev</button>
            <span className="is-tnum is-mut" style={{ fontWeight: 500 }}>
              {offset + 1}–{Math.min(offset + PAGE, total)} of {total}
            </span>
            <button className="is-btn" onClick={() => setOffset(offset + PAGE)} disabled={offset + PAGE >= total}>Next</button>
          </div>
        </>
      )}
    </div>
  );
}

export function History() {
  const { error } = useQuery({ queryKey: ["store", "metrics"], queryFn: api.storeMetrics });
  return (
    <>
      <div className="is-note">
        <b>Persistent event store · counts are real totals · severity is source-reported.</b> Windows
        EVTX ingest, Command-Center counts, full event history, and retention controls — never a verdict.
      </div>
      {error && (
        <p className="is-mut" style={{ fontSize: 12.5 }}>
          Backend not reachable — start the console server to view stored history.
        </p>
      )}
      <Kpis />
      <div className="is-grid-2" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <EvtxIngest />
        <Retention />
      </div>
      <EventsTable />
    </>
  );
}
