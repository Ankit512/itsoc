import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Database, FileUp, Trash2, TriangleAlert, Upload } from "lucide-react";
import { api, type StoreEvent, type HistoryQuery } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { sevVar } from "@/lib/severity";

/** History — the persistent store's event history, Command-Center KPIs, EVTX
 *  ingest, and retention controls. Every number is a real store count and every
 *  row is a stored event (raw verbatim, severity source-reported). An empty
 *  store shows an honest empty state; purge is destructive and gated behind a
 *  typed confirmation. */

const field = "w-full rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground outline-none focus:ring-1 focus:ring-primary";
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
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
      {tiles.map((t) => (
        <Card key={t.label} className="rounded-xl border border-border bg-card shadow-sm">
          <CardContent className="flex flex-col gap-1 p-3.5">
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{t.label}</span>
            <span className="text-[22px] font-bold tabular-nums leading-tight text-foreground">{t.value ?? "—"}</span>
            {t.note && <span className="text-[10px] text-muted-foreground">{t.note}</span>}
          </CardContent>
        </Card>
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
        setTone("var(--sev-low)");
        setMsg(`Ingested ${out.result.file ?? "file"} — stored ${out.result.stored} of ${out.result.parsed} record(s)`
          + (out.result.skipped ? ` (${out.result.skipped} unreadable)` : "") + ".");
        queryClient.invalidateQueries({ queryKey: ["store"] });
      } else {
        setTone("var(--sev-critical)");
        setMsg(out.error ?? "Ingest failed.");
      }
    },
  });

  const unavailable = status && !status.available;

  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          <FileUp className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Ingest Windows Event Log (.evtx)
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3 flex flex-col gap-3">
        <p className="text-[12px] text-muted-foreground leading-relaxed">
          Upload a Windows <span className="font-mono text-primary text-[11.5px]">.evtx</span> file to record its events in the
          store. Each event's severity is the level Windows itself assigned (the EVTX
          <span className="font-mono text-foreground font-medium"> Level</span>), and its raw is the verbatim record — never
          keyword-guessed or rewritten.
        </p>
        {unavailable && (
          <div className="flex items-start gap-2 rounded-lg border p-2.5 text-[11.5px]"
               style={{ borderColor: "var(--sev-medium)", color: "var(--sev-medium)", background: "color-mix(in srgb, var(--sev-medium) 8%, transparent)" }}>
            <TriangleAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
            <span>{status?.message}</span>
          </div>
        )}
        <div className="flex items-center gap-2 pt-1">
          <input ref={inputRef} type="file" accept=".evtx" className="hidden" data-testid="evtx-file"
                 aria-label="Choose an .evtx file"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) ingest.mutate(f); e.target.value = ""; }} />
          <button onClick={() => inputRef.current?.click()} disabled={ingest.isPending || unavailable}
            className="inline-flex items-center gap-1.5 rounded-lg border border-primary bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60 transition-opacity">
            <Upload className="h-3.5 w-3.5" strokeWidth={2} aria-hidden />
            {ingest.isPending ? "Ingesting…" : "Choose .evtx"}
          </button>
          {msg && <span className="text-[12px]" style={{ color: tone }}>{msg}</span>}
        </div>
      </CardContent>
    </Card>
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
      setMsg(`Purged ${n} row(s) — the store is now empty.`); setConfirm(""); invalidate();
    },
  });

  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          <Database className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Retention &amp; cleanup
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3 flex flex-col gap-3">
        <label className="text-[11px] font-medium text-muted-foreground">
          Retention window (days) — history older than this is removed on cleanup
          <div className="mt-1 flex items-center gap-2">
            <input className={field} inputMode="numeric" value={days}
                   onChange={(e) => setDays(e.target.value.replace(/[^0-9]/g, ""))}
                   aria-label="Retention days" placeholder={`current: ${stored}`} />
            <button onClick={() => save.mutate()} disabled={!days || save.isPending}
              className="whitespace-nowrap rounded-lg border border-border bg-card px-3 py-2 text-xs font-semibold text-foreground hover:bg-muted disabled:opacity-50 transition-colors">
              Save
            </button>
          </div>
        </label>
        <div>
          <button onClick={() => cleanup.mutate()} disabled={cleanup.isPending}
            className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-foreground hover:bg-muted disabled:opacity-50 transition-colors">
            {cleanup.isPending ? "Cleaning…" : `Run cleanup (older than ${stored} days)`}
          </button>
        </div>

        <div className="flex flex-col gap-2 rounded-lg border p-3"
             style={{ borderColor: "var(--sev-critical)", background: "color-mix(in srgb, var(--sev-critical) 6%, transparent)" }}>
          <span className="flex items-center gap-1.5 text-[12px] font-semibold" style={{ color: "var(--sev-critical)" }}>
            <Trash2 className="h-3.5 w-3.5" aria-hidden /> Danger — purge all history
          </span>
          <p className="text-[11px] text-muted-foreground leading-normal">
            Permanently wipes ALL stored events, assets, vulnerabilities, IOCs and investigations.
            Type <span className="font-mono font-bold text-foreground">PURGE</span> to confirm.
          </p>
          <div className="flex items-center gap-2">
            <input className={field} value={confirm} onChange={(e) => setConfirm(e.target.value)}
                   aria-label="Type PURGE to confirm" placeholder="PURGE" />
            <button onClick={() => purge.mutate()} disabled={confirm !== "PURGE" || purge.isPending}
              className="whitespace-nowrap rounded-lg border px-3 py-2 text-xs font-semibold text-primary-foreground disabled:opacity-40 transition-opacity"
              style={{ background: confirm === "PURGE" ? "var(--sev-critical)" : "var(--muted)",
                       borderColor: "var(--sev-critical)" }}>
              {purge.isPending ? "Purging…" : "Purge everything"}
            </button>
          </div>
        </div>
        {msg && <span className="text-[12px] text-muted-foreground">{msg}</span>}
      </CardContent>
    </Card>
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
    queryKey: ["store", "events", query], queryFn: () => api.historyEvents(query),
    refetchInterval: 5000,
  });
  const items: StoreEvent[] = data?.items ?? [];
  const total = data?.total ?? 0;

  const reset = () => setOffset(0);

  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          Events
          <span className="text-[12px] font-normal text-muted-foreground">· {total} total</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3 flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <input className="w-56 rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-foreground outline-none focus:ring-1 focus:ring-primary"
                 value={q} onChange={(e) => { setQ(e.target.value); reset(); }}
                 aria-label="Search events" placeholder="Search text…" />
          <select className="rounded-lg border border-border bg-card px-2.5 py-1.5 text-xs text-foreground outline-none focus:ring-1 focus:ring-primary" value={severity}
                  onChange={(e) => { setSeverity(e.target.value); reset(); }} aria-label="Filter severity">
            <option value="">All severities</option>
            {["CRITICAL", "HIGH", "ERROR", "WARNING", "MEDIUM", "LOW", "INFORMATION", "NOTICE", "VERBOSE"].map((s) =>
              <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="rounded-lg border border-border bg-card px-2.5 py-1.5 text-xs text-foreground outline-none focus:ring-1 focus:ring-primary" value={sourceType}
                  onChange={(e) => { setSourceType(e.target.value); reset(); }} aria-label="Filter source type">
            <option value="">All sources</option>
            {["evtx", "syslog", "file", "oem:cisco", "oem:ruckus", "oem:log360"].map((s) =>
              <option key={s} value={s}>{s}</option>)}
          </select>
        </div>

        {items.length === 0 ? (
          <p className="text-[12.5px] text-muted-foreground py-2">
            No events in the store yet. Ingest an .evtx above, start the syslog collector, or add an
            OEM connector — stored events appear here.
          </p>
        ) : (
          <>
            <p className="text-[11.5px] text-muted-foreground">
              Severity is the level the source reported (never a verdict).
              <span className="font-mono text-foreground font-medium"> raw</span> is the exact stored record.
            </p>
            <div className="overflow-auto rounded-lg border border-border">
              <table className="w-full border-collapse text-left text-[12.5px]">
                <thead className="sticky top-0 z-10 bg-card border-b border-border text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="border-b border-border px-3 py-2.5">Time</th>
                    <th className="border-b border-border px-3 py-2.5">Source type</th>
                    <th className="border-b border-border px-3 py-2.5">Host</th>
                    <th className="border-b border-border px-3 py-2.5">Event ID</th>
                    <th className="border-b border-border px-3 py-2.5">Severity</th>
                    <th className="border-b border-border px-3 py-2.5">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((e) => (
                    <tr key={e.id} className="hover:bg-muted/40 transition-colors">
                      <td className="border-b border-border px-3 py-2 tabular-nums text-muted-foreground whitespace-nowrap text-[11px]">
                        {new Date(e.ts).toLocaleString()}
                      </td>
                      <td className="border-b border-border px-3 py-2 font-mono text-xs text-muted-foreground">{e.source_type || "—"}</td>
                      <td className="border-b border-border px-3 py-2 font-mono text-xs font-medium text-foreground">{e.host || "—"}</td>
                      <td className="border-b border-border px-3 py-2 font-mono text-xs">{e.event_id || "—"}</td>
                      <td className="border-b border-border px-3 py-2 font-semibold text-xs" style={{ color: e.severity ? sevVar(e.severity) : undefined }}>
                        {e.severity || <span className="font-normal text-muted-foreground">none</span>}
                      </td>
                      <td className="border-b border-border px-3 py-2 font-mono break-all text-[11px] text-muted-foreground leading-relaxed" title={e.raw}>{e.message || e.raw}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center gap-3 text-[12px] pt-1">
              <button onClick={() => setOffset(Math.max(0, offset - PAGE))} disabled={offset === 0}
                className="rounded-lg border border-border px-3 py-1 font-semibold text-foreground hover:bg-muted disabled:opacity-40 transition-colors">Prev</button>
              <span className="tabular-nums text-muted-foreground font-medium">
                {offset + 1}–{Math.min(offset + PAGE, total)} of {total}
              </span>
              <button onClick={() => setOffset(offset + PAGE)} disabled={offset + PAGE >= total}
                className="rounded-lg border border-border px-3 py-1 font-semibold text-foreground hover:bg-muted disabled:opacity-40 transition-colors">Next</button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function History() {
  const { error } = useQuery({ queryKey: ["store", "metrics"], queryFn: api.storeMetrics });
  return (
    <div className="flex flex-col gap-4">
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground leading-relaxed">
          <b className="text-foreground">Persistent Event Store.</b> Windows EVTX ingest, Command-Center counts, full event
          history, and retention controls. Counts are real store totals; severity is always the level
          the source reported, never a verdict.
        </CardContent>
      </Card>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to view stored history.
        </p>
      )}
      <Kpis />
      <div className="grid gap-4 lg:grid-cols-2">
        <EvtxIngest />
        <Retention />
      </div>
      <EventsTable />
    </div>
  );
}
