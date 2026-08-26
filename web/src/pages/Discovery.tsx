import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleDot, Network, Radar, ShieldAlert, TriangleAlert } from "lucide-react";
import { api, type DiscoveryStatus, type StoreAsset } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Discovery — the control panel for real nmap network discovery + service /
 *  vulnerability scanning. This is a dual-use tool, so the page is explicit
 *  about its guardrails: only private / loopback / link-local targets are ever
 *  accepted (the backend refuses a public or publicly-resolving target with an
 *  honest error), every scan is user-initiated from here, and when nmap is not
 *  installed the backend says so rather than faking a result. Everything shown
 *  is the REAL scanner state and REAL stored assets — never a simulated node. */

const field = "w-full rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground outline-none focus:ring-1 focus:ring-primary";

function StatusRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 border-b border-border last:border-0">
      <span className="text-[12px] text-muted-foreground">{label}</span>
      <span className="text-right text-[12.5px] font-medium text-foreground">{children}</span>
    </div>
  );
}

function ScanStatus({ status }: { status?: DiscoveryStatus }) {
  const running = !!status?.running;
  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          <CircleDot
            className={running ? "h-4 w-4" : "h-4 w-4 text-muted-foreground"}
            style={running ? { color: "var(--sev-low)" } : undefined}
            strokeWidth={2} aria-hidden
          />
          Scan status
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-2 flex flex-col">
        <StatusRow label="State">
          <span style={{ color: running ? "var(--sev-low)" : undefined }} className="font-semibold">
            {running ? "Scanning…" : status?.finishedAt ? "Idle (last scan complete)" : "Idle"}
          </span>
        </StatusRow>
        <StatusRow label="Target">
          <span className="font-mono text-xs">{status?.target || "—"}</span>
        </StatusRow>
        <StatusRow label="Mode">
          {status?.vuln ? "Service + vulnerability scan" : "Host discovery"}
        </StatusRow>
        <StatusRow label="Hosts found">
          <span className="tabular-nums font-semibold">{status?.hostsFound ?? 0}</span>
        </StatusRow>
        <StatusRow label="Assets stored">
          <span className="tabular-nums font-semibold">{status?.assetsStored ?? 0}</span>
        </StatusRow>
        <StatusRow label="Vulns stored">
          <span className="tabular-nums font-semibold">{status?.vulnsStored ?? 0}</span>
        </StatusRow>
        <StatusRow label="Started">
          {status?.startedAt ? new Date(status.startedAt).toLocaleString() : "—"}
        </StatusRow>
        <StatusRow label="Finished">
          {status?.finishedAt ? new Date(status.finishedAt).toLocaleString() : running ? "in progress" : "—"}
        </StatusRow>
        {status?.error && (
          <div className="pt-2 text-[12px]" style={{ color: "var(--sev-critical)" }}>
            {status.error}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Controls({ status }: { status?: DiscoveryStatus }) {
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const [msg, setMsg] = useState("");
  const running = !!status?.running;

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["discovery"] });

  const scan = useMutation({
    mutationFn: (vuln: boolean) => api.discoveryScan({ target: target.trim(), vuln }),
    onSuccess: (out) => {
      setMsg(out.ok
        ? "Scan started — results appear below as nmap reports them."
        : (out.error ?? "Could not start the scan."));
      refresh();
    },
  });

  const nmapMissing = status && !status.nmapInstalled;
  const canScan = target.trim().length > 0 && !running && !scan.isPending && !nmapMissing;

  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          <Radar className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Scan a private network or host
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3 flex flex-col gap-3">
        <p className="text-[12px] text-muted-foreground leading-relaxed">
          Runs real <span className="font-mono text-primary text-[11.5px]">nmap</span> against the target and records every
          host it observes in the persistent store. A vulnerability scan additionally runs nmap's
          NSE <span className="font-mono text-primary text-[11.5px]">vuln</span> scripts; a finding's severity is taken from the
          CVSS score NSE reports (empty when it gives none) — never keyword-guessed.
        </p>

        {nmapMissing && (
          <div className="flex items-start gap-2 rounded-lg border p-2.5 text-[11.5px]"
               style={{ borderColor: "var(--sev-critical)", color: "var(--sev-critical)", background: "color-mix(in srgb, var(--sev-critical) 8%, transparent)" }}>
            <TriangleAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
            <span>
              <span className="font-semibold">nmap is not installed.</span> Network discovery needs
              the <span className="font-mono">nmap</span> binary on this host (e.g.{" "}
              <span className="font-mono">brew install nmap</span> or{" "}
              <span className="font-mono">apt install nmap</span>). No scan can run until it is
              present — nothing here is simulated.
            </span>
          </div>
        )}

        <label className="text-[11px] font-medium text-muted-foreground">
          Target host or CIDR range
          <input className={`mt-1 ${field}`} value={target}
                 onChange={(e) => setTarget(e.target.value)}
                 aria-label="Target host or CIDR"
                 placeholder="192.168.1.0/24  ·  10.0.0.5  ·  127.0.0.1" />
          <span className="mt-1 block text-[11px] text-muted-foreground">
            Private (RFC1918), loopback, and link-local targets only. Public or
            internet-routable targets are refused — this scans only networks you own.
          </span>
        </label>

        <div className="flex items-start gap-2 rounded-lg border p-2.5 text-[11.5px]"
             style={{ borderColor: "var(--sev-medium)", color: "var(--sev-medium)", background: "color-mix(in srgb, var(--sev-medium) 8%, transparent)" }}>
          <ShieldAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
          <span>
            Only scan networks you are authorized to test. Every scan is initiated by you
            here — nothing runs on a timer.
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button onClick={() => scan.mutate(false)} disabled={!canScan}
            className="inline-flex items-center gap-1.5 rounded-lg border border-primary bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60 transition-opacity">
            <Network className="h-3.5 w-3.5" strokeWidth={1.8} aria-hidden />
            {scan.isPending ? "Starting…" : "Discover live nodes"}
          </button>
          <button onClick={() => scan.mutate(true)} disabled={!canScan}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground hover:bg-muted disabled:opacity-50 transition-colors">
            <ShieldAlert className="h-3.5 w-3.5" strokeWidth={1.8} aria-hidden />
            Service + vulnerability scan
          </button>
        </div>
        {msg && <span className="text-[12px] text-muted-foreground">{msg}</span>}
      </CardContent>
    </Card>
  );
}

function DiscoveredAssets({ running }: { running: boolean }) {
  const { data } = useQuery({
    queryKey: ["discovery", "assets"], queryFn: () => api.discoveryAssets(100),
    refetchInterval: running ? 3000 : false,
  });
  const items: StoreAsset[] = data?.items ?? [];

  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          <Network className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Discovered assets
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3">
        {items.length === 0 ? (
          <p className="text-[12.5px] text-muted-foreground">
            No hosts discovered yet. Enter a private target above and run a scan —
            hosts nmap actually observes appear here and in the assets store.
          </p>
        ) : (
          <div className="overflow-auto rounded-lg border border-border">
            <table className="w-full border-collapse text-left text-[12.5px]">
              <thead className="sticky top-0 z-10 bg-card border-b border-border text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="border-b border-border px-3 py-2.5">Seen</th>
                  <th className="border-b border-border px-3 py-2.5">IP</th>
                  <th className="border-b border-border px-3 py-2.5">Hostname</th>
                  <th className="border-b border-border px-3 py-2.5">MAC / vendor</th>
                  <th className="border-b border-border px-3 py-2.5">OS</th>
                  <th className="border-b border-border px-3 py-2.5">Open ports</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} className="hover:bg-muted/40 transition-colors">
                    <td className="border-b border-border px-3 py-2 tabular-nums text-muted-foreground whitespace-nowrap text-[11px]">
                      {new Date(a.ts).toLocaleString()}
                    </td>
                    <td className="border-b border-border px-3 py-2 font-mono text-xs font-medium text-foreground">{a.ip || "—"}</td>
                    <td className="border-b border-border px-3 py-2 font-mono text-xs">{a.hostname || <span className="text-muted-foreground">—</span>}</td>
                    <td className="border-b border-border px-3 py-2 font-mono text-xs">
                      {a.mac ? `${a.mac}${a.vendor ? ` (${a.vendor})` : ""}` : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="border-b border-border px-3 py-2 text-xs">{a.os || <span className="text-muted-foreground">—</span>}</td>
                    <td className="border-b border-border px-3 py-2 font-mono text-xs break-all">{a.ports || <span className="text-muted-foreground">none open</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function Discovery() {
  const { data: status, error } = useQuery({
    queryKey: ["discovery", "status"], queryFn: api.discoveryStatus,
    refetchInterval: 3000,
  });

  return (
    <div className="flex flex-col gap-4">
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground leading-relaxed">
          <b className="text-foreground">Network discovery &amp; scanning.</b> Real nmap-driven discovery and vulnerability scanning for networks you own.
          Everything shown is the actual scanner state and the actual hosts nmap
          observed — never a fabricated node or a fake “scanning”.
        </CardContent>
      </Card>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to run a discovery scan.
        </p>
      )}
      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <Controls status={status} />
        <ScanStatus status={status} />
      </div>
      <DiscoveredAssets running={!!status?.running} />
    </div>
  );
}
