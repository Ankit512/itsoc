import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type DiscoveryStatus, type StoreAsset } from "@/lib/api";

/** Discovery — the control panel for real nmap network discovery + service /
 *  vulnerability scanning, in the itsoc. design system (mirrors prototype
 *  #p-discovery + handoff §3). A dual-use tool, so the page is explicit about
 *  its guardrails: only private / loopback / link-local targets are accepted
 *  (the backend refuses a public target honestly), every scan is user-initiated
 *  here (never on a timer), and this is an ACTIVE network operation, not
 *  read-only. Everything shown is the REAL scanner state and REAL stored assets. */

function Fact({ label, children, na }: { label: string; children: React.ReactNode; na?: boolean }) {
  return (
    <div className="is-facts-row"><span>{label}</span><b className={na ? "na" : undefined}>{children}</b></div>
  );
}

function ScanStatus({ status }: { status?: DiscoveryStatus }) {
  const running = !!status?.running;
  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Scan status</h3></div>
      <Fact label="State">
        <span style={{ color: running ? "var(--low)" : "var(--mut)" }}>
          {running ? "Scanning…" : status?.finishedAt ? "Idle (last scan complete)" : "Idle"}
        </span>
      </Fact>
      {status?.target
        ? <Fact label="Target"><span className="is-mono">{status.target}</span></Fact>
        : <Fact label="Target" na>—</Fact>}
      <Fact label="Mode">{status?.vuln ? "Service + vulnerability scan" : "Host discovery"}</Fact>
      <Fact label="Hosts found"><span className="is-tnum">{status?.hostsFound ?? 0}</span></Fact>
      <Fact label="Assets stored"><span className="is-tnum">{status?.assetsStored ?? 0}</span></Fact>
      <Fact label="Vulns stored"><span className="is-tnum">{status?.vulnsStored ?? 0}</span></Fact>
      {/* dc pairs both stamps on one "Started / finished" row. */}
      <Fact label="Started / finished" na={!status?.startedAt && !status?.finishedAt}>
        <span className="is-mono">
          {status?.startedAt ? new Date(status.startedAt).toLocaleString() : "—"}
          {" / "}
          {status?.finishedAt
            ? new Date(status.finishedAt).toLocaleString()
            : running ? "in progress" : "—"}
        </span>
      </Fact>
      {status?.error && <div className="is-facts-row" style={{ color: "var(--crit)" }}>{status.error}</div>}
    </div>
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
      setMsg(out.ok ? "Scan started — results appear below as nmap reports them." : (out.error ?? "Could not start the scan."));
      refresh();
    },
  });

  const nmapMissing = status && !status.nmapInstalled;
  const canScan = target.trim().length > 0 && !running && !scan.isPending && !nmapMissing;

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Scan a private network or host</h3></div>
      <p className="is-mut" style={{ fontSize: 12, lineHeight: 1.5, margin: "0 0 4px" }}>
        Runs real <span className="is-mono" style={{ color: "var(--acc)" }}>nmap</span> against the target and records
        every host it observes in the persistent store. A vulnerability scan additionally runs nmap's NSE{" "}
        <span className="is-mono" style={{ color: "var(--acc)" }}>vuln</span> scripts; a finding's severity is taken
        from the CVSS score NSE reports (empty when it gives none) — never keyword-guessed.
      </p>

      {nmapMissing && (
        <div className="is-note" style={{ borderColor: "var(--crit)", color: "var(--crit)" }}>
          <b>nmap is not installed.</b> Network discovery needs the <span className="is-mono">nmap</span> binary on
          this host (e.g. <span className="is-mono">brew install nmap</span> or <span className="is-mono">apt install nmap</span>).
          No scan can run until it is present — nothing here is simulated.
        </div>
      )}

      <label className="is-field" style={{ margin: "8px 0" }}>
        <span>Target host / CIDR</span>
        <input className="is-input" value={target} aria-label="Target host or CIDR"
               onChange={(e) => setTarget(e.target.value)}
               placeholder="192.168.1.0/24  ·  10.0.0.5  ·  127.0.0.1" />
      </label>
      <div className="is-mut" style={{ fontSize: 11, lineHeight: 1.5 }}>
        Scanning sends packets to the target. Only scan networks you own — private (RFC1918), loopback,
        and link-local targets only; public or internet-routable targets are refused.
      </div>

      <div className="is-note" style={{ borderColor: "var(--high)", color: "var(--high)", marginTop: 8 }}>
        <b>Active scan — private/loopback targets only · user-initiated · this is an active network
        operation, not read-only.</b> Only scan networks you are authorized to test; nothing runs on a timer.
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, marginTop: 8 }}>
        <button className="is-btn is-btn--primary" onClick={() => scan.mutate(false)} disabled={!canScan}>
          {scan.isPending ? "Starting…" : "Discover live nodes"}
        </button>
        <button className="is-btn" onClick={() => scan.mutate(true)} disabled={!canScan}>Service + vulnerability scan</button>
        {msg && <span className="is-mut" style={{ fontSize: 12 }}>{msg}</span>}
      </div>
    </div>
  );
}

function DiscoveredAssets({ running }: { running: boolean }) {
  const { data } = useQuery({
    queryKey: ["discovery", "assets"], queryFn: () => api.discoveryAssets(100),
    refetchInterval: running ? 3000 : false,
  });
  const items: StoreAsset[] = data?.items ?? [];

  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Discovered assets</h3></div>
      {items.length === 0 ? (
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
          No scans have run — results appear here after a user-initiated scan. Enter a private target
          above; hosts nmap actually observes appear here and in the assets store.
        </p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="is-table">
            <thead>
              <tr><th>Seen</th><th>IP</th><th>Hostname</th><th>MAC / vendor</th><th>OS</th><th>Open ports</th></tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id} style={{ cursor: "default" }}>
                  <td className="col-mono" style={{ whiteSpace: "nowrap" }}>{new Date(a.ts).toLocaleString()}</td>
                  <td className="col-mono" style={{ color: "var(--ink)", fontWeight: 500 }}>{a.ip || "—"}</td>
                  <td className="col-mono">{a.hostname || <span className="is-mut">—</span>}</td>
                  <td className="col-mono">{a.mac ? `${a.mac}${a.vendor ? ` (${a.vendor})` : ""}` : <span className="is-mut">—</span>}</td>
                  <td style={{ fontSize: 12 }}>{a.os || <span className="is-mut">—</span>}</td>
                  <td className="col-mono" style={{ wordBreak: "break-all" }}>{a.ports || <span className="is-mut">none open</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function Discovery() {
  const { data: status, error } = useQuery({
    queryKey: ["discovery", "status"], queryFn: api.discoveryStatus, refetchInterval: 3000,
  });

  return (
    <>
      <div className="is-note">
        <b>Active nmap discovery</b> — private/loopback targets only, user-initiated, never on a timer.
        This is an <b>active network operation</b>, not read-only. Everything shown is the actual scanner
        state and the actual hosts nmap observed — never a fabricated node or a fake “scanning”.
      </div>
      {error && (
        <p className="is-mut" style={{ fontSize: 12.5 }}>
          Backend not reachable — start the console server to run a discovery scan.
        </p>
      )}
      <div className="is-grid-2">
        <Controls status={status} />
        <ScanStatus status={status} />
      </div>
      <DiscoveredAssets running={!!status?.running} />
    </>
  );
}
