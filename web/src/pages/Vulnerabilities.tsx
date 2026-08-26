import { useQuery } from "@tanstack/react-query";
import { api, type StoreVuln } from "@/lib/api";
import { sevVar } from "@/lib/severity";

/** Vulnerabilities — every finding nmap's NSE vuln scripts recorded in the
 *  persistent store, newest first, in the itsoc. design system (mirrors
 *  prototype #p-vulns). Severity is derived from the CVSS score NSE reported;
 *  when NSE gives no score the severity is shown as "unknown" rather than
 *  guessed. An empty store is an honest empty state — never a seeded sample. */
function SevCell({ sev }: { sev: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11.5, fontWeight: 600 }}>
      <span aria-hidden style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%",
                                 background: sev ? sevVar(sev) : "var(--mut)" }} />
      {sev ? sev.toUpperCase() : <span className="is-mut" style={{ fontWeight: 400 }}>unknown</span>}
    </span>
  );
}

export function Vulnerabilities() {
  const { data, error } = useQuery({
    queryKey: ["vulns"], queryFn: () => api.vulns(200), refetchInterval: 5000,
  });
  const items: StoreVuln[] = data?.items ?? [];

  return (
    <>
      <div className="is-note">
        Vulnerabilities discovered by nmap NSE <span className="is-mono" style={{ color: "var(--acc)" }}>vuln</span> scripts
        during a scan. Severity is the CVSS band NSE reported — an empty severity means NSE gave no score,
        shown honestly as “unknown” rather than guessed.
      </div>
      {error && (
        <p className="is-mut" style={{ fontSize: 12.5 }}>
          Backend not reachable — start the console server to view stored vulnerabilities.
        </p>
      )}
      <div className="is-panel">
        <div className="is-panel__h">
          <h3>Vulnerabilities</h3>
          {items.length > 0 && <span className="is-panel__sub">{data?.total ?? items.length} total</span>}
        </div>
        {items.length === 0 ? (
          <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
            No vulnerabilities recorded yet. Run a “Service + vulnerability scan” from the Discovery page
            against a private target — real NSE findings appear here.
          </p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="is-table">
              <thead>
                <tr><th>Found</th><th>Asset</th><th>Severity</th><th>CVSS</th><th>CVE</th><th>Script</th><th>Status</th><th>Details</th></tr>
              </thead>
              <tbody>
                {items.map((v) => (
                  <tr key={v.id} style={{ cursor: "default" }}>
                    <td className="col-mono" style={{ whiteSpace: "nowrap" }}>{new Date(v.ts).toLocaleString()}</td>
                    <td className="col-mono" style={{ color: "var(--ink)", fontWeight: 500 }}>{v.asset_ip || "—"}</td>
                    <td><SevCell sev={v.severity} /></td>
                    <td className="is-tnum" style={{ fontWeight: 600 }}>
                      {v.cvss > 0 ? v.cvss.toFixed(1) : <span className="is-mut" style={{ fontWeight: 400 }}>—</span>}
                    </td>
                    <td className="is-mono" style={{ fontSize: 11, color: "var(--acc)" }}>{v.cve || <span className="is-mut">—</span>}</td>
                    <td className="col-mono">{v.name || "—"}</td>
                    <td style={{ fontSize: 12, fontWeight: 500 }}>{v.status || "OPEN"}</td>
                    <td className="is-mono" style={{ fontSize: 11, color: "var(--mut)", wordBreak: "break-all" }}>
                      {v.details ? (v.details.length > 240 ? v.details.slice(0, 240) + "…" : v.details) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
