import { useQuery } from "@tanstack/react-query";
import { api, type Asset, type UserEntity } from "@/lib/api";

/** Assets — observed entities only, in the itsoc. design system (mirrors
 *  prototype #p-assets). Both endpoints return {error} (HTTP 200) when the
 *  server is idle; that is the honest "no run" state, distinct from "a run
 *  exists but observed no assets/users" — never conflated into a fake inventory. */
function hasError(v: unknown): v is { error: string } {
  return !!v && typeof v === "object" && "error" in v;
}

/** Severity-weighted risk tag: shows the highest finding severity touching this
 *  entity (CRITICAL/HIGH/MEDIUM/LOW), or "clean" when no findings exist. The
 *  backend already computes maxSeverity; if absent, falls back to the binary
 *  atRisk flag for backward compatibility. */
function RiskTag({ atRisk, maxSeverity }: { atRisk: boolean; maxSeverity?: string | null }) {
  if (!atRisk) return <span className="is-tag is-tag--info">clean</span>;
  const sev = (maxSeverity || "HIGH").toUpperCase();
  const cls =
    sev.startsWith("CRIT") ? "is-tag--crit" :
    sev.startsWith("HIGH") ? "is-tag--high" :
    sev.startsWith("MED")  ? "is-tag--med"  :
                             "is-tag--low";
  return <span className={`is-tag ${cls}`}>{sev.startsWith("CRIT") ? "CRITICAL" : sev.startsWith("MED") ? "MEDIUM" : sev}</span>;
}

function AssetsTable({ assets }: { assets: Asset[] }) {
  return (
    <div className="is-table-wrap" style={{ overflowX: "auto" }}>
      <table className="is-table">
        <thead>
          <tr><th>Asset</th><th>Kind</th><th>Events</th><th>Findings</th><th>Risk</th><th>Score</th><th>Last seen</th></tr>
        </thead>
        <tbody>
          {assets.map((a) => (
            <tr key={a.id} data-testid="asset-row" style={{ cursor: "default" }}>
              <td className="col-mono">{a.name}</td>
              <td style={{ fontSize: 11, textTransform: "uppercase", color: "var(--mut)" }}>{a.kind}</td>
              <td className="is-tnum">{a.events}</td>
              <td className="is-tnum" style={{ fontWeight: 600 }}>{a.findings}</td>
              <td><RiskTag atRisk={a.atRisk} maxSeverity={a.maxSeverity} /></td>
              <td className="is-tnum" style={{ color: "var(--mut)" }}>{a.riskScore ?? 0}</td>
              <td className="col-mono">{a.lastSeen ?? "n/a"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UsersTable({ users }: { users: UserEntity[] }) {
  return (
    <div className="is-table-wrap" style={{ overflowX: "auto" }}>
      <table className="is-table">
        <thead>
          <tr><th>User</th><th>Events</th><th>Findings</th><th>Risk</th><th>Score</th></tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} data-testid="user-row" style={{ cursor: "default" }}>
              <td className="col-mono">{u.name}</td>
              <td className="is-tnum">{u.events}</td>
              <td className="is-tnum" style={{ fontWeight: 600 }}>{u.findings}</td>
              <td><RiskTag atRisk={u.atRisk} maxSeverity={u.maxSeverity} /></td>
              <td className="is-tnum" style={{ color: "var(--mut)" }}>{u.riskScore ?? 0}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Assets() {
  const assetsQ = useQuery({ queryKey: ["assets"], queryFn: api.assets, refetchInterval: 5000 });
  const usersQ = useQuery({ queryKey: ["users"], queryFn: api.users, refetchInterval: 5000 });

  if (assetsQ.isLoading || usersQ.isLoading) return <p className="is-mut">Loading observed entities…</p>;

  const assetsData = assetsQ.data;
  const usersData = usersQ.data;

  if (hasError(assetsData)) {
    return (
      <div className="is-note">
        {(assetsData as { error: string }).error} — assets and users are derived only from entities the
        parser actually observed in a run. There is no inventory to invent.
      </div>
    );
  }

  const assets = (assetsData as { assets: Asset[] } | undefined)?.assets ?? [];
  const users = hasError(usersData) ? [] : (usersData?.users ?? []);
  const assetsHighPlus = assets.filter((a) => {
    const s = (a.maxSeverity || "").toUpperCase();
    return s.startsWith("CRIT") || s.startsWith("HIGH");
  }).length;
  const usersHighPlus = users.filter((u) => {
    const s = (u.maxSeverity || "").toUpperCase();
    return s.startsWith("CRIT") || s.startsWith("HIGH");
  }).length;

  return (
    <>
      <div className="is-note">
        <b>Observed entities only — nothing inventoried, nothing assumed.</b> Hosts come from parsed
        events, IPs from finding entities, usernames from event messages and finding titles.{" "}
        {assetsHighPlus} of {assets.length} asset(s) and {usersHighPlus} of {users.length} user(s) at HIGH+ risk.
        Risk level reflects the highest-severity finding per entity.
      </div>

      <div className="is-panel">
        <div className="is-panel__h"><h3>Assets</h3><span className="is-panel__sub">{assets.length} observed</span></div>
        {assets.length === 0
          ? <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>This run observed no hosts or IPs.</p>
          : <AssetsTable assets={assets} />}
      </div>

      <div className="is-panel">
        <div className="is-panel__h"><h3>Users at risk</h3><span className="is-panel__sub">{users.length} observed</span></div>
        {users.length === 0
          ? <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>No usernames were extracted from this run.</p>
          : <UsersTable users={users} />}
      </div>
    </>
  );
}
