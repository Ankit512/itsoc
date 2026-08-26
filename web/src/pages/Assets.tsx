import { useQuery } from "@tanstack/react-query";
import { api, type Asset, type UserEntity } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const th = "border-b border-border px-3 py-2.5 text-left text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground";
const td = "border-b border-border px-3 py-2.5 align-middle text-[12.5px]";

/** Both endpoints return {error} (HTTP 200) when the server is idle. We treat
 *  that as the honest "no run" state, distinct from "a run exists but observed
 *  no assets/users" — never conflate them into a fake-empty inventory. */
function hasError(v: unknown): v is { error: string } {
  return !!v && typeof v === "object" && "error" in v;
}

function RiskBadge({ atRisk }: { atRisk: boolean }) {
  return atRisk ? (
    <Badge style={{ borderColor: "var(--sev-high)", color: "var(--sev-high)", background: "color-mix(in srgb, var(--sev-high) 12%, transparent)" }}>
      at risk
    </Badge>
  ) : (
    <Badge className="border-border text-muted-foreground bg-muted/30">clean</Badge>
  );
}

function AssetsTable({ assets }: { assets: Asset[] }) {
  return (
    <div className="overflow-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-[12.5px]">
        <thead className="sticky top-0 z-10 bg-card border-b border-border">
          <tr>
            <th className={th}>Asset</th>
            <th className={th}>Kind</th>
            <th className={th}>Events</th>
            <th className={th}>Findings</th>
            <th className={th}>Risk</th>
            <th className={th}>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((a) => (
            <tr key={a.id} data-testid="asset-row" className="hover:bg-muted/40 transition-colors">
              <td className={`${td} font-mono text-[12px] font-medium`}>{a.name}</td>
              <td className={`${td} text-[11px] uppercase text-muted-foreground`}>{a.kind}</td>
              <td className={`${td} tabular-nums`}>{a.events}</td>
              <td className={`${td} tabular-nums font-semibold`}>{a.findings}</td>
              <td className={td}><RiskBadge atRisk={a.atRisk} /></td>
              <td className={`${td} font-mono text-[11px] tabular-nums text-muted-foreground`}>{a.lastSeen ?? "n/a"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UsersTable({ users }: { users: UserEntity[] }) {
  return (
    <div className="overflow-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-[12.5px]">
        <thead className="sticky top-0 z-10 bg-card border-b border-border">
          <tr>
            <th className={th}>User</th>
            <th className={th}>Events</th>
            <th className={th}>Findings</th>
            <th className={th}>Risk</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} data-testid="user-row" className="hover:bg-muted/40 transition-colors">
              <td className={`${td} font-mono text-[12px] font-medium`}>{u.name}</td>
              <td className={`${td} tabular-nums`}>{u.events}</td>
              <td className={`${td} tabular-nums font-semibold`}>{u.findings}</td>
              <td className={td}><RiskBadge atRisk={u.atRisk} /></td>
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

  if (assetsQ.isLoading || usersQ.isLoading) {
    return <p className="text-muted-foreground">Loading observed entities…</p>;
  }

  const assetsData = assetsQ.data;
  const usersData = usersQ.data;
  const idle = hasError(assetsData);

  if (idle) {
    return (
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-6 text-[12.5px] text-muted-foreground">
          {(assetsData as { error: string }).error} — assets and users are derived only
          from entities the parser actually observed in a run. There is no inventory to invent.
        </CardContent>
      </Card>
    );
  }

  const assets = (assetsData as { assets: Asset[] } | undefined)?.assets ?? [];
  const users = hasError(usersData) ? [] : (usersData?.users ?? []);
  const assetsAtRisk = assets.filter((a) => a.atRisk).length;
  const usersAtRisk = users.filter((u) => u.atRisk).length;

  return (
    <div className="space-y-4">
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground">
          <b className="text-foreground">Observed entities only.</b>{" "}
          Hosts come from parsed events, IPs from finding entities, usernames from event
          messages and finding titles. An asset that never appeared in a log does not exist here.
          <span className="ml-1">
            {assetsAtRisk} of {assets.length} asset(s) and {usersAtRisk} of {users.length} user(s) at risk (≥1 finding).
          </span>
        </CardContent>
      </Card>

      <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        <CardHeader className="p-4 pb-3 border-b border-border">
          <CardTitle className="text-[14px] font-semibold">Assets ({assets.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-3">
          {assets.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              This run observed no hosts or IPs.
            </p>
          ) : (
            <AssetsTable assets={assets} />
          )}
        </CardContent>
      </Card>

      <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        <CardHeader className="p-4 pb-3 border-b border-border">
          <CardTitle className="text-[14px] font-semibold">Users at risk ({users.length})</CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-3">
          {users.length === 0 ? (
            <p className="text-[12.5px] text-muted-foreground">
              No usernames were extracted from this run.
            </p>
          ) : (
            <UsersTable users={users} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
