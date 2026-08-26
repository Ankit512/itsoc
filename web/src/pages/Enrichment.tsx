import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Search, ShieldCheck, TriangleAlert } from "lucide-react";
import { api, type StoreIoc, type TiEnrichResult } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Enrichment — look up an IP against external threat-intel providers (OTX and
 *  AbuseIPDB) using YOUR API keys. Keys are stored write-only (masked): the
 *  page only ever learns whether a key is present. A provider with no key is
 *  reported as not-configured and never called; a verdict/score always comes
 *  from the provider's real response — never keyword-guessed. */

const field = "w-full rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground outline-none focus:ring-1 focus:ring-primary";

function verdictColor(verdict: string): string | undefined {
  const v = verdict.toLowerCase();
  if (v === "malicious") return "var(--sev-critical)";
  if (v === "suspicious") return "var(--sev-medium)";
  if (v === "clean") return "var(--sev-low)";
  return undefined;
}

function KeyField({ which, label, configured }: { which: "otx" | "abuseipdb"; label: string; configured: boolean }) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState("");
  const save = useMutation({
    mutationFn: () => api.setTiKey(which, value),
    onSuccess: () => { setValue(""); queryClient.invalidateQueries({ queryKey: ["ti"] }); },
  });
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center gap-2 text-[12.5px]">
        <span className="font-semibold text-foreground">{label}</span>
        {configured ? (
          <span className="inline-flex items-center gap-1 text-[11px] font-medium" style={{ color: "var(--sev-low)" }}>
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden /> key configured
          </span>
        ) : (
          <span className="text-[11px] text-muted-foreground">no key configured</span>
        )}
      </div>
      <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (value.trim()) save.mutate(); }}>
        <input className={field} type="password" value={value} autoComplete="off"
               onChange={(e) => setValue(e.target.value)}
               aria-label={`${label} API key`}
               placeholder={configured ? "Replace stored key…" : "Paste API key…"} />
        <button type="submit" disabled={!value.trim() || save.isPending}
          className="whitespace-nowrap rounded-lg border border-border bg-card px-3 py-2 text-xs font-semibold text-foreground hover:bg-muted disabled:opacity-50 transition-colors">
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </form>
    </div>
  );
}

function KeysCard({ otx, abuseipdb }: { otx: boolean; abuseipdb: boolean }) {
  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          <KeyRound className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Provider keys
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3 flex flex-col gap-3.5">
        <p className="text-[12px] text-muted-foreground leading-relaxed">
          Your API keys are stored write-only and never sent back to the browser — this page
          only shows whether each is set. Enrichment calls go only to the provider you supplied
          a key for.
        </p>
        <KeyField which="otx" label="AlienVault OTX" configured={otx} />
        <KeyField which="abuseipdb" label="AbuseIPDB" configured={abuseipdb} />
      </CardContent>
    </Card>
  );
}

function EnrichPanel({ anyKey }: { anyKey: boolean }) {
  const queryClient = useQueryClient();
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<TiEnrichResult | null>(null);
  const [err, setErr] = useState("");

  const enrich = useMutation({
    mutationFn: () => api.tiEnrich(ip.trim()),
    onSuccess: (r) => {
      setResult(r); setErr(r.error ?? "");
      queryClient.invalidateQueries({ queryKey: ["ti", "iocs"] });
    },
    onError: (e: Error) => { setErr(e.message); setResult(null); },
  });

  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="flex items-center gap-2 text-[14px] font-semibold">
          <Search className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Enrich an IP
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3 flex flex-col gap-3">
        {!anyKey && (
          <div className="flex items-start gap-2 rounded-lg border p-2.5 text-[11.5px]"
               style={{ borderColor: "var(--sev-medium)", color: "var(--sev-medium)", background: "color-mix(in srgb, var(--sev-medium) 8%, transparent)" }}>
            <TriangleAlert className="mt-px h-4 w-4 flex-none" aria-hidden />
            <span>No provider key is configured yet. Add an OTX or AbuseIPDB key above — until
              then a lookup honestly reports every provider as not-configured.</span>
          </div>
        )}
        <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (ip.trim()) enrich.mutate(); }}>
          <input className={field} value={ip} onChange={(e) => setIp(e.target.value)}
                 aria-label="IP address to enrich" inputMode="numeric"
                 placeholder="203.0.113.9" />
          <button type="submit" disabled={!ip.trim() || enrich.isPending}
            className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-primary bg-primary px-3 py-2 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60 transition-opacity">
            <Search className="h-3.5 w-3.5" strokeWidth={2} aria-hidden />
            {enrich.isPending ? "Enriching…" : "Enrich"}
          </button>
        </form>

        {err && <p className="text-[11.5px]" style={{ color: "var(--sev-critical)" }}>{err}</p>}

        {result && !result.error && (
          <div className="flex flex-col gap-2.5 text-[12px] pt-1">
            {result.notConfigured.length > 0 && (
              <p className="text-muted-foreground text-[11.5px]">
                Not configured (skipped): {result.notConfigured.join(", ")}
              </p>
            )}
            {result.errors.map((e) => (
              <p key={e.provider} className="text-[11.5px]" style={{ color: "var(--sev-critical)" }}>
                {e.provider}: {e.error}
              </p>
            ))}
            {result.results.length === 0 && result.errors.length === 0 && result.notConfigured.length > 0 && (
              <p className="text-muted-foreground text-[11.5px]">No provider was called — add a key to enrich.</p>
            )}
            {result.results.length > 0 && (
              <div className="overflow-auto rounded-lg border border-border">
                <table className="w-full border-collapse text-left text-[12.5px]">
                  <thead className="sticky top-0 z-10 bg-card border-b border-border text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
                    <tr>
                      <th className="border-b border-border px-3 py-2">Provider</th>
                      <th className="border-b border-border px-3 py-2">Verdict</th>
                      <th className="border-b border-border px-3 py-2">Score</th>
                      <th className="border-b border-border px-3 py-2">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.results.map((r) => (
                      <tr key={r.provider} className="hover:bg-muted/40 transition-colors">
                        <td className="border-b border-border px-3 py-2 font-medium text-foreground text-xs">{r.provider}</td>
                        <td className="border-b border-border px-3 py-2 font-semibold text-xs" style={{ color: verdictColor(r.verdict) }}>
                          {r.verdict}
                        </td>
                        <td className="border-b border-border px-3 py-2 tabular-nums text-xs font-medium">{r.score}</td>
                        <td className="border-b border-border px-3 py-2 font-mono break-all text-[11px] text-muted-foreground leading-relaxed">{r.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function IocHistory() {
  const { data } = useQuery({ queryKey: ["ti", "iocs"], queryFn: () => api.iocs(100) });
  const items: StoreIoc[] = data?.items ?? [];
  return (
    <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
      <CardHeader className="p-4 pb-3 border-b border-border">
        <CardTitle className="text-[14px] font-semibold">Recent IOC lookups</CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-3">
        {items.length === 0 ? (
          <p className="text-[12.5px] text-muted-foreground">
            No IOC lookups recorded yet. Enrich an IP above — real provider results appear here
            and in the IOC store.
          </p>
        ) : (
          <div className="overflow-auto rounded-lg border border-border">
            <table className="w-full border-collapse text-left text-[12.5px]">
              <thead className="sticky top-0 z-10 bg-card border-b border-border text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="border-b border-border px-3 py-2.5">Time</th>
                  <th className="border-b border-border px-3 py-2.5">IOC</th>
                  <th className="border-b border-border px-3 py-2.5">Provider</th>
                  <th className="border-b border-border px-3 py-2.5">Verdict</th>
                  <th className="border-b border-border px-3 py-2.5">Score</th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.id} className="hover:bg-muted/40 transition-colors">
                    <td className="border-b border-border px-3 py-2 tabular-nums text-muted-foreground whitespace-nowrap text-[11px]">
                      {new Date(i.ts).toLocaleString()}
                    </td>
                    <td className="border-b border-border px-3 py-2 font-mono text-xs font-medium text-foreground">{i.ioc}</td>
                    <td className="border-b border-border px-3 py-2 text-xs">{i.provider}</td>
                    <td className="border-b border-border px-3 py-2 font-semibold text-xs" style={{ color: verdictColor(i.verdict) }}>{i.verdict}</td>
                    <td className="border-b border-border px-3 py-2 tabular-nums text-xs font-medium">{i.score}</td>
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

export function Enrichment() {
  const { data: keys, error } = useQuery({ queryKey: ["ti", "keys"], queryFn: api.tiKeys });
  const otx = !!keys?.otx, abuseipdb = !!keys?.abuseipdb;

  return (
    <div className="flex flex-col gap-4">
      <Card className="rounded-xl border border-dashed border-border bg-card">
        <CardContent className="p-4 text-[12.5px] text-muted-foreground leading-relaxed">
          <b className="text-foreground">Threat Intel Enrichment.</b> External provider lookups using your own API keys. Every
          verdict and score shown is the provider's real response — never a fabricated or
          keyword-guessed result.
        </CardContent>
      </Card>
      {error && (
        <p className="text-[12.5px] text-muted-foreground">
          Backend not reachable — start the console server to run enrichment.
        </p>
      )}
      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <KeysCard otx={otx} abuseipdb={abuseipdb} />
        <EnrichPanel anyKey={otx || abuseipdb} />
      </div>
      <IocHistory />
    </div>
  );
}
