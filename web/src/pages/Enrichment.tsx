import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Search, ShieldCheck, TriangleAlert } from "lucide-react";
import { api, type StoreIoc, type TiEnrichResult } from "@/lib/api";

/** Enrichment — look up an IP against external threat-intel providers (OTX and
 *  AbuseIPDB) using YOUR API keys, in the itsoc. design system (mirrors v3 dc
 *  "Enrichment"). Keys are stored write-only (masked): the page only ever learns
 *  whether a key is present. A provider with no key is reported as not-configured
 *  and never called; a verdict/score always comes from the provider's real
 *  response — never keyword-guessed. */

/** A verdict is a provider's own label, not a rule severity — colour it with the
 *  severity tokens only for legibility (malicious→crit, suspicious→med, clean→low). */
function verdictColor(verdict: string): string | undefined {
  const v = verdict.toLowerCase();
  if (v === "malicious") return "var(--crit)";
  if (v === "suspicious") return "var(--med)";
  if (v === "clean") return "var(--low)";
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
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 500 }}>{label}</div>
        {configured ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--low)" }}>
            <ShieldCheck size={13} aria-hidden /> key configured
          </span>
        ) : (
          <div className="is-mut2" style={{ fontSize: 11 }}>no key configured</div>
        )}
      </div>
      <form style={{ display: "flex", alignItems: "center", gap: 8 }}
            onSubmit={(e) => { e.preventDefault(); if (value.trim()) save.mutate(); }}>
        <input className="is-input" type="password" value={value} autoComplete="off" style={{ width: 120 }}
               onChange={(e) => setValue(e.target.value)} aria-label={`${label} API key`}
               placeholder={configured ? "Replace stored key…" : "Paste API key…"} />
        <button className="is-btn" type="submit" disabled={!value.trim() || save.isPending}>
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </form>
    </div>
  );
}

function KeysCard({ otx, abuseipdb }: { otx: boolean; abuseipdb: boolean }) {
  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3 style={{ display: "flex", alignItems: "center", gap: 7 }}><KeyRound size={15} aria-hidden /> Provider keys</h3></div>
      <p className="is-mut" style={{ fontSize: 12, lineHeight: 1.5, margin: "0 0 4px" }}>
        Your API keys are stored write-only and never sent back to the browser — this page only shows
        whether each is set. Enrichment calls go only to the provider you supplied a key for.
      </p>
      <KeyField which="otx" label="AlienVault OTX" configured={otx} />
      <div style={{ borderTop: "1px solid var(--bd)" }} />
      <KeyField which="abuseipdb" label="AbuseIPDB" configured={abuseipdb} />
    </div>
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
    <div className="is-panel">
      <div className="is-panel__h"><h3 style={{ display: "flex", alignItems: "center", gap: 7 }}><Search size={15} aria-hidden /> Enrich an IP</h3></div>
      {!anyKey && (
        <div className="is-note" style={{ display: "flex", alignItems: "flex-start", gap: 8, borderColor: "var(--high)", color: "var(--high)" }}>
          <TriangleAlert size={15} aria-hidden style={{ flex: "none", marginTop: 1 }} />
          <span>No provider key is configured — lookups will fail until one is saved. Add an OTX or
            AbuseIPDB key above; until then a lookup honestly reports every provider as not-configured.</span>
        </div>
      )}
      <form style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}
            onSubmit={(e) => { e.preventDefault(); if (ip.trim()) enrich.mutate(); }}>
        <input className="is-input" value={ip} onChange={(e) => setIp(e.target.value)} style={{ flex: 1 }}
               aria-label="IP address to enrich" inputMode="numeric" placeholder="203.0.113.9" />
        <button className="is-btn is-btn--primary" type="submit" disabled={!ip.trim() || enrich.isPending}
                style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <Search size={13} aria-hidden />
          {enrich.isPending ? "Enriching…" : "Enrich"}
        </button>
      </form>

      {err && <p style={{ color: "var(--crit)", fontSize: 11.5, margin: "6px 0 0" }}>{err}</p>}

      {result && !result.error && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 12, marginTop: 8 }}>
          {result.notConfigured.length > 0 && (
            <p className="is-mut" style={{ fontSize: 11.5, margin: 0 }}>
              Not configured (skipped): {result.notConfigured.join(", ")}
            </p>
          )}
          {result.errors.map((e) => (
            <p key={e.provider} style={{ fontSize: 11.5, margin: 0, color: "var(--crit)" }}>{e.provider}: {e.error}</p>
          ))}
          {result.results.length === 0 && result.errors.length === 0 && result.notConfigured.length > 0 && (
            <p className="is-mut" style={{ fontSize: 11.5, margin: 0 }}>No provider was called — add a key to enrich.</p>
          )}
          {result.results.length > 0 && (
            <div style={{ overflowX: "auto" }}>
              <table className="is-table">
                <thead><tr><th>Provider</th><th>Verdict</th><th>Score</th><th>Details</th></tr></thead>
                <tbody>
                  {result.results.map((r) => (
                    <tr key={r.provider} style={{ cursor: "default" }}>
                      <td style={{ fontSize: 12, fontWeight: 500, color: "var(--ink)" }}>{r.provider}</td>
                      <td style={{ fontSize: 12, fontWeight: 600, color: verdictColor(r.verdict) }}>{r.verdict}</td>
                      <td className="is-tnum" style={{ fontWeight: 600 }}>{r.score}</td>
                      <td className="is-mono" style={{ fontSize: 11, color: "var(--mut)", wordBreak: "break-all" }}>{r.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function IocHistory() {
  const { data } = useQuery({ queryKey: ["ti", "iocs"], queryFn: () => api.iocs(100) });
  const items: StoreIoc[] = data?.items ?? [];
  return (
    <div className="is-panel">
      <div className="is-panel__h"><h3>Recent IOC lookups</h3></div>
      {items.length === 0 ? (
        <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>
          No lookups yet — results here are real provider responses only. Enrich an IP above.
        </p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="is-table">
            <thead><tr><th>Time</th><th>IOC</th><th>Provider</th><th>Verdict</th><th>Score</th></tr></thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id} style={{ cursor: "default" }}>
                  <td className="col-mono" style={{ whiteSpace: "nowrap" }}>{new Date(i.ts).toLocaleString()}</td>
                  <td className="col-mono" style={{ color: "var(--ink)", fontWeight: 500 }}>{i.ioc}</td>
                  <td style={{ fontSize: 12 }}>{i.provider}</td>
                  <td style={{ fontSize: 12, fontWeight: 600, color: verdictColor(i.verdict) }}>{i.verdict}</td>
                  <td className="is-tnum" style={{ fontWeight: 600 }}>{i.score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function Enrichment() {
  const { data: keys, error } = useQuery({ queryKey: ["ti", "keys"], queryFn: api.tiKeys });
  const otx = !!keys?.otx, abuseipdb = !!keys?.abuseipdb;

  return (
    <>
      <div className="is-note">
        <b>Real provider responses — never fabricated.</b> External threat-intel lookups using your own API
        keys. Every verdict and score shown is the provider's real response, never a fabricated or
        keyword-guessed result.
      </div>
      {error && (
        <p className="is-mut" style={{ fontSize: 12.5 }}>
          Backend not reachable — start the console server to run enrichment.
        </p>
      )}
      <div className="is-grid-2">
        <KeysCard otx={otx} abuseipdb={abuseipdb} />
        <EnrichPanel anyKey={otx || abuseipdb} />
      </div>
      <IocHistory />
    </>
  );
}
