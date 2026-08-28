import { useSearchParams } from "react-router-dom";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Search, Shield, ShieldCheck, TriangleAlert, Zap } from "lucide-react";
import { api, type StoreIoc, type ThreatIntel, type TiEnrichResult } from "@/lib/api";

/** Intel — merged threat intelligence screen (Feeds + Live Enrichment)
 *  in the itsoc. design system (C1-T3 fan-out unit).
 *
 *  HONESTY & EGRESS MODEL:
 *  - Feeds is OFFLINE (static STIX bundle + static MITRE rule mapping). It never
 *    makes outbound network requests ("Surfaced, not generated").
 *  - Live Enrichment CALLS OUT to external APIs (OTX / AbuseIPDB) using user API
 *    keys ("Real provider responses — never fabricated").
 *  - Provider keys are write-only (masked); the UI only learns whether a key is set.
 *  - Every empty state and unconfigured provider is reported honestly.
 */

export type IntelSection = "feeds" | "enrichment";

function verdictColor(verdict: string): string | undefined {
  const v = verdict.toLowerCase();
  if (v === "malicious") return "var(--crit)";
  if (v === "suspicious") return "var(--med)";
  if (v === "clean") return "var(--low)";
  return undefined;
}

// ---------------------------------------------------------------------------
// FEEDS SECTION (Offline STIX + MITRE)
// ---------------------------------------------------------------------------

function FeedsSection() {
  const { data, isLoading, isError, error } = useQuery<ThreatIntel>({
    queryKey: ["threat-intel"],
    queryFn: api.threatIntel,
  });

  if (isLoading) return <p className="is-mut">Loading threat intel…</p>;
  if (isError || !data) {
    return <div className="is-note">Couldn't load threat intel — {(error as Error)?.message ?? "no data"}</div>;
  }

  const ruleEntries = Object.entries(data.ruleTechniques);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Offline egress banner — distinct from Live Enrichment */}
      <div className="is-note" data-testid="feeds-egress-note">
        <b>Surfaced, not generated — derived tags, not verdicts.</b> Indicators come from an offline
        STIX bundle; the technique rollups are the static MITRE mapping each rule carries. Nothing here
        changes a finding's severity.
      </div>

      <div className="is-grid-2">
        <div className="is-panel">
          <div className="is-panel__h">
            <h3>Indicators of Compromise</h3>
            <span className="is-panel__sub">{data.indicatorSource}</span>
          </div>
          {data.indicators.length === 0 ? (
            <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>The bundle holds no indicators.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="is-table">
                <thead>
                  <tr><th>Name</th><th>Pattern</th><th>Types</th><th>Valid from</th></tr>
                </thead>
                <tbody>
                  {data.indicators.map((ind) => (
                    <tr key={ind.id} data-testid="ioc-row" style={{ cursor: "default" }}>
                      <td style={{ fontWeight: 500 }}>{ind.name}</td>
                      <td className="is-mono" style={{ fontSize: 11, color: "var(--acc)", wordBreak: "break-all" }}>{ind.pattern}</td>
                      <td style={{ fontSize: 11, color: "var(--mut)" }}>{ind.types.join(", ") || "—"}</td>
                      <td className="col-mono">{ind.validFrom || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="is-panel">
          <div className="is-panel__h">
            <h3>Rule → MITRE map</h3>
            <span className="is-panel__sub">static per-rule mapping — derived, not verdicts</span>
          </div>
          {ruleEntries.length === 0 ? (
            <p className="is-mut" style={{ fontSize: 12.5, margin: 0 }}>No rule mappings available.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {ruleEntries.map(([rule, techniques]) => (
                <div key={rule} style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span className="is-mono" style={{ fontSize: 12, fontWeight: 600 }}>{rule}</span>
                  {techniques.map((t) => (
                    <span key={t.id} className="is-tid" title={`${t.id} · ${t.name} · ${t.tactic}`}>{t.id}</span>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="is-panel">
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10, fontSize: 12.5 }}>
          <span className="is-mut" style={{ fontWeight: 500 }}>MITRE ATT&amp;CK offline cache:</span>
          <span className={data.attackCacheWarm ? "is-chip is-chip--ok" : "is-chip"}
                title="~/.cache/mitre_attack — populated once the ATT&CK dataset has been fetched">
            {data.attackCacheWarm ? "warm" : "cold — technique names come from the static map only"}
          </span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// LIVE ENRICHMENT SECTION (OTX / AbuseIPDB Outbound Calls)
// ---------------------------------------------------------------------------

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

function LiveEnrichmentSection() {
  const { data: keys, error } = useQuery({ queryKey: ["ti", "keys"], queryFn: api.tiKeys });
  const otx = !!keys?.otx, abuseipdb = !!keys?.abuseipdb;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Live egress banner — distinct from Feeds */}
      <div className="is-note" data-testid="enrichment-egress-note">
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
    </div>
  );
}

// ---------------------------------------------------------------------------
// MAIN INTEL MERGED COMPONENT
// ---------------------------------------------------------------------------

export function Intel({ defaultSection = "feeds" }: { defaultSection?: IntelSection }) {
  const [params, setParams] = useSearchParams();
  const paramTab = params.get("tab");
  const currentSection: IntelSection =
    paramTab === "enrichment" || paramTab === "live" ? "enrichment" :
    paramTab === "feeds" ? "feeds" :
    defaultSection;

  const setSection = (s: IntelSection) => {
    setParams({ tab: s }, { replace: true });
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Section Switcher Tabs */}
      <div className="is-tabs" style={{ maxWidth: 360 }} role="tablist" aria-label="Intel sections">
        <button
          type="button"
          role="tab"
          aria-selected={currentSection === "feeds"}
          className={currentSection === "feeds" ? "on" : ""}
          onClick={() => setSection("feeds")}
          style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6 }}
        >
          <Shield size={14} aria-hidden /> Feeds (TAXII / static)
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={currentSection === "enrichment"}
          className={currentSection === "enrichment" ? "on" : ""}
          onClick={() => setSection("enrichment")}
          style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6 }}
        >
          <Zap size={14} aria-hidden /> Live Enrichment
        </button>
      </div>

      {currentSection === "feeds" ? <FeedsSection /> : <LiveEnrichmentSection />}
    </div>
  );
}
