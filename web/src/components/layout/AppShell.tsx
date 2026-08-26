import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Antenna, Bell, Cable, Database, FileText, Filter, Folder, House, Link as LinkIcon, LogOut, Monitor,
  Radar, RefreshCw, Search, Settings, Shield, ShieldAlert, ShieldCheck, TriangleAlert, Upload,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Dialog } from "@/components/ui/dialog";
import { RunHistory } from "@/components/RunHistory";
import { RunSwitcher } from "@/components/RunSwitcher";
import { CommandPalette } from "@/components/CommandPalette";
import { IngestNotifier } from "@/components/IngestNotifier";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useJobs } from "@/store/jobs";
import { useUi } from "@/store/ui";
import { isBlobPageUrl, rawFileUrl } from "@/lib/rawUrl";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

/** Core navigation per SPEC §3 (Overview · Findings · Incidents · Sources · Settings) */
export const CORE_NAV = [
  { to: "/", label: "Overview", icon: House, ready: true },
  { to: "/alerts", label: "Findings", icon: Bell, ready: true },
  { to: "/incidents", label: "Incidents", icon: TriangleAlert, ready: true },
  { to: "/collectors", label: "Sources", icon: Antenna, ready: true },
  { to: "/settings", label: "Settings", icon: Settings, ready: true },
] as const;

/** Experimental navigation group (off by default via flag per SPEC §3) */
export const EXPERIMENTAL_NAV = [
  { to: "/discovery", label: "Discovery", icon: Radar, ready: true },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, ready: true },
  { to: "/enrichment", label: "Enrichment", icon: Search, ready: true },
  { to: "/oem", label: "OEM Engine", icon: Cable, ready: true },
  { to: "/history", label: "History", icon: Database, ready: true },
  { to: "/threat-intel", label: "Threat Intel", icon: Shield, ready: true },
  { to: "/assets", label: "Assets", icon: Monitor, ready: true },
  { to: "/reports", label: "Reports", icon: FileText, ready: true },
  { to: "/cases", label: "Cases", icon: Folder, ready: true },
] as const;

export const NAV = [...CORE_NAV, ...EXPERIMENTAL_NAV];

const TITLES: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "SOC Dashboard", subtitle: "Security Overview" },
  "/alerts": { title: "Findings", subtitle: "Alerts & Detections" },
  "/findings": { title: "Findings", subtitle: "Alerts & Detections" },
  "/incidents": { title: "Incidents", subtitle: "Incident Management & RCA" },
  "/collectors": { title: "Sources", subtitle: "Live Collectors & Syslog" },
  "/sources": { title: "Sources", subtitle: "Live Collectors & Syslog" },
  "/settings": { title: "Settings", subtitle: "Configuration & Model" },
  "/threat-intel": { title: "Threat Intel", subtitle: "MITRE ATT&CK & IOCs" },
  "/assets": { title: "Assets", subtitle: "Observed Assets & Users" },
  "/discovery": { title: "Discovery", subtitle: "Network Discovery & Scans" },
  "/vulnerabilities": { title: "Vulnerabilities", subtitle: "Vulnerability Scanning" },
  "/enrichment": { title: "Enrichment", subtitle: "Threat Intelligence Feeds" },
  "/oem": { title: "OEM Engine", subtitle: "Vendor Connectors" },
  "/history": { title: "History", subtitle: "EVTX Ingest & Store" },
  "/reports": { title: "Reports", subtitle: "Export Reports & Scorecards" },
  "/cases": { title: "Cases", subtitle: "Case Management" },
  "/logout": { title: "Logout", subtitle: "Local Session Reset" },
};

function Sidebar() {
  const { experimentalEnabled, toggleExperimental, setCommandPaletteOpen } = useUi();
  const { user } = useAuth();
  const { data: ov } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  const model = ov && !("error" in ov) ? ov.model : "qwen3:8b";

  return (
    <aside className="flex w-[200px] flex-none flex-col border-r border-border bg-card px-3 py-4">
      {/* Brand wordmark with accent dot */}
      <div className="flex items-center gap-2 px-2 pb-3">
        <ShieldCheck className="h-[28px] w-[28px] flex-none text-primary" strokeWidth={1.8} aria-hidden />
        <span className="text-[19px] font-bold leading-none tracking-tight" data-testid="wordmark">
          itsoc<span className="text-primary">.</span>
        </span>
      </div>

      {/* Quick ⌘K button in sidebar */}
      <button
        onClick={() => setCommandPaletteOpen(true)}
        className="mb-3 flex items-center gap-2 rounded-lg border border-border bg-background px-2.5 py-1.5 text-[12px] text-muted-foreground transition-colors hover:border-primary hover:text-foreground"
      >
        <kbd className="rounded border border-border bg-muted px-1 font-mono text-[10px]">⌘K</kbd>
        <span className="truncate">Search or ask…</span>
      </button>

      {/* Core navigation */}
      <nav aria-label="Main" className="flex flex-col gap-0.5">
        {CORE_NAV.map(({ to, label, icon: Icon, ready }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            title={ready ? undefined : "Not built yet — the page says so honestly"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-medium text-muted-foreground transition-colors hover:bg-background hover:text-foreground",
                isActive && "bg-primary/15 font-semibold text-primary hover:bg-primary/20 hover:text-primary",
              )
            }
          >
            <Icon className="h-4 w-4 flex-none" strokeWidth={1.8} aria-hidden />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Experimental group per SPEC §3 */}
      <div className="mt-4 flex flex-col gap-1 border-t border-border pt-3">
        <button
          onClick={toggleExperimental}
          className="flex items-center justify-between rounded px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground"
        >
          <span>Experimental</span>
          <span
            className={cn(
              "rounded px-1.5 py-0.5 text-[9.5px] font-medium",
              experimentalEnabled ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
            )}
          >
            {experimentalEnabled ? "on" : "off"}
          </span>
        </button>

        {experimentalEnabled ? (
          <div className="flex flex-col gap-0.5 pl-1">
            {EXPERIMENTAL_NAV.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-2 rounded-lg px-2 py-1.5 text-[12px] text-muted-foreground transition-colors hover:bg-background hover:text-foreground",
                    isActive && "bg-primary/15 font-medium text-primary",
                  )
                }
              >
                <Icon className="h-3.5 w-3.5 flex-none" strokeWidth={1.8} aria-hidden />
                {label}
              </NavLink>
            ))}
          </div>
        ) : (
          <div
            onClick={toggleExperimental}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && toggleExperimental()}
            className="cursor-pointer rounded-lg border border-dashed border-border p-2 text-[11px] leading-relaxed text-muted-foreground hover:border-primary/50"
          >
            Command Center · <span className="opacity-70">off</span>
          </div>
        )}
      </div>

      {/* Footer / Logout */}
      <div className="mt-auto border-t border-border pt-3">
        {user && (
          <div className="mb-2 px-2.5 text-[11.5px] text-muted-foreground">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
              <span className="truncate">{user.username}</span>
            </div>
            <div className="text-[10.5px] uppercase tracking-wider">{user.role}</div>
          </div>
        )}
        <NavLink
          to="/logout"
          title="Sign out of this local demo session"
          className={({ isActive }) =>
            cn(
              "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[13px] text-muted-foreground transition-colors hover:bg-background hover:text-foreground",
              isActive && "bg-primary/15 font-semibold text-primary hover:bg-primary/20",
            )
          }
        >
          <LogOut className="h-4 w-4 flex-none" strokeWidth={1.8} aria-hidden />
          Logout
        </NavLink>
        <div
          className="mt-2 truncate px-2.5 text-[10.5px] font-mono text-muted-foreground"
          title={`rules v1 · ${model} · local`}
        >
          rules v1 · {model} · local
        </div>
      </div>
    </aside>
  );
}

const ACCEPTED_TITLE =
  "Accepted: LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text. Analyzed locally by the rules engine; results open in Alerts. Windows EVTX (.evtx) is ingested into the persistent store and appears on the History page.";

function UploadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const startUpload = useJobs((s) => s.startUpload);
  const startUrl = useJobs((s) => s.startUrl);
  const startEvtx = useJobs((s) => s.startEvtx);
  const [mode, setMode] = useState<"file" | "link">("file");

  const routeFiles = (files: FileList) => {
    const all = Array.from(files);
    const evtx = all.filter((f) => f.name.toLowerCase().endsWith(".evtx"));
    const rest = all.filter((f) => !f.name.toLowerCase().endsWith(".evtx"));
    if (rest.length) startUpload(rest);
    if (evtx.length) startEvtx(evtx);
  };
  const [url, setUrl] = useState("");

  const isBlob = isBlobPageUrl(url);

  const submitUrl = () => {
    const u = rawFileUrl(url);
    if (!u.trim()) return;
    startUrl(u);
    setUrl("");
    onClose();
  };

  const seg = (active: boolean) =>
    cn(
      "flex-1 rounded-md px-3 py-1.5 text-[12.5px] font-medium transition-colors",
      active ? "bg-card shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground",
    );

  return (
    <Dialog open={open} onClose={onClose} title="Add logs to analyze">
      <div className="mb-3 flex gap-1 rounded-lg bg-background p-1">
        <button className={seg(mode === "file")} onClick={() => setMode("file")}>
          Upload from this computer
        </button>
        <button className={seg(mode === "link")} onClick={() => setMode("link")}>
          Attach a link
        </button>
      </div>

      {mode === "file" ? (
        <div className="flex flex-col gap-2">
          <label
            title={ACCEPTED_TITLE}
            className="flex cursor-pointer flex-col items-center gap-1 rounded-lg border border-dashed border-border px-4 py-6 text-center text-[12.5px] text-muted-foreground hover:border-primary"
          >
            <Upload className="h-5 w-5" strokeWidth={1.6} aria-hidden />
            <span className="text-[13px] font-semibold text-foreground">Choose a log file</span>
            Analyzed locally — the file never leaves this machine.
            <input
              type="file"
              multiple
              className="hidden"
              data-testid="ingest-file"
              aria-label="Upload logs"
              onChange={(e) => {
                if (e.target.files?.length) {
                  routeFiles(e.target.files);
                  onClose();
                }
                e.target.value = "";
              }}
            />
          </label>
          <p className="text-[11px] text-muted-foreground">{ACCEPTED_TITLE}</p>
        </div>
      ) : (
        <form
          className="flex flex-col gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            submitUrl();
          }}
        >
          <label className="text-[11.5px] text-muted-foreground">
            Public URL of a raw log file
            <input
              className="mt-1 w-full rounded-md border border-border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              aria-label="Log file URL"
              placeholder="https://raw.githubusercontent.com/…/app.log"
              inputMode="url"
              autoComplete="off"
            />
          </label>
          {isBlob && (
            <p className="text-[11px]" style={{ color: "var(--sev-medium)" }}>
              That’s a web-page link, not the raw file — we’ll fetch the raw version instead:{" "}
              <span className="break-all font-mono">{rawFileUrl(url)}</span>
            </p>
          )}
          <p className="text-[11px] text-muted-foreground">
            The server fetches it (http/https only, public hosts, size- and text-gated) and runs the
            same analysis. A page that isn’t a text log is rejected honestly.
          </p>
          <div>
            <button
              type="submit"
              disabled={!url.trim()}
              className="inline-flex items-center gap-2 rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60"
            >
              <LinkIcon className="h-4 w-4" strokeWidth={1.8} aria-hidden /> Fetch &amp; analyze
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function UploadButton({ onClick }: { onClick: () => void }) {
  const busy = useJobs((s) => s.busy);

  return (
    <button
      onClick={onClick}
      title={ACCEPTED_TITLE}
      className={cn(
        "inline-flex cursor-pointer items-center gap-2 whitespace-nowrap rounded-[10px] border border-primary bg-primary px-3.5 py-2 text-[13px] font-semibold text-primary-foreground transition-opacity hover:opacity-90",
        busy && "cursor-progress opacity-70",
      )}
    >
      <Upload className="h-4 w-4" strokeWidth={1.8} aria-hidden />
      {busy ? "Analyzing…" : "Upload Logs"}
    </button>
  );
}

const chip =
  "inline-flex items-center gap-2 whitespace-nowrap rounded-[10px] border border-border bg-card px-3 py-2 text-[13px] transition-colors";

function Header({ onOpenUpload }: { onOpenUpload: () => void }) {
  const { pathname } = useLocation();
  const queryClient = useQueryClient();
  const { setCommandPaletteOpen } = useUi();
  const info = TITLES[pathname] ?? { title: "itsoc.", subtitle: "Security Overview" };

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div>
        <h1 className="text-[24px] font-bold leading-tight tracking-[-0.015em] text-foreground">
          {info.title}
        </h1>
        <div className="mt-0.5 text-xs font-medium text-muted-foreground">{info.subtitle}</div>
      </div>

      {/* Top ⌘K command bar */}
      <button
        onClick={() => setCommandPaletteOpen(true)}
        className="mx-auto hidden md:flex max-w-[280px] flex-1 items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-[12.5px] text-muted-foreground shadow-sm transition-colors hover:border-primary hover:text-foreground"
        aria-label="Open command palette"
      >
        <kbd className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
        <span className="truncate">Search or ask itsoc…</span>
      </button>

      <div className="ml-auto flex flex-wrap items-center gap-2">
        <UploadButton onClick={onOpenUpload} />
        <RunSwitcher />
        <RunHistory />
        <button
          className={cn(chip, "cursor-pointer hover:border-primary hover:bg-background")}
          onClick={() => queryClient.invalidateQueries()}
        >
          <RefreshCw className="h-3.5 w-3.5 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Refresh
        </button>
        <button
          disabled
          title="Filtering is not built yet — alert filters live on the Alerts page"
          className={cn(chip, "cursor-not-allowed opacity-50")}
        >
          <Filter className="h-3.5 w-3.5 text-muted-foreground" strokeWidth={1.8} aria-hidden />
          Filters
        </button>
        <ThemeToggle />
      </div>
    </div>
  );
}

function RunFacts() {
  const { data: state } = useQuery({ queryKey: ["consoleState"], queryFn: api.consoleState });
  const { data: ov } = useQuery({ queryKey: ["overview"], queryFn: api.overview });

  if (!state || state.idle || !state.findings) return null;
  const sha = state.manifest?.detector_sha256;
  const model = ov && !("error" in ov) ? ov.model : null;
  const meta = [
    state.runWindow,
    state.manifest?.ruleset && `ruleset ${state.manifest.ruleset}`,
    model,
    state.generatedAt && `generated ${state.generatedAt}`,
  ].filter(Boolean);

  return (
    <div className="flex flex-wrap items-center gap-x-[18px] gap-y-1.5 text-[11.5px] text-muted-foreground">
      {state.sourceLabel && (
        <span
          title={state.sourceLabel}
          className="cursor-help border-b border-dotted font-mono text-[12.5px] font-semibold text-foreground"
        >
          {state.sourceLabel.split("/").pop()}
        </span>
      )}
      {state.runHosts && <span>host {state.runHosts}</span>}
      {state.runParsed && <span className="tabular-nums">{state.runParsed}</span>}
      {meta.length > 0 && (
        <span className="font-mono text-[10.5px]">
          {meta.map(String).join(" · ")}
          {sha && <span title={`detector_sha256 ${sha}`}> · detector {sha.slice(0, 8)}…{sha.slice(-6)}</span>}
        </span>
      )}
      {state.llmNote && (
        <span title={state.llmNote} className="cursor-help border-b border-dotted">
          rules-only run — explanations skipped (model offline)
        </span>
      )}
    </div>
  );
}

export function AppShell() {
  const { pathname } = useLocation();
  const [uploadOpen, setUploadOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <Sidebar />
      <main className="flex min-w-0 flex-1 flex-col gap-4 px-[22px] py-5">
        <Header onOpenUpload={() => setUploadOpen(true)} />
        {pathname === "/" && <RunFacts />}
        <Outlet />
      </main>

      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
      <CommandPalette onUploadClick={() => setUploadOpen(true)} />
      <IngestNotifier />
    </div>
  );
}
