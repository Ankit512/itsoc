import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Antenna, Bell, Cable, Database, FileText, Folder, House, Link as LinkIcon, LogOut, Monitor,
  Radar, RefreshCw, Search, Settings, Shield, ShieldAlert, ShieldCheck, TriangleAlert, Upload,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Dialog } from "@/components/ui/dialog";
import { RunHistory } from "@/components/RunHistory";
import { RunSwitcher } from "@/components/RunSwitcher";
import { CommandPalette } from "@/components/CommandPalette";
import { CopilotRail } from "@/components/CopilotRail";
import { IngestNotifier } from "@/components/IngestNotifier";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useJobs } from "@/store/jobs";
import { useUi } from "@/store/ui";
import { isBlobPageUrl, rawFileUrl } from "@/lib/rawUrl";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

/** Core navigation per DESIGN_HANDOFF §2 (Overview · Findings · Incidents · Sources · Settings) */
export const CORE_NAV = [
  { to: "/", label: "Overview", icon: House, ready: true },
  { to: "/alerts", label: "Findings", icon: Bell, ready: true },
  { to: "/incidents", label: "Incidents", icon: TriangleAlert, ready: true },
  { to: "/collectors", label: "Sources", icon: Antenna, ready: true },
  { to: "/settings", label: "Settings", icon: Settings, ready: true },
] as const;

/** Experimental group (off by default). Leads with the handoff's named five
 *  (Assets · Threat Intel · Discovery · Vulnerabilities · History), then the
 *  remaining real experimental pages so none is orphaned. */
export const EXPERIMENTAL_NAV = [
  { to: "/assets", label: "Assets", icon: Monitor, ready: true },
  { to: "/threat-intel", label: "Threat Intel", icon: Shield, ready: true },
  { to: "/discovery", label: "Discovery", icon: Radar, ready: true },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert, ready: true },
  { to: "/history", label: "History", icon: Database, ready: true },
  { to: "/enrichment", label: "Enrichment", icon: Search, ready: true },
  { to: "/oem", label: "OEM Engine", icon: Cable, ready: true },
  { to: "/reports", label: "Reports", icon: FileText, ready: true },
  { to: "/cases", label: "Cases", icon: Folder, ready: true },
] as const;

export const NAV = [...CORE_NAV, ...EXPERIMENTAL_NAV];

const TITLES: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Overview", subtitle: "Security Overview" },
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
    <aside className="is-side">
      {/* Brand wordmark: 'itsoc.' with the dot in --acc (DESIGN_HANDOFF §1) */}
      <div className="is-brand">
        <span className="mark"><ShieldCheck className="h-4 w-4" strokeWidth={1.9} aria-hidden /></span>
        <span data-testid="wordmark">itsoc<span className="dot">.</span></span>
      </div>

      {/* ⌘K search pill */}
      <button className="is-side-search" onClick={() => setCommandPaletteOpen(true)}>
        <kbd>⌘K</kbd>
        <span className="truncate">Search or ask…</span>
      </button>

      {/* Primary nav */}
      <nav className="is-nav" aria-label="Main">
        {CORE_NAV.map(({ to, label, icon: Icon, ready }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            title={ready ? undefined : "Not built yet — the page says so honestly"}
            className={({ isActive }) => cn(isActive && "active")}
          >
            <Icon className="ic" strokeWidth={1.8} aria-hidden />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Experimental group with ON/OFF badge (DESIGN_HANDOFF §2) */}
      <div className="is-nav-group">
        <span>Experimental</span>
        <button
          className={cn("badge", experimentalEnabled && "on")}
          onClick={toggleExperimental}
          aria-pressed={experimentalEnabled}
          aria-label="Toggle experimental group"
        >
          {experimentalEnabled ? "ON" : "OFF"}
        </button>
      </div>
      {experimentalEnabled ? (
        <nav className="is-nav" aria-label="Experimental">
          {EXPERIMENTAL_NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} className={({ isActive }) => cn(isActive && "active")}>
              <Icon className="ic" strokeWidth={1.8} aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
      ) : (
        <div
          className="is-exp-empty"
          role="button"
          tabIndex={0}
          onClick={toggleExperimental}
          onKeyDown={(e) => e.key === "Enter" && toggleExperimental()}
        >
          Command Center · <span className="is-mut2">off</span>
        </div>
      )}

      {/* Footer: user + role, Logout, rules · model · local meta */}
      <div className="is-side-foot">
        {user && (
          <>
            <div className="is-side-user">
              <span className="dot" />
              <span className="truncate">{user.username}</span>
            </div>
            <div className="role" style={{ paddingLeft: 14, marginBottom: 8 }}>{user.role}</div>
          </>
        )}
        <NavLink to="/logout" className="is-side-logout" title="Sign out of this local demo session">
          <LogOut className="h-4 w-4" strokeWidth={1.8} aria-hidden />
          Logout
        </NavLink>
        <div className="is-side-meta" title={`rules v1 · ${model} · local`}>
          rules v1 · {model} · local
        </div>
      </div>
    </aside>
  );
}

const ACCEPTED_TITLE =
  "Accepted: LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text. Analyzed locally by the rules engine; results open in Findings. Windows EVTX (.evtx) is ingested into the persistent store and appears on the History page.";

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
            <p className="text-[11px]" style={{ color: "var(--high)" }}>
              That’s a web-page link, not the raw file — we’ll fetch the raw version instead:{" "}
              <span className="break-all font-mono">{rawFileUrl(url)}</span>
            </p>
          )}
          <p className="text-[11px] text-muted-foreground">
            The server fetches it (http/https only, public hosts, size- and text-gated) and runs the
            same analysis. A page that isn’t a text log is rejected honestly.
          </p>
          <div>
            <button type="submit" disabled={!url.trim()} className="is-btn is-btn--primary">
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
      className={cn("is-btn is-btn--primary", busy && "cursor-progress opacity-70")}
    >
      <Upload className="h-4 w-4" strokeWidth={1.8} aria-hidden />
      {busy ? "Analyzing…" : "Upload Logs"}
    </button>
  );
}

function Header({ onOpenUpload }: { onOpenUpload: () => void }) {
  const { pathname } = useLocation();
  const queryClient = useQueryClient();
  const { setCommandPaletteOpen } = useUi();
  const info = TITLES[pathname] ?? { title: "itsoc.", subtitle: "Security Overview" };

  return (
    <div className="is-top">
      <div className="is-title">
        <h1>{info.title}</h1>
        <div className="sub">{info.subtitle}</div>
      </div>

      {/* Centered ⌘K search */}
      <button className="is-top-search" onClick={() => setCommandPaletteOpen(true)} aria-label="Open command palette">
        <kbd>⌘K</kbd>
        <span className="truncate">Search or ask itsoc…</span>
      </button>

      <div className="is-top-actions">
        <UploadButton onClick={onOpenUpload} />
        <RunSwitcher />
        <RunHistory />
        <button className="is-btn" onClick={() => queryClient.invalidateQueries()}>
          <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.8} aria-hidden />
          Refresh
        </button>
        <ThemeToggle />
      </div>
    </div>
  );
}

export function AppShell() {
  const { pathname } = useLocation();
  const [uploadOpen, setUploadOpen] = useState(false);
  const [railOpen, setRailOpen] = useState(false);

  // Copilot is a slide-in drawer (.is-rail) launched by the floating
  // .is-cop-fab (DESIGN_HANDOFF §2 / §4). Hidden on the logout screen.
  const showCopilot = pathname !== "/logout";

  return (
    <div className="itsoc is-app">
      <Sidebar />
      <main className="is-main">
        <Header onOpenUpload={() => setUploadOpen(true)} />
        <div className="is-content">
          <Outlet />
        </div>
      </main>

      {showCopilot && (
        <>
          <aside
            data-testid="copilot-rail-drawer"
            className={cn("is-rail-drawer", railOpen && "open")}
            aria-hidden={!railOpen}
          >
            <CopilotRail docked />
          </aside>
          <button
            className="is-cop-fab"
            data-testid="copilot-fab"
            onClick={() => setRailOpen((o) => !o)}
            aria-label={railOpen ? "Close AI Analyst" : "Open AI Analyst"}
          >
            <b className="n">◆ AI Analyst</b>
            <span className="adv">advisory</span>
          </button>
        </>
      )}

      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
      <CommandPalette onUploadClick={() => setUploadOpen(true)} />
      <IngestNotifier />
    </div>
  );
}
