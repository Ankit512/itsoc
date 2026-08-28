import { useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Antenna, Bell, Cable, Database, FileText, Folder, House, Link as LinkIcon, LogOut, Monitor,
  Radar, RefreshCw, Search, Settings, Shield, Sparkles, TriangleAlert, Upload, X,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { sevVar } from "@/lib/severity";
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
  { to: "/sources", label: "Sources", icon: Antenna, ready: true },
  { to: "/settings", label: "Settings", icon: Settings, ready: true },
] as const;

/** Experimental group (off by default). Leads with the handoff's named five
 *  (Assets · Threat Intel · Discovery · Vulnerabilities · History), then the
 *  remaining real experimental pages so none is orphaned. */
export const EXPERIMENTAL_NAV = [
  { to: "/intel", label: "Intel", icon: Shield, ready: true },
  { to: "/assets", label: "Assets", icon: Monitor, ready: true },
  { to: "/threat-intel", label: "Threat Intel", icon: Shield, ready: true },
  { to: "/network", label: "Network", icon: Radar, ready: true },
  { to: "/history", label: "History", icon: Database, ready: true },
  { to: "/enrichment", label: "Enrichment", icon: Search, ready: true },
  { to: "/oem", label: "OEM Engine", icon: Cable, ready: true },
  { to: "/reports", label: "Reports", icon: FileText, ready: true },
  { to: "/cases", label: "Cases", icon: Folder, ready: true },
] as const;

export const NAV = [...CORE_NAV, ...EXPERIMENTAL_NAV];

/** Page title + subtitle, verbatim from the v3 dc `TITLES` map. The subtitle is
 *  a mono provenance/intent line (what this screen is honest about), never a
 *  restatement of the title. */
const TITLES: Record<string, { title: string; subtitle: string }> = {
  "/intel": { title: "Intel", subtitle: "feeds & live enrichment — external context" },
  "/": { title: "Overview", subtitle: "" },
  "/alerts": { title: "Findings", subtitle: "" },
  "/findings": { title: "Findings", subtitle: "" },
  "/incidents": { title: "Incidents", subtitle: "" },
  "/collectors": { title: "Sources", subtitle: "live collectors — real listener state" },
  "/sources": { title: "Sources", subtitle: "live collectors — real listener state" },
  "/settings": { title: "Settings", subtitle: "only settings that do something" },
  "/threat-intel": { title: "Threat Intel", subtitle: "derived tags — not verdicts" },
  "/assets": { title: "Assets", subtitle: "observed entities only" },
  "/network": { title: "Network", subtitle: "active nmap discovery & vulnerabilities" },
  "/discovery": { title: "Network", subtitle: "active nmap discovery & vulnerabilities" },
  "/vulnerabilities": { title: "Network", subtitle: "active nmap discovery & vulnerabilities" },
  "/enrichment": { title: "Enrichment", subtitle: "real provider responses only" },
  "/oem": { title: "OEM Engine", subtitle: "read-only connectors · credentials masked" },
  "/history": { title: "History", subtitle: "persistent event store" },
  "/reports": { title: "Reports", subtitle: "real files only" },
  "/cases": { title: "Cases", subtitle: "analyst-entered · stored locally" },
  "/logout": { title: "Log out", subtitle: "local, single-user tool" },
};

/** crit/high/med/low map to the tiny severity word in the recent-incidents list. */
const sevWord = (s: string) =>
  ({ critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" } as Record<string, string>)[
    s.toLowerCase()
  ] ?? s.toUpperCase();

function Sidebar() {
  const { experimentalEnabled, toggleExperimental, setCommandPaletteOpen } = useUi();
  const { user } = useAuth();
  const { pathname } = useLocation();
  const onIncidents = pathname.startsWith("/incidents");
  const { data: ov } = useQuery({ queryKey: ["overview"], queryFn: api.overview });
  const model = ov && !("error" in ov) ? ov.model : "qwen3:8b";
  // Contextual "RECENT INCIDENTS" list — only fetched/shown on the Incidents
  // route (DESIGN_HANDOFF §sidebar). Real incidents, honest-empty otherwise.
  const { data: incData } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => api.incidents(),
    enabled: onIncidents,
  });
  const recent = (incData?.incidents ?? []).slice(0, 5);

  return (
    <aside className="is-side">
      {/* Brand wordmark: 'itsoc.' with the dot in --acc (DESIGN_HANDOFF §1) */}
      <div className="is-brand">
        <span data-testid="wordmark">itsoc<span className="dot">.</span></span>
      </div>

      {/* ⌘K search pill — dc order: icon · label · shortcut */}
      <button
        className="is-side-search"
        onClick={() => setCommandPaletteOpen(true)}
        aria-label="Open command palette"
      >
        <Search className="h-3 w-3" strokeWidth={1.7} aria-hidden />
        <span className="lbl">Search…</span>
        <kbd>⌘K</kbd>
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

      {/* Contextual recent-incidents list — Incidents route only */}
      {onIncidents && (
        <div className="is-recent" aria-label="recent incidents">
          <div className="is-recent__h">RECENT INCIDENTS</div>
          {recent.length ? (
            recent.map((inc) => (
              <NavLink key={inc.id} to={`/incidents?sel=${inc.id}`} className="is-recent__row">
                <span className="rdot" style={{ background: sevVar(inc.severity) }} />
                <span className="ent">{inc.entity}</span>
                <span className="sev" style={{ color: sevVar(inc.severity) }}>{sevWord(inc.severity)}</span>
              </NavLink>
            ))
          ) : (
            <div className="is-recent__empty">No incidents in this run.</div>
          )}
        </div>
      )}

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
          <div className="is-side-user">
            <span className="dot" />
            <div className="who">
              <div className="name truncate">{user.username}</div>
              <div className="role">{user.role}</div>
            </div>
          </div>
        )}
        <NavLink to="/logout" className="is-side-logout" title="Sign out of this local demo session">
          <LogOut className="h-3.5 w-3.5" strokeWidth={1.7} aria-hidden />
          Log out
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

  const routeFiles = (files: FileList) => {
    const all = Array.from(files);
    const evtx = all.filter((f) => f.name.toLowerCase().endsWith(".evtx"));
    const rest = all.filter((f) => !f.name.toLowerCase().endsWith(".evtx"));
    if (rest.length) startUpload(rest);
    if (evtx.length) startEvtx(evtx);
  };
  const [url, setUrl] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const isBlob = isBlobPageUrl(url);

  const submitUrl = () => {
    const u = rawFileUrl(url);
    if (!u.trim()) return;
    startUrl(u);
    setUrl("");
    onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="Upload logs"
      subtitle="parsed locally · nothing leaves this machine"
    >
      {/* dc "Upload logs": two side-by-side sections — files on the left,
          a link on the right. No tab switcher; both are always available. */}
      <div className="is-upload">
        <section>
          <div className="is-upload__lbl">UPLOAD FILES</div>
          <label title={ACCEPTED_TITLE} className="is-drop">
            <Upload className="h-5 w-5" strokeWidth={1.7} aria-hidden />
            <div className="t">
              Drop log files here or <span style={{ color: "var(--acc)" }}>browse</span>
            </div>
            <div className="s">.log · .txt · .csv · .tsv · .json · .xml · .evtx — max 64 MB</div>
            <input
              ref={fileRef}
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
          <button type="button" className="is-btn" onClick={() => fileRef.current?.click()}>
            Choose files…
          </button>
          <p className="is-mut" style={{ fontSize: 11, margin: 0, lineHeight: 1.5 }}>
            Files are parsed by the rules engine on this machine and become a new run.
            EVTX is ingested into the persistent store and appears on History.
          </p>
        </section>

        <section>
          <div className="is-upload__lbl">PASTE A LOG LINK</div>
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              submitUrl();
            }}
          >
            <label className="is-field">
              <span>URL</span>
              <input
                className="is-input is-mono"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                aria-label="Log file URL"
                placeholder="https://host.local/var/log/auth.log"
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
            <p className="is-mut" style={{ fontSize: 11, margin: 0, lineHeight: 1.5 }}>
              The file is fetched once, read-only, then parsed locally (http/https only, public hosts,
              size- and text-gated). A page that isn’t a text log is rejected honestly.
            </p>
            <p style={{ display: "flex", gap: 7, fontSize: 11, margin: 0, color: "var(--high)", lineHeight: 1.5 }}>
              <TriangleAlert size={12} strokeWidth={1.7} aria-hidden style={{ flex: "none", marginTop: 2 }} />
              <span>A remote URL is an outbound request from this machine — only fetch sources you trust.</span>
            </p>
            <div>
              <button type="submit" disabled={!url.trim()} className="is-btn is-btn--primary">
                <LinkIcon className="h-4 w-4" strokeWidth={1.8} aria-hidden /> Fetch &amp; parse →
              </button>
            </div>
          </form>
        </section>
      </div>
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
      {busy ? "Analyzing…" : "Upload logs"}
    </button>
  );
}

function Header({ onOpenUpload }: { onOpenUpload: () => void }) {
  const { pathname } = useLocation();
  const queryClient = useQueryClient();
  const info = TITLES[pathname] ?? { title: "itsoc.", subtitle: "" };

  return (
    <div className="is-top">
      <div className="is-title">
        <h1>{info.title}</h1>
        {info.subtitle && <div className="sub">{info.subtitle}</div>}
      </div>

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
          {/* dc launcher: a 42px round button — sparkle when closed, X when
              open. The label lives in the panel header, not on the button. */}
          <button
            className={cn("is-cop-fab", railOpen && "open")}
            data-testid="copilot-fab"
            onClick={() => setRailOpen((o) => !o)}
            aria-label={railOpen ? "Close AI Analyst" : "Open AI Analyst"}
            aria-expanded={railOpen}
          >
            {railOpen
              ? <X size={14} strokeWidth={1.7} aria-hidden />
              : <Sparkles size={16} strokeWidth={1.7} aria-hidden />}
          </button>
        </>
      )}

      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
      <CommandPalette onUploadClick={() => setUploadOpen(true)} />
      <IngestNotifier />
    </div>
  );
}
