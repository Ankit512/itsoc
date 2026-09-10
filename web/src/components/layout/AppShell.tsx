import { useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Antenna, Bell, Cable, Database, FileText, FolderKanban, House, Link as LinkIcon, LogOut, Monitor,
  BrainCircuit, Plug, Radar, RefreshCw, Search, Settings, Shield, ShieldCheck, TriangleAlert, Upload, X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { sevVar } from "@/lib/severity";
import { Dialog } from "@/components/ui/dialog";
import { RunHistory } from "@/components/RunHistory";
import { RunSwitcher } from "@/components/RunSwitcher";
import { CommandPalette } from "@/components/CommandPalette";
import { CopilotRail } from "@/components/CopilotRail";
import { SpotlightTour } from "@/components/SpotlightTour";
import { IngestNotifier } from "@/components/IngestNotifier";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useJobs } from "@/store/jobs";
import { useUi } from "@/store/ui";
import { isBlobPageUrl, rawFileUrl } from "@/lib/rawUrl";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  ready: boolean;
}

export interface NavGroup {
  id: string;
  label: string;
  /** Why this group exists, in the analyst's own terms. Rendered as the
   *  section's tooltip so the grouping explains itself in the product, not
   *  only in the report. */
  rationale: string;
  items: readonly NavItem[];
}

/** Overview is the home surface, not a peer of the working screens: it is what
 *  the wordmark points at and what the tour starts on. It therefore sits above
 *  the groups rather than inside one (G1 · Stage F §3). */
export const HOME_NAV: NavItem = { to: "/", label: "Overview", icon: House, ready: true };

/** G1 information architecture. Three groups, ordered by the question a
 *  security lead asks in sequence during a 30-minute demo:
 *
 *    Triage   — "what happened, and what do I do about it?"  (the work)
 *    Context  — "what else do I know about the things involved?"  (the lookup)
 *    Operate  — "how is this workspace wired, and what leaves it?"  (the plumbing)
 *
 *  Ordering INSIDE a group is not alphabetical either. Triage follows the
 *  analyst's own escalation path (a finding becomes an incident, an incident
 *  earns a case, a case proposes an action that needs approval). Context runs
 *  outside-in: external intel, then the network we observed, then the assets we
 *  own, then the collectors that fed the run. Operate runs from inbound wiring
 *  through the stored past to what goes out and what is configured.
 *
 *  These are display groupings only. `web/` never derives a verdict, a priority
 *  or an eligibility — grouping a link is not deriving anything about the data
 *  behind it (CLAUDE.md, Stage F §2.1). */
export const NAV_GROUPS: readonly NavGroup[] = [
  {
    id: "triage",
    label: "Triage",
    rationale: "What happened and what to do about it — a finding becomes an incident, an incident earns a case, a case proposes an action that needs approval.",
    items: [
      { to: "/alerts", label: "Findings", icon: Bell, ready: true },
      { to: "/incidents", label: "Incidents", icon: TriangleAlert, ready: true },
      { to: "/cases", label: "Cases", icon: FolderKanban, ready: true },
      { to: "/approvals", label: "Approvals", icon: ShieldCheck, ready: true },
    ],
  },
  {
    id: "context",
    label: "Context",
    rationale: "What else is known about the entities in a finding — read outside-in: external intel, the observed network, the assets we own, the collectors that fed this run.",
    items: [
      { to: "/intel", label: "Intel", icon: Shield, ready: true },
      { to: "/network", label: "Network", icon: Radar, ready: true },
      { to: "/assets", label: "Assets", icon: Monitor, ready: true },
      { to: "/sources", label: "Sources", icon: Antenna, ready: true },
    ],
  },
  {
    id: "operate",
    label: "Operate",
    rationale: "How this workspace is wired and what leaves it — inbound connectors, the stored past, outbound reports, and the settings that govern both.",
    items: [
      { to: "/integrations", label: "Integrations", icon: Plug, ready: true },
      { to: "/history", label: "History", icon: Database, ready: true },
      { to: "/reports", label: "Reports", icon: FileText, ready: true },
      { to: "/settings", label: "Settings", icon: Settings, ready: true },
    ],
  },
];

/** The flat roster, DERIVED from what the sidebar actually renders. Deriving it
 *  rather than maintaining a second list is the point: `TOUR_STEPS` and the
 *  nav-alias tests both compare against `CORE_NAV`, and a hand-kept copy is how
 *  the rendered nav and its tests drift apart without either side going red.
 *  The order below is therefore, by construction, top-to-bottom visual order —
 *  and it is unchanged from the pre-G1 flat nav, which is why the guided tour
 *  needed no edit. */
export const CORE_NAV: readonly NavItem[] = [
  HOME_NAV,
  ...NAV_GROUPS.flatMap((group) => group.items),
];

/** Experimental group (off by default). Houses OEM Engine. `/oem` is reachable
 *  whether or not this is on: the command palette lists it unconditionally, and
 *  the route is registered unconditionally in `App.tsx`. The toggle changes
 *  whether the sidebar advertises it, never whether it exists. */
export const EXPERIMENTAL_NAV: readonly NavItem[] = [
  { to: "/oem", label: "OEM Engine", icon: Cable, ready: true },
];

export const NAV: readonly NavItem[] = [...CORE_NAV, ...EXPERIMENTAL_NAV];

/** Page title + subtitle, verbatim from the v3 dc `TITLES` map. The subtitle is
 *  a mono provenance/intent line (what this screen is honest about), never a
 *  restatement of the title. */
const TITLES: Record<string, { title: string; subtitle: string }> = {
  "/intel": { title: "Intel", subtitle: "feeds & live enrichment — external context" },
  "/integrations": { title: "Integrations", subtitle: "sovereign local connectors · masked credentials" },
  "/": { title: "Overview", subtitle: "" },
  "/alerts": { title: "Findings", subtitle: "" },
  "/findings": { title: "Findings", subtitle: "" },
  "/incidents": { title: "Incidents", subtitle: "" },
  "/approvals": { title: "Approvals", subtitle: "single authoritative approval surface · step-up required per action" },
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

/** One nav anchor. Shared by the core groups and the experimental group so a
 *  link can never gain an affordance in one place and lose it in the other —
 *  including the `data-tour` anchor the guided tour spotlights. */
function NavItemLink({ item }: { item: NavItem }) {
  const { to, label, icon: Icon, ready } = item;
  return (
    <NavLink
      to={to}
      end={to === "/"}
      data-tour={to === "/" ? "nav-overview" : `nav-${label.toLowerCase()}`}
      title={ready ? undefined : "Not built yet — the page says so honestly"}
      className={({ isActive }) => cn(isActive && "active")}
    >
      <Icon className="ic" strokeWidth={1.8} aria-hidden />
      {label}
    </NavLink>
  );
}

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
      <NavLink to="/" end className="is-brand" aria-label="Return to Overview">
        <span data-testid="wordmark">itsoc<span className="dot">.</span></span>
      </NavLink>

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

      {/* Primary nav — Overview as home, then the three G1 groups. Group
          headings are plain text, so the Tab order through the nav is exactly
          the anchor order it always was: no new keyboard mode, no roving
          tabindex, no heading that swallows a stop. */}
      <nav className="is-nav" aria-label="Main">
        <NavItemLink item={HOME_NAV} />
        {NAV_GROUPS.map((group) => (
          <div
            key={group.id}
            className="is-nav-sec"
            role="group"
            aria-labelledby={`nav-sec-${group.id}`}
          >
            <div className="is-nav-sec__h" id={`nav-sec-${group.id}`} title={group.rationale}>
              {group.label}
            </div>
            {group.items.map((item) => <NavItemLink key={item.to} item={item} />)}
          </div>
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

      {/* Experimental group — one disclosure row, not a permanent fake-off
          panel. G1 removed a dashed `is-exp-empty` box reading "Command Center
          · off": it took a nav slot to advertise a destination that has no
          route in App.tsx at all, so it could never have been navigated to.
          The honest statement is the toggle's own OFF badge, and the count of
          what is hidden — and `/oem` stays reachable from ⌘K regardless. */}
      <div className="is-nav-exp">
        <button
          className="is-nav-exp__h"
          onClick={toggleExperimental}
          aria-pressed={experimentalEnabled}
          aria-expanded={experimentalEnabled}
          aria-controls="nav-experimental"
          title={
            experimentalEnabled
              ? `Experimental: ${EXPERIMENTAL_NAV.length} screen(s) shown in the sidebar.`
              : `Experimental: ${EXPERIMENTAL_NAV.length} screen(s) hidden from the sidebar (${EXPERIMENTAL_NAV.map((i) => i.label).join(", ")}). Still reachable from the ⌘K command palette.`
          }
        >
          <span className="lbl">Experimental</span>
          <span className="count">{EXPERIMENTAL_NAV.length}</span>
          <span className={cn("badge", experimentalEnabled && "on")}>
            {experimentalEnabled ? "ON" : "OFF"}
          </span>
        </button>
        {experimentalEnabled && (
          <nav id="nav-experimental" className="is-nav" aria-label="Experimental">
            {EXPERIMENTAL_NAV.map((item) => <NavItemLink key={item.to} item={item} />)}
          </nav>
        )}
      </div>

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

        {/* G1 density: the run selector and the run history were two separately
            bordered buttons doing one job — saying which run is loaded and
            letting you change it. They are now segments of ONE bordered
            provenance cluster. Nothing is hidden: the loaded run's filename,
            its `· unparsed` marker and the full history popover are all still
            here, and RunHistory keeps its own honest "unreadable" row that the
            selector does not have. */}
        <div className="is-top-runs" role="group" aria-label="Loaded run">
          <RunSwitcher />
          <RunHistory />
        </div>

        {/* Refresh is a utility, not provenance: icon-only, still named for
            assistive tech and still explained on hover. */}
        <button
          className="is-icobtn"
          onClick={() => queryClient.invalidateQueries()}
          aria-label="Refresh"
          title="Re-fetch every dashboard query from the local API"
        >
          <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.8} aria-hidden />
        </button>
        <ThemeToggle />
      </div>
    </div>
  );
}

export function AppShell() {
  const { pathname, search } = useLocation();
  const [uploadOpen, setUploadOpen] = useState(false);
  const [railOpen, setRailOpen] = useState(false);

  // Copilot is a slide-in drawer (.is-rail) launched by the floating
  // .is-cop-fab (DESIGN_HANDOFF §2 / §4). Hidden on the logout screen.
  // On an open case file the case overlay owns Copilot so we don't stack two chats.
  const caseFileOpen = pathname === "/cases" && new URLSearchParams(search).has("sel");
  const showCopilot = pathname !== "/logout" && !caseFileOpen;

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
          {/* The analyst mark is distinct from generic AI sparkle affordances. */}
          <button
            className={cn("is-cop-fab", railOpen && "open")}
            data-testid="copilot-fab"
            onClick={() => setRailOpen((o) => !o)}
            aria-label={railOpen ? "Close AI Analyst" : "Open AI Analyst"}
            aria-expanded={railOpen}
          >
            {railOpen
              ? <X size={14} strokeWidth={1.7} aria-hidden />
              : <BrainCircuit size={18} strokeWidth={1.8} aria-hidden />}
          </button>
        </>
      )}

      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
      <CommandPalette onUploadClick={() => setUploadOpen(true)} />
      <IngestNotifier />
      <SpotlightTour />
    </div>
  );
}
