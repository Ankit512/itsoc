import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Antenna, Bell, Cable, Database, Filter, House, Link as LinkIcon,
  RefreshCw, Settings, ShieldCheck, Upload,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Dialog } from "@/components/ui/dialog";
import { RunHistory } from "@/components/RunHistory";
import { RunDropdown } from "@/components/RunDropdown";
import { IngestNotifier } from "@/components/IngestNotifier";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useJobs } from "@/store/jobs";
import { useUi } from "@/store/ui";
import { isBlobPageUrl, rawFileUrl } from "@/lib/rawUrl";
import { cn } from "@/lib/utils";

/** The uniform v6 shell: every route renders inside this exact frame, so the
 *  sidebar, header, and page container are identical across the app. */

/** Phase 0 nav (ITSOC_V2_SPEC.md §3): exactly four default items. Incidents /
 *  Assets / Threat Intel / Reports / Cases live as facets INSIDE the Findings
 *  review; Discovery / Vulnerabilities / Enrichment / Logout are cut. */
export const NAV = [
  { to: "/", label: "Overview", icon: House, ready: true },
  { to: "/findings", label: "Findings", icon: Bell, ready: true },
  // socf-syslog: read-only live syslog receiver — the sanctioned live ingest.
  { to: "/collectors", label: "Sources", icon: Antenna, ready: true },
  { to: "/settings", label: "Settings", icon: Settings, ready: true },
] as const;

/** Fenced Command-Center pages: rendered only when the off-by-default
 *  experimental flag (Settings) is on. Kept in the repo — never deleted. */
export const EXPERIMENTAL_NAV = [
  { to: "/oem", label: "OEM Engine", icon: Cable },
  { to: "/history", label: "History", icon: Database },
] as const;

const TITLES: Record<string, string> = {
  "/": "SOC Dashboard", "/findings": "Findings",
  "/collectors": "Sources", "/settings": "Settings",
  "/oem": "OEM Engine", "/history": "History",
};

const navLink = ({ isActive }: { isActive: boolean }) =>
  cn(
    "flex items-center gap-[11px] rounded-md px-[11px] py-[9px] text-[13.5px] text-muted-foreground hover:bg-background",
    isActive && "bg-accent font-semibold text-accent-foreground hover:bg-accent",
  );

function Sidebar() {
  const experimental = useUi((s) => s.experimental);
  return (
    <aside className="flex w-[172px] flex-none flex-col border-r bg-card px-3 py-[18px]">
      <div className="px-2.5 pb-[22px]">
        <ShieldCheck className="h-[34px] w-[34px] text-primary" strokeWidth={1.8} role="img" aria-label="itsoc" />
      </div>
      <nav aria-label="Main" className="flex flex-col gap-[3px]">
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === "/"} className={navLink}>
            <Icon className="h-[17px] w-[17px] flex-none" strokeWidth={1.8} aria-hidden />
            {label}
          </NavLink>
        ))}
        {experimental && (
          <>
            <div className="mt-8 px-[11px] pb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground"
                 data-testid="experimental-section">
              Experimental
            </div>
            {EXPERIMENTAL_NAV.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to} className={navLink}
                       title="Fenced Command-Center page — shown because the experimental flag is on">
                <Icon className="h-[17px] w-[17px] flex-none" strokeWidth={1.8} aria-hidden />
                {label}
              </NavLink>
            ))}
          </>
        )}
      </nav>
    </aside>
  );
}

/** Header upload: the design's primary action, posting to the real
 *  /api/analyze path. It hands the file to the shell-level job store, which
 *  runs the analysis as a BACKGROUND job and drives the persistent
 *  IngestNotifier — so the upload survives navigating away from the Overview. */
const ACCEPTED_TITLE =
  "Accepted: LOG, TXT, CSV, TSV, JSON, XML, HTML, RAW — anything that reads as plain text. Analyzed locally by the rules engine; results open in Findings. Windows EVTX (.evtx) is ingested into the persistent store and appears on the History page (experimental).";

/** Two-mode ingest dialog: a local file OR a pasted public URL. Both feed the
 *  same background job store + IngestNotifier — the source is the only
 *  difference. URL validity/safety is enforced by the backend (honest error in
 *  the notifier); here we only sanity-check the shape before submitting. */
function UploadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const startUpload = useJobs((s) => s.startUpload);
  const startUrl = useJobs((s) => s.startUrl);
  const startEvtx = useJobs((s) => s.startEvtx);
  const [mode, setMode] = useState<"file" | "link">("file");

  // Split a selection: .evtx files ingest into the store (History), everything
  // else runs the analyzer. Each path drives the same honest notifier.
  const routeFiles = (files: FileList) => {
    const all = Array.from(files);
    const evtx = all.filter((f) => f.name.toLowerCase().endsWith(".evtx"));
    const rest = all.filter((f) => !f.name.toLowerCase().endsWith(".evtx"));
    if (rest.length) startUpload(rest);
    if (evtx.length) startEvtx(evtx);
  };
  const [url, setUrl] = useState("");

  // A repo "blob" URL is a web page, not the file — convert it to the raw URL
  // so the fetch gets the log instead of 500 lines of HTML.
  const isBlob = isBlobPageUrl(url);

  const submitUrl = () => {
    const u = rawFileUrl(url);
    if (!u.trim()) return;
    startUrl(u);         // the notifier takes over; a bad URL is an honest error
    setUrl("");
    onClose();
  };

  const seg = (active: boolean) => cn(
    "flex-1 rounded-md px-3 py-1.5 text-[12.5px] font-medium",
    active ? "bg-card shadow-card" : "text-muted-foreground hover:text-foreground",
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
            className="flex cursor-pointer flex-col items-center gap-1 rounded-lg border border-dashed px-4 py-6 text-center text-[12.5px] text-muted-foreground hover:border-primary"
          >
            <Upload className="h-5 w-5" strokeWidth={1.6} aria-hidden />
            <span className="text-[13px] font-semibold text-foreground">Choose a log file</span>
            Analyzed locally — the file never leaves this machine.
            <input
              type="file" multiple className="hidden" data-testid="ingest-file"
              aria-label="Upload logs"
              onChange={(e) => {
                if (e.target.files?.length) { routeFiles(e.target.files); onClose(); }
                e.target.value = "";
              }}
            />
          </label>
          <p className="text-[11px] text-muted-foreground">{ACCEPTED_TITLE}</p>
        </div>
      ) : (
        <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); submitUrl(); }}>
          <label className="text-[11.5px] text-muted-foreground">
            Public URL of a raw log file
            <input
              className="mt-1 w-full rounded-md border bg-card px-2.5 py-2 text-[13px] outline-none focus:border-primary"
              value={url} onChange={(e) => setUrl(e.target.value)}
              aria-label="Log file URL" placeholder="https://raw.githubusercontent.com/…/app.log"
              inputMode="url" autoComplete="off"
            />
          </label>
          {isBlob && (
            <p className="text-[11px]" style={{ color: "var(--sev-medium)" }}>
              That’s a web-page link, not the raw file — we’ll fetch the raw
              version instead: <span className="break-all font-mono">{rawFileUrl(url)}</span>
            </p>
          )}
          <p className="text-[11px] text-muted-foreground">
            The server fetches it (http/https only, public hosts, size- and
            text-gated) and runs the same analysis. A page that isn’t a text log
            is rejected honestly.
          </p>
          <div>
            <button type="submit" disabled={!url.trim()}
              className="inline-flex items-center gap-2 rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-60">
              <LinkIcon className="h-4 w-4" strokeWidth={1.8} aria-hidden /> Fetch &amp; analyze
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function UploadButton() {
  const busy = useJobs((s) => s.busy);
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title={ACCEPTED_TITLE}
        className={cn(
          "inline-flex cursor-pointer items-center gap-2 whitespace-nowrap rounded-[10px] border border-primary bg-primary px-[15px] py-2.5 text-[13.5px] font-semibold text-primary-foreground hover:opacity-90",
          busy && "cursor-progress opacity-70",
        )}
      >
        <Upload className="h-4 w-4" strokeWidth={1.8} aria-hidden />
        {busy ? "Analyzing…" : "Upload Logs"}
      </button>
      <UploadDialog open={open} onClose={() => setOpen(false)} />
    </>
  );
}

const chip = "inline-flex items-center gap-[9px] whitespace-nowrap rounded-[10px] border bg-card px-3.5 py-2.5 text-[13.5px]";

function Header() {
  const { pathname } = useLocation();
  const queryClient = useQueryClient();

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div>
        <h1 className="text-[26px] font-bold leading-tight tracking-[-0.015em]">
          {TITLES[pathname] ?? "itsoc"}
        </h1>
        <div className="mt-px text-sm font-medium text-accent-foreground">Security Overview</div>
      </div>
      <div className="ml-auto flex flex-wrap items-center gap-2.5">
        <UploadButton />
        <RunDropdown />
        <RunHistory />
        <button className={cn(chip, "cursor-pointer hover:bg-background")}
                onClick={() => queryClient.invalidateQueries()}>
          <RefreshCw className="h-4 w-4" strokeWidth={1.8} aria-hidden />
          Refresh
        </button>
        <button disabled title="Filtering is not built yet — finding filters live on the Findings page"
                className={cn(chip, "cursor-not-allowed opacity-50")}>
          <Filter className="h-4 w-4" strokeWidth={1.8} aria-hidden />
          Filters
        </button>
        <ThemeToggle />
      </div>
    </div>
  );
}

/** The run-facts line under the Overview header — every segment is read from
 *  the adapter state or the overview payload; absent facts are omitted, never
 *  filled in. Overview-only: Findings carries its own scope banner. */
function RunFacts() {
  const { data: state } = useQuery({ queryKey: ["consoleState"], queryFn: api.consoleState });
  const { data: ov } = useQuery({ queryKey: ["overview"], queryFn: api.overview });

  if (!state || state.idle || !state.findings) return null;
  const sha = state.manifest?.detector_sha256;
  const model = ov && !("error" in ov) ? ov.model : null;
  const meta = [
    state.runWindow, state.manifest?.ruleset && `ruleset ${state.manifest.ruleset}`,
    model, state.generatedAt && `generated ${state.generatedAt}`,
  ].filter(Boolean);

  return (
    <div className="flex flex-wrap items-center gap-x-[18px] gap-y-1.5 text-[11.5px] text-muted-foreground">
      {state.sourceLabel && (
        <span title={state.sourceLabel}
              className="cursor-help border-b border-dotted font-mono text-[12.5px] font-semibold text-foreground">
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
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex min-w-0 flex-1 flex-col gap-4 px-[22px] py-5">
        <Header />
        {pathname === "/" && <RunFacts />}
        <Outlet />
      </main>
      {/* Shell-level: the upload runs as a background job and its notification
          persists across navigation, independent of any page. */}
      <IngestNotifier />
    </div>
  );
}
