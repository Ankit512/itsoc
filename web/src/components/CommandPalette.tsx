import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  House, Bell, TriangleAlert, Antenna, Settings, FileText,
  Shield, ShieldCheck, Monitor, Database, Radar, Cable,
  Sun, Moon, Upload, RefreshCw, Sparkles, LogOut, CornerDownLeft, Search
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useUi } from "@/store/ui";
import { cn } from "@/lib/utils";

interface CommandItem {
  id: string;
  label: string;
  group: "Navigation" | "Actions" | "Ask";
  icon: typeof House;
  shortcut?: string;
  onSelect: () => void;
  keywords?: string[];
}

/** dc §command-menu group headings — Screens / Actions / Ask itsoc. */
const GROUP_LABEL: Record<CommandItem["group"], string> = {
  Navigation: "Screens",
  Actions: "Actions",
  Ask: "Ask itsoc",
};

export function CommandPalette({ onUploadClick }: { onUploadClick?: () => void }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const {
    commandPaletteOpen,
    setCommandPaletteOpen,
    theme,
    toggleTheme,
    experimentalEnabled,
    toggleExperimental
  } = useUi();
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  // Global ⌘K / Ctrl+K keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandPaletteOpen(!commandPaletteOpen);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [commandPaletteOpen, setCommandPaletteOpen]);

  useEffect(() => {
    if (commandPaletteOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [commandPaletteOpen]);

  const close = () => setCommandPaletteOpen(false);

  const go = (path: string) => {
    close();
    navigate(path);
  };

  /** Canonical 12-screen roster + Logout. Every old screen name aliases to its new home:
   *  - Cases -> Incidents (/incidents)
   *  - Threat Intel / Enrichment -> Intel (/intel)
   *  - Discovery / Vulnerabilities -> Network (/network)
   *  - Collectors -> Sources (/sources)
   */
  const navItems: CommandItem[] = [
    { id: "nav-overview", label: "Overview", group: "Navigation", icon: House, onSelect: () => go("/"), keywords: ["overview", "home", "dashboard"] },
    { id: "nav-findings", label: "Findings", group: "Navigation", icon: Bell, onSelect: () => go("/alerts"), keywords: ["findings", "alerts", "events"] },
    { id: "nav-incidents", label: "Incidents", group: "Navigation", icon: TriangleAlert, onSelect: () => go("/incidents"), keywords: ["incidents", "rca", "incident", "investigate", "cases", "case", "tracking", "ticket", "workflow"] },
    { id: "nav-approvals", label: "Approvals", group: "Navigation", icon: ShieldCheck, onSelect: () => go("/approvals"), keywords: ["approvals", "approval", "gated", "response", "actions"] },
    { id: "nav-intel", label: "Intel", group: "Navigation", icon: Shield, onSelect: () => go("/intel"), keywords: ["intel", "threat intel", "threat-intel", "enrichment", "feeds", "taxii", "stix", "otx", "abuseipdb", "mitre", "attack", "ioc"] },
    { id: "nav-network", label: "Network", group: "Navigation", icon: Radar, onSelect: () => go("/network"), keywords: ["network", "discovery", "vulnerabilities", "nmap", "scan", "cve", "ports", "vuln"] },
    { id: "nav-assets", label: "Assets", group: "Navigation", icon: Monitor, onSelect: () => go("/assets"), keywords: ["assets", "hosts", "users", "inventory", "assets/users"] },
    { id: "nav-sources", label: "Sources", group: "Navigation", icon: Antenna, onSelect: () => go("/sources"), keywords: ["sources", "collectors", "syslog", "ingest", "listener"] },
    { id: "nav-history", label: "History", group: "Navigation", icon: Database, onSelect: () => go("/history"), keywords: ["history", "sqlite", "evtx", "retention", "store", "events"] },
    { id: "nav-reports", label: "Reports", group: "Navigation", icon: FileText, onSelect: () => go("/reports"), keywords: ["reports", "export", "pdf", "markdown", "dora"] },
    { id: "nav-settings", label: "Settings", group: "Navigation", icon: Settings, onSelect: () => go("/settings"), keywords: ["settings", "config", "model", "compute", "preferences"] },
    { id: "nav-oem", label: "OEM Engine", group: "Navigation", icon: Cable, onSelect: () => go("/oem"), keywords: ["oem", "oem engine", "connectors", "cisco", "api", "integration"] },
    { id: "nav-logout", label: "Logout", group: "Navigation", icon: LogOut, onSelect: () => go("/logout"), keywords: ["logout", "sign out", "clear", "session", "reset"] },
  ];

  const actionItems: CommandItem[] = [
    {
      id: "act-theme",
      label: theme === "dark" ? "Switch to Light Theme" : "Switch to Dark Theme",
      group: "Actions",
      icon: theme === "dark" ? Sun : Moon,
      onSelect: () => { toggleTheme(); close(); },
      keywords: ["theme", "mode", "color", "dark", "light"]
    },
    {
      id: "act-refresh",
      label: "Refresh Dashboard Queries",
      group: "Actions",
      icon: RefreshCw,
      onSelect: () => { queryClient.invalidateQueries(); close(); },
      keywords: ["reload", "refresh", "invalidate"]
    },
    {
      id: "act-upload",
      label: "Upload Logs / Add Source",
      group: "Actions",
      icon: Upload,
      onSelect: () => { close(); onUploadClick?.(); },
      keywords: ["ingest", "file", "url", "upload"]
    },
    {
      id: "act-exp",
      label: experimentalEnabled ? "Disable Experimental Features" : "Enable Experimental Features",
      group: "Actions",
      icon: Sparkles,
      onSelect: () => { toggleExperimental(); close(); },
      keywords: ["experimental", "command center", "flag", "features"]
    },
  ];

  const allItems = [...navItems, ...actionItems];

  const trimmed = query.trim().toLowerCase();
  const filtered = trimmed
    ? allItems.filter((item) =>
        item.label.toLowerCase().includes(trimmed) ||
        item.keywords?.some((k) => k.toLowerCase().includes(trimmed))
      )
    : allItems;

  const askItem: CommandItem | null = trimmed.length > 1 ? {
    id: "ask-ai",
    label: `Ask itsoc: "${query.trim()}"`,
    group: "Ask",
    icon: Sparkles,
    onSelect: () => {
      close();
      navigate(`/?q=${encodeURIComponent(query.trim())}`);
    },
  } : null;

  const displayItems = askItem ? [askItem, ...filtered] : filtered;

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((i) => (i + 1) % Math.max(1, displayItems.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((i) => (i - 1 + displayItems.length) % Math.max(1, displayItems.length));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (displayItems[selectedIndex]) {
        displayItems[selectedIndex].onSelect();
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      close();
    }
  };

  if (!commandPaletteOpen) return null;

  return (
    <div
      className="is-palette-overlay itsoc"
      onMouseDown={(e) => { if (e.target === e.currentTarget) close(); }}
    >
      <div role="dialog" aria-modal="true" aria-label="Command Palette" className="is-palette">
        <div className="is-palette__in">
          <Search className="ic h-4 w-4 flex-none" aria-hidden />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search screens, actions, or ask itsoc..."
            aria-label="Search command palette"
          />
          <kbd>ESC</kbd>
        </div>

        <ul ref={listRef} aria-label="Command options" className="is-palette__list">
          {displayItems.length === 0 ? (
            <li className="px-3 py-6 text-center text-xs is-mut">
              No results found for &ldquo;{query}&rdquo;
            </li>
          ) : (
            displayItems.map((item, idx) => {
              const Icon = item.icon;
              const isSelected = idx === selectedIndex;
              const newGroup = idx === 0 || displayItems[idx - 1].group !== item.group;
              return (
                <li key={item.id}>
                  {newGroup && (
                    <div className="is-palette__group" aria-hidden>{GROUP_LABEL[item.group]}</div>
                  )}
                  <button
                    onClick={item.onSelect}
                    onMouseEnter={() => setSelectedIndex(idx)}
                    className={cn("is-palette__item w-full", isSelected && "active")}
                  >
                    <Icon className="ic h-4 w-4 flex-none" strokeWidth={1.8} aria-hidden />
                    <span className="flex-1 truncate">{item.label}</span>
                    {item.group === "Ask" && (
                      <span className="is-chip is-chip--adv">
                        Ask AI <Sparkles className="h-3 w-3" />
                      </span>
                    )}
                    {isSelected && (
                      <CornerDownLeft className="enter h-3.5 w-3.5" aria-hidden />
                    )}
                  </button>
                </li>
              );
            })
          )}
        </ul>

        <div className="is-palette__foot">
          <span>↑↓ navigate · ↵ select · esc close</span>
          <span className="is-mono">itsoc. command palette</span>
        </div>
      </div>
    </div>
  );
}
