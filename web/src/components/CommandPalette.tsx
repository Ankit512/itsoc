import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  House, Bell, TriangleAlert, Antenna, Settings, FileText, Folder,
  Shield, Monitor, Database, Radar, ShieldAlert, Search, Cable,
  Sun, Moon, Upload, RefreshCw, Sparkles, LogOut, CornerDownLeft
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

  const navItems: CommandItem[] = [
    { id: "nav-overview", label: "Overview", group: "Navigation", icon: House, onSelect: () => go("/"), keywords: ["home", "dashboard"] },
    { id: "nav-findings", label: "Findings", group: "Navigation", icon: Bell, onSelect: () => go("/alerts"), keywords: ["alerts", "findings", "events"] },
    { id: "nav-incidents", label: "Incidents", group: "Navigation", icon: TriangleAlert, onSelect: () => go("/incidents"), keywords: ["rca", "incident", "investigate"] },
    { id: "nav-sources", label: "Sources & Collectors", group: "Navigation", icon: Antenna, onSelect: () => go("/collectors"), keywords: ["syslog", "collectors", "ingest"] },
    { id: "nav-settings", label: "Settings", group: "Navigation", icon: Settings, onSelect: () => go("/settings"), keywords: ["config", "model", "compute"] },
    { id: "nav-threat-intel", label: "Threat Intel", group: "Navigation", icon: Shield, onSelect: () => go("/threat-intel"), keywords: ["mitre", "attack", "ioc"] },
    { id: "nav-assets", label: "Assets", group: "Navigation", icon: Monitor, onSelect: () => go("/assets"), keywords: ["hosts", "users", "inventory"] },
    { id: "nav-reports", label: "Reports", group: "Navigation", icon: FileText, onSelect: () => go("/reports"), keywords: ["export", "pdf", "markdown"] },
    { id: "nav-cases", label: "Cases", group: "Navigation", icon: Folder, onSelect: () => go("/cases"), keywords: ["tracking", "ticket", "workflow"] },
    { id: "nav-history", label: "History (EVTX Store)", group: "Navigation", icon: Database, onSelect: () => go("/history"), keywords: ["sqlite", "evtx", "retention"] },
    { id: "nav-discovery", label: "Discovery (Nmap)", group: "Navigation", icon: Radar, onSelect: () => go("/discovery"), keywords: ["network", "scan", "hosts"] },
    { id: "nav-vulnerabilities", label: "Vulnerabilities", group: "Navigation", icon: ShieldAlert, onSelect: () => go("/vulnerabilities"), keywords: ["vuln", "cve", "ports"] },
    { id: "nav-enrichment", label: "Enrichment (OTX/AbuseIPDB)", group: "Navigation", icon: Search, onSelect: () => go("/enrichment"), keywords: ["threat intel", "ip", "reputation"] },
    { id: "nav-oem", label: "OEM Engine", group: "Navigation", icon: Cable, onSelect: () => go("/oem"), keywords: ["connectors", "cisco", "api"] },
    { id: "nav-logout", label: "Logout (Honest Reset)", group: "Navigation", icon: LogOut, onSelect: () => go("/logout"), keywords: ["sign out", "clear"] },
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
      className="fixed inset-0 z-[70] flex items-start justify-center bg-black/60 p-4 pt-[14vh] backdrop-blur-[2px]"
      onMouseDown={(e) => { if (e.target === e.currentTarget) close(); }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command Palette"
        className="w-full max-w-[560px] overflow-hidden rounded-xl border border-border bg-card shadow-[0_20px_60px_-15px_rgba(0,0,0,0.5)] outline-none animate-in fade-in zoom-in-95 duration-100"
      >
        <div className="flex items-center gap-2.5 border-b border-border px-3.5 py-3">
          <Search className="h-4 w-4 flex-none text-muted-foreground" aria-hidden />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search screens, actions, or ask itsoc..."
            aria-label="Search command palette"
            className="flex-1 bg-transparent text-[14px] text-foreground outline-none placeholder:text-muted-foreground"
          />
          <kbd className="flex h-5 items-center gap-0.5 rounded border border-border bg-muted px-1.5 font-mono text-[10px] text-muted-foreground">
            ESC
          </kbd>
        </div>

        <ul
          ref={listRef}
          aria-label="Command options"
          className="max-h-[340px] overflow-y-auto p-1.5"
        >
          {displayItems.length === 0 ? (
            <li className="px-3 py-6 text-center text-xs text-muted-foreground">
              No results found for &ldquo;{query}&rdquo;
            </li>
          ) : (
            displayItems.map((item, idx) => {
              const Icon = item.icon;
              const isSelected = idx === selectedIndex;
              return (
                <li key={item.id}>
                  <button
                    onClick={item.onSelect}
                    onMouseEnter={() => setSelectedIndex(idx)}
                    className={cn(
                      "flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-[13px] transition-colors",
                      isSelected
                        ? "bg-accent font-medium text-accent-foreground"
                        : "text-foreground hover:bg-muted/50"
                    )}
                  >
                    <Icon
                      className={cn(
                        "h-4 w-4 flex-none",
                        isSelected ? "text-primary" : "text-muted-foreground"
                      )}
                      strokeWidth={1.8}
                      aria-hidden
                    />
                    <span className="flex-1 truncate">{item.label}</span>
                    {item.group === "Ask" && (
                      <span className="flex items-center gap-1 rounded bg-primary/15 px-1.5 py-0.5 text-[10.5px] font-medium text-primary">
                        Ask AI <Sparkles className="h-3 w-3" />
                      </span>
                    )}
                    {isSelected && (
                      <CornerDownLeft className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                    )}
                  </button>
                </li>
              );
            })
          )}
        </ul>

        <div className="flex items-center justify-between border-t border-border bg-muted/30 px-3.5 py-2 text-[11px] text-muted-foreground">
          <div className="flex items-center gap-3">
            <span><kbd className="font-mono">↑↓</kbd> navigate</span>
            <span><kbd className="font-mono">↵</kbd> select</span>
            <span><kbd className="font-mono">esc</kbd> close</span>
          </div>
          <div className="font-mono text-[10px]">
            itsoc. command palette
          </div>
        </div>
      </div>
    </div>
  );
}
