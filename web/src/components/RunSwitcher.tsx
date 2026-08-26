import { useState, useRef, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Calendar, Search, Check, FileText } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface RunItem {
  file: string;
  runId: string;
  label?: string;
  generatedAt?: string;
  findings?: number;
  unrecognized?: boolean;
  compareRun?: boolean;
}

export function RunSwitcher() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [switching, setSwitching] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const { data: runs } = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const { data: summary } = useQuery({ queryKey: ["runs-summary"], queryFn: api.runsSummary, enabled: open });

  const list: RunItem[] = runs?.runs ?? [];
  const currentRunId = runs?.current;
  const currentRun = list.find((r) => r.runId === currentRunId || r.file === currentRunId) ?? list[0];
  const currentFile = currentRun?.file ?? "";

  useEffect(() => {
    if (open) {
      setTimeout(() => searchInputRef.current?.focus(), 50);
    }
  }, [open]);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  const selectRun = async (file: string) => {
    if (!file || file === currentFile) {
      setOpen(false);
      return;
    }
    setSwitching(file);
    try {
      const out = await api.openRun(file);
      if (out.ok) {
        await queryClient.invalidateQueries();
      }
    } catch {
      // keep quiet or handle error
    } finally {
      setSwitching(null);
      setOpen(false);
    }
  };

  if (list.length === 0) {
    return (
      <span
        className="inline-flex items-center gap-[9px] whitespace-nowrap rounded-[10px] border bg-card px-3.5 py-2 text-[13px] text-muted-foreground"
        title="No saved runs yet — analyze a log to start the history"
      >
        <Calendar className="h-4 w-4" strokeWidth={1.8} aria-hidden />
        No runs yet
      </span>
    );
  }

  const currentLabel = currentRun
    ? `${(currentRun.label || currentRun.file).split("/").pop() ?? currentRun.file}${
        currentRun.unrecognized ? " · unparsed" : ""
      }`
    : "Select run";

  const filtered = list.filter((r) => {
    if (!filter.trim()) return true;
    const q = filter.toLowerCase();
    const name = (r.label || r.file).toLowerCase();
    const stamp = (r.generatedAt || "").toLowerCase();
    return name.includes(q) || stamp.includes(q);
  });

  // Group by date relative
  const today = new Date().toISOString().slice(0, 10);
  const groups: { label: string; runs: RunItem[] }[] = [];
  const todayRuns: RunItem[] = [];
  const earlierRuns: RunItem[] = [];

  filtered.forEach((r) => {
    const dateStr = (r.generatedAt || "").slice(0, 10);
    if (dateStr === today) {
      todayRuns.push(r);
    } else {
      earlierRuns.push(r);
    }
  });

  if (todayRuns.length > 0) groups.push({ label: "Today", runs: todayRuns });
  if (earlierRuns.length > 0) groups.push({ label: "Previous Runs", runs: earlierRuns });
  if (groups.length === 0 && filtered.length > 0) groups.push({ label: "All Runs", runs: filtered });

  // Summary map for rich counts
  const summaryMap = new Map(summary?.runs?.map((s) => [s.file, s]) ?? []);

  return (
    <div className="relative inline-block" ref={dropdownRef}>
      {/* Hidden native select for accessibility and standard test runners */}
      <select
        aria-label="Select run"
        value={currentFile}
        disabled={switching !== null}
        onChange={(e) => selectRun(e.target.value)}
        className="sr-only"
        tabIndex={-1}
      >
        {list.map((r) => {
          const name = (r.label || r.file).split("/").pop() ?? r.file;
          const when = (r.generatedAt || "").slice(0, 16).replace("T", " ");
          const optLabel = `${name}${when ? ` · ${when}` : ""}${r.unrecognized ? " · unparsed" : ""}`;
          return (
            <option key={r.file} value={r.file}>
              {optLabel}
            </option>
          );
        })}
      </select>

      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label="Switch run"
        className={cn(
          "inline-flex cursor-pointer items-center gap-2 whitespace-nowrap rounded-[10px] border border-border bg-card px-3 py-2 text-[13px] font-medium text-foreground transition-colors hover:border-primary",
          open && "border-primary ring-1 ring-primary/30",
          switching && "opacity-60 cursor-progress"
        )}
      >
        <Calendar className="h-4 w-4 text-muted-foreground flex-none" strokeWidth={1.8} aria-hidden />
        <span className="max-w-[180px] truncate font-mono">{currentLabel}</span>
        <ChevronDown className="h-3.5 w-3.5 text-muted-foreground ml-0.5" strokeWidth={2} />
      </button>

      {open && (
        <div
          role="region"
          aria-label="Run switcher panel"
          className="absolute right-0 top-full z-50 mt-2 w-[340px] max-w-[calc(100vw-32px)] rounded-xl border border-border bg-card p-2 shadow-[0_16px_40px_-10px_rgba(0,0,0,0.35)] animate-in fade-in zoom-in-95 duration-100"
        >
          <div className="flex items-center gap-2 border-b border-border px-2.5 pb-2 pt-1">
            <Search className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            <input
              ref={searchInputRef}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Search runs..."
              aria-label="Filter runs"
              className="flex-1 bg-transparent text-[12.5px] outline-none placeholder:text-muted-foreground"
            />
            {filter && (
              <button
                onClick={() => setFilter("")}
                className="text-[11px] text-muted-foreground hover:text-foreground"
              >
                Clear
              </button>
            )}
          </div>

          <div className="max-h-[280px] overflow-y-auto pt-1">
            {groups.length === 0 ? (
              <div className="py-4 text-center text-xs text-muted-foreground">
                No matching runs found
              </div>
            ) : (
              groups.map((group) => (
                <div key={group.label} className="mb-1.5 last:mb-0">
                  <div className="px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">
                    {group.label}
                  </div>
                  <div className="flex flex-col gap-0.5">
                    {group.runs.map((r) => {
                      const isCurrent = r.file === currentFile;
                      const sInfo = summaryMap.get(r.file);
                      const fCount = sInfo?.findingCount ?? r.findings ?? 0;
                      const name = (r.label || r.file).split("/").pop() ?? r.file;
                      const when = (r.generatedAt || "").slice(0, 16).replace("T", " ");

                      return (
                        <button
                          key={r.file}
                          onClick={() => selectRun(r.file)}
                          disabled={switching !== null}
                          className={cn(
                            "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[12.5px] transition-colors",
                            isCurrent
                              ? "bg-accent font-medium text-accent-foreground"
                              : "hover:bg-muted/60 text-foreground"
                          )}
                        >
                          <FileText className="h-3.5 w-3.5 flex-none text-muted-foreground" />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5">
                              <span className="truncate font-mono font-medium">{name}</span>
                              {isCurrent && (
                                <span className="rounded bg-primary/15 px-1 py-0.2 text-[9px] font-semibold uppercase tracking-wider text-primary">
                                  current
                                </span>
                              )}
                              {r.unrecognized && (
                                <span className="rounded border border-border px-1 py-0.2 text-[9px] uppercase tracking-wider text-muted-foreground">
                                  unparsed
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                              <span>{when || "No date"}</span>
                              <span>·</span>
                              <span className="tabular-nums font-medium">{fCount} findings</span>
                            </div>
                          </div>
                          {isCurrent && (
                            <Check className="h-4 w-4 flex-none text-primary" strokeWidth={2.5} />
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
