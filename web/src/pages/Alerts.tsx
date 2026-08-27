import { useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import {
  createColumnHelper, flexRender, getCoreRowModel, getFilteredRowModel,
  getSortedRowModel, useReactTable, type Row,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ChevronDown, ChevronUp } from "lucide-react";
import { api, type Finding } from "@/lib/api";
import { useLogStream, type LogStream } from "@/lib/useLogStream";
import { sevVar, SEV_ORDER } from "@/lib/severity";
import { UnrecognizedBanner } from "@/components/UnrecognizedBanner";
import { cn } from "@/lib/utils";

/** Map a rule severity ("CRITICAL"…) to the design-system short token used by
 *  .is-tag--<sev> and .is-block.<sev>. */
function sevShort(sev: string): "crit" | "high" | "med" | "low" {
  const s = (sev || "").toUpperCase();
  if (s.startsWith("CRIT")) return "crit";
  if (s.startsWith("HIGH")) return "high";
  if (s.startsWith("MED")) return "med";
  return "low";
}
function SevTag({ sev }: { sev: string }) {
  return <span className={`is-tag is-tag--${sevShort(sev)}`}>{(sev || "").toUpperCase()}</span>;
}

const col = createColumnHelper<Finding>();

const columns = [
  col.accessor("sev", {
    header: "Sev",
    cell: (c) => <SevTag sev={c.getValue()} />,
    sortingFn: (a, b) =>
      SEV_ORDER.indexOf(b.original.sev as never) - SEV_ORDER.indexOf(a.original.sev as never),
  }),
  col.accessor("time", {
    header: "Time",
    cell: (c) => <span className="col-mono">{c.getValue() || "—"}</span>,
  }),
  col.accessor("type", {
    header: "Rule",
    cell: (c) => <span className="col-mono">{c.getValue()}</span>,
  }),
  col.accessor("host", { header: "Host", cell: (c) => <span className="is-mono">{c.getValue()}</span> }),
  col.accessor((f) => (f.mitre ?? []).map((m) => m.id).join(" "), {
    id: "mitre",
    header: "ATT&CK",
    cell: (c) =>
      c.row.original.mitre?.length
        ? c.row.original.mitre.map((m) => (
            <span key={m.id} className="is-tid" style={{ marginRight: 3 }}
                  title={`${m.id} · ${m.name} · ${m.tactic} — derived, does not affect severity`}>
              {m.id}
            </span>
          ))
        : null,
  }),
  // Title is shown in the detail pane, not the list (prototype §3 columns are
  // Sev/Time/Rule/Host/ATT&CK). Kept as a hidden column so the filter box can
  // still match a finding by its text.
  col.accessor("title", { id: "title", header: "Finding" }),
];

/** Virtualize only past this row count. */
const VIRTUALIZE_AT = 100;

/** Live tail of the current run's log via GET /api/stream (SSE) — augments the
 *  5s polling; a gap marker shows wherever events were dropped under
 *  backpressure. Honest by construction: real lines, verbatim raw. */
function LiveTail({ stream }: { stream: LogStream }) {
  const recent = stream.rows.slice(-200);
  return (
    <div className="is-panel">
      <div className="is-panel__h">
        <h3>Live tail</h3>
        {stream.connected ? (
          <span className="is-panel__sub inline-flex items-center gap-1.5" data-testid="stream-status">
            <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: "var(--low)" }} />
            streaming — lines appear as the log grows
          </span>
        ) : (
          <span className="is-panel__sub" data-testid="stream-status">
            {stream.unsupported ? "streaming unavailable in this browser — " : "stream disconnected — "}
            5s polling fallback active
          </span>
        )}
        {stream.dropped > 0 && (
          <span className="is-runs__unparsed" data-testid="stream-dropped">
            {stream.dropped} event(s) dropped under backpressure
          </span>
        )}
      </div>
      {recent.length === 0 ? (
        <p className="is-panel__sub">
          No new lines yet — the tail starts at the end of the current log and shows only what
          arrives after connecting.
        </p>
      ) : (
        <pre className="is-evidence" style={{ maxHeight: "30vh" }} data-testid="live-tail">
          {recent.map((row, i) =>
            row.kind === "gap" ? (
              <div key={`gap-${i}`} data-testid="gap-row" style={{ color: "var(--high)", fontWeight: 600 }}>
                {row.dropped} event(s) dropped here (stream backpressure) — the log itself is intact;
                a reconnect resumes from the last delivered line
              </div>
            ) : (
              <div key={row.event.n} data-testid="tail-row" className="flex gap-3">
                <span className="ln" style={{ minWidth: 40, textAlign: "right" }}>{row.event.n}</span>
                <span style={{ minWidth: 64 }} className="is-mut">{row.event.ts ? row.event.ts.slice(11, 19) : "n/a"}</span>
                <span style={{ minWidth: 64, color: sevVar(row.event.bucket), fontWeight: 600 }}>{row.event.bucket}</span>
                <span className="flex-1 whitespace-pre-wrap break-all">{row.event.raw}</span>
              </div>
            ))}
        </pre>
      )}
    </div>
  );
}

/** Master-detail right pane (DESIGN_HANDOFF §3). */
function FindingDetail({ f }: { f: Finding }) {
  const s = sevShort(f.sev);
  return (
    <div className="is-md__detail">
      <div className="is-detail-head">
        <SevTag sev={f.sev} />
        <span className="is-mono is-mut">{f.type}</span>
        <span className="id">{f.stamp}</span>
      </div>
      <h2>{f.title}</h2>

      <div className="is-vgrid">
        <div className={`is-block ${s}`}>
          <div className="cap authoritative">Rule verdict · authoritative</div>
          <div className="verdict">{f.ruleSev}</div>
          <p>{f.ruleWhy}</p>
        </div>
        <div className="is-block">
          <div className="cap">Plain-language explanation · advisory</div>
          <p className="is-mut">
            {f.explanation || "Explanation pending — the deterministic verdict above is already final."}
          </p>
        </div>
      </div>

      {f.lines.length > 0 && (
        <div>
          <div className="cap" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--mut)", marginBottom: 6 }}>
            Evidence <span style={{ fontWeight: 400 }}>— {f.linesNote ?? "verbatim from the source log — nothing generated"}</span>
          </div>
          <pre className="is-evidence" data-testid="evidence">
            {f.lines.map((l, i) => (
              <div key={i}>
                <span className="ln">{l.n}</span>
                {l.a}
                {l.hit && <mark>{l.hit}</mark>}
                {l.b}
              </div>
            ))}
          </pre>
        </div>
      )}

      <div className="is-vgrid">
        {f.predicate && (
          <div>
            <div className="cap" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--mut)", marginBottom: 6 }}>
              Rule predicate that fired
            </div>
            <div className="is-predicate">{f.predicate}</div>
            <div className="is-mono is-mut" style={{ marginTop: 6, fontSize: 10 }}>{f.ruleRef}</div>
          </div>
        )}
        {f.timeline.length > 0 && (
          <div>
            <div className="cap" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--mut)", marginBottom: 6 }}>
              Event sequence
            </div>
            {f.timeline.map((t, i) => (
              <div key={i} className="flex gap-2" style={{ fontSize: 12, padding: "2px 0" }}>
                <span className="is-mono is-mut" style={{ minWidth: 56 }}>{t.t}</span>
                <span>{t.label}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function Alerts() {
  const { data, isLoading } = useQuery({
    queryKey: ["console-state"],
    queryFn: api.consoleState,
    refetchInterval: 5000,
  });
  const [params, setParams] = useSearchParams();
  const [filter, setFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("");

  const stream = useLogStream(data && !data.idle ? data.logPath : undefined);

  const allFindings = useMemo(() => {
    const base = data?.findings ?? [];
    const live = stream.findings.filter(
      (f) => !base.some((b) => b.type === f.type && b.title === f.title));
    return [...base, ...live];
  }, [data, stream.findings]);

  const findings = useMemo(
    () => (sevFilter ? allFindings.filter((f) => f.sev === sevFilter) : allFindings),
    [allFindings, sevFilter]);

  const table = useReactTable({
    data: findings,
    columns,
    state: { globalFilter: filter },
    initialState: { columnVisibility: { title: false } },
    onGlobalFilterChange: setFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const rows = table.getRowModel().rows;
  const selId = params.get("sel");
  // Master-detail always shows a detail (prototype selF(0)): the URL selection
  // if present, else the first row in the current (filtered/sorted) view.
  const selected =
    findings.find((f) => f.id === selId) ?? (rows[0]?.original ?? findings[0] ?? null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtual = rows.length > VIRTUALIZE_AT;
  const virtualizer = useVirtualizer({
    count: virtual ? rows.length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 44,
    overscan: 12,
  });

  if (isLoading) return <p className="is-mut">Loading the current run…</p>;

  if (!data || data.idle) {
    return (
      <div className="is-note">
        No run yet — analyze a log from the Overview's ingestion panel (or the legacy console).
        Findings will appear here.
      </div>
    );
  }

  const renderRow = (row: Row<Finding>) => (
    <tr
      key={row.id}
      onClick={() => setParams({ sel: row.original.id })}
      className={cn(selected?.id === row.original.id && "active")}
      data-testid="alert-row"
    >
      {row.getVisibleCells().map((cell) => (
        <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
      ))}
    </tr>
  );

  return (
    <>
      <UnrecognizedBanner state={data} />

      {data.logPath && <LiveTail stream={stream} />}

      {/* Filter row (DESIGN_HANDOFF §3) */}
      <div className="flex flex-wrap items-center gap-2.5">
        <input
          className="is-input"
          style={{ maxWidth: 340 }}
          placeholder="Filter findings…"
          aria-label="Filter findings"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <select
          className="is-select"
          style={{ maxWidth: 160 }}
          aria-label="Severity filter"
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
        >
          <option value="">All severities</option>
          {SEV_ORDER.map((s) => <option key={s}>{s}</option>)}
        </select>
        <span className="is-panel__sub">
          {rows.length} of {allFindings.length} finding(s) · {data.runParsed ?? ""}
        </span>
      </div>

      <div className={cn("is-md", !selected && "!grid-cols-1")}>
        <div className="is-md__list">
          <div ref={scrollRef} className="max-h-[56vh] overflow-auto" data-testid="alerts-scroll">
            <table className="is-table">
              <thead>
                {table.getHeaderGroups().map((hg) => (
                  <tr key={hg.id}>
                    {hg.headers.map((h) => (
                      <th key={h.id} className="cursor-pointer select-none" onClick={h.column.getToggleSortingHandler()}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {{
                          asc: <ChevronUp size={12} className="inline align-middle ml-0.5" aria-hidden />,
                          desc: <ChevronDown size={12} className="inline align-middle ml-0.5" aria-hidden />,
                        }[h.column.getIsSorted() as string] ?? null}
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {virtual ? (
                  <>
                    {virtualizer.getVirtualItems().length > 0 && (
                      <tr style={{ height: virtualizer.getVirtualItems()[0].start }} aria-hidden />
                    )}
                    {virtualizer.getVirtualItems().map((vi) => renderRow(rows[vi.index]))}
                    {virtualizer.getVirtualItems().length > 0 && (
                      <tr aria-hidden style={{
                        height: virtualizer.getTotalSize() - (virtualizer.getVirtualItems().at(-1)!.end),
                      }} />
                    )}
                  </>
                ) : (
                  rows.map(renderRow)
                )}
                {rows.length === 0 && (
                  <tr><td colSpan={table.getVisibleLeafColumns().length} className="is-mut" style={{ textAlign: "center", padding: "24px 12px" }}>
                    {data.findings.length === 0
                      ? (data.unrecognized || data.emptyInput
                         ? "Nothing was analyzed, so there are no findings to show."
                         : "All clear — 0 anomalies. Every rule evaluated; nothing crossed a threshold.")
                      : "Nothing matches this filter."}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {selected && <FindingDetail f={selected} />}
      </div>
    </>
  );
}
