import type { AuditEntry, AuditVerification } from "@/lib/api";

export interface AuditTimelineProps {
  entries?: AuditEntry[];
  verification?: AuditVerification | null;
  incidentId?: string;
  className?: string;
  isLoading?: boolean;
}

/**
 * Helper to render the status chip for an audit entry.
 * INVARIANT: Severity palette (--crit #f26d78) is used for `failed` ONLY.
 * `approved` is neutral outline, `rejected` is muted, `executed` is accent.
 * No alarm or green colors on non-failed statuses.
 */
function renderStatusChip(status: string) {
  switch (status) {
    case "approved":
      return (
        <span className="is-chip is-chip--approved" data-testid="chip-approved">
          approved
        </span>
      );
    case "rejected":
      return (
        <span className="is-chip is-chip--rejected" data-testid="chip-rejected">
          rejected
        </span>
      );
    case "executed":
      return (
        <span className="is-chip is-chip--executed" data-testid="chip-executed">
          executed
        </span>
      );
    case "failed":
      return (
        <span className="is-chip is-chip--failed" data-testid="chip-failed">
          failed
        </span>
      );
    default:
      return <span className="is-chip">{status}</span>;
  }
}

/**
 * Format an ISO timestamp for display in the audit timeline.
 */
function formatTs(isoStr?: string): string {
  if (!isoStr) return "n/a";
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toISOString().replace("T", " ").replace("Z", " UTC");
  } catch {
    return isoStr;
  }
}

/**
 * is-audit-timeline — Vertical hash-chain audit view (Stage C / C4-T2).
 *
 * Guaranteed Honesty Properties:
 * 1. Broken state: Renders a loud `CHAIN BROKEN` banner with verbatim diagnostic
 *    index, reason, expected hash, and found hash from verify_chain().
 * 2. Verified state: Renders "chain verified ✓" with entry count and head hash.
 * 3. Empty state: An empty ledger honestly renders as empty (never verified).
 * 4. Palette isolation: Critical palette used strictly on `failed` entries.
 * 5. No stagger: Entries appear without transition delays or staggered animations.
 */
export function AuditTimeline({
  entries = [],
  verification,
  incidentId,
  className = "",
  isLoading = false,
}: AuditTimelineProps) {
  if (isLoading) {
    return (
      <div className={`is-audit-timeline ${className}`} data-testid="audit-timeline-loading">
        <div className="is-note is-mut">Loading audit ledger…</div>
      </div>
    );
  }

  const visibleEntries = incidentId
    ? entries.filter((e) => e.incident_id === incidentId)
    : entries;

  const isBroken = Boolean(verification && !verification.ok && verification.break);
  const isClean = Boolean(verification && verification.ok && verification.count > 0);
  const isEmpty = visibleEntries.length === 0 && (!verification || verification.count === 0);

  return (
    <div className={`is-audit-timeline ${className}`} data-testid="is-audit-timeline">
      {/* 1. Loud CHAIN BROKEN banner when verification fails */}
      {isBroken && verification?.break && (
        <div className="is-audit-broken" data-testid="audit-chain-broken-banner" role="alert">
          <div className="is-audit-broken__h">
            <span aria-hidden="true">⚠️</span>
            <span>CHAIN BROKEN at entry #{verification.break.index}</span>
          </div>
          <div className="is-audit-broken__reason">{verification.break.reason}</div>
          {(verification.break.expected != null || verification.break.found != null) && (
            <div className="is-audit-broken__hashes is-mono">
              {verification.break.expected != null && (
                <div>
                  Expected hash: <code>{verification.break.expected}</code>
                </div>
              )}
              {verification.break.found != null && (
                <div>
                  Found hash: <code>{verification.break.found}</code>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 2. Empty state: must read as empty rather than verified */}
      {isEmpty ? (
        <div className="is-audit-empty" data-testid="audit-chain-empty">
          No audit entries recorded yet
        </div>
      ) : (
        /* 3. Vertical timeline entries (no stagger) */
        <div className="is-audit-chain" data-testid="audit-entries-list">
          {visibleEntries.map((entry, idx) => {
            const isEntryBroken =
              isBroken && verification?.break?.index === idx;

            return (
              <div
                key={`${entry.entry_hash || idx}-${idx}`}
                className={`is-audit-entry ${isEntryBroken ? "is-audit-entry--broken" : ""}`}
                data-testid={`audit-entry-${idx}`}
              >
                <div className="is-audit-entry__h">
                  <div className="is-audit-entry__meta">
                    <span className="is-audit-entry__ts is-mono">{formatTs(entry.ts)}</span>
                    {renderStatusChip(entry.status)}
                    <span className="is-audit-entry__actor" title="Verified actor identity">
                      @{entry.actor}
                    </span>
                    <span className="is-audit-entry__step">{entry.step}</span>
                  </div>

                  <div className="is-audit-entry__hashes is-mono">
                    {entry.runbook_id && (
                      <span className="is-audit-entry__runbook" title="Runbook ID">
                        {entry.runbook_id}
                      </span>
                    )}
                    {entry.incident_id && (
                      <span className="is-audit-entry__incident" title="Incident ID">
                        {entry.incident_id}
                      </span>
                    )}
                    <span title={`Previous entry hash: ${entry.prev_hash}`}>
                      prev: <code>{entry.prev_hash ? entry.prev_hash.slice(0, 8) : "00000000"}…</code>
                    </span>
                    <span title={`Entry SHA256 hash: ${entry.entry_hash}`}>
                      hash: <code>{entry.entry_hash ? entry.entry_hash.slice(0, 8) : "none"}…</code>
                    </span>
                  </div>
                </div>

                {/* Evidence / request payload preview (redacted) */}
                {(entry.request_redacted || entry.response_verbatim) && (
                  <div className="is-audit-entry__body">
                    {entry.request_redacted && (
                      <div>
                        <div className="is-mut is-mono" style={{ fontSize: "10.5px", marginBottom: "3px" }}>
                          Command Preview (redacted):
                        </div>
                        <pre className="is-evidence">{entry.request_redacted}</pre>
                      </div>
                    )}
                    {entry.response_verbatim && (
                      <div>
                        <div className="is-mut is-mono" style={{ fontSize: "10.5px", marginBottom: "3px" }}>
                          Execution Response (verbatim):
                        </div>
                        <pre className="is-evidence">{entry.response_verbatim}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* 4. Subtle footer when chain is intact and verified */}
      {isClean && verification && (
        <div className="is-audit-foot" data-testid="audit-chain-verified">
          <span className="check" aria-hidden="true">✓</span>
          <span>
            chain verified · {verification.count} {verification.count === 1 ? "entry" : "entries"}
            {verification.head ? ` · head ${verification.head.slice(0, 8)}…` : ""}
          </span>
        </div>
      )}
    </div>
  );
}

export default AuditTimeline;
