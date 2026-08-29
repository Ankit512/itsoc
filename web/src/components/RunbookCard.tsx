import { cn } from "@/lib/utils";

/** One runbook surfaced against an incident. Rule-owned throughout: `eligible`
 *  and `missing` come verbatim from the rules engine (runbooks.eligible()); this
 *  component renders them and never recomputes a verdict. `triggerRules` are the
 *  runbook's own trigger.rule_ids. */
export interface RunbookCardData {
  runbookId: string;
  name?: string | null;
  severityFloor?: string | null;
  /** The runbook's trigger.rule_ids — rule-owned; rendered as chips. */
  triggerRules?: string[];
  eligible: boolean;
  /** The engine's `missing` array, rendered VERBATIM when ineligible. */
  missing?: string[];
}

/** is-runbook-card (C4-F1). A runbook's name, the rule ids that can trigger it,
 *  and a rule-owned eligibility badge.
 *
 *  INELIGIBILITY IS INFORMATION, NOT ALARM: the ineligible badge is MUTED and
 *  never borrows the crit/severity palette — an ineligible runbook is a normal
 *  state, not a failure. The missing-evidence list is the engine's `missing`
 *  array verbatim, never reworded (same discipline as the 409 create path).
 *
 *  The card carries NO approve control and NO request control — requesting an
 *  approval is a single action owned by the Response panel, and approving
 *  happens only in the Approvals screen. */
export function RunbookCard({
  rb,
  selected,
  onSelect,
  testid,
}: {
  rb: RunbookCardData;
  selected?: boolean;
  onSelect?: () => void;
  testid?: string;
}) {
  const rules = rb.triggerRules ?? [];
  const missing = rb.missing ?? [];
  return (
    <div
      className={cn("is-runbook-card", selected && "is-selected", !rb.eligible && "is-ineligible")}
      data-testid={testid ?? "runbook-card"}
      data-runbook-id={rb.runbookId}
      data-eligible={rb.eligible ? "true" : "false"}
      role={onSelect ? "button" : undefined}
      tabIndex={onSelect ? 0 : undefined}
      aria-pressed={onSelect ? Boolean(selected) : undefined}
      onClick={onSelect}
      onKeyDown={onSelect ? (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(); }
      } : undefined}
    >
      <div className="is-runbook-card__h">
        <span className="is-runbook-card__name">{rb.name || rb.runbookId}</span>
        {/* Eligibility badge — rule-owned. Eligible = low-accent outline;
            ineligible = MUTED, never a severity colour (invariant 1). */}
        {rb.eligible ? (
          <span className="is-rb-badge is-rb-badge--eligible" data-testid="rb-badge-eligible">
            ELIGIBLE
          </span>
        ) : (
          <span className="is-rb-badge is-rb-badge--ineligible" data-testid="rb-badge-ineligible">
            INELIGIBLE
          </span>
        )}
      </div>

      <div className="is-runbook-card__meta is-mono is-mut">
        {rb.runbookId}
        {rb.severityFloor ? ` · floor ${rb.severityFloor}` : ""}
      </div>

      {rules.length > 0 && (
        <div className="is-runbook-card__rules" data-testid="rb-trigger-rules">
          {rules.map((r) => (
            <span key={r} className="is-rb-rule is-mono">{r}</span>
          ))}
        </div>
      )}

      {!rb.eligible && missing.length > 0 && (
        <div className="is-runbook-card__missing" data-testid="rb-missing">
          <span className="is-rb-missing__lbl">missing:</span>
          <ul className="is-rb-missing__list">
            {missing.map((m, i) => (
              // Verbatim from the engine's `missing` array (invariant 2).
              <li key={i} className="is-rb-missing__item is-mono">{m}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
