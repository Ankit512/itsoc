import { cn } from "@/lib/utils";
import { runbookPlainCopy } from "@/lib/runbookCopy";

/** One runbook surfaced against an incident. Rule-owned throughout: `eligible`
 *  and `missing` come verbatim from the rules engine (runbooks.eligible()); this
 *  component renders them and never recomputes a verdict. `triggerRules` are the
 *  runbook's own trigger.rule_ids. */
export interface RunbookCardData {
  runbookId: string;
  name?: string | null;
  severityFloor?: string | null;
  /** The runbook's trigger.rule_ids — rule-owned; shown inside the disclosure. */
  triggerRules?: string[];
  eligible: boolean;
  /** The engine's `missing` array, rendered VERBATIM inside the disclosure. */
  missing?: string[];
}

/** is-runbook-card (C4-F1, made legible by F0).
 *
 *  WHO THIS CARD IS FOR: someone who did not build itsoc. By default it answers
 *  five plain questions — What it does, Fires on, Needs, the numbered Steps, and
 *  whether it is Reversible — in words, from `@/lib/runbookCopy`, which is a
 *  transcription of the shipped `console/runbooks/*.yaml` definitions. A runbook
 *  id that module does not describe gets an honest bounded fallback that says
 *  so; steps are never guessed and never padded out.
 *
 *  SCHEMA VOCABULARY IS NOT ON THE DEFAULT CARD. The severity floor, the raw
 *  trigger rule ids, the runbook id and the engine's eligibility machinery are
 *  all real and all still here — they live inside a CLOSED <details> disclosure,
 *  one click away, so the default surface reads as English.
 *
 *  INELIGIBILITY IS INFORMATION, NOT ALARM: the ineligible badge is MUTED and
 *  never borrows the crit/severity palette — an ineligible runbook is a normal
 *  state, not a failure. Behind the plain-language "Why ineligible?" summary,
 *  the missing-evidence list is still the engine's `missing` array verbatim,
 *  never reworded (same discipline as the 409 create path).
 *
 *  This card RENDERS ONLY. It carries NO approve control and NO request control
 *  — requesting an approval is a single action owned by the Response panel, and
 *  approving happens only in the Approvals screen. Describing a step is not
 *  performing one: nothing here executes anything. */
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
  const copy = runbookPlainCopy(rb.runbookId);
  // The disclosure carries the machinery. When ineligible it is titled in plain
  // language, because "why not" is the question a reader actually has.
  const summary = rb.eligible ? "Rule detail" : "Why ineligible?";
  // A click or a key inside the disclosure toggles the disclosure — it must not
  // also fall through to the card's select handler and swallow the toggle.
  const stop = (e: { stopPropagation: () => void }) => e.stopPropagation();

  return (
    <div
      className={cn("is-runbook-card", selected && "is-selected", !rb.eligible && "is-ineligible")}
      data-testid={testid ?? "runbook-card"}
      data-runbook-id={rb.runbookId}
      data-eligible={rb.eligible ? "true" : "false"}
      data-described={copy.described ? "true" : "false"}
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

      {/* The plain-language body. Words only — no ids, no floors, no schema. */}
      <dl className="is-rb-plain" data-testid="rb-plain">
        <div className="is-rb-plain__row" data-testid="rb-what">
          <dt className="is-rb-plain__k">What it does</dt>
          <dd className="is-rb-plain__v">{copy.whatItDoes}</dd>
        </div>
        <div className="is-rb-plain__row" data-testid="rb-fires">
          <dt className="is-rb-plain__k">Fires on</dt>
          <dd className="is-rb-plain__v">{copy.firesOn}</dd>
        </div>
        <div className="is-rb-plain__row" data-testid="rb-needs">
          <dt className="is-rb-plain__k">Needs</dt>
          <dd className="is-rb-plain__v">{copy.needs}</dd>
        </div>
      </dl>

      <div className="is-rb-steps" data-testid="rb-steps">
        <span className="is-rb-steps__lbl">Steps</span>
        {copy.steps.length > 0 ? (
          // As many steps as the runbook defines, in order — never padded.
          <ol className="is-rb-steps__list">
            {copy.steps.map((s, i) => (
              <li key={i} className="is-rb-steps__item">{s}</li>
            ))}
          </ol>
        ) : (
          <p className="is-rb-steps__none" data-testid="rb-steps-none">{copy.stepsNote}</p>
        )}
      </div>

      <p className="is-rb-rev" data-testid="rb-reversible">
        <span className="is-rb-rev__k">Reversible?</span>{" "}
        <span className="is-rb-rev__a">{copy.reversible}</span>{" "}
        <span className="is-rb-rev__v">{copy.reversibleDetail}</span>
      </p>

      {/* CLOSED BY DEFAULT. Everything machine-shaped lives in here: the id, the
          severity floor, the raw trigger rule ids, and — when the rules said no
          — their `missing` array, verbatim. Native <details>, so it is reachable
          and toggleable from the keyboard with no handler of our own. */}
      <details
        className="is-rb-detail"
        data-testid="rb-detail"
        onClick={stop}
        onKeyDown={stop}
      >
        <summary className="is-rb-detail__s" data-testid="rb-detail-summary">{summary}</summary>
        <div className="is-rb-detail__body">
          {!rb.eligible && (
            <p className="is-rb-detail__lead" data-testid="rb-detail-lead">
              The rules decide which runbooks fit an incident. This one does not fit yet.
              Below is exactly what the engine reported, in its own words.
            </p>
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

          <div className="is-runbook-card__meta is-mono is-mut" data-testid="rb-detail-meta">
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
        </div>
      </details>
    </div>
  );
}
