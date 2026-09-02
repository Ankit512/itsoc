/** runbookCopy — plain-language descriptions of the runbooks itsoc ships.
 *
 *  CARD F0. A runbook card has to be legible to someone who did not build
 *  itsoc: What it does, Fires on, Needs, the numbered Steps, and whether it is
 *  Reversible. The runbook-recommendation API carries only `runbookId`, `name`,
 *  `severityFloor`, `triggerRules` and the engine's eligibility proof — it does
 *  not carry steps or rollbacks — so the prose lives here, on the client.
 *
 *  EVERY line below is a transcription of a shipped runbook definition in
 *  `console/runbooks/*.yaml`, field by field:
 *
 *    whatItDoes  ← steps[].type / connector / params_template (what the step asks for)
 *    firesOn     ← trigger.rule_ids + trigger.entity_types + severity_floor
 *    needs       ← preconditions.required_evidence
 *    steps       ← steps[], in order, one entry per shipped step
 *    reversible  ← steps[].rollback (a mapping = undoable; explicit null = not)
 *
 *  Nothing is invented. No capability, approval, execution or reversibility is
 *  described here that is not written in the YAML. In particular:
 *
 *   - The step lists are NOT padded to a fixed length. rb-block-ip ships two
 *     steps and rb-draft-notify ships one; inventing a third would be exactly
 *     the fabricated evidence this repo forbids.
 *   - Describing a step is not performing it. Nothing in itsoc executes a
 *     runbook; a runbook remains a reference behind the existing approval gate,
 *     and this module renders words only.
 *   - Eligibility stays rule-owned. Nothing here is an input to
 *     runbooks.eligible(); `firesOn` merely restates, in plain words, the
 *     trigger the engine already evaluates on its own.
 *
 *  A runbook id this module has never heard of gets `UNDESCRIBED` — an honest
 *  bounded fallback that says so, rather than guessed steps. */

export type Reversibility = "Yes" | "Partly" | "No" | "Not recorded";

export interface RunbookPlainCopy {
  /** false for the fallback: this runbook has no transcribed description. */
  described: boolean;
  whatItDoes: string;
  firesOn: string;
  needs: string;
  /** One entry per shipped step, in definition order. Empty when undescribed. */
  steps: string[];
  /** Shown in place of the step list when `steps` is empty. */
  stepsNote: string | null;
  reversible: Reversibility;
  reversibleDetail: string;
}

/** console/runbooks/rb-block-ip.yaml */
const RB_BLOCK_IP: RunbookPlainCopy = {
  described: true,
  whatItDoes:
    "Asks the perimeter firewall to stop traffic coming from this IP address, " +
    "then drafts a note for the SOC channel saying what was blocked and which log records show why.",
  firesOn:
    "An incident about an IP address, where the rules found repeated failed logins, " +
    "a login that finally succeeded after them, or a suspected break-in — " +
    "and the incident is rated High or Critical.",
  needs:
    "The IP address itself, the log lines that name it, the first and last time it was seen, " +
    "and a count of how often it happened.",
  steps: [
    // steps[0]: connector "firewall", operation deny, direction inbound, ttl_minutes 240
    "Ask the firewall to deny traffic coming in from that IP address for the next 4 hours.",
    // steps[1]: connector "notify", channel soc-actions
    "Draft a note to the SOC actions channel naming the address, the incident, " +
      "and the log records and time window behind it.",
  ],
  stepsNote: null,
  // steps[0].rollback is a mapping (allow the address again); steps[1].rollback is an explicit null.
  reversible: "Partly",
  reversibleDetail:
    "The firewall block records an undo — allowing the address again removes it. " +
    "The drafted note records no undo.",
};

/** console/runbooks/rb-draft-notify.yaml */
const RB_DRAFT_NOTIFY: RunbookPlainCopy = {
  described: true,
  whatItDoes:
    "Writes an unsent message about the incident for an analyst to read. " +
    "Nothing is sent, and nothing on any system changes.",
  firesOn:
    "An incident about an IP address, a user or a host, where the rules found a login problem, " +
    "a serious Linux or service event, or a spike in errors — at any severity.",
  needs:
    "Something to name — the IP address, user or host the incident is about — " +
    "and the log lines that mention it.",
  steps: [
    // steps[0]: connector "notify", channel soc-review, requires_review true
    "Draft a message for the SOC review channel carrying the rules that fired and the log records " +
      "behind them, marked so a person has to review it before it goes anywhere.",
  ],
  stepsNote: null,
  // steps[0].rollback is a mapping: discard_draft.
  reversible: "Yes",
  reversibleDetail: "The draft records an undo — it can be discarded before anyone sends it.",
};

/** The honest bounded fallback for a runbook this module has no transcription
 *  for. It states the gap instead of filling it. Its eligibility is unaffected:
 *  the rules still decide, and the card still shows their answer. */
export const UNDESCRIBED: RunbookPlainCopy = {
  described: false,
  whatItDoes: "This screen has no plain-language description for this runbook.",
  firesOn: "Not described here.",
  needs: "Not described here.",
  steps: [],
  stepsNote:
    "The steps are not described here, and none are guessed. " +
    "Only the runbooks itsoc ships are written out in plain language.",
  reversible: "Not recorded",
  reversibleDetail: "Whether this runbook can be undone is not recorded here — treat it as unknown.",
};

const SHIPPED: Record<string, RunbookPlainCopy> = {
  "rb-block-ip": RB_BLOCK_IP,
  "rb-draft-notify": RB_DRAFT_NOTIFY,
};

/** The plain-language copy for a runbook id, or the honest fallback. */
export function runbookPlainCopy(runbookId: string | null | undefined): RunbookPlainCopy {
  return SHIPPED[String(runbookId ?? "")] ?? UNDESCRIBED;
}

/** The ids this module actually describes — used by tests, never to gate UI. */
export const DESCRIBED_RUNBOOK_IDS = Object.keys(SHIPPED);
