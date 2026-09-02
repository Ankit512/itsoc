import { describe, it, expect, vi } from "vitest";
import { render, screen, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RunbookCard, type RunbookCardData } from "@/components/RunbookCard";
import { runbookPlainCopy, UNDESCRIBED } from "@/lib/runbookCopy";

/** C4-F1 + F0 — is-runbook-card. Component-level invariants, each proven by a
 *  run, not by a visual claim. (Invariant 3 — the accent-button budget in the
 *  Incidents VIEW — is proven where the Response panel is wired, not here.)
 *
 *  F0 adds the legibility contract: the DEFAULT card answers five plain
 *  questions and contains no schema vocabulary; the machinery is one collapsed
 *  disclosure away, and the engine's `missing` is still verbatim inside it. */

const SEVERITY_FAMILY = /is-(tag|block|badge)?--?(crit|high|med|low)\b|--(crit|high|med|low)\b/;

/** Vocabulary that must never reach the default (uncollapsed) card surface. */
const SCHEMA_VOCAB = [
  "severity_floor",
  "params_template",
  "required_evidence",
  "trigger.rule_ids",
  "entity_types",
  "rule_ids",
  "record_refs",
  "entity_kind",
  "rollback",
  "connector",
  "notify_draft",
  "floor",
  "auth_bruteforce",
  "possible_break_in",
  "rb-block-ip",
  "rb-draft-notify",
];

/** The card text a reader actually sees before opening anything: the card minus
 *  the closed <details>. */
function defaultVisibleText(card: HTMLElement): string {
  const clone = card.cloneNode(true) as HTMLElement;
  clone.querySelectorAll("details").forEach((d) => d.remove());
  return clone.textContent ?? "";
}

function blockIp(over: Partial<RunbookCardData> = {}): RunbookCardData {
  return {
    runbookId: "rb-block-ip",
    name: "Block source IP at the perimeter",
    severityFloor: "HIGH",
    triggerRules: ["auth_bruteforce_success", "auth_bruteforce"],
    eligible: true,
    ...over,
  };
}
function draftNotify(over: Partial<RunbookCardData> = {}): RunbookCardData {
  return {
    runbookId: "rb-draft-notify",
    name: "Draft a notification for analyst review",
    severityFloor: "LOW",
    triggerRules: ["auth_bruteforce", "error_rate_spike"],
    eligible: true,
    ...over,
  };
}
function ineligibleRb(over: Partial<RunbookCardData> = {}): RunbookCardData {
  return {
    ...blockIp(),
    triggerRules: ["auth_bruteforce_success"],
    eligible: false,
    missing: [
      "trigger.rule_ids: none of auth_bruteforce_success present (incident rules: port_scan)",
      "severity_floor: incident is MEDIUM, below the HIGH floor",
    ],
    ...over,
  };
}

describe("is-runbook-card — presentational invariants", () => {
  it("renders the runbook name, and its trigger rule chips inside the disclosure", () => {
    render(<RunbookCard rb={blockIp()} />);
    expect(screen.getByText("Block source IP at the perimeter")).toBeInTheDocument();
    const rules = screen.getByTestId("rb-trigger-rules");
    expect(within(rules).getByText("auth_bruteforce_success")).toBeInTheDocument();
    expect(within(rules).getByText("auth_bruteforce")).toBeInTheDocument();
    // …and they are inside the collapsed disclosure, not on the default card.
    expect(screen.getByTestId("rb-detail").contains(rules)).toBe(true);
  });

  it("INVARIANT 1 — ineligibility is INFORMATION, not alarm: the ineligible badge is MUTED and its class never matches the severity family", () => {
    render(<RunbookCard rb={ineligibleRb()} />);
    const badge = screen.getByTestId("rb-badge-ineligible");
    expect(badge).toHaveTextContent("INELIGIBLE");
    expect(badge.className).toMatch(/is-rb-badge--ineligible/);
    expect(badge.className).not.toMatch(SEVERITY_FAMILY);
    expect(badge.className).not.toMatch(/crit|danger|alarm/i);
    const card = screen.getByTestId("runbook-card");
    expect(card.querySelector('[class*="--crit"], [class*="--high"], [class*="--med"], [class*="--low"]')).toBeNull();
  });

  it("INVARIANT 2 — the missing-evidence list renders the engine's missing[] VERBATIM, never reworded", () => {
    const rb = ineligibleRb();
    render(<RunbookCard rb={rb} />);
    const missing = screen.getByTestId("rb-missing");
    for (const line of rb.missing!) {
      expect(within(missing).getByText(line)).toBeInTheDocument();
    }
    const items = within(missing).getAllByRole("listitem").map((li) => li.textContent);
    expect(items).toEqual(rb.missing);
  });

  it("an eligible card shows the ELIGIBLE badge and NO missing-evidence list", () => {
    render(<RunbookCard rb={blockIp()} />);
    expect(screen.getByTestId("rb-badge-eligible")).toHaveTextContent("ELIGIBLE");
    expect(screen.queryByTestId("rb-missing")).toBeNull();
    expect(screen.queryByTestId("rb-badge-ineligible")).toBeNull();
  });

  it("INVARIANT 4 — the card carries NO approve control and NO primary/accent button", () => {
    const { container } = render(<RunbookCard rb={blockIp()} />);
    expect(screen.queryByTestId("approval-approve")).toBeNull();
    expect(container.querySelector('[data-testid="approval-approve"]')).toBeNull();
    expect(container.querySelector(".is-btn--primary")).toBeNull();
    expect(container.querySelectorAll("button")).toHaveLength(0);
  });
});

describe("F0 — a non-builder can read the card", () => {
  it("every card answers the five questions: What it does, Fires on, Needs, Steps, Reversible", () => {
    render(<RunbookCard rb={blockIp()} />);
    const card = screen.getByTestId("runbook-card");
    for (const label of ["What it does", "Fires on", "Needs", "Steps", "Reversible?"]) {
      expect(within(card).getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByTestId("rb-what")).toBeInTheDocument();
    expect(screen.getByTestId("rb-fires")).toBeInTheDocument();
    expect(screen.getByTestId("rb-needs")).toBeInTheDocument();
    expect(screen.getByTestId("rb-steps")).toBeInTheDocument();
    expect(screen.getByTestId("rb-reversible")).toBeInTheDocument();
  });

  it("SHIPPED RUNBOOK 1 — rb-block-ip reads in plain English, with both of its steps and its partial reversibility", () => {
    render(<RunbookCard rb={blockIp()} />);
    const copy = runbookPlainCopy("rb-block-ip");
    expect(copy.described).toBe(true);

    expect(screen.getByTestId("rb-what")).toHaveTextContent(/firewall to stop traffic coming from this IP address/i);
    expect(screen.getByTestId("rb-fires")).toHaveTextContent(/repeated failed logins/i);
    expect(screen.getByTestId("rb-fires")).toHaveTextContent(/High or Critical/);
    expect(screen.getByTestId("rb-needs")).toHaveTextContent(/first and last time it was seen/i);

    // Exactly the two steps the shipped definition declares — never padded out.
    const steps = within(screen.getByTestId("rb-steps")).getAllByRole("listitem");
    expect(steps).toHaveLength(2);
    expect(steps.map((li) => li.textContent)).toEqual(copy.steps);
    expect(steps[0]).toHaveTextContent(/deny traffic coming in from that IP address for the next 4 hours/i);
    expect(steps[1]).toHaveTextContent(/draft a note to the SOC actions channel/i);

    // rollback: step 1 has one, step 2 is an explicit null → "Partly".
    const rev = screen.getByTestId("rb-reversible");
    expect(rev).toHaveTextContent("Partly");
    expect(rev).toHaveTextContent(/firewall block records an undo/i);
    expect(rev).toHaveTextContent(/drafted note records no undo/i);
  });

  it("SHIPPED RUNBOOK 2 — rb-draft-notify reads as the draft-only, fully reversible runbook it is", () => {
    render(<RunbookCard rb={draftNotify()} />);
    const copy = runbookPlainCopy("rb-draft-notify");
    expect(copy.described).toBe(true);

    expect(screen.getByTestId("rb-what")).toHaveTextContent(/unsent message/i);
    expect(screen.getByTestId("rb-what")).toHaveTextContent(/nothing on any system changes/i);
    expect(screen.getByTestId("rb-fires")).toHaveTextContent(/at any severity/i);

    const steps = within(screen.getByTestId("rb-steps")).getAllByRole("listitem");
    expect(steps).toHaveLength(1);
    expect(steps.map((li) => li.textContent)).toEqual(copy.steps);
    expect(steps[0]).toHaveTextContent(/a person has to review it/i);

    const rev = screen.getByTestId("rb-reversible");
    expect(rev).toHaveTextContent("Yes");
    expect(rev).toHaveTextContent(/discarded before anyone sends it/i);
  });

  it("HONEST FALLBACK — an unknown runbook says it is not described instead of inventing steps", () => {
    render(<RunbookCard rb={blockIp({ runbookId: "rb-not-shipped-yet", name: "Some future runbook" })} />);
    const card = screen.getByTestId("runbook-card");
    expect(card.getAttribute("data-described")).toBe("false");

    // No fabricated steps at all — an ordered list would be a fabrication.
    expect(within(screen.getByTestId("rb-steps")).queryAllByRole("listitem")).toHaveLength(0);
    const none = screen.getByTestId("rb-steps-none");
    expect(none).toHaveTextContent(/not described here, and none are guessed/i);
    expect(screen.getByTestId("rb-what")).toHaveTextContent(/no plain-language description/i);
    expect(screen.getByTestId("rb-reversible")).toHaveTextContent("Not recorded");
    expect(runbookPlainCopy("rb-not-shipped-yet")).toBe(UNDESCRIBED);

    // The honest fallback is still not an alarm, and the rules still spoke:
    // the eligibility badge is unaffected by our lack of prose.
    expect(screen.getByTestId("rb-badge-eligible")).toBeInTheDocument();
    expect(card.querySelector('[class*="--crit"], [class*="--danger"]')).toBeNull();
  });

  it("NO SCHEMA VOCABULARY on the default card — for both shipped runbooks and the fallback", () => {
    for (const rb of [blockIp(), draftNotify(), blockIp({ runbookId: "rb-unknown" }), ineligibleRb()]) {
      const { unmount } = render(<RunbookCard rb={rb} />);
      const visible = defaultVisibleText(screen.getByTestId("runbook-card"));
      for (const word of SCHEMA_VOCAB) {
        expect(visible.toLowerCase(), `"${word}" leaked onto the default card for ${rb.runbookId}`)
          .not.toContain(word.toLowerCase());
      }
      unmount();
    }
  });

  it("the machinery is COLLAPSED behind a disclosure, closed by default, and still complete inside", () => {
    render(<RunbookCard rb={ineligibleRb()} />);
    const details = screen.getByTestId("rb-detail") as HTMLDetailsElement;
    expect(details.tagName).toBe("DETAILS");
    expect(details.open).toBe(false);

    // Plain-language summary for the question a reader actually has.
    expect(screen.getByTestId("rb-detail-summary")).toHaveTextContent("Why ineligible?");
    expect(screen.getByTestId("rb-detail-lead")).toHaveTextContent(/the rules decide which runbooks fit/i);

    // Nothing is hidden away: the id, the floor, the raw rule ids and the
    // engine's missing[] are all inside it.
    expect(details.contains(screen.getByTestId("rb-missing"))).toBe(true);
    expect(details.contains(screen.getByTestId("rb-trigger-rules"))).toBe(true);
    expect(screen.getByTestId("rb-detail-meta")).toHaveTextContent("rb-block-ip");
    expect(screen.getByTestId("rb-detail-meta")).toHaveTextContent("floor HIGH");
  });

  it("an eligible card's disclosure is titled neutrally, never 'Why ineligible?'", () => {
    render(<RunbookCard rb={blockIp()} />);
    expect(screen.getByTestId("rb-detail-summary")).toHaveTextContent("Rule detail");
    expect(screen.queryByTestId("rb-detail-lead")).toBeNull();
  });
});

describe("F0 — keyboard accessibility", () => {
  it("the card is reachable and selectable from the keyboard (Enter and Space)", () => {
    const onSelect = vi.fn();
    render(<RunbookCard rb={blockIp()} onSelect={onSelect} />);
    const card = screen.getByTestId("runbook-card");
    expect(card).toHaveAttribute("role", "button");
    expect(card).toHaveAttribute("tabindex", "0");
    expect(card).toHaveAttribute("aria-pressed", "false");

    card.focus();
    expect(document.activeElement).toBe(card);
    fireEvent.keyDown(card, { key: "Enter" });
    fireEvent.keyDown(card, { key: " " });
    expect(onSelect).toHaveBeenCalledTimes(2);
  });

  it("the disclosure toggles on its own and does NOT fall through to selecting the card", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(<RunbookCard rb={ineligibleRb()} onSelect={onSelect} />);
    const details = screen.getByTestId("rb-detail") as HTMLDetailsElement;
    const summary = screen.getByTestId("rb-detail-summary");

    // <summary> is natively focusable, so the disclosure needs no handler of ours.
    summary.focus();
    expect(document.activeElement).toBe(summary);

    await user.click(summary);
    expect(details.open).toBe(true);
    // Opening the machinery is not selecting the runbook.
    expect(onSelect).not.toHaveBeenCalled();

    await user.click(summary);
    expect(details.open).toBe(false);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("a card with no onSelect is not a button and is not in the tab order", () => {
    render(<RunbookCard rb={blockIp()} />);
    const card = screen.getByTestId("runbook-card");
    expect(card).not.toHaveAttribute("role");
    expect(card).not.toHaveAttribute("tabindex");
  });
});
