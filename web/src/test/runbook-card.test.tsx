import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { RunbookCard, type RunbookCardData } from "@/components/RunbookCard";

/** C4-F1 — is-runbook-card. Component-level invariants, each proven by a run,
 *  not by a visual claim. (Invariant 3 — the accent-button budget in the
 *  Incidents VIEW — is proven where the Response panel is wired, not here.) */

const SEVERITY_FAMILY = /is-(tag|block|badge)?--?(crit|high|med|low)\b|--(crit|high|med|low)\b/;

function eligibleRb(over: Partial<RunbookCardData> = {}): RunbookCardData {
  return {
    runbookId: "rb-block-ip",
    name: "Block source IP at the edge",
    severityFloor: "HIGH",
    triggerRules: ["auth_bruteforce_success", "auth_bruteforce"],
    eligible: true,
    ...over,
  };
}
function ineligibleRb(over: Partial<RunbookCardData> = {}): RunbookCardData {
  return {
    runbookId: "rb-block-ip",
    name: "Block source IP at the edge",
    severityFloor: "HIGH",
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
  it("renders the runbook name and its trigger rule chips", () => {
    render(<RunbookCard rb={eligibleRb()} />);
    expect(screen.getByText("Block source IP at the edge")).toBeInTheDocument();
    const rules = screen.getByTestId("rb-trigger-rules");
    expect(within(rules).getByText("auth_bruteforce_success")).toBeInTheDocument();
    expect(within(rules).getByText("auth_bruteforce")).toBeInTheDocument();
  });

  it("INVARIANT 1 — ineligibility is INFORMATION, not alarm: the ineligible badge is MUTED and its class never matches the severity family", () => {
    render(<RunbookCard rb={ineligibleRb()} />);
    const badge = screen.getByTestId("rb-badge-ineligible");
    expect(badge).toHaveTextContent("INELIGIBLE");
    // The point of the card: an ineligible runbook is a normal state. Its badge
    // class must NOT borrow the crit/severity palette.
    expect(badge.className).toMatch(/is-rb-badge--ineligible/);
    expect(badge.className).not.toMatch(SEVERITY_FAMILY);
    expect(badge.className).not.toMatch(/crit|danger|alarm/i);
    // And no severity-family element is rendered anywhere in the ineligible card.
    const card = screen.getByTestId("runbook-card");
    expect(card.querySelector('[class*="--crit"], [class*="--high"], [class*="--med"], [class*="--low"]')).toBeNull();
  });

  it("INVARIANT 2 — the missing-evidence list renders the engine's missing[] VERBATIM, never reworded", () => {
    const rb = ineligibleRb();
    render(<RunbookCard rb={rb} />);
    const missing = screen.getByTestId("rb-missing");
    // Each entry appears byte-for-byte as the engine emitted it.
    for (const line of rb.missing!) {
      expect(within(missing).getByText(line)).toBeInTheDocument();
    }
    // No paraphrase creeps in: the rendered items equal the source array exactly.
    const items = within(missing).getAllByRole("listitem").map((li) => li.textContent);
    expect(items).toEqual(rb.missing);
  });

  it("an eligible card shows the ELIGIBLE badge and NO missing-evidence list", () => {
    render(<RunbookCard rb={eligibleRb()} />);
    expect(screen.getByTestId("rb-badge-eligible")).toHaveTextContent("ELIGIBLE");
    expect(screen.queryByTestId("rb-missing")).toBeNull();
    expect(screen.queryByTestId("rb-badge-ineligible")).toBeNull();
  });

  it("INVARIANT 4 — the card carries NO approve control and NO primary/accent button", () => {
    const { container } = render(<RunbookCard rb={eligibleRb()} />);
    // Approving lives only in the Approvals screen; requesting is the panel's
    // single action. The card itself has neither.
    expect(screen.queryByTestId("approval-approve")).toBeNull();
    expect(container.querySelector('[data-testid="approval-approve"]')).toBeNull();
    expect(container.querySelector(".is-btn--primary")).toBeNull();
    expect(container.querySelectorAll("button")).toHaveLength(0);
  });
});
