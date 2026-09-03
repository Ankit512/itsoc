import { describe, it, expect, vi } from "vitest";
import { render, screen, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RunbookCard, type RunbookCardData } from "@/components/RunbookCard";
import { runbookPlainCopy, UNDESCRIBED } from "@/lib/runbookCopy";
// @ts-expect-error node:fs type declarations not included in the browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations not included in the browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations not included in the browser tsconfig
import { fileURLToPath } from "node:url";

/** The shipped stylesheet, read from disk. The F0-FIX block below asserts the
 *  COMPUTED result of these real bytes, so the rules cannot be restated (and
 *  quietly kept correct) inside the test. */
const ITSOC_CSS_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../styles/itsoc.css",
);
function readItsocCss(): string {
  return fs.readFileSync(ITSOC_CSS_PATH, "utf-8") as string;
}
/** Concatenate the declaration blocks of the named selectors, comments stripped. */
function extractRules(css: string, selectors: string[]): string {
  const bare = css.replace(/\/\*[\s\S]*?\*\//g, "");
  return selectors
    .map((sel) => {
      const esc = sel.replace(/[.+*?^${}()|[\]\\]/g, "\\$&");
      const m = bare.match(new RegExp(`(?:^|\\})\\s*${esc}\\s*\\{([^}]*)\\}`, "m"));
      if (!m) throw new Error(`selector not found in itsoc.css: ${sel}`);
      return m[1];
    })
    .join("\n");
}

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

/* ────────────────────────────────────────────────────────────────────────────
 * CARD F0-FIX — the steps must RENDER as a numbered list, not merely BE one.
 *
 * WHY THIS BLOCK EXISTS. The 15 F0 tests above passed for the entire life of
 * the "steps are not numbered" defect, because every one of them asserts
 * STRUCTURE — that an <ol> exists and that it holds N `listitem` roles. That is
 * true of a list whose markers are invisible, so the suite could not see the
 * bug. These tests assert the COMPUTED RESULT under the real shipped
 * stylesheets instead, so they fail if either cause returns.
 *
 * WHAT THE ENVIRONMENT LETS US PROVE, EXACTLY. jsdom does not lay out or paint,
 * so it generates no ::marker box: nothing here reads an actual painted "1.".
 * Within that limit the two causes are asserted at the strongest level each
 * one admits, and each assertion was verified by reverting the fix and watching
 * it fail:
 *   - CAUSE 1 (`display:flex`, which blockifies the <li> children so no marker
 *     box is ever generated) is asserted on the COMPUTED style of the rendered
 *     <ol>, resolved by jsdom's cascade from the real bytes of itsoc.css.
 *   - CAUSE 2 (Tailwind preflight's `ol,ul{ list-style:none }`) is asserted on
 *     the CSS SOURCE, because jsdom's cascade propagates `display` but not
 *     `list-style-type` — getComputedStyle reports the UA default `decimal`
 *     whatever the stylesheets say, so a computed assertion would have been
 *     vacuous. The source assertion is not vacuous: it is what fails on a fix
 *     that unflexes the list but leaves the marker to the preflight.
 * So these tests prove both suppression mechanisms are gone from the shipped
 * stylesheet and stay gone. They do NOT prove the final pixel — that is what
 * the before/after screenshots of the running app in
 * docs/STAGE_E_REPORTS/F0-fix-evidence/ are for.
 * ──────────────────────────────────────────────────────────────────────────── */
describe("F0-FIX — the steps list renders numbered, and keeps its list semantics", () => {
  /** Load the real shipped CSS in the real cascade order the app uses:
   *  main.tsx imports index.css (Tailwind, whose preflight resets
   *  `ol,ul{ list-style:none }`) and THEN styles/itsoc.css. Reproducing that
   *  order matters — the preflight reset is half of the original defect, so a
   *  test that omitted it could pass on a fix that the real app would lose. */
  function applyShippedStyles(): void {
    const preflight = document.createElement("style");
    // The two Tailwind preflight declarations that reach an <ol>, verbatim.
    preflight.textContent = "ol,ul{ list-style:none; margin:0; padding:0; }";
    document.head.appendChild(preflight);

    const itsoc = document.createElement("style");
    itsoc.textContent = readItsocCss();
    document.head.appendChild(itsoc);
  }

  const FLEXED = ["flex", "inline-flex", "grid", "inline-grid"];

  it("REGRESSION — the shipped stylesheet gives the steps <ol> a counting marker and does NOT flex it", () => {
    applyShippedStyles();
    render(<RunbookCard rb={blockIp()} />);

    const ol = within(screen.getByTestId("rb-steps")).getByRole("list");
    const cs = getComputedStyle(ol);

    // CAUSE 1 — `display:flex` blockifies the <li> children, so the browser
    // never generates a ::marker box and the reserved gutter stays empty.
    expect(FLEXED).not.toContain(cs.display);

    // The gutter the markers occupy is still reserved, so nothing shifts.
    expect(cs.paddingLeft).not.toBe("");
    expect(cs.paddingLeft).not.toBe("0px");
  });

  it("REGRESSION — the rule states a counting marker EXPLICITLY, so Tailwind's `list-style:none` preflight cannot win", () => {
    // CAUSE 2, and the reason this one assertion is made at the source rather
    // than on a computed value: jsdom's cascade propagates `display` (proven by
    // the test above, which fails on the pre-fix stylesheet) but does NOT
    // propagate `list-style-type` — getComputedStyle returns the UA default
    // `decimal` no matter what any stylesheet says, so a computed assertion
    // here would pass even on an <ol> that the real browser renders bare. It
    // was checked: reverting to a fix that removes the flex but leaves the
    // marker to the preflight is caught by THIS test and by nothing else.
    //
    // What must hold is that .is-rb-steps__list declares a list-style itself.
    // An <ol> that inherits `list-style:none` from the preflight is not merely
    // unnumbered — Safari/VoiceOver stops announcing it as a list at all, so
    // the step ORDER is lost to that reader.
    const rule = extractRules(readItsocCss(), [".is-rb-steps__list"]);
    const listStyle = rule.match(/list-style(?:-type)?\s*:\s*([^;}]+)/);
    expect(listStyle, ".is-rb-steps__list must declare its own list-style").not.toBeNull();
    expect(listStyle![1].trim()).not.toMatch(/^none\b/);
    expect(listStyle![1]).toMatch(/decimal/);
  });

  it("REGRESSION — every step is a real list-item under the shipped stylesheet, so each one gets its own number", () => {
    applyShippedStyles();
    render(<RunbookCard rb={blockIp()} />);

    const items = within(screen.getByTestId("rb-steps")).getAllByRole("listitem");
    expect(items.length).toBeGreaterThan(1); // more than one step ⇒ order is meaningful
    for (const li of items) {
      expect(getComputedStyle(li).display).toBe("list-item");
    }
  });

  it("the ordinals stay legible in BOTH themes — the marker inherits the item's token colour and names no colour of its own", () => {
    // A ::marker cannot be read in jsdom, so this is proven at the source: the
    // steps rules declare no colour for the list or the marker, which means the
    // ordinal inherits `color: var(--ink2)` from the item — a token defined in
    // both theme blocks (c4-themes.test.tsx owns that both-themes guarantee).
    const css = readItsocCss();
    const stepsRules = extractRules(css, [
      ".is-rb-steps__list",
      ".is-rb-steps__item",
      ".is-rb-steps__item + .is-rb-steps__item",
    ]);
    expect(stepsRules).not.toMatch(/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/);
    expect(stepsRules).not.toMatch(/::marker/);
    expect(stepsRules).toMatch(/color:\s*var\(--ink2\)/);
  });

  it("HONEST FALLBACK — an undescribed runbook still says so and does NOT sprout an empty numbered list", () => {
    applyShippedStyles();
    render(<RunbookCard rb={blockIp({ runbookId: "rb-unknown-xyz" })} />);

    const steps = screen.getByTestId("rb-steps");
    // No list element at all — not a list that merely happens to be empty.
    expect(within(steps).queryByRole("list")).toBeNull();
    expect(within(steps).queryAllByRole("listitem")).toHaveLength(0);
    // stepsNote is `string | null` on the type; for the fallback it is the
    // honest note, and the card must be showing exactly that.
    expect(UNDESCRIBED.stepsNote).not.toBeNull();
    expect(screen.getByTestId("rb-steps-none")).toHaveTextContent(UNDESCRIBED.stepsNote!);
  });
});
