import { describe, it, expect } from "vitest";
// @ts-expect-error node:fs type declarations not included in browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations not included in browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations not included in browser tsconfig
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const css = fs.readFileSync(path.resolve(__dirname, "../styles/itsoc.css"), "utf-8");

/** A severity-palette reference in its usable form, e.g. `var(--crit)`. Bare
 *  token names in prose/comments (e.g. "--crit") do NOT match — only actual
 *  `var(--…)` references, which is what paints a pixel. */
const SEVERITY_TOKEN = /var\(\s*--(?:crit|high|med|low)\s*\)/;

type Rule = { selector: string; body: string };

/** Every rule whose selector list satisfies `pred`, with its declaration block.
 *  itsoc.css rules are flat (no nested braces), so a non-brace body capture is
 *  exact; comments carry no braces and fall into the selector prefix, which we
 *  never assert on. */
function rulesMatching(pred: (selector: string) => boolean): Rule[] {
  const out: Rule[] = [];
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(css)) !== null) {
    const selector = m[1].trim();
    if (pred(selector)) out.push({ selector, body: m[2] });
  }
  return out;
}

function hasRuleFor(rules: Rule[], needle: string): boolean {
  return rules.some((r) => r.selector.includes(needle));
}

describe("C4-R1 — palette confinement (severity ramp stays out of priority & advisory)", () => {
  it("D1: no priority-chip rule references a severity token", () => {
    const rules = rulesMatching((s) => /\.is-chip--(?:priority|p[1-4])\b/.test(s));
    // Vacuity guard: the four priority levels must actually be present.
    for (const lvl of ["--p1", "--p2", "--p3", "--p4"]) {
      expect(hasRuleFor(rules, `.is-chip${lvl}`), `.is-chip${lvl} rule must exist`).toBe(true);
    }
    for (const r of rules) {
      const name = r.selector.match(/\.is-chip--\S+/)?.[0] ?? r.selector;
      expect(r.body, `${name} must not reference a severity token`).not.toMatch(SEVERITY_TOKEN);
    }
  });

  it("D2: no advisory-state rule references a severity token", () => {
    // Advisory-state rules = the §22 pending/timeout containers AND `.note-timeout`
    // WHEREVER it is declared (the bare C2-T4 base rule and the scoped
    // `.is-advisory-timeout .note-timeout`). `.note-timeout` is exclusively the
    // advisory timeout note — every user sits inside `.is-advisory-timeout` — so a
    // severity token on its base rule is a latent violation that would wake up the
    // day the class renders outside that wrapper. The lock covers the class
    // wherever it lives, not just where it currently lives. The timeout reads as a
    // warning via --warn, never a severity token. (C4-R1a.)
    const rules = rulesMatching(
      (s) => /is-advisory-(?:pending|timeout)/.test(s) || /\.note-timeout\b/.test(s),
    );
    // Vacuity guard: both advisory states and the note rule must actually be present.
    expect(hasRuleFor(rules, "is-advisory-pending"), "advisory-pending rule must exist").toBe(true);
    expect(hasRuleFor(rules, "is-advisory-timeout"), "advisory-timeout rule must exist").toBe(true);
    expect(hasRuleFor(rules, "note-timeout"), "note-timeout rule must exist").toBe(true);
    for (const r of rules) {
      expect(r.body, `${r.selector} must not reference a severity token`).not.toMatch(SEVERITY_TOKEN);
    }
  });
});
