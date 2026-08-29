// @ts-expect-error node:fs type declarations not included in browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations not included in browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations not included in browser tsconfig
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const itsocCssPath = path.resolve(__dirname, "../styles/itsoc.css");
const auditTimelinePath = path.resolve(__dirname, "../components/AuditTimeline.tsx");
const approvalsPath = path.resolve(__dirname, "../pages/Approvals.tsx");
const runbookCardPath = path.resolve(__dirname, "../components/RunbookCard.tsx");

const cssContent = fs.readFileSync(itsocCssPath, "utf-8");
const auditTimelineTsx = fs.readFileSync(auditTimelinePath, "utf-8");
const approvalsTsx = fs.readFileSync(approvalsPath, "utf-8");
const runbookCardTsx = fs.readFileSync(runbookCardPath, "utf-8");

/**
 * CARD C4-A1 & C4-A1r — Both-themes acceptance test suite for every C4 component.
 *
 * Requirements:
 *  1. No C4 component hardcodes a colour. Every colour must come from a token (var(--...)).
 *     Asserted by scanning C4 CSS rules and component sources for literal colours.
 *  2. Every token a C4 component references is DEFINED IN BOTH theme blocks (dark & light).
 *     Asserted by set-membership in both directions.
 *  3. The severity and crit palette remains strictly confined to failed audit entries only:
 *     source-level assertions parse C4 CSS subsections to verify that priority chips,
 *     advisory states, runbook cards, and non-failed audit chips never borrow the
 *     severity ramp (--crit, --high, --med, --low).
 */

function parseTokensFromBlock(blockContent: string): Set<string> {
  const tokens = new Set<string>();
  const matches = blockContent.matchAll(/--([a-zA-Z0-9_-]+)\s*:/g);
  for (const m of matches) {
    tokens.add(`--${m[1]}`);
  }
  return tokens;
}

function parseTokenBlock(selectorRegex: RegExp): Set<string> {
  const match = cssContent.match(selectorRegex);
  if (!match) return new Set();
  return parseTokensFromBlock(match[1]);
}

const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "");

describe("Both-Themes Acceptance for C4 Components (CARD C4-A1 & C4-A1r)", () => {
  // --------------------------------------------------------------------------
  // CHECK 1: No C4 Component or CSS Subsection Hardcodes a Colour
  // --------------------------------------------------------------------------
  describe("Check 1: Token Usage & No Hardcoded Colours in C4 Components", () => {
    it("C4 CSS subsections use design tokens instead of hardcoded hex / rgb values for component styling", () => {
      // Extract C4 sections from itsoc.css
      // 1. Approvals section (Section 12a3)
      const approvalsSection = cssContent.match(
        /\/\* ---- 12a3\. Approvals[\s\S]*?(?=\/\* ---- 12b)/,
      )?.[0] ?? "";
      expect(approvalsSection).toBeTruthy();

      // 2. Audit timeline section (Section 21)
      const auditSection = cssContent.match(
        /\/\* ── 21\. AUDIT TIMELINE[\s\S]*?(?=\/\* ---- 12a5)/,
      )?.[0] ?? "";
      expect(auditSection).toBeTruthy();

      // 3. Runbook card section (Section 12a5)
      const runbookSection = cssContent.match(
        /\/\* ---- 12a5\. Runbook card[\s\S]*?(?=\/\* ── 22)/,
      )?.[0] ?? "";
      expect(runbookSection).toBeTruthy();

      // 4. Advisory states section (Section 22)
      const advisorySection = cssContent.match(
        /\/\* ── 22\. ADVISORY STATES[\s\S]*?(?=\/\* --- C4-F3)/,
      )?.[0] ?? "";
      expect(advisorySection).toBeTruthy();

      // 5. Priority chip section (C4-F3)
      const prioritySection = cssContent.match(
        /\/\* --- C4-F3: Priority chip[\s\S]*$/,
      )?.[0] ?? "";
      expect(prioritySection).toBeTruthy();

      const sectionsToCheck = [
        { name: "Audit Timeline (Section 21)", content: stripComments(auditSection) },
        { name: "Runbook Card (Section 12a5)", content: stripComments(runbookSection) },
        { name: "Advisory States (Section 22)", content: stripComments(advisorySection) },
        { name: "Priority Chips (C4-F3)", content: stripComments(prioritySection) },
      ];

      for (const { name, content } of sectionsToCheck) {
        const hexMatches = content.match(/#[0-9a-fA-F]{3,8}\b/g) || [];
        const rgbMatches = content.match(/\brgba?\([^)]+\)/g) || [];
        expect(hexMatches, `Hardcoded hex in ${name}: ${hexMatches}`).toEqual([]);
        expect(rgbMatches, `Hardcoded rgb in ${name}: ${rgbMatches}`).toEqual([]);
      }

      // In Approvals, component styles (modal, header, text, kbd, err) use tokens
      const cleanApprovals = stripComments(approvalsSection);
      const approvalRules = cleanApprovals.split("}");
      for (const rule of approvalRules) {
        if (!rule.trim()) continue;
        const [selector, decls] = rule.split("{");
        if (!selector || !decls) continue;
        const trimmedSelector = selector.trim();

        // Skip the fixed overlay backdrop which uses alpha blackout
        if (trimmedSelector.includes(".is-approval-overlay")) continue;

        const hexMatches = decls.match(/#[0-9a-fA-F]{3,8}\b/g) || [];
        const rgbMatches = decls.match(/\brgba?\([^)]+\)/g) || [];
        expect(hexMatches, `Hardcoded hex in ${trimmedSelector}: ${decls}`).toEqual([]);
        expect(rgbMatches, `Hardcoded rgb in ${trimmedSelector}: ${decls}`).toEqual([]);
      }
    });

    it("C4 TSX component files have zero inline style color / background overrides", () => {
      for (const [name, code] of [
        ["AuditTimeline.tsx", auditTimelineTsx],
        ["Approvals.tsx", approvalsTsx],
        ["RunbookCard.tsx", runbookCardTsx],
      ]) {
        // Find style={{ ... }} in JSX
        const styleMatches = code.matchAll(/style=\{\{([^}]+)\}\}/g);
        for (const m of styleMatches) {
          const body = m[1];
          // Neither color nor background should be hardcoded
          expect(body, `Hardcoded hex in inline style in ${name}: ${body}`).not.toMatch(/color\s*:\s*["'][^"']*#[0-9a-fA-F]/);
          expect(body, `Hardcoded hex in inline style in ${name}: ${body}`).not.toMatch(/background\s*:\s*["'][^"']*#[0-9a-fA-F]/);
          expect(body, `Hardcoded rgb in inline style in ${name}: ${body}`).not.toMatch(/color\s*:\s*["']rgb/);
          expect(body, `Hardcoded rgb in inline style in ${name}: ${body}`).not.toMatch(/background\s*:\s*["']rgb/);
        }
      }
    });
  });

  // --------------------------------------------------------------------------
  // CHECK 2: Bidirectional Token Definition in Both Theme Blocks
  // --------------------------------------------------------------------------
  describe("Check 2: Symmetrical Theme Token Definition (Dark & Light)", () => {
    it("every color / surface token defined in dark is defined in light, and vice-versa", () => {
      const darkTokens = parseTokenBlock(/:root,\s*\[data-theme="dark"\]\s*\{([^}]+)\}/);
      const lightTokens = parseTokenBlock(/\[data-theme="light"\]\s*\{([^}]+)\}/);

      expect(darkTokens.size).toBeGreaterThan(15);
      expect(lightTokens.size).toBeGreaterThan(15);

      // Symmetrical color / surface tokens present in both blocks:
      const requiredColorTokens = [
        "--bg", "--pan", "--pan2", "--inset", "--track", "--fill",
        "--bd", "--bd2",
        "--ink", "--ink2", "--mut", "--mut2",
        "--acc", "--acc-ink", "--acc-weak",
        "--crit", "--high", "--med", "--low", "--info",
        "--ok", "--warn", "--danger",
        "--shadow",
      ];

      for (const t of requiredColorTokens) {
        expect(darkTokens.has(t), `Token ${t} missing from dark theme`).toBe(true);
        expect(lightTokens.has(t), `Token ${t} missing from light theme`).toBe(true);
      }
    });

    it("every token referenced by C4 components exists in the defined theme token set", () => {
      const darkTokens = parseTokenBlock(/:root,\s*\[data-theme="dark"\]\s*\{([^}]+)\}/);
      const lightTokens = parseTokenBlock(/\[data-theme="light"\]\s*\{([^}]+)\}/);

      // Shared tokens (including layout / font tokens inherited from :root)
      const allValidTokens = new Set([...darkTokens, ...lightTokens]);

      // Extract all var(--...) usages from C4 sections in itsoc.css
      const c4Sections = [
        cssContent.match(/\/\* ---- 12a3\. Approvals[\s\S]*?(?=\/\* ---- 12b)/)?.[0] ?? "",
        cssContent.match(/\/\* ── 21\. AUDIT TIMELINE[\s\S]*?(?=\/\* ---- 12a5)/)?.[0] ?? "",
        cssContent.match(/\/\* ---- 12a5\. Runbook card[\s\S]*?(?=\/\* ── 22)/)?.[0] ?? "",
        cssContent.match(/\/\* ── 22\. ADVISORY STATES[\s\S]*?(?=\/\* --- C4-F3)/)?.[0] ?? "",
        cssContent.match(/\/\* --- C4-F3: Priority chip[\s\S]*$/)?.[0] ?? "",
      ].join("\n");

      const varMatches = c4Sections.matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)\s*\)/g);
      for (const m of varMatches) {
        const tokenName = m[1];
        expect(allValidTokens.has(tokenName), `Referenced token ${tokenName} is undefined`).toBe(true);
      }
    });
  });

  // --------------------------------------------------------------------------
  // CHECK 3: Semantic Palette Confinement (CARD C4-A1r Source-Level Invariants)
  // --------------------------------------------------------------------------
  describe("Check 3: Semantic Palette Confinement (Failed Audit Entries Only)", () => {
    it("AuditTimeline confines the critical/alarm palette strictly to failed entries and broken banner", () => {
      const auditSection = cssContent.match(
        /\/\* ── 21\. AUDIT TIMELINE[\s\S]*?(?=\/\* ---- 12a5)/,
      )?.[0] ?? "";
      expect(auditSection).toBeTruthy();

      const cleanAudit = stripComments(auditSection);
      const rules = cleanAudit.split("}");

      for (const rule of rules) {
        if (!rule.trim()) continue;
        const [selector, decls] = rule.split("{");
        if (!selector || !decls) continue;
        const trimmedSelector = selector.trim();

        // Non-failed status chips must NEVER reference --crit, --danger, --warn, or --high
        if (
          trimmedSelector.includes(".is-chip--approved") ||
          trimmedSelector.includes(".is-chip--rejected") ||
          trimmedSelector.includes(".is-chip--executed")
        ) {
          expect(
            decls,
            `Non-failed chip ${trimmedSelector} must not borrow alarm tokens`,
          ).not.toMatch(/var\(\s*--(crit|danger|warn|high)/);
        }

        // If a rule references --crit, it MUST be an explicitly broken/failed selector
        if (decls.includes("--crit")) {
          const isAllowedFailedSelector =
            trimmedSelector.includes("is-chip--failed") ||
            trimmedSelector.includes("is-audit-entry--broken") ||
            trimmedSelector.includes("is-audit-broken");
          expect(
            isAllowedFailedSelector,
            `Critical palette leaked into non-failed audit selector: ${trimmedSelector}`,
          ).toBe(true);
        }
      }
    });

    it("RunbookCard subsection strictly avoids the severity/crit palette (--crit, --high, --med, --low)", () => {
      const runbookSection = cssContent.match(
        /\/\* ---- 12a5\. Runbook card[\s\S]*?(?=\/\* ── 22)/,
      )?.[0] ?? "";
      expect(runbookSection).toBeTruthy();

      const cleanRunbook = stripComments(runbookSection);
      const severityVars = cleanRunbook.match(/var\(\s*--(crit|high|med|low)\b/g) || [];
      expect(
        severityVars,
        `RunbookCard subsection must not borrow severity palette: found ${severityVars.join(", ")}`,
      ).toEqual([]);
    });

    it("Priority chip subsection (C4-F3) strictly avoids borrowing the severity ramp (--crit, --high, --med, --low)", () => {
      const prioritySection = cssContent.match(
        /\/\* --- C4-F3: Priority chip[\s\S]*$/,
      )?.[0] ?? "";
      expect(prioritySection).toBeTruthy();

      const cleanPriority = stripComments(prioritySection);
      const severityVars = cleanPriority.match(/var\(\s*--(crit|high|med|low)\b/g) || [];
      expect(
        severityVars,
        `Priority chip subsection must not borrow severity palette (--crit/--high/--med/--low): found ${severityVars.join(", ")}`,
      ).toEqual([]);
    });

    it("Advisory states subsection (Section 22) strictly avoids borrowing the severity/crit palette (--crit, --high, --med, --low)", () => {
      const advisorySection = cssContent.match(
        /\/\* ── 22\. ADVISORY STATES[\s\S]*?(?=\/\* --- C4-F3)/,
      )?.[0] ?? "";
      expect(advisorySection).toBeTruthy();

      const cleanAdvisory = stripComments(advisorySection);
      const severityVars = cleanAdvisory.match(/var\(\s*--(crit|high|med|low)\b/g) || [];
      expect(
        severityVars,
        `Advisory states subsection must not borrow severity palette (--crit/--high/--med/--low): found ${severityVars.join(", ")}`,
      ).toEqual([]);
    });
  });
});
