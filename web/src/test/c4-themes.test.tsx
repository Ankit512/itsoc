// @ts-expect-error node:fs type declarations not included in browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations not included in browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations not included in browser tsconfig
import { fileURLToPath } from "node:url";

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp, mockFetch } from "./helpers";
import { AuditTimeline } from "@/components/AuditTimeline";
import { Approvals } from "@/pages/Approvals";
import { RunbookCard, type RunbookCardData } from "@/components/RunbookCard";
import { useUi, applyThemeClass } from "@/store/ui";
import { ThemeToggle } from "@/components/ThemeToggle";
import type { AuditVerification, AuditEntry, Approval } from "@/lib/api";

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
 * CARD C4-A1 — Both-themes acceptance test suite for every C4 component.
 *
 * Requirements:
 *  1. No C4 component hardcodes a colour. Every colour must come from a token (var(--...)).
 *     Asserted by scanning C4 CSS rules and component sources for literal colours.
 *  2. Every token a C4 component references is DEFINED IN BOTH theme blocks (dark & light).
 *     Asserted by set-membership in both directions.
 *  3. The severity/crit palette remains strictly confined to failed audit entries only,
 *     and theme switching never causes non-failed components to acquire alarm colouring.
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

function mockCleanAudit(): { entries: AuditEntry[]; verification: AuditVerification } {
  return {
    entries: [
      {
        ts: "2026-08-29T12:00:00Z",
        actor: "analyst",
        step: "0",
        status: "approved",
        incident_id: "INC-4a7f",
        runbook_id: "rb-block-ip",
        prev_hash: "GENESIS",
        entry_hash: "entryhash0",
        request_redacted: "nft add element inet filter blocklist { [IP-1] }",
        response_verbatim: null,
      },
      {
        ts: "2026-08-29T12:05:00Z",
        actor: "analyst",
        step: "0",
        status: "executed",
        incident_id: "INC-4a7f",
        runbook_id: "rb-block-ip",
        prev_hash: "entryhash0",
        entry_hash: "entryhash1",
        request_redacted: "nft add element inet filter blocklist { [IP-1] }",
        response_verbatim: null,
      },
      {
        ts: "2026-08-29T12:10:00Z",
        actor: "analyst",
        step: "0",
        status: "rejected",
        incident_id: "INC-4a7f",
        runbook_id: "rb-block-ip",
        prev_hash: "entryhash1",
        entry_hash: "entryhash2",
        request_redacted: "nft add element inet filter blocklist { [IP-1] }",
        response_verbatim: null,
      },
    ],
    verification: {
      ok: true,
      count: 3,
      head: "entryhash2",
      break: null,
    },
  };
}

function mockBrokenAudit(): { entries: AuditEntry[]; verification: AuditVerification } {
  return {
    entries: [
      {
        ts: "2026-08-29T12:00:00Z",
        actor: "analyst",
        step: "0",
        status: "failed",
        incident_id: "INC-4a7f",
        runbook_id: "rb-block-ip",
        prev_hash: "GENESIS",
        entry_hash: "entryhash0",
        request_redacted: "nft add element inet filter blocklist { [IP-1] }",
        response_verbatim: null,
      },
    ],
    verification: {
      ok: false,
      count: 1,
      head: null,
      break: {
        index: 0,
        reason: "entry hash mismatch: expected bad0 found hash0",
        expected: "bad0",
        found: "hash0",
      },
    },
  };
}

function mockApproval(): Approval {
  return {
    id: "appr-abc123",
    incidentId: "INC-4a7f",
    runbookId: "rb-block-ip",
    connector: "nftables-ssh",
    step: 0,
    state: "pending",
    eligibilityProof: { eligible: true, missing: [] },
    evidenceRefs: ["5", "6"],
    requestRedacted: {
      command: "nft add element inet filter blocklist { [IP-1] }",
      description: "Block source IP at the edge",
      connector: "nftables-ssh",
      action: "block_ip",
      params: { ip: "[IP-1]" },
    },
    responseVerbatim: null,
    actor: null,
    failureReason: null,
    createdAt: "2026-08-29T12:00:00Z",
    updatedAt: "2026-08-29T12:00:00Z",
  };
}

const eligibleRunbook: RunbookCardData = {
  runbookId: "rb-block-ip",
  name: "Block source IP at the edge",
  severityFloor: "HIGH",
  triggerRules: ["auth_bruteforce_success", "auth_bruteforce"],
  eligible: true,
};

const ineligibleRunbook: RunbookCardData = {
  runbookId: "rb-block-ip",
  name: "Block source IP at the edge",
  severityFloor: "HIGH",
  triggerRules: ["auth_bruteforce_success"],
  eligible: false,
  missing: [
    "trigger.rule_ids: none of auth_bruteforce_success present (incident rules: port_scan)",
    "severity_floor: incident is MEDIUM, below the HIGH floor",
  ],
};

describe("Both-Themes Acceptance for C4 Components (CARD C4-A1)", () => {
  beforeEach(() => {
    localStorage.clear();
    useUi.setState({ theme: "light" });
    applyThemeClass("light");
  });

  afterEach(() => {
    localStorage.clear();
  });

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

      // Strip comments before checking rules
      const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "");

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
  // CHECK 3: Severity & Crit Palette Confinement Under Theme Switch
  // --------------------------------------------------------------------------
  describe("Check 3: Palette Confinement Under Theme Switching", () => {
    it("AuditTimeline confines the critical/alarm palette to failed entries under both themes", () => {
      const cleanData = mockCleanAudit();
      const brokenData = mockBrokenAudit();

      for (const theme of ["light", "dark"] as const) {
        useUi.setState({ theme });
        applyThemeClass(theme);
        document.documentElement.setAttribute("data-theme", theme);

        // 1. Clean chain: approved / rejected / executed have isolated non-crit palettes
        const { unmount: unmountClean } = renderApp(
          <AuditTimeline entries={cleanData.entries} verification={cleanData.verification} />,
        );

        const approvedChip = screen.getByText("approved");
        const executedChip = screen.getByText("executed");
        const rejectedChip = screen.getByText("rejected");

        expect(approvedChip.className).toMatch(/\bis-chip--approved\b/);
        expect(approvedChip.className).not.toMatch(/\bis-chip--failed\b/);
        expect(approvedChip.className).not.toMatch(/\bcrit\b/);

        expect(executedChip.className).toMatch(/\bis-chip--executed\b/);
        expect(executedChip.className).not.toMatch(/\bis-chip--failed\b/);
        expect(executedChip.className).not.toMatch(/\bcrit\b/);

        expect(rejectedChip.className).toMatch(/\bis-chip--rejected\b/);
        expect(rejectedChip.className).not.toMatch(/\bis-chip--failed\b/);
        expect(rejectedChip.className).not.toMatch(/\bcrit\b/);

        expect(screen.queryByTestId("audit-chain-broken-banner")).toBeNull();
        unmountClean();

        // 2. Broken chain: strictly failed entry and broken banner carry crit
        const { unmount: unmountBroken } = renderApp(
          <AuditTimeline entries={brokenData.entries} verification={brokenData.verification} />,
        );

        const failedChip = screen.getByText("failed");
        expect(failedChip.className).toMatch(/\bis-chip--failed\b/);

        const banner = screen.getByTestId("audit-chain-broken-banner");
        expect(banner.className).toMatch(/\bis-audit-broken\b/);

        unmountBroken();
      }
    });

    it("Approvals screen and modal remain free of alarm coloring across theme toggling", async () => {
      mockFetch({
        "/api/approvals": { approvals: [mockApproval()] },
        "/api/approvals/appr-abc123/re-evaluate": { eligible: true, missing: [] },
      });

      renderApp(
        <div>
          <ThemeToggle />
          <Approvals />
        </div>,
      );

      // Light theme default
      expect(document.documentElement.getAttribute("data-theme")).toBe("light");
      const card = await screen.findByTestId("approval-row");
      expect(card.querySelector(".is-chip--failed")).toBeNull();
      expect(card.querySelector(".crit")).toBeNull();

      // Toggle to dark theme
      const toggleBtn = screen.getByRole("button", { name: /switch to dark mode/i });
      await userEvent.click(toggleBtn);
      expect(document.documentElement.getAttribute("data-theme")).toBe("dark");

      // Verify no alarm classes leaked under dark theme
      expect(card.querySelector(".is-chip--failed")).toBeNull();
      expect(card.querySelector(".crit")).toBeNull();
      expect(document.querySelector(".is-approval-modal")).toBeNull(); // not opened yet

      // Toggle back to light
      const toggleLightBtn = screen.getByRole("button", { name: /switch to light mode/i });
      await userEvent.click(toggleLightBtn);
      expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    });

    it("RunbookCard maintains eligibility palette isolation under both themes", () => {
      for (const theme of ["light", "dark"] as const) {
        useUi.setState({ theme });
        applyThemeClass(theme);
        document.documentElement.setAttribute("data-theme", theme);

        // 1. Eligible runbook: low-accent outline, no crit/severity classes
        const { unmount: unmountEligible } = renderApp(
          <RunbookCard rb={eligibleRunbook} />,
        );
        const eligibleBadge = screen.getByTestId("rb-badge-eligible");
        expect(eligibleBadge).toHaveTextContent("ELIGIBLE");
        expect(eligibleBadge.className).toMatch(/is-rb-badge--eligible/);
        expect(eligibleBadge.className).not.toMatch(/crit|danger|alarm/i);
        expect(screen.queryByTestId("rb-badge-ineligible")).toBeNull();
        unmountEligible();

        // 2. Ineligible runbook: muted grey, no crit/severity classes
        const { unmount: unmountIneligible } = renderApp(
          <RunbookCard rb={ineligibleRunbook} />,
        );
        const ineligibleBadge = screen.getByTestId("rb-badge-ineligible");
        expect(ineligibleBadge).toHaveTextContent("INELIGIBLE");
        expect(ineligibleBadge.className).toMatch(/is-rb-badge--ineligible/);
        expect(ineligibleBadge.className).not.toMatch(/crit|danger|alarm/i);
        expect(screen.queryByTestId("rb-badge-eligible")).toBeNull();
        unmountIneligible();
      }
    });

    it("C4 priority and advisory design elements maintain palette isolation under both themes", () => {
      for (const theme of ["light", "dark"] as const) {
        useUi.setState({ theme });
        applyThemeClass(theme);
        document.documentElement.setAttribute("data-theme", theme);

        // Priority chips (P1, P2, P3, P4) and Advisory states (pending, timeout)
        const { unmount } = renderApp(
          <div data-testid="c4-surfaces">
            <span className="is-chip is-chip--priority is-chip--p1" data-testid="chip-p1">P1</span>
            <span className="is-chip is-chip--priority is-chip--p2" data-testid="chip-p2">P2</span>
            <span className="is-chip is-chip--priority is-chip--p3" data-testid="chip-p3">P3</span>
            <span className="is-chip is-chip--priority is-chip--p4" data-testid="chip-p4">P4</span>
            <div className="is-block is-adv is-advisory-pending" data-testid="adv-pending">Pending</div>
            <div className="is-block is-adv is-advisory-timeout" data-testid="adv-timeout">
              <div className="note-timeout">Timed out</div>
            </div>
          </div>,
        );

        const container = screen.getByTestId("c4-surfaces");
        const pending = within(container).getByTestId("adv-pending");
        const timeout = within(container).getByTestId("adv-timeout");

        // Advisory pending & timeout states MUST NOT borrow critical/severity palette
        expect(pending.className).not.toMatch(/\bis-chip--crit\b/);
        expect(pending.className).not.toMatch(/\bcrit\b/);
        expect(timeout.className).not.toMatch(/\bis-chip--crit\b/);
        expect(timeout.className).not.toMatch(/\bcrit\b/);

        unmount();
      }
    });
  });
});
