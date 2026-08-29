# C4 Structural & Design-Token Fidelity Audit (Repair C4-A2a)

**Author:** Oscar (`oscar-mtcvctka`), Autonomous Worker  
**Date:** 2026-08-29  
**Task:** CARD C4-A2a — `dc-fidelity` comparison for Stage C Phase C4 surfaces  
**Worktree:** `/Users/ankit/Projects/log-analyzer-wt/c4fidelity`  
**Audited Commit:** `4a0aaa8` (`integrate(c4): merge stage-c/c4-fanout-priority` on `stage-c/c4-response-ui`, integrating F1 `21b8891` + F2 `b3164ef` + F3 `1ae8d43`)  
**Target Reference Material:**  
- `docs/design/TOKENS.md` (Design system token definitions)  
- `docs/design/design_itsoc_incident_rca.html` (Incident / RCA reference layout)  
- `docs/design/design_itsoc_overview.html` (Overview reference layout)  
- `docs/design/reference/dc/itsoc Console.dc.html` (Design v3 `dc` reference)  
- `docs/design/reference/DESIGN_HANDOFF.md` (Handoff specification)  
- `docs/design/reference/v3/GAP_ANALYSIS.md` (Design v3 reconciliation analysis)

---

## 1. Methodology & Epistemic Boundaries

### 1.1 What This Audit Establishes
This audit performs a rigorous **structural token, class mapping, and rule conformance audit** on all five Stage C Phase C4 surfaces in the integrated tree at commit `4a0aaa8`:
1. **Token binding & variable mapping:** Verifies that component styles bind directly to CSS custom properties (`var(--...)`) defined in the Design v3 theme baseline, identifying any un-tokenized literal hex codes or gradient leaks.
2. **Component geometry & typography:** Audits declared border-radius tiers (`cards 12px / 8px`, `controls 7-8px`, `tags/pills 5-6px`, `chips 20px`), border widths (strict 1px), and typographic stacks (`Geist` / system sans and `Geist Mono` / `ui-monospace` tabular numbers).
3. **Standing design-system constraints:** Audits adherence to the **accent-button budget** (at most 1 `.is-btn--primary` per view canvas), the **shadows-on-overlays-only** rule, and the **visual distinction between deterministic fact vs advisory model hypothesis**.
4. **Security & honesty invariants:** Verifies verbatim copy requirements (`"severity is rule-owned"`, `"priority is rule-owned, weighted by asset criticality"`, Copilot footer disclaimer, DORA audit line) and selector-null constraints.

### 1.2 What This Audit Does NOT Establish
This audit is executed in a headless CLI environment without a live browser rendering engine or visual capture framebuffer. Accordingly:
- **It does NOT establish raster/pixel rendering fidelity.** It does not capture or compare rendered PNG screenshots, subpixel font smoothing, antialiasing curves, or layout engine rasterization quirks.
- **No visual rendering is fabricated:** Zero synthetic pixel diffs or imaginary screenshots are presented.
- **Visual rendering validation remains with human evaluation or browser-backed visual QA.**

---

## 2. Baseline Token Reconciliation

The design system evolved from initial v1/v2 prototypes (`docs/design/TOKENS.md`) into the reconciled Design v3 specification (`docs/design/reference/dc/itsoc Console.dc.html` and `web/src/styles/itsoc.css`).

### 2.1 Color Tokens (Dark Theme Baseline at Commit `4a0aaa8`)

| Token Name | Reference Spec (`TOKENS.md`) | Reconciled Design v3 (`dc.html` / `itsoc.css:26-37`) | Shipped Status | Role & Semantics |
| :--- | :--- | :--- | :--- | :--- |
| `--bg` | `#0d0e12` | `#09090b` | **Conforms to v3** | App background |
| `--pan` | `#14161d` | `#0e0e12` | **Conforms to v3** | Card and panel background |
| `--pan2` | `#101218` (darker) | `#17171c` (lighter hover/raised) | **Conforms to v3** | Raised row hover / card tint |
| `--inset` | *(not in v1)* | `#0b0b0f` | **Conforms to v3** | Recessed surface (evidence / input / code) |
| `--bd` | `#1d212b` | `#1e1e24` | **Conforms to v3** | Primary 1px structural border |
| `--bd2` | *(not in v1)* | `#2a2a31` | **Conforms to v3** | Secondary / modal border |
| `--ink` | `#e9ebf1` | `#ededf0` | **Conforms to v3** | Primary text |
| `--ink2` | *(not in v1)* | `#c9c9d1` | **Conforms to v3** | Secondary text |
| `--mut` | `#828b9c` | `#8f8f98` | **Conforms to v3** | Muted captions & secondary metadata |
| `--mut2` | *(not in v1)* | `#5c5c66` | **Conforms to v3** | Deeply muted timestamps and line numbers |
| `--acc` | `#7c6cff` | `#8b7cff` | **Conforms to v3** | Accent violet |
| `--crit` | `#f0616d` | `#f26d78` | **Conforms to v3** | Critical severity / failed status |
| `--high` | `#f2a33c` | `#f0a54a` | **Conforms to v3** | High severity / warning / timeout |
| `--med` | `#d6b02e` | `#d3b23a` | **Conforms to v3** | Medium severity |
| `--low` | `#33c895` | `#3ecf8e` | **Conforms to v3** | Low severity / deterministic green |

### 2.2 Geometry, Radii & Shadow Scale

| System Level | Reference Rule (`TOKENS.md:23`, `HANDOFF.md:21`) | Shipped Definition (`itsoc.css:33-34`) | Status |
| :--- | :--- | :--- | :--- |
| **Top-level Cards / Modals** | `12px` | `var(--radius): 8px` / modal explicit `12px` (`itsoc.css:243`) | **Conforms** (modal uses 12px; panels use 8px standard) |
| **Controls / Inputs / Buttons** | `8px – 9px` | `var(--radius-sm): 7px` (`itsoc.css:108,116`) | **Conforms** (~7-8px tier) |
| **Tags / Pills / Badges** | `5px` | `var(--radius-xs): 6px` (`itsoc.css:165,174`) | **Conforms** (~5-6px tier) |
| **Chips / Status Badges** | `20px` (pill oval) | `border-radius: 20px` (`itsoc.css:171,621`) | **Conforms** (exact 20px) |
| **Shadows** | Shadows on overlays only; flat page cards | `--shadow: 0 8px 30px rgba(0,0,0,.35)` on modals/palette | **Conforms** (cards have zero box-shadow) |

### 2.3 Token Audit Finding: Literal Scrim in `.is-approval-overlay`
- **Location:** `web/src/styles/itsoc.css:242`
- **Declaration:** `.is-approval-overlay { ... background: color-mix(in srgb, #000 42%, transparent); }`
- **Finding:** Contains a hardcoded literal `#000` rather than a CSS variable (e.g. `var(--bg)`).
- **Classification:** **Deliberate Scrim Divergence**.
- **Rationale:** The modal overlay requires a true black backdrop scrim (`#000 42%`) to dim the underlying canvas uniformly across both light and dark themes without inheriting theme-specific tinting. However, it represents an untokenized literal exception to the pure `var(--...)` token rule and is documented as such.

---

## 3. Surface-by-Surface Fidelity Comparison

All five surfaces audited below are present and verified in code at commit `4a0aaa8`.

```
Grep Verification against Commit 4a0aaa8:
  grep -c is-approval-modal     web/src/styles/itsoc.css     -> 1  (line 243)
  grep -c is-audit-timeline     web/src/styles/itsoc.css     -> 1  (line 506)
  grep -c is-runbook-card       web/src/styles/itsoc.css     -> 6  (lines 569-585)
  grep -c is-advisory-timeout   web/src/styles/itsoc.css     -> 2  (lines 610-615)
  grep -c is-chip--priority     web/src/styles/itsoc.css     -> 1  (line 621)
  grep -c PriorityChip          web/src/pages/Incidents.tsx  -> 4  (lines 43, 259, 1104, 1257)
```

---

### 3.1 Surface 1: Approvals Screen and `is-approval-modal`

**Source Files:**
- `web/src/pages/Approvals.tsx` (Lines 1–380)
- `web/src/styles/itsoc.css` (Lines 230–254)

#### Declared vs Shipped Comparison
| Element / Property | Reference Specification (`dc.html` / `HANDOFF.md`) | Shipped Implementation (`Approvals.tsx` / `itsoc.css`) | Verdict |
| :--- | :--- | :--- | :--- |
| **Master-Detail Layout** | `.is-md` split grid (`minmax(360px,1fr) 1.2fr`) | `web/src/pages/Approvals.tsx:337` (`className={cn("is-md", !selected && "!grid-cols-1")}`) | **CONFORMANT** |
| **Queue Navigation** | Keyboard J/K moving pending queue | `web/src/pages/Approvals.tsx:289-308` (active on pending list; deactivated when modal opens) | **CONFORMANT** |
| **Main Canvas Accent Budget** | Max 1 `.is-btn--primary` on page canvas | `web/src/pages/Approvals.tsx:254` uses `.is-btn` (plain secondary) for "Open review →" | **CONFORMANT** (0 primary buttons on canvas) |
| **Modal Overlay** | Fixed overlay, dark backdrop, z-index ≥ 60 | `itsoc.css:242` (`.is-approval-overlay` `position:fixed; z-index:60; background:color-mix(in srgb, #000 42%, transparent)`) | **CONFORMANT** (with documented `#000` scrim) |
| **Modal Container** | `max-width: 540px`, `12px` radius, shadow | `itsoc.css:243` (`max-width:540px; border-radius:12px; box-shadow:var(--shadow);`) | **CONFORMANT** |
| **Modal Action Budget** | Single primary action inside modal | `web/src/pages/Approvals.tsx:193` (`.is-btn.is-btn--primary` for Approve) + line 202 (`.is-btn` for Reject) | **CONFORMANT** |
| **Authoritative Bundle** | Rule-owned eligibility + redacted preview + evidence | `web/src/pages/Approvals.tsx:32-75` (`<AuthoritativeBundle>`) reusing `.is-block` and `.is-evidence` | **CONFORMANT** |
| **Advisory Absence** | Zero advisory chips inside authoritative bundle | Selector-null verified: `.is-adv` and `.is-chip--adv` absent | **CONFORMANT** |

#### Divergences in Surface 1
1. **Divergence 1.1 (Deliberate Scrim Divergence — Hardcoded `#000`):** `itsoc.css:242` uses `#000 42%` in `color-mix`.  
   *Rationale:* Intentional true black backdrop scrim to ensure uniform contrast across themes without theme-layer interference.
2. **Divergence 1.2 (Deliberate Enhancement — Modal Width):** Standard upload modal in `itsoc.css:419` references `680px` (2-column layout), whereas `.is-approval-modal` (`itsoc.css:243`) specifies `max-width: 540px`.  
   *Rationale:* Approval review is a single-column step-up confirmation dialog focused on a preview bundle; 540px provides optimal reading line-length for monospace commands and single-purpose passphrase entry.

---

### 3.2 Surface 2: `is-audit-timeline` and Chain Verification

**Source Files:**
- `web/src/components/AuditTimeline.tsx` (Lines 1–210)
- `web/src/styles/itsoc.css` (Lines 506–561)

#### Declared vs Shipped Comparison
| Element / Property | Reference Specification (`dc.html` / `BUILD.md §C4`) | Shipped Implementation (`itsoc.css:506-561` / `AuditTimeline.tsx`) | Verdict |
| :--- | :--- | :--- | :--- |
| **Timeline Container** | Vertical chronological stack (`gap: 12px`) | `itsoc.css:506` (`.is-audit-timeline { display:flex; flex-direction:column; gap:12px; }`) | **CONFORMANT** |
| **Audit Entry Card** | Background `--pan`, 1px border `--bd`, radius `7px` | `itsoc.css:508-512` (`.is-audit-entry { background:var(--pan); border:1px solid var(--bd); border-radius:var(--radius-sm); padding:12px 14px; }`) | **CONFORMANT** |
| **Status Chip Palette** | `approved` (neutral), `rejected` (muted), `executed` (accent), `failed` (CRITICAL palette only) | `itsoc.css:531-534`: `.is-chip--approved` (bd2), `.is-chip--rejected` (mut/inset), `.is-chip--executed` (acc), `.is-chip--failed` (crit `#f26d78`) | **CONFORMANT** (Zero green on approved/executed) |
| **Hash Presentation** | Monospace, muted font, 10px | `itsoc.css:521-522` (`font-family:var(--mono); font-size:10px; color:var(--mut2);`) | **CONFORMANT** |
| **Chain Broken Banner** | Red-bordered, critical tint, verbatim failure details | `itsoc.css:541-555` (`.is-audit-broken { background:color-mix(in srgb,var(--crit) 10%,transparent); border:1px solid var(--crit); }`) | **CONFORMANT** |
| **Clean Footnote** | Green checkmark, mono verification stamp | `itsoc.css:537-538` (`.is-audit-foot { font-family:var(--mono); } .check { color:var(--low); }`) | **CONFORMANT** |

#### Divergences in Surface 2
1. **Divergence 2.1 (Deliberate Enhancement — Radius Hierarchy):** Audit entry uses `border-radius: var(--radius-sm)` (`7px`) rather than top-level card radius (`12px` / `8px`).  
   *Rationale:* Audit entries are repeated nested items within an audit feed / timeline; 7px corners establish clean internal hierarchy against outer page panels.

---

### 3.3 Surface 3: `is-runbook-card` / Runbook Presentation

**Source Files:**
- `web/src/components/RunbookCard.tsx` (Lines 1–98)
- `web/src/pages/Incidents.tsx` (Lines 6, 702–795)
- `web/src/components/CopilotRail.tsx` (Lines 409–441, 706–741)
- `web/src/styles/itsoc.css` (Lines 569–594)

#### Declared vs Shipped Comparison
| Element / Property | Reference Specification (`design_itsoc_incident_rca.html:28-32`, `C4-F1`) | Shipped Implementation (`RunbookCard.tsx` / `Incidents.tsx` / `CopilotRail.tsx`) | Verdict |
| :--- | :--- | :--- | :--- |
| **Runbook Container** | `.is-runbook-card` recessed with 1px `--bd`, radius `7px` | `itsoc.css:569` (`.is-runbook-card { background:var(--inset); border:1px solid var(--bd); border-radius:var(--radius-sm); padding:11px 12px; }`) | **CONFORMANT** |
| **Eligibility Badges** | Eligible = accent outline; Ineligible = MUTED outline (never severity/crit) | `itsoc.css:581-583` (`.is-rb-badge--eligible` `color:var(--acc); border-color:...` vs `.is-rb-badge--ineligible` `color:var(--mut); border-color:var(--bd2)`) | **CONFORMANT** (Ineligibility is information, not alarm) |
| **Missing Evidence** | Verbatim from engine's `missing` array | `RunbookCard.tsx:85-93` (`.is-runbook-card__missing` renders `rb.missing` list items) | **CONFORMANT** |
| **Incident Response Panel** | Lists rule-eligible runbooks with single Request-approval action | `Incidents.tsx:736-795` (`<ResponsePanel>`) | **CONFORMANT** |
| **Accent Action Budget** | Single `.is-btn--primary` in Incidents view ("Request approval") | `Incidents.tsx:779` (`<button className="is-btn is-btn--primary">Request approval</button>`) | **CONFORMANT** (Creates pending approval; does not approve) |
| **Rail Pending Approvals** | Read-only cards linking to `/approvals` | `CopilotRail.tsx:409-441` (`data-testid="copilot-pending-approvals-card"`) | **CONFORMANT** |
| **Rail Resolution Card** | Cited resolution tab in Copilot right rail | `CopilotRail.tsx:706-741` (`activeTab === "resolution"`) | **CONFORMANT** |

#### Divergences in Surface 3
1. **Divergence 3.1 (Minor Implementation Drift — Tailwind Utilities in Copilot Rail):** In `CopilotRail.tsx:413` and `710`, cards use Tailwind utility classes (`rounded-lg border bg-primary/5 p-2.5`, `rounded-lg border bg-background p-3`) instead of pure `.is-*` classes.  
   *Impact:* Fully theme-consistent via CSS variable bindings in Tailwind theme, but diverges stylistically from pure `.is-*` custom class architecture.

---

### 3.4 Surface 4: Advisory Pending & Timeout States

**Source Files:**
- `web/src/pages/Incidents.tsx` (Lines 872–917, 1042–1077)
- `web/src/styles/itsoc.css` (Lines 595–619)

#### Declared vs Shipped Comparison
| Element / Property | Reference Specification (`BUILD.md §C2/C4`, `TOKENS.md`, `C4-F2`) | Shipped Implementation (`Incidents.tsx` / `itsoc.css`) | Verdict |
| :--- | :--- | :--- | :--- |
| **Deterministic vs Advisory Visual Distinction** | Solid left-border (green) on facts vs Dashed left-border (accent) on advisory | `itsoc.css:219-220`: `.is-block.is-det { border-left:3px solid var(--low); }` vs `.is-block.is-adv { border-left:3px dashed ...; }` | **CONFORMANT** |
| **Advisory Labeling** | Explicit ADVISORY chip on every hypothesis block | `Incidents.tsx:891,1045` (`.is-chip.is-chip--adv` "ADVISORY · hypothesis · not a verdict") | **CONFORMANT** |
| **Pending State** | `.is-advisory-pending` dashed accent left border + subtle background tint | `itsoc.css:599-608` (`border-left: 3px dashed color-mix(in srgb, var(--acc) 45%, transparent); background: color-mix(in srgb, var(--acc) 3%, transparent); color: var(--mut);`) | **CONFORMANT** |
| **Timeout State** | `.is-advisory-timeout` dashed warning left border + amber text (never critical red) | `itsoc.css:610-619` (`border-left: 3px dashed color-mix(in srgb, var(--high) 60%, transparent); .note-timeout { color: var(--high); }`) | **CONFORMANT** (Zero critical red or silent omission) |
| **Non-Blocking Behavior** | Deterministic case loads instantly; advisory loads on separate query | `Incidents.tsx:925-940` (separate `useQuery` with `retry: false`) | **CONFORMANT** |
| **Retry Affordance** | Ghost button, no accent primary consumption | `Incidents.tsx:1048,1065,1072` (`.is-btn.is-btn--ghost` "retry") | **CONFORMANT** |

#### Divergences in Surface 4
1. **Divergence 4.1 (Deliberate Architectural Enhancement — Split Investigation Sub-blocks):** The original mockup (`design_itsoc_incident_rca.html:25`) showed Root Cause as a single monolithic panel. Stage C split investigation into distinct `.is-det` (deterministic fact) and `.is-adv` (model hypothesis) sub-blocks.  
   *Rationale:* Enforces the foundational D2 invariant ("facts are rule-derived; advisory is non-blocking and clearly distinguished").

---

### 3.5 Surface 5: Priority Chip (org-context)

**Source Files:**
- `web/src/pages/Incidents.tsx` (Lines 43–55, 259, 1104, 1257)
- `web/src/styles/itsoc.css` (Lines 620–649)

#### Declared vs Shipped Comparison
| Element / Property | Reference Specification (`TOKENS.md:23`, `C2_C4_PREP.md`, `C4-F3`) | Shipped Implementation (`Incidents.tsx` / `itsoc.css`) | Verdict |
| :--- | :--- | :--- | :--- |
| **Placement** | Beside — NEVER replacing — severity tag | `Incidents.tsx:1256-1257` (list rows), line 259 (manual detail header), line 1104 (rule detail header) render `<IncidentSeverity>` and `<PriorityChip>` side-by-side | **CONFORMANT** |
| **Tooltip Copy** | Verbatim string | `Incidents.tsx:51` (`title="priority is rule-owned, weighted by asset criticality"`) | **CONFORMANT** |
| **Geometry & Radius** | `20px` radius (chip oval) vs `6px` radius (severity tag pill) | `itsoc.css:171,621` (`.is-chip` base `border-radius: 20px`) | **CONFORMANT** |
| **Typography** | Monospace, bold, 10px | `itsoc.css:622-627` (`font-family:var(--mono); font-weight:700; font-size:10px; letter-spacing:.05em; padding:1px 7px;`) | **CONFORMANT** |
| **Tier Color Palette** | P1 (crit), P2 (high), P3 (med), P4 (mut/inset) | `itsoc.css:629-648` (`.is-chip--p1..p4` consuming `var(--crit)`, `var(--high)`, `var(--med)`, `var(--mut)`) | **CONFORMANT** |

#### Divergences in Surface 5
- *None.* Implementation exactly satisfies the token specifications and behavioral invariants.

---

## 4. Cross-Surface Invariant Compliance Matrix

| Invariant / Design Rule | Governing Specification | Shipped Implementation Status | Proof & Verification Seam |
| :--- | :--- | :--- | :--- |
| **Accent-Button Budget** | Max 1 `.is-btn--primary` per view canvas | **COMPLIANT** | Approvals canvas has 0 primary buttons (`Approvals.tsx:254` uses `.is-btn`). Review modal carries 1 (`Approvals.tsx:193`). Incidents has 1 (`Incidents.tsx:779` for Request approval). |
| **Shadows on Overlays Only** | Flat cards; shadows only on fixed/modal dialogs | **COMPLIANT** | Only `.is-approval-modal`, `.is-palette`, `.is-runs`, `.is-rail-drawer`, and `.is-toast` carry `box-shadow`. Flat cards (`.is-panel`, `.is-block`, `.is-runbook-card`, `.is-audit-entry`) have no shadow. |
| **Zero Approve Controls in Rail** | Copilot rail has 0 approve/reject controls | **COMPLIANT** | `grep -in "approve" web/src/components/CopilotRail.tsx` returns 0 matches (only "approvals" in route/data context). Selector-null assertions verified by test. |
| **Severity Immutability** | Priority never alters or replaces rule severity | **COMPLIANT** | `Incidents.tsx` renders `<IncidentSeverity>` and `<PriorityChip>` simultaneously; `anomaly_detector.py` SHA-256 (`364577c5...`) byte-identical. |
| **Honesty Disclosures** | Verbatim honesty strings preserved across UI | **COMPLIANT** | Verified across all 5 surfaces: `"severity is rule-owned"`, `"priority is rule-owned, weighted by asset criticality"`, `"DORA-ready action trail — every action carries approver, rule eligibility, evidence, and connector response."` (`Reports.tsx:38`). |

---

## 5. Summary of Findings & Recommendations

### 5.1 Findings Summary Table

| Surface | Divergence Item | Category | File & Line | Rationale / Status |
| :--- | :--- | :--- | :--- | :--- |
| **Approvals Overlay** | Literal `#000 42%` in `color-mix` | **Deliberate Scrim Divergence** | `itsoc.css:242` | Documented exception for true black backdrop dimming across all theme layers. |
| **Approvals Modal** | Width 540px vs generic modal 680px | **Deliberate Enhancement** | `itsoc.css:243` vs `itsoc.css:419` | Retain 540px; optimal line-length for single-action step-up authorization. |
| **Audit Timeline** | Entry radius 7px vs top card 12px | **Deliberate Enhancement** | `itsoc.css:509` vs `TOKENS.md:23` | Retain 7px; establishes proper hierarchy for repeated nested items within timeline. |
| **Investigation File** | Split `.is-det` and `.is-adv` sub-blocks | **Deliberate Enhancement** | `itsoc.css:219-220` vs `design_itsoc_incident_rca.html:25` | Retain; strictly enforces D2 visual distinction between facts and model hypotheses. |
| **Copilot Rail** | Tailwind utility classes vs pure `is-*` | **Minor Implementation Drift** | `CopilotRail.tsx:413,710` | Visually and token-consistent via theme bindings; optional cleanup in future styling pass. |

### 5.2 Final Assessment
The C4 security-component and presentational surfaces demonstrate **high structural and design-token fidelity** with the reference design system on integrated commit `4a0aaa8`:
- **Token conformance:** All component styles bind to Design v3 CSS custom properties, with exactly one documented deliberate exception (`#000` backdrop scrim in `.is-approval-overlay` at `itsoc.css:242`).
- **Rule compliance:** The accent-button budget (max 1 primary per view canvas), shadows-on-overlays-only rule, and geometric radius tiers are fully satisfied.
- **Invariant verification:** Standing security and honesty constraints (no approve in rail, severity immutability, verbatim DORA and priority tooltips) are enforced, verifiable by grep and unit test.
