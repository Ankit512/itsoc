# FU-2 · Copilot footer copy drift

**Tier:** any. **Branch:** `fix/copilot-footer-copy` (suggested).
**Source:** owner ruling 2026-08-30, after the Antigravity pixel pass on `fix/shadow-tokens`.
**Does not block** the shadow-tokens merge (`c2f7e75`).

## Problem

Two honesty-footer strings are in the tree:

| Source of truth candidate | String |
|---|---|
| `docs/design/TOKENS.md` | `Rules set severity. I explain & prioritize — I don't decide.` |
| Live product + tests + incident mockup | `Rules set severity. I interpret & explain — I don't decide.` |

Owner default: **code aligns to TOKENS.md** unless someone deliberately changed the line, in which case TOKENS.md is amended **in the same commit**.

## Grep the tree first (binding)

Do not pick a string from memory. A first-pass grep (2026-08-30) found:

**"interpret & explain" (the live line):**

- `web/src/components/CopilotRail.tsx` (the rail footer, `data-testid="copilot-footer"`)
- `web/src/pages/Incidents.tsx` (`data-testid="incident-analyst-footer"`)
- `web/src/test/copilot-rail.test.tsx` (asserts the rail footer verbatim)
- `web/src/test/overview.test.tsx`
- `docs/design/design_itsoc_incident_rca.html` (`.cop-f`)
- `docs/design/reference/design_itsoc_incident_rca.html`
- `docs/design/reference/dc/itsoc Console.dc.html`
- `docs/design/reference/v3/itsoc_console_v3.dc.html`
- `docs/design/reference/v3/ITSOC_CLAUDE_DESIGN_PROMPT.md`

**"explain & prioritize" (TOKENS.md only):**

- `docs/design/TOKENS.md`

That pattern — mockup + product + tests on one side, TOKENS.md alone on the other — is evidence the line was **deliberately** set to the design-kit wording and TOKENS.md drifted. If a re-grep still shows that split, amend TOKENS.md to the live line in the same commit. If a re-grep shows TOKENS.md was the one people were supposed to follow, align the code and tests to it instead. Either way, one string, one commit.

## Audit-accuracy note (doctrine, not extra work)

Antigravity's pixel-pass report claimed a **verbatim** match to `"Rules set severity. I explain & prioritize — I don't decide."` The capture `overlay_copilot_drawer_open_light.png` shows `"Rules set severity. I interpret & explain — I don't decide."`

Same defect class as **C4-A2**: Oscar's fidelity audit claimed 100% conformance for surfaces that did not exist at the audited commit, and missed a hardcoded `#000`. The claim was accepted until a coordinator grepped. **The grep-the-tree doctrine applies to copy claims too.** A report that says "verbatim" without a tree grep is not evidence.

Logged in `docs/POST_C_CHECKLIST.md`.

## Allowlist

- The files the grep actually hits (product, tests, TOKENS.md, and only the mockup/prompt files that must stay in lock-step)
- Do not edit `anomaly_detector.py`

## Acceptance

- [x] Confirming grep (2026-08-30): product + tests + incident mockup pin *"I interpret & explain"*. TOKENS.md was the remaining footer declaration that said *"I explain & prioritize"* and was amended to the live string. `docs/design/design_itsoc_overview.html` still has an older "Rules set **the** severity. I explain & prioritize" line — not the live footer; left alone as out of this light card.
- [x] Product tests already pinned the live string; they did not move.
- [x] Detector sha unchanged.

**Closed** 2026-08-30. `e4b0712` / merge `326b436`. OPEN-12(a).
