# CARD F0 — runbook legibility (worker report)

**Branch:** `feat/f0-runbook-legibility`
**Head at start:** `5978d719d59807a6e626e919df15468160b30e16` (`docs: update Stage E action cards`)
**Worker:** Claude Code (light tier). Routing: Antigravity UI evidence and Gemini copy were the
preferred tiers, both absent in the Step 3 probe; per routing policy this card was routed up to
Claude Code as the single logged fallback for both absent tiers. Codex was not used.

## Guardrail checks

| Check | Before | After |
| --- | --- | --- |
| `git branch --show-current` | `feat/f0-runbook-legibility` — matched, work proceeded | — |
| `shasum -a 256 anomaly_detector.py` | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |

The detector was never opened for edit. The freeze hash is unchanged and matches the value recorded
in `CLAUDE.md`.

## Allowlist compliance

Files touched — nothing outside the allowlist:

```
 M web/src/components/RunbookCard.tsx
 M web/src/styles/itsoc.css
 M web/src/test/c4-themes.test.tsx
 M web/src/test/runbook-card.test.tsx
?? web/src/lib/runbookCopy.ts
```

`git status --porcelain` shows no other change. **No engine or backend file is in the diff** — no
`anomaly_detector.py`, no `console/`, no `rules_*`, no `normalize.py`, no test-eval fixture.
`console/runbooks/*.yaml` and `console/runbooks.py` were **read only**, as the source of truth the
copy is transcribed from.

## What was built

### 1. `web/src/lib/runbookCopy.ts` (new)

A client-side transcription of the two shipped runbook definitions into plain language. Every field
maps to a YAML field, and the mapping is documented in the module header:

| Card line | Source field in `console/runbooks/<id>.yaml` |
| --- | --- |
| What it does | `steps[].type` / `connector` / `params_template` |
| Fires on | `trigger.rule_ids` + `trigger.entity_types` + `severity_floor` |
| Needs | `preconditions.required_evidence` |
| Steps | `steps[]`, in order, one entry per shipped step |
| Reversible? | `steps[].rollback` (mapping = undoable, explicit `null` = not) |

The copy module exists on the client because the API is the constraint, not a preference: the
`/api/incidents/<id>/runbook-recommendation` payload (`EligibleRunbook` in `web/src/lib/api.ts`)
carries only `runbookId`, `name`, `severityFloor`, `triggerRules` and `eligibilityProof`. It does
not carry steps or rollbacks, and backend files are forbidden on this card.

Grounding, line by line:

- **rb-block-ip** — "deny traffic coming in from that IP address for the next 4 hours" is
  `steps[0].params_template` (`operation: deny`, `direction: inbound`, `ttl_minutes: 240`).
  "High or Critical" is `severity_floor: HIGH`. "Partly" reversible is `steps[0].rollback` being a
  mapping (`operation: allow`) while `steps[1].rollback` is an explicit `null`.
- **rb-draft-notify** — "unsent message… nothing on any system changes" is the single
  `notify_draft` step with `requires_review: true`. "At any severity" is `severity_floor: LOW`.
  "Yes" reversible is `rollback: {operation: discard_draft}`.

Nothing else is claimed. No approval, execution, connector capability or reversibility appears that
is not written in the YAML.

**Unknown runbooks** get `UNDESCRIBED`: an honest bounded fallback that says "this screen has no
plain-language description for this runbook", renders **no step list at all**, and reports
reversibility as "Not recorded". The card still shows the rule-owned eligibility badge, so a runbook
we have no prose for is still fully and honestly surfaced.

### 2. `web/src/components/RunbookCard.tsx`

The default card now answers five questions in English: **What it does / Fires on / Needs / Steps
(numbered) / Reversible?**

Removed from the default surface: the `rb-…` id line, `floor HIGH`, and the raw trigger-rule chips
(`auth_bruteforce_success`, …). None of it was deleted — all of it moved, unchanged, into a
`<details>` disclosure that is **closed by default**:

- Ineligible card → summary reads **"Why ineligible?"**, with a plain-language lead
  ("The rules decide which runbooks fit an incident. This one does not fit yet.") followed by the
  engine's `missing[]` **verbatim**, exactly as before.
- Eligible card → summary reads **"Rule detail"** (there is no "why ineligible" to answer).

Preserved unchanged: rule-owned eligibility (the component still never computes a verdict), the
verbatim `missing[]` discipline, the muted-not-alarming ineligible badge, and the approval gate
(the card still has zero buttons — requesting lives in the Response panel, approving in Approvals).
This card renders only; describing a step is not performing one.

**Keyboard accessibility.** The card keeps `role="button"` / `tabIndex=0` / `aria-pressed` with
Enter and Space. The disclosure is a native `<summary>`, so it is focusable and toggleable with no
handler of ours; `onClick`/`onKeyDown` on the `<details>` stop propagation so opening the machinery
does not fall through to selecting the runbook (and so the card's Space handler cannot swallow the
toggle). A focus-visible outline was added for the summary.

### 3. `web/src/styles/itsoc.css`

New rules inside the existing **section 12a5 (Runbook card)** only, so the theme guard's section
parsing keeps working. Every colour is a token (`--ink`, `--ink2`, `--mut`, `--mut2`, `--bd`,
`--acc`), no hex, no rgb, and no severity token — an ineligible or undescribed runbook still reads
as information, never alarm.

### 4. Tests

`web/src/test/runbook-card.test.tsx` — 15 tests. The five C4-F1 invariants are kept intact, plus:

- both shipped runbooks render their plain copy, with **exactly** their real step counts (2 and 1);
- the honest unknown fallback renders zero list items and says so;
- **no schema vocabulary** on the default card, checked for all four card shapes against a banned
  list (`severity_floor`, `params_template`, `required_evidence`, `trigger.rule_ids`, `rule_ids`,
  `entity_types`, `record_refs`, `entity_kind`, `rollback`, `connector`, `notify_draft`, `floor`,
  `auth_bruteforce`, `possible_break_in`, and the raw runbook ids) — measured on the card's text
  with the `<details>` subtree removed, i.e. what a reader actually sees;
- the disclosure is a real `<details>`, `open === false`, and still contains the id, the floor, the
  rule ids and `missing[]`;
- keyboard: card selects on Enter and Space; summary is focusable, toggles open and closed, and
  never fires `onSelect`; a card with no `onSelect` is not in the tab order.

`web/src/test/c4-themes.test.tsx` — one added test asserting the F0 selectors are actually styled,
use no hex/rgb, borrow no severity token, and that every colour token they reference is defined in
**both** the dark and light theme blocks. Both themes therefore remain legible by construction.

## Green outputs

```
$ git branch --show-current
feat/f0-runbook-legibility

$ npm --prefix web test
 Test Files  43 passed (43)
      Tests  262 passed (262)
   Duration  17.99s

$ npm --prefix web run build
✓ 1689 modules transformed.
dist/index.html                   1.10 kB │ gzip:   0.61 kB
dist/assets/index-CiYN0Tr9.css   89.23 kB │ gzip:  16.69 kB
dist/assets/index-fsxTRU_U.js   650.98 kB │ gzip: 181.67 kB
✓ built in 1.44s

$ python3 tests/eval/run_eval.py
  cases           : 20 passed, 0 failed, 20 total
  true positives  : 16
  false positives : 0
  false negatives : 0
  precision       : 1.000
  recall          : 1.000
  f1              : 1.000
  false positives by rule type:
    (none)

$ shasum -a 256 anomaly_detector.py
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876  anomaly_detector.py
```

The chunk-size line in the build output is the repo's pre-existing advisory warning, not a failure,
and is unrelated to this card. No pytest was run, per the card.

## Deviations and judgement calls

1. **Steps are numbered 1..n, not forced to three.** The card brief says "Steps 1-2-3";
   `rb-block-ip` ships two steps and `rb-draft-notify` ships one. Padding either to three would
   invent a step that no runbook definition contains — the exact fabrication guardrail 2 forbids.
   The cards therefore render a numbered ordered list of the real steps, and a test asserts the
   counts are 2 and 1 so a future definition change has to be reflected deliberately.
2. **The prose lives on the client, not in the API.** Steps and rollbacks are not in the
   recommendation payload and backend files are outside the allowlist. `runbookCopy.ts` is
   therefore a transcription with its source field documented per line; if a later card widens the
   API, this module is the single place to delete.
3. **The disclosure is present on eligible cards too, titled "Rule detail".** The brief names only
   the "Why ineligible?" disclosure, but the raw trigger rule ids had to leave the default surface
   for *every* card, not just ineligible ones, and `incidents-response.test.tsx` (outside the
   allowlist) asserts those chips still render for an eligible card. One always-present, always
   closed disclosure satisfies both: the machinery is off the default surface, and the existing
   panel test passes unmodified.
4. **`data-runbook-id` is retained** on the card root. It is an attribute, not visible text; it
   keeps the panel's selection wiring and the existing tests addressable.
5. `npm install` was run in this worktree because `web/node_modules` was absent. `package.json` and
   `package-lock.json` are unmodified.

## Not done / out of scope

No engine, backend, API, approval or execution behaviour was touched. Eligibility remains entirely
rule-owned; this card only changes how the answer is rendered.
