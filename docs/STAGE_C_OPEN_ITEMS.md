# ITSOC Stage C — Open Items Register

_Maintained by the Stage C orchestrator. Every gating ask is recorded here in full and quoted
**verbatim** in any message that asks the owner to unblock it. Each ask stands alone — it must be
answerable without reference to prior conversation._

**Status legend:** `OPEN` = awaiting owner · `RATIFIED` = decided, actioned · `RETIRED` = no longer applies.

---

## OPEN-1 · Product-code allowlist for `threat_intel/rule_mitre_map.py` — **OPEN**
_Gates: Phase C1 (owner required a zero-known-red baseline before C1 opens)._

**Background.** Card C0-T6 (worker Oscar, commit `7db891b`) cleared the test-side portion of the 16
`threat_intel/test_threat_intel.py` failures: 3 became expected-skips carrying the visible reason string
`doctored cache fixture — needs a live/large ATT&CK fixture`, and the stale unmapped-rule examples were
corrected. Verified by god: product code untouched, zero check lines removed, standing gate green.

**12 failures remain**, and none can be honestly fixed test-side — making the test accept a stale name
would be masking, which guardrail 2 forbids. The correct fix is product code:

- **Genuine upstream MITRE renames** (our table is out of date; the local cache already has the correct
  modern names, so a `--refresh` fixes none of these):
  - `T1499.002` — table says `'Service Exhaustion'`, real name is **`'Service Exhaustion Flood'`** —
    8 rules at `rule_mitre_map.py` lines 6, 7, 8, 40, 41, 42, 43, 44.
  - `T1046` — table says `'Network Service Scanning'`, real name is
    **`'Network Service Discovery'`** — line 22.
  - `T1136.001` — parent:sub vs bare-sub naming mismatch — line 38.
- **Two genuine defects:**
  - `techniques_for_rule` (lines 46-48) does a plain `dict.get` and returns the table's **own list/dict
    objects**, so any caller can mutate the shared mapping table. Fix: return deep copies.
  - An `'ioc_observed': []` sentinel (line 12) fails the well-formedness check.

**Blast radius is low:** the file header states *"MITRE mappings are derived annotations only; they do
not determine severity/verdict."* Oscar has prepared exact before→after strings.

> **THE ASK:** Approve a one-shot card with allowlist `threat_intel/rule_mitre_map.py` +
> `threat_intel/test_threat_intel.py`? Acceptance: that suite reports 0 failures / 3 reasoned skips,
> everything else green.
> **Orchestrator recommends YES** — it is the last item between us and the zero-known-red C1 baseline.

---

## OPEN-2 · C1-T1 design ruling: cases with no linked incident — **OPEN**
_Gates: Phase C1 card C1-T1 (backend migration)._

**Background.** Worker Pam's read-only inventory established that build doc §1 — *"Existing case records
migrate into incident metadata (additive migration in `soc.py`)"* — is **not literally implementable**:

1. **Incidents are DERIVED and ephemeral per run.** `sync_incidents` (`console/soc.py:212-225`)
   recomputes title/severity/findingIds/createdAt on **every** analysis and preserves **only**
   `state`, `acknowledgedAt`, `resolvedAt` (lines 221-224). Case data written into any derived field
   would look correct and then be **silently wiped on the next run**.
2. **A case with `links.incidents == []` has no merge target at all** — a *model* gap, not a field gap.
3. Cases link **many-to-many** with incidents; copying notes into all N duplicates, into one is arbitrary.
4. **Status enums do not line up:** 3 case statuses vs 4 current incident states vs the 5 target
   lifecycle states; only `investigating` maps 1:1.
5. `cases.json` **does not exist** — 0 cases persisted, so a migration test would pass **vacuously**
   without a seeded fixture. (`incidents.json` holds 30, all `state:'new'`.)
6. `console/export.py` has **no case exporter** — the required honest legacy export is net-new code and
   must route through `redact.py`.

**Pam's additive-safe design, which the orchestrator concurs with:**
(i) add case metadata (`id`/`notes`/`assignee`/`caseTitle`/`caseStatus`/`caseCreatedAt`/`caseUpdatedAt`)
as a **preserved `cases[]` sub-structure** on the incident; (ii) **extend the sync preserve-list at
`soc.py:221-224`** so it survives re-derivation; (iii) **keep a real cases store** for incident-less
cases rather than fabricating a holding incident; (iv) an explicit documented status map; (v) a
redact-routed honest legacy export.

Item (iii) departs from a literal "merge into incidents" reading, though it honours the build doc's own
*"Nothing is deleted from storage — screens merge, stores migrate additively."*

> **THE ASK:** Ratify this design (particularly item (iii), keeping a cases store for incident-less
> cases) before C1-T1 is dispatched? If ratified it is logged as a deviation with owner sign-off.
> **Orchestrator recommends ratifying.**

---

## OPEN-3 · C2 acceptance wording is unmeasurable as written — **OPEN**
_Gates: Phase C2 acceptance (not blocking C1)._

Build doc Phase C2 acceptance says *"≥ 95% advisory citation coverage measured by the guard."* Worker
Toby's read-only inventory of `explanation_guard.verify_explanation` (`explanation_guard.py:186`) found
the guard measures **grounding** — that every IPv4, quoted username, host-like token, and numeric count
in the prose exists in the finding's deterministic corpus — and returns `{ok, reasons[]}`.

It **cannot** measure citation *markers* (`[1]`, `{line 42}`), citation density, or paragraph
completeness. So "citation coverage measured by the guard" has no implementation.

> **THE ASK:** Amend the C2 acceptance to **"≥ 95% grounding pass rate measured by
> `explanation_guard`"**? Orchestrator recommends yes; it is what the guard actually measures.

---

## OPEN-4 · Foreign uncommitted work in the Stage C working tree — **OPEN**
_Not a Stage C breach. Raised for the owner's decision because it affects gate integrity._

`/Users/ankit/Projects/log-analyzer/` contains a **second, independent task queue** at `inbox/`
(untracked, and **not gitignored**): `001`–`005` in `inbox/.done/` (the pre-Stage-C redesign phases),
with `006-asset-risk-weight.md`, `007-rfc5424-json-parsers.md`, `008-efficacy-harness.md`,
`009-live-tail-input.md` still pending.

Someone/something is working that queue **concurrently in the same working tree**. Uncommitted edits
implementing card `006` (severity-weighted asset risk, sourced from `ITSOC_REDESIGN_SPEC.md` §Phase 4 —
**not** Stage C) appeared at **11:20-11:22**, after the C0 merge at **11:01**:
```
 console/soc.py                    |  9 +++---   (assetsAtRisk/usersAtRisk -> HIGH+ only)
 web/src/components/OpsMetrics.tsx |  2 +-
 web/src/pages/Assets.tsx          | 40 ++++++---  (RiskTag -> severity-weighted)
 web/src/test/assets.test.tsx      |  8 ++---
```
**Not touched by any Stage C worker** — no Stage C card's allowlist includes any of those files.

Two real hazards: (1) `inbox/` is not gitignored, so any `git add -A` would commit a foreign work
queue — every Stage C card explicitly forbids `git add -A`, which is why it has not happened; (2)
future Stage C gates would be measuring foreign uncommitted changes. The C0 exit gate and post-merge
gate both ran **before** these appeared, so no Stage C result is contaminated.

The orchestrator has **not** reverted or committed these — they are not Stage C's to touch.

> **THE ASK:** How should Stage C treat this concurrent queue? Options: (A) it is your other session,
> leave it alone and I will stash-and-restore around each Stage C gate; (B) pause it while Stage C
> runs; (C) something else. Also: should `inbox/` be gitignored to remove the `git add -A` hazard?
