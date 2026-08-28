# ITSOC Stage C — Open Items Register

_Maintained by the Stage C orchestrator. Every gating ask is recorded here in full and quoted
**verbatim** in any message that asks the owner to unblock it. Each ask stands alone — it must be
answerable without reference to prior conversation._

**Status legend:** `OPEN` = awaiting owner · `RATIFIED` = decided, actioned · `RETIRED` = no longer applies.

---

## OPEN-1 · Product-code allowlist for `threat_intel/rule_mitre_map.py` — **RATIFIED 2026-08-28 — dispatched**
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

## OPEN-2 · C1-T1 design ruling: cases with no linked incident — **RATIFIED 2026-08-28 — dispatched**
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

## OPEN-3 · C2 acceptance wording is unmeasurable as written — **RATIFIED 2026-08-28**
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

## OPEN-4 · Foreign uncommitted work in the Stage C working tree — **RATIFIED 2026-08-28**
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


---

# Ruling record — 2026-08-28

## OPEN-3 — RATIFIED and ACTIONED (commit `b6f5028`)
Owner: *"Correct catch; the acceptance was under-specified."* C2 acceptance amended in the build doc to
a measurable definition: the guard's grounding check ENFORCES (any advisory factual sentence lacking a
resolvable citation is rejected/stripped before render); the pipeline emits per-block
`{factual_sentences, cited_and_resolvable}`; the metric is the **aggregate ratio over the INC-4a7f
investigation >= 0.95**, reported in the C2 log entry with real numbers. If the guard's parser cannot
classify "factual sentence", the minimal extension is in-scope for C2's first card — **but the metric
definition is FIXED and must not be redefined to whatever is convenient to measure.**

## OPEN-4 — RATIFIED. Card HK-1 dispatched (Oscar)
Owner confirmed the orchestrator's read: not Stage C's to touch, not Stage C's contamination.
Authorized ONE housekeeping card: add `inbox/`, `hive/`, `fleet.json` and other fleet-infrastructure
paths to `.gitignore`; **commit only the `.gitignore` change**; the foreign files stay **uncommitted and
unreverted pending the owner's inspection**. The **`git add -A` prohibition is ratified as a standing
guardrail**. Follow-on (deferred until current gates clear): write `docs/STAGE_C_FLEET.md` documenting
roster, routing, liveness doctrine and inbox mechanics — fleet infrastructure operating inside the repo
undocumented is itself a gap.

## OPEN-1 — CONDITIONAL ruling received; **ASSUMPTION PARTIALLY MISMATCHES -> HELD**
Owner's constraints (1)-(3) match reality and are already satisfied by the existing table. Constraint
(4) does not: it presumes a **new module** wired into `console/investigate.py`. Reality: the mapping
**already exists** at `threat_intel/rule_mitre_map.py` and is already wired; `console/investigate.py`
does not exist (it is created in C2). This ask is a **C0 known-red repair of an existing table**, not
the creation of a C2 grounding module. Held; quoted verbatim to the owner for a scope confirmation.

## OPEN-2 — CONDITIONAL ruling received; **ASSUMPTION MISMATCHES -> HELD**
Owner's assumption: *"the C1 migration found case records with no incident linkage."* Reality:
**`console/.soc/cases.json` does not exist — there are ZERO case records.** (`console/.soc/` holds only
`auth.json` and `incidents.json`.) Nothing has been "found"; the incident-less case is a **structural
possibility the data model permits**, not an observed record set, and C1 has not run. The ruling is
sound as a **forward design**, but its premise is prospective, not retrospective. Held; quoted verbatim
to the owner.


## OPEN-1 — RESOLVED 2026-08-28: approved as re-scoped. Dispatched as card C0-T7 (Oscar).
Owner accepted the re-scope: this is a data-and-hygiene repair to an existing grounding module, not new
product surface. Allowlist granted for the threat_intel mapping module plus its tests. Constraints carry
over unchanged — static declarative table, no scoring, no LLM input, annotations never touch severity,
verdict or eligibility. Three additions were imposed. First, every name correction must cite the ATT&CK
version it is corrected against in a comment at the table head, because "correct" needs an anchor.
Second, the mutable-reference fix must return defensive copies; the owner's framing is that callers
mutating a guardrail-bearing table is the same disease as the DEFAULT_MODE finding and must be fixed the
same way. Third, eval and the TI severity-cap tests must be byte-identical green afterwards, and if any
name correction shifts a severity outcome that is a hard stop, not a manifest edit. investigate.py
wiring stays deferred to C2, confirmed.

## OPEN-2 — RESOLVED 2026-08-28: confirmed on both counts. Dispatched as card C1-T1 (Pam).
The manual-incident ruling applies structurally: the migration handles the incident-less-case shape
whether or not any instance exists today, with origin manual, the badge, and additive semantics all as
ruled. This supersedes Pam's own recommendation (iii) of keeping a separate cases store. C1-T1 must seed
fixtures — at minimum one incident-less case and one multi-incident-linked case — because a migration
acceptance that passes vacuously against an empty store proves nothing. The owner credited Pam's
read-only reconnaissance for surfacing the distinction between "found none" and "handled none".

## OPEN-5 — RECLASSIFIED 2026-08-28 by owner: a POINTER, not a deviation. Stays open, non-gating.
Two C3 findings worth the owner's awareness now rather than at C3. First, per-action step-up auth does
not exist: the auth surface is session and token only, so D3's "step-up required every time, no session
grace" needs new plumbing. The right primitive already exists — _verify_passphrase at auth.py:49-67,
constant-time via hmac.compare_digest — but it is module-private and wired to nothing; login() is its
only caller and it also mints a session. Second, and more serious: redact.py currently covers only the
LLM path. Connector request bodies bypass it entirely, masked today only by an off-by-default fence.
Guardrail 4 requires all egress through redact.py, so C3 must close this rather than inherit it.


# Ruling record — 2026-08-28 (second batch)

## C1 merge gate — DECLINED as premature, by design
Owner: C1-T1 is the first card of an in-progress phase; merging the phase branch now would land partial
phase work on main. Under autonomous mode the phase branch auto-merges **at phase completion**, when
acceptance is fully green with zero tripwires and zero unratified deviations — **not per card**. a8fa7ae
stays on the branch; the sequence continues T2 -> fan-out -> T6. Orchestrator note: this corrects my
framing — I had offered a per-card gate, which was the wrong unit.

## oob/at-risk-nuance — MERGED (owner-approved)
Suite verified green on the branch first (eval 17/17 f1 1.000, console PASSED, fsafe PASSED, intake 4/4,
itsoc_mcp 93/0, threat_intel 0 failures/3 skips, vitest 107/107, build clean, detector frozen). Merged
no-ff to main as **`63e201d`** with the carded message. Then main was brought forward into the phase
branch as **`88b5d96`** so C1 tracks current reality before T2 proceeds; gate re-run green there.

## Pam's lifecycle deferral — APPROVED
`pending-approval` and `contained` belong to C3/C4 flows; `closed` would have forced a `metrics()` edit
outside her card. Deferring was correct scope discipline, and preserving the analyst lifecycle verbatim
as `caseStatus` means nothing was lost. **The three states are now added explicitly to the C3 and C4
card inventories**, so the deferral has a named landing site rather than being a hope.

## Worktrees — ADOPTED before any further dispatch
One worktree per active worker; orchestrator owns lifecycle (create at dispatch, prune at close);
migration/store-touching cards run **exclusive**; the branch pre-check stays, now per worktree. Written
into `hive/stage-c/GUARDRAILS.md`. Live: `log-analyzer-wt/pam-c1-t2` (phase branch) and
`log-analyzer-wt/oscar-readonly` (detached — an accidental commit is impossible). The orchestrator's own
checkout at `~/Projects/log-analyzer` is now integration-only.

## OPEN-5 — RECLASSIFIED as a pointer, and one REAL finding the owner asked for
The owner's reclassification is correct: per-action step-up not existing, and connector bodies not being
redact-routed, are **what C3 exists to build**, not deviations. OPEN-5 stays as a pointer and closes when
C3's acceptance proves both.

**But the owner asked specifically whether any CURRENT egress path ships connector-like bodies
un-redacted today. It does.** `console/ti_oem.py:_http_request` (lines ~303-310) accepts a `data=` body,
encodes it, and sends it via `urllib.request.urlopen` — and **`ti_oem.py` does not import `redact.py` at
all** (grep is clean). Its consumer is the Check Point Management API connector (`_checkpoint_poll`:
login -> show-logs -> logout), so the body it posts is a **login containing credentials**. Connectors are
gated behind an `enabled` flag and are off by default, so nothing is egressing today unless a user
enables one — but the code path is live and shipping, not hypothetical. This is a **pre-existing
guardrail-4 gap in the OEM connector**, distinct from the C3 work, and it is the thing the owner said
"that's different — say so."

## Defect 5 (mislabelled metric) — logged so it cannot slip
`console/soc.py:793` exposes `mttdSeconds`, which is actually **MTTA** (`acknowledgedAt - createdAt`).
An honestly-mislabelled metric is still a dishonest surface. A one-line rename is **folded into C5's KPI
card inventory** and recorded here so it cannot be lost between phases.

## Defect 4 (fabricated revocation date in the doctored cache) — disclosure sufficient
Header disclosure stands; a clean checked-in ATT&CK fixture remains parked with future TI work.

---

## OPEN-6 · `INC-4a7f` — **RULED 2026-08-28: SEED IT, do not rename it**

Worker Oscar's C5 fact-base prep established that **`INC-4a7f` is illustrative shorthand in the build
doc, not a real fixture id.** Real incident ids are `inc-<hash[:12]>`. The actual brute-force incident on
`203.0.113.44` in `sample-2.log` is **`inc-d5e79b3ca9b5`** (CRITICAL, T1110).

This matters because **two acceptance criteria name it**, and both become unmeasurable as written:

1. **C2:** *"INC-4a7f case assembles < 2 min"*.
2. **C2, as amended under OPEN-3 by owner ruling:** *"the acceptance metric is the aggregate ratio over
   the INC-4a7f investigation >= 0.95"*. This is the same class of defect OPEN-3 itself fixed — an
   acceptance that cannot be executed against reality.

Orchestrator recommendation: amend both to name the incident **dynamically** — "the brute-force incident
derived from `sample-2.log` for entity `203.0.113.44`" — rather than hardcoding either `INC-4a7f` or
`inc-d5e79b3ca9b5`, since the hash id is derived and would change if the fixture or clustering changed.
That keeps the acceptance executable without pinning it to a volatile value.

> **THE ASK:** Approve amending the two C2 acceptance criteria to identify the incident dynamically by
> its source fixture and entity, instead of the non-existent `INC-4a7f`? Also confirm whether the C5
> demo script should capture the id at runtime (orchestrator recommends yes).

## OPEN-7 · Battle-card headline figure — **RULED 2026-08-28: literature citation, pinned**

Oscar fact-checked every claim the build doc implies for `docs/BATTLECARD_TORQ.md`:

- **"Cyber Defense Benchmark ~3.8%"** — **NO in-repo evidence whatsoever.** Nothing in this repo computes
  or contains that figure. It requires a **real external citation** to a published source, and must never
  be presented as something evaluated in-repo.
- **"Under-5-minute demo with the human gate"** — unassertable in advance; must be **measured live** and
  recorded honestly even if it misses.
- **Verdict trust**, **data sovereignty**, and **provable gating** are all **fully supported in-repo**,
  with named backing files.

One caveat the orchestrator adds: the *data sovereignty / all-egress-through-redact* claim currently has
a real exception — `console/ti_oem.py` sends connector bodies without importing `redact.py` at all (see
the OPEN-5 ruling record). That exception must be closed, or the claim qualified, before it appears in a
competitive document. Overstating it there would be exactly the failure mode the honesty rules exist to
prevent.

> **THE ASK:** Supply (or authorise sourcing) a real citation for the ~3.8% figure before C5 drafts the
> battle card — or direct that the claim be dropped. The orchestrator will not let an unsourced number
> into a competitive document.


# Ruling record — 2026-08-28 (third batch). REGISTER IS NOW CLEAR OF OWNER GATES.

## OPEN-6 — RULED: seed the scenario, do not rename it
The orchestrator proposed renaming to a dynamic identifier. **The owner overruled that, correctly.**
`INC-4a7f` comes from the design kit: it is the canonical demo scenario (brute-force,
**203.0.113.44 -> server-01**) named by the prototype, the sample-data plan and the C5 demo script. So the
name stays and the fixture gets created.

**C2 gains an explicit fixture obligation as its FIRST card**, landing before the investigation-engine
cards run against it: seed the INC-4a7f scenario as deterministic sample data — a log fixture that fires
the brute-force rule and correlates to an incident carrying that id, or an id-mapping since ids are
derived as `inc-<hash[:12]>`. Both C2 acceptance criteria now read **"the seeded INC-4a7f brute-force
scenario (203.0.113.44 -> server-01)"**, so it is self-evidently a fixture rather than an assumed
pre-existing record. **The acceptance scenario and the C5 demo scenario are now the same object** — which
is the point, and is better than the orchestrator's proposal.

## OPEN-7 — RULED: it is a literature citation, and the battle card must say so
The figure is **not** a claim about itsoc, which is why no in-repo evidence exists. It is evidence against
**LLM-owned verdicts generally** — the very thing itsoc's architecture rejects.

Source: **arXiv 2604.19533**, Cyber Defense Benchmark. Claim, precisely: the best frontier LLM flagged
**~3.8% of malicious events**; **no model passed 50% per-tactic**.

Binding representation rules, now recorded in `docs/research/CITATIONS.md`: cite the arXiv id; state the
claim precisely; **do not round it**; **do not invert it into "LLMs miss 96%"**; never imply it was
measured in-repo. C5's card gains the obligation to archive title, id, retrieval date and the exact
sentence relied on.

**Standing rule for all future figures:** repo-provable claims get repo evidence; literature claims get
pinned citations; **nothing floats.**

## Out-of-allowlist defects — ratified as doctrine
Fix at an **owned seam** when one exists; otherwise **report**. Never edit a foreign component. Precedent:
the `severity: null` sidebar crash, fixed at the `normIncident` api seam with a null-path test rather than
by reaching into `AppShell.tsx`. Written into `hive/stage-c/GUARDRAILS.md`.

## Register status
OPEN-1 ruled · OPEN-2 ruled · OPEN-3 ruled · OPEN-4 ruled · OPEN-5 open by design, pointing at C3 ·
OPEN-6 ruled · OPEN-7 ruled. **Nothing gates on the owner.**

---

## OPEN-8 · Pre-existing cross-file test isolation bug in `shell.test.tsx` — **OPEN, non-gating**

Surfaced by the owner-mandated shuffled-order verification on C1-T5. **The owner's instinct to demand
that run was right — it found something the normal-order gate cannot see.**

**Measured (god, on `stage-c/c1-fanout-sources`, T5's branch):** normal order 115/115 green; shuffled
order green on one seed but **FAILED on two of three seeds**, with `src/test/shell.test.tsx` failing
("houses Experimental group and toggles its visibility", "renders the top bar header actions and ⌘K
trigger").

**Measured on the TEMPLATE BASE `069ff19`, WITHOUT T5:** shuffled order failed on **three of three**
seeds — `shell.test.tsx` every time, plus `unrecognized-honesty.test.tsx` on one.

**Conclusion: PRE-EXISTING, and T5 strictly IMPROVED it.** Zero delta introduced; the base is worse than
the branch. Pam's global `afterEach(useJobs.getState()._reset())` in `web/src/test/setup.ts` genuinely
fixed the upload-store leak she diagnosed. A **second, independent** isolation bug remains in
`shell.test.tsx` — some module-level state it neither resets nor owns.

**Why this matters beyond tidiness:** a suite that only passes in one file order is not really green. It
means at least one existing test depends on state leaked from another file, so the standing gate has
been reporting a slightly optimistic result all along.

> **THE ASK (non-gating, C1 can proceed):** authorise a small card to find and reset the remaining
> module-level state `shell.test.tsx` depends on — same shape as Pam's fix, at an owned seam in
> `web/src/test/`. Orchestrator recommends folding it into the C1 integration rather than blocking a
> fan-out unit, and adding `--sequence.shuffle` to the standing gate afterwards so the suite cannot
> silently regress to order-dependence again.

---

## OPEN-9 · C3 prerequisite: the Docker daemon is not running — **human action, not gating until C3**

Oscar's C3 feasibility established that the Docker **CLI is installed (28.1.1)** but the **daemon is not
running** — `docker info` fails to connect. No code dependency is blocked and nothing in C0/C1/C2 needs
it, but **C3's live end-to-end acceptance cannot run without it**, and starting Docker Desktop is an
action only the owner can take on their own machine.

Recorded now rather than discovered mid-C3. Everything else about the target is settled: Alpine 3.20
recommended, the nft bootstrap/preview/execute/verify/revoke bodies are written, revoke is provably
atomic and cannot touch a bystander (blocks are elements of a dedicated `itsoc` set, each tagged
`comment "itsoc:appr-<id>"`), `console/.soc/` is confirmed gitignored so keys stay untracked, and only
`key_path` ever enters config — never the key value.

**Host firewall risk assessed as ZERO**, conditional on one hard rule now recorded in
`hive/stage-c/GUARDRAILS.md`: the container **must never** be started with `--net=host`. The entire
isolation argument depends on the container having its own network namespace.

> **THE ASK (no action needed until C3 opens):** start the Docker daemon before C3's live acceptance,
> or tell me to mark that item BLOCKED and build C3 against the abstract connector with a mock.

---

## OPEN-10 · `main` moved outside Stage C; concurrent queue is active again — **OPEN, owner decision**

While the orchestrator was idle, local `main` advanced **outside Stage C**: a concurrent task queue
merged `feat/asset-risk-weight` (`b6a4d53`, merge commit `a79791a`).

**Stage C is intact — verified, not assumed.** All Stage C commits remain ancestors of `main`
(`18b03dd` C0 merge, `63e201d` oob merge, `09f73f0` C1 merge, `c30588d` and `3c11674` docs). The gate on
`main` is green — eval 17/17 f1 1.000, `console/test_console.py` PASSED, detector `364577c5…a4a876`
frozen. Nothing was lost.

**Two consequences the owner should rule on.**

**1. Probable duplicate implementation.** `b6a4d53` changes `console/soc.py`, `OpsMetrics.tsx`,
`Assets.tsx` and `assets.test.tsx` — the *same four files*, implementing the *same* severity-weighted
asset risk, that the owner already ratified and the orchestrator rehomed to `oob/at-risk-nuance`
(merged as `63e201d`). `main` may now carry that feature twice, applied through two routes. It currently
reconciles cleanly and the gate is green, so this is not breakage — but it is duplicated provenance, and
the rehoming exercise it duplicates was done at the owner's explicit direction.

**2. New foreign work is in the integration checkout again.** `normalize.py` is modified (+16) and
`console/formats/jsonlog.py` and `console/formats/rfc5424.py` are new and untracked — that queue's card
`007-rfc5424-json-parsers`. The "uncommitted foreign changes" state that OPEN-4 retired has therefore
returned, because the queue that produces it is still running.

**Worktree isolation contained this exactly as intended.** Every Stage C worker is in its own worktree,
so none of this reached our branches, and the orchestrator noticed only because a new worktree checked
out at an unexpected commit. That is the adoption paying for itself a second time.

> **THE ASK:** how should Stage C coexist with the concurrent queue on shared `main`? Options: (A) the
> concurrent queue pauses while Stage C runs; (B) Stage C stops treating `main` as stable and branches
> only from tagged Stage C merge points; (C) the concurrent queue moves to its own branch and merges on
> your gate like everything else. Also: should the duplicated at-risk implementation be reconciled, or is
> carrying both acceptable? The orchestrator will not unilaterally revert another actor's merge.
