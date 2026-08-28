# ITSOC Stage C — Progress Report

**As of:** 2026-08-28 · **Orchestrator:** god (Michael) · **Owner / sole merge authority:** Ankit
**Repo:** `~/Projects/log-analyzer` · **Push authority:** Q1 = (c) never — *nothing has been pushed*
**Detector:** frozen at `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — **unchanged in every commit**

---

## 1. Headline status

**Phase C0 is COMPLETE and merged to local `main`. Phase C1 is IN PROGRESS with its first card delivered.**

| Phase | State | Detail |
|---|---|---|
| **C0 — Foundations** | ✅ **COMPLETE, merged** | 8 cards; merge commit `18b03dd` |
| **C1 — Screen & store consolidation** | 🔄 **In progress** | C1-T1 delivered (`a8fa7ae`), awaiting merge gate |
| C2 — Investigation engine | ⏸ Not started | prep inventory complete |
| C3 — Gated response | ⏸ Not started | prep inventory complete |
| C4 — Response UI | ⏸ Not started | prep inventory complete |
| C5 — Demo hardening | ⏸ Not started | prep inventory complete |

`main` is **28 commits ahead of `origin/main`**, all local. Working tree is **clean**.

---

## 2. What was actually built

### Phase C0 — Foundations (merged at `18b03dd`)

| Card | Commit | Worker | What it delivered |
|---|---|---|---|
| C0-T0 | `c963b20` | Claude Code | Honest unrecognized/empty ingestion. Moved the environment gate from 7/8 to **8/8** |
| C0-T1 | `0e7af92` | Claude Code | Runbook schema + **structurally LLM-closed** eligibility engine; `rb-block-ip`, `rb-draft-notify` |
| C0-T2 | `4ba2530` | Claude Code | `fsafe.py` recovered; append-only **hash-chained audit ledger**; additive sqlite index |
| C0-T3 | `cbd3099` | Claude Code | TI severity **cap** (CRITICAL unreachable from threat intel); path-only TAXII auth |
| C0-T4 | `141db71` (+ fix `649aea4`) | **Toby** | Runbook terminology sweep |
| C0-T5 | `261f226` | **Jim** | Aligned `itsoc_mcp` severity assertion to the new cap |
| C0-T6 | `7db891b` | **Oscar** | Test-side TI repair: 3 reasoned skips, zero tests deleted |
| C0-T7 / T7a | `3998f06` / `538e414` | **Oscar** | ATT&CK name corrections, defensive copies, pinned version anchor |

### Phase C1 — Consolidation (in progress)

**C1-T1 delivered** — `a8fa7ae` on `stage-c/c1-consolidation`, 6 files, **+445/−2**, worker Pam.
Cases → Incidents additive migration: preserved `cases[]` sub-structure, extended sync preserve-block,
incident-less cases become first-class **manual incidents** (`origin: manual`, badged
*"MANUAL — analyst-created, no rule verdict"*), explicit status map, redact-routed legacy export.
**Awaiting the owner's merge gate.**

### Out-of-band

`oob/at-risk-nuance` → `f0e65df`, 4 files, +40/−19. Ratified pre-Stage-C orphaned work, rehomed to its
own branch and **deliberately never absorbed into Stage C**. Awaiting a separate merge gate.

---

## 3. Test baseline — green on `main`

`tests/eval/run_eval.py` 17/17, precision 1.000, recall 1.000, **f1 1.000** · `console/test_console.py`
PASSED · `console/test_fsafe.py` PASSED (10 checks) · `tests/test_intake.py` 4/4 *(was 3 errors at
pre-flight)* · `itsoc_mcp/test_mcp.py` 93/0 · `threat_intel/test_threat_intel.py` **0 failures, 3
reasoned skips** · vitest 107/107 · `npm run build` clean.

**Note:** `pytest` is not installed and was deliberately not installed. The above canonical suites are
the green-bar wherever the build doc says "pytest".

---

## 4. Guarantees proven, not asserted

Every worker claim was independently re-run by the orchestrator. Several were attacked adversarially:

- **Rules own eligibility.** `inspect.signature(eligible)` → `(runbook, incident, findings)`, no
  `*args`/`**kwargs`. Poisoned an incident and all findings with `llmSev: CRITICAL`, `llmWhy`,
  `advisory`: could **neither force nor suppress** a verdict. Also proved **non-vacuity** — the positive
  path genuinely reaches `eligible: True`, so the guarantee isn't passing for the wrong reason.
- **Audit chain honest under attack.** Tampered a middle entry → break reported at the **correct index**;
  re-reading does not self-heal; appending afterwards does **not** launder the break.
- **Migration additive.** Re-run on a `copy2` of the live 7.9 MB store: `+audit_index` only, zero drops,
  zero row changes, live DB untouched. Retention can never reach audit evidence.
- **Defensive copies hold.** Mutated the list returned by `techniques_for_rule` and appended to it — the
  guardrail-bearing table stayed intact.
- **TI cap holds.** CRITICAL is unreachable from threat intel; the feed may only de-escalate.

---

## 5. Deviations (owner-ratified, none absorbed silently)

**D-1 — build doc self-contradiction.** Line 49 named a literal `--taxii-token`; a value-taking flag puts
the secret in `argv` (visible via `ps`), contradicting §4 guardrail 4. Resolved toward the guardrail
(path-only auth), build doc amended, owner-ratified. **Precedent now binding on every worker: where the
build doc's letter contradicts §4, §4 wins — implement the guardrail form, but halt and report.**

**D-2 — reference connector changed (owner-initiated).** OPNsense VM → **nftables-over-SSH against a
local Docker target**. `opnsense.py` becomes the designated follow-on behind the same abstract interface.
C3 acceptance and the C5 demo line amended; **"BLOCKED — VM required" retired**.

---

## 6. Defects found that pre-dated Stage C

Prep inventories surfaced real problems in shipping code:

1. **Fake-green on unrecognized input** — `run()` force-parsed unknown formats into `generic_text`, so an
   11-line unparseable file reported "0 findings / 11 lines parsed". Guardrail-4 violation. **Fixed (C0-T0).**
2. **Collector can drop silently** — `syslog_collector.py` has no ingestion queue; under load the OS
   kernel discards UDP datagrams before Python sees them, and the counter only increments *after*
   `recvfrom`. Violates "never silently drop an event". **C5 will fix; documented.**
3. **Deterministic path blocks on the LLM** — `serve.py:1425-1426` waits for the model before returning
   RCA, though facts resolve in <1 ms. **D2 forbids this; now C2's central constraint.**
4. **Doctored ATT&CK cache** — the local fixture has no `defense-evasion` tactic, invents 'Stealth' and
   'Defense Impairment', and marks `T1070.001` revoked with a **fabricated 2026-04-14 date**. Disclosed
   in the mapping header so nobody mistakes it for clean provenance.
5. **Mislabelled metric** — `soc.py:793` `mttdSeconds` is actually MTTA.
6. **Connector egress bypasses `redact.py`** — see OPEN-5.

---

## 7. Open items

| # | Item | Status |
|---|---|---|
| OPEN-1 | Product-code allowlist for the MITRE mapping | ✅ Ratified, delivered |
| OPEN-2 | Incident-less cases design | ✅ Ratified, delivered |
| OPEN-3 | C2 citation-coverage acceptance unmeasurable | ✅ Ratified, build doc amended |
| OPEN-4 | Foreign uncommitted work in the tree | ✅ Ratified, rehomed; **state retired** |
| OPEN-5 | C3: per-action step-up doesn't exist; connector bodies bypass `redact.py` | ⚠️ **Open**, not gating |

**Also awaiting a ruling:** Pam's precedence deferral (the `pending-approval`/`contained`/`closed`
lifecycle states were *not* introduced in C1 — they are C3/C4 flow, and `closed` would require editing
`metrics()`). Analyst lifecycle is preserved verbatim as `caseStatus`, so nothing is lost.

---

## 8. Systemic risk — recommend a decision before C2

**All agents share one working tree.** This bit a single card twice: a foreign edit inside a worker's
allowlist file, and a concurrent HEAD switch that landed a commit on the wrong branch. Both were
recoverable only because the worker was careful. For migration-bearing cards this is a live corruption
vector. **Git worktrees would remove it structurally.**

---

## 9. Process rules now binding

- **`git add -A` is prohibited** — stage allowlist files by explicit path.
- **Branch pre-work check** — verify `git rev-parse --abbrev-ref HEAD` against the card's `branch:` field
  *before the first edit*. A mismatch is a stop before work, not a cleanup after.
- **Liveness doctrine** — delivery is the signal; `fleet.json` token/`lastTool` counters are unreliable
  and must never justify a stall call. Required sequence: delivered? → `memory.md` → `inbox/`.
  Reassign, never respawn; a recovered slot takes a *new* card.
- **Reference recovery pattern** — backup first; restore the foreign hunk to its HEAD form verbatim;
  `checkout -B` preserving the tree; selective commit; foreign work survives uncommitted.
- **Open items stand alone** — a gating item is quoted in full, inline, as plain prose.
- **Phase order** — prep and inventory anytime; execution strictly in phase order.

---

## 10. Next steps

1. Owner merge gate on **`stage-c/c1-consolidation`** (`a8fa7ae`).
2. Owner merge gate on **`oob/at-risk-nuance`** (`f0e65df`).
3. Confirm Pam's lifecycle-state deferral.
4. Decide on **git worktrees** before C2 opens.
5. Remaining C1 cards (T2 Incidents template → T3/T4/T5 fan-out → T6 nav/⌘K) are drafted and ready.
