# Stage C — Orchestrator Handoff

Written at a model change. Everything a successor orchestrator needs to resume without re-deriving.
Authoritative companions: `docs/STAGE_C_LOG.md` (per-phase execution record),
`docs/STAGE_C_OPEN_ITEMS.md` (every gating ask + owner rulings), `docs/STAGE_C_ANSWERS.md` (Q1–Q6),
`docs/research/CITATIONS.md` (provenance), `hive/stage-c/GUARDRAILS.md` (worker-facing binding rules).

## 1. Role and standing constraints (owner-set, never relax)

Orchestrator for Stage C at `~/Projects/log-analyzer`. **Plan, route, verify, report — do not build
unless routed to you.** The owner (Ankit) is the only merge authority for anything leaving local.

- **Never push. Never touch `anomaly_detector.py`; never let a worker touch it.** A task that seems to
  require it is a STOP-and-ask.
- Detector sha must remain `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.
- **Q1 push authority = (c) NEVER.** Nothing reaches GitHub during this run. Local `main` only.
- Phase order **C0→C1→C2→C3→C4→C5 is binding.** Prep, inventory and card-drafting are allowed at any
  time; execution is not.
- **Autonomous mode:** a phase whose acceptance is fully green with zero tripwires and zero unratified
  deviations auto-merges to local `main` and the next phase opens without asking. Hard stops remain:
  any tripwire, any unratified deviation, any BLOCKED acceptance item, or any item failing after two
  repair attempts.
- **`git add -A` is prohibited.** Stage allowlist files by explicit path.
- Credentials never in CLI args or logs; key **paths** only in config, never key values; passphrases
  never in chat, answers files, cards or logs. Q3: the owner's local profile passphrase is the
  production step-up identity — never request it.
- When asking the owner for a ruling, **quote the relevant register entries verbatim inline** as plain
  flowing text (no box drawing, no columns) — the ask must stand alone.
- Dispatch to the **named hive agents via `agents/god/outbox/`**, not Agent-tool subagents.

## 2. Where the work is

Local `main` = **`c9a7107`**, ~80 commits ahead of origin, nothing pushed.

Phases C0 (`18b03dd`), C1 (`09f73f0`), C2 (`b231163`), C3 (`04e9b52`) are merged to local main.
Out-of-band merged: `1644da8` (TI/OEM egress), `dc36a5d` (egress label), `c9a7107` (OPEN-13).

**C4 is open and unmerged.** Phase branch `stage-c/c4-response-ui` = `b5356d3` (holds C4-T1 Approvals
screen + C4-T2 audit timeline + the OPEN-13 fix). Integration worktree `.../log-analyzer-wt/c4`.

| Branch | Head | State |
|---|---|---|
| `stage-c/c4-response-ui` | `b5356d3` | phase branch, integrated base |
| `stage-c/c4-fanout-runbook` | `21b8891` | **C4-F1 JUST DELIVERED — unverified** |
| `stage-c/c4-fanout-advisory` | `b3164ef` | C4-F2 accepted, unmerged |
| `stage-c/c4-fanout-priority` | `1ae8d43` | C4-F3 accepted, unmerged |
| `stage-c/c4theme` | `b5356d3` | C4-A1 dispatched, not started |
| `stage-c/c4fidelity` | `316a94b` | C4-A2 **rejected**, repair C4-A2a in flight |

`/Users/ankit/Projects/log-analyzer` is **integration-only** — never let a worker write there.
One worktree per active worker; the orchestrator owns worktree lifecycle and **seeds the gitignored
`console/.soc/` fixture (`soc_history.db` + `auth.json`) at creation**, else store-touching suites
report a spurious `NOT TESTED`. Fresh worktrees have no `node_modules`; run `npm ci` (pre-run it while
workers are idle). **Never share one `node_modules` across worktrees** — vitest caches in
`node_modules/.vite` and concurrent runs collide.

## 3. Immediate next actions

1. **Verify C4-F1 (`21b8891`, Pam) by attack.** Its stated invariant: the INELIGIBLE badge must be
   muted and must never match the severity/crit family. Mutate the badge class to a severity class and
   confirm tests fail. Also confirm: `missing[]` rendered verbatim; exactly one `.is-btn--primary` in
   the Incidents view; no approve control in the panel; `runbooks.eligible()` signature still the
   closed `(runbook, incident, findings)`. Files touched are within the granted allowlist including
   the ratified `tests/test_recommend.py`.
2. **C4-A2a** (Oscar) — repair attempt 1 of 2 outstanding. See §5.
3. **C4-A1** (Toby) — both-themes acceptance, dispatched, not started.
4. Integrate F1+F2+F3 into `stage-c/c4-response-ui` from the one base, run the integrated gate, then
   the two acceptance items must be green before C4 can close.
5. C4 acceptance also requires: approve control in exactly one component (**proven**), keyboard path
   (**proven**), both themes (**C4-A1**), screenshots vs dc-fidelity bar (**C4-A2a**).

## 4. Gate commands (run from the branch's worktree)

```
python3 console/test_console.py            # ~35 subsystem groups
python3 tests/test_approvals.py            # 14
python3 tests/test_recommend.py            # 12
python3 tests/test_audit_drift.py          # 4  (authority fixture guard)
python3 tests/test_ti_oem_egress.py        # 3
python3 tests/eval/run_eval.py             # 19/19, f1 1.000
python3 console/test_fsafe.py ; python3 tests/test_intake.py ; python3 itsoc_mcp/test_mcp.py  # 131
cd web && npm test                         # carries --sequence.shuffle; 164 on the C4 base
shasum -a 256 anomaly_detector.py          # must be unchanged
```
After any `npm run build`, restore `web/dist` (`git checkout -- web/dist` + remove new hashed files).
**Committed build output is a standing tripwire** and has fired once.

## 5. Open items with the owner

- **OPEN-10** — a concurrent non-Stage-C queue writes to shared `main`. Has caused two incidents.
  Foreign-work inventory (untouched, for the owner's keep/revert): `tools/attack_generator.py`,
  `tools/efficacy_data/`, `tools/efficacy_score.py`, plus recurring `web/dist` churn.
- **Meredith (`meredith-mtconud5`) is non-functional, not idle** — 43 unconsumed messages, `.done/`
  never created, zero processed all run. Parked pending the owner's kill/replace call. Nothing depends
  on her. Do not route work to her; do not spawn a replacement (the floor does not need one).
- **C4-A2a** in flight: Oscar's fidelity audit claimed 100% conformance for five surfaces, but three
  (`is-runbook-card`, `is-advisory-timeout`, priority chip) do not exist at the audited commit
  `b5356d3` — they live on unmerged branches. Also `itsoc.css:242` has a hardcoded `#000` inside the
  audited subsection, contradicting the 100% claim. Repair attempt 1 of 2.

Rulings already given and binding: **OPEN-9** the Docker daemon is a run-level environment
requirement — if it is down the live item **reverts to BLOCKED** and the owner is notified, never
substituted by the mock. **OPEN-11** Guardrail 4 narrowed (wire carries minimum required indicator and
auth values; every log, stored error, display and exception carries the redacted + credential-masked
representation) and external TI/OEM connectors ship **disabled by default** with an honest egress
label. **OPEN-12** out-of-allowlist authority split by blast radius (see §6). **OPEN-13** closed.

## 6. Doctrine earned in this run — the part worth keeping

- **Security components are accepted by attack, not by green.** Mutate the guarantee, observe the
  tests fail, restore, re-run green. A passing suite proves the tests ran, not that they bind.
  Generalised: **a guard that has never been seen to fail is not yet a guard.**
- **A mutation that does not compile proves nothing.** vitest reports "no tests", which reads like a
  pass. Make the mutation valid code.
- **Read pasted evidence for what is MISSING.** The C3 fake-containment bug — an nft chain with no
  enforcement rule, so a block would record without enforcing — was visible in a worker report that
  otherwise read as a pass.
- **`2>/dev/null || true` on setup commands is an honesty defect, not style.** It turned a broken
  container into a healthy-looking one.
- **Before believing an audit, grep the commit it claims to have examined** for what it claims to have
  found.
- **A drift-guard must exercise the artifact in use.** Comparing an authority against a retyped copy
  guards nothing. Reduce the number of independent implementations: one authority, one authority-
  emitted fixture, consumers reading the fixture.
- **Out-of-allowlist diffs (OPEN-12):** (a) non-behavioral — comments, docstrings, formatting,
  test-isolation, documented seam-fixes — the orchestrator ratifies and logs as a deviation, after
  reading every hunk; (b) behavioral — product logic, schemas, egress, auth, anything within one
  import of the detector — **halts for the owner regardless of how right the worker seems.**
- **Pre-dispatch card check (binding):** "does this ask plausibly require files beyond its allowlist?
  If yes, fix the card, not the worker's discipline." **Grep where the behaviour actually lives before
  writing an allowlist** — six cards in this run had allowlists scoped from assumption and the worker
  was right every time.
- **Verify a dispatch landed by grepping the RECIPIENT's inbox**, not by watching the outbox drain.
  Three fan-out cards were silently lost to an unquoted heredoc whose backticks the shell substituted.
  **Always write message JSON with a quoted heredoc (`<<'JSON'`).** A `FileNotFoundError` on a
  post-write validation usually means the harness already collected the file, not a write failure.
- **The injected roster is authoritative.** When an agent id vanishes, any in-flight card to it is dead
  and must be re-issued self-contained. This fired twice.
- **A stand-down is not a lock** — plan to reconcile duplicate deliveries rather than assuming one.
- **Delivery is the signal**; `fleet.json` token/`lastTool` counters are unreliable, and a large inbox
  count is a symptom to diagnose (read senders, check `.done/`), not a number to report.
- **"Queued-not-started" is a hypothesis, not an observation.** Check before reporting it.
- **A live run against the real `.soc` mutates fixtures other tests depend on.** The C3 e2e applied the
  `audit_index` migration and made the additive-migration check vacuous. Snapshot first or redirect
  every module — including `audit` — to a temp `SOC_DIR`.
- **Pre-empt foreseeable boundary questions.** Watching a worker's `git status` against the allowlist
  granted, and ratifying in advance, is cheaper than the stall.
- **Reuse a rule-owned endpoint rather than re-deriving state.** The Response panel reads
  `GET /api/incidents/<id>/runbook-recommendation` so it *cannot* disagree with the eligibility engine.

## 7. C5 — not started, execution forbidden until C4 closes

1. Scripted Torq-comparison demo, run **twice from a fresh store**, real wall-clock recorded honestly
   even if it misses the 5-minute target. Fresh store = delete `.soc/audit/chain.jsonl`, reset
   `incidents.json`/`cases.json` to `{}`, clear `.soc/runs/*` and `.soc/reports/*`, `nft flush ruleset`
   on the target; **`.soc/auth.json` must PERSIST** so step-up works without re-signup.
2. Collector back-pressure: bounded queue, honest `ingested / dropped / lagging` counters, drops shown.
3. `docs/BATTLECARD_TORQ.md` — every number fact-checked against the repo and `CITATIONS.md`. The
   arXiv **2604.19533** figure (best frontier LLM flagged ~3.8% of malicious events; no model passed
   50% per-tactic) is a **literature citation, never an in-repo measurement**; never round it, never
   invert it to "LLMs miss 96%". The `ti_oem` egress exception must not be papered over.
4. KPI panel from real timestamps with honest `n/a`; includes the `mttdSeconds` → `mttaSeconds` rename
   at `soc.py:793`.

Demo scenario is the seeded brute-force incident (`203.0.113.44` → `server-01`, T1110). Note the real
id is `inc-<hash[:12]>`; `INC-4a7f` is design-kit shorthand and is **seeded, not renamed**.

## 8. Carry-forward nits (not carded)

- The connector egress disclosure string is duplicated as a literal in two places in `OemEngine.tsx`;
  a shared constant would stop the two disclosures diverging.
- `docs/design/` holds the fidelity reference (`TOKENS.md`, reference HTML). No browser is available in
  this environment — **never claim visual verification that was not performed.**
