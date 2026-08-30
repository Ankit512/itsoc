# Stage C — Closeout

**Status: COMPLETE.** C0 through C5 merged to local `main`.
**Head at closeout:** `de63f3a` · **Detector frozen throughout:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`

Read this document first. It is the record of what was built, what was decided,
what was deliberately not fixed, and what a reader should distrust.

---

## 1. Phases and merge commits

| Phase | Delivered | Merge commit |
|---|---|---|
| **C0** | Foundations — runbooks, audit hash-chain, TI fixes | `18b03dd` |
| **C1** | Screen & store consolidation (16 screens → 12) | `09f73f0` |
| **C2** | Investigation engine + org context | `b231163` |
| **C3** | Gated response — action layer, SSH-firewall connector, approvals + per-action step-up, gated MCP `propose_block_ip`, copilot recommendation | `04e9b52` |
| **C4** | Response UI — runbook cards, honest advisory states, priority chip, mechanically-locked palette boundary | `fba046c` |
| **C5** | Demo, back-pressure, battlecard, KPI panel | merged per item (below) |

**C4 internal integration:** `f05bf2c` (F1 runbook) · `a20515c` (F2 advisory) · `4a0aaa8` (F3 priority) · `30e4f7c` (OPEN-14) · `47fd17e` (C4-R1) · `9a8d79f` (C4-A1/A1r)

**C5 items:** `8490547` battlecard · `9c226a2` egress constant · `8d03f84` KPI panel · `3e003ab` collector back-pressure · `df3b094` scripted demo · `bbf4a82` OPEN-14b · `de63f3a` OPEN-10 clean fence

**Final gate at closeout:** web **201/201** across 39 files (declaration order and shuffled) · python `tests/` **38/38** · `console/test_console.py` exit 0 · `run_eval.py` 19/19 (F1 = 1.000). One unexplained anomaly — see §7.

---

## 2. Deviations D-1 … D-3

| ID | What | Origin | Resolution |
|---|---|---|---|
| **D-1** | Build-doc self-contradiction: §0/§2 named a literal `--taxii-token`, a value-taking flag, against the §4 guardrail forbidding credentials in CLI args | Worker-found | **Resolved toward the guardrail**, owner-ratified. Build doc amended (`c2418fb`). The guardrail won over the instruction that contradicted it — the correct precedence, and the precedent for the rest of the stage. |
| **D-2** | Reference write-connector changed from an OPNsense VM to **nftables-over-SSH against a container** | **Owner-initiated** | Ratified as a scope amendment. Amended the same way as D-1: revised build doc synced into the repo rather than held in conversation. |
| **D-3** | `73167a5` (C3-MCP) contained out-of-allowlist edits | Worker | **Signed off**, conditional on verification that the edits fell within the card's stated intent. Verified, then signed. First deviation recorded under the "in-intent out-of-allowlist" procedure that later became OPEN-12. |

No further deviations were required. Every later out-of-allowlist edit was pre-ratified under OPEN-12's authority split (§4).

---

## 3. Open-items register — final state

| Item | Subject | Final state |
|---|---|---|
| OPEN-1 | Product-code allowlist for `threat_intel/rule_mitre_map.py` | **RESOLVED** — approved as re-scoped, dispatched as C0-T7 |
| OPEN-2 | C1-T1: cases with no linked incident | **RESOLVED** — confirmed, dispatched as C1-T1 |
| OPEN-3 | C2 acceptance wording unmeasurable as written | **RESOLVED/ACTIONED** (`b6f5028`) |
| OPEN-4 | Foreign uncommitted work in the working tree | **RATIFIED** — card HK-1; superseded in substance by OPEN-10 |
| OPEN-5 | (reclassified) | **A POINTER, not a deviation** — owner reclassification; stayed open and non-gating by design |
| OPEN-6 | `INC-4a7f` | **RULED: seed it, do not rename it.** Real ids remain `inc-<hash[:12]>` |
| OPEN-7 | Battlecard headline figure | **RULED: literature citation, pinned.** Enforced in the artefact (§6) |
| OPEN-8 | Pre-existing cross-file test isolation bug in `shell.test.tsx` | **CLOSED** by OPEN-13's fix |
| OPEN-9 | Docker daemon prerequisite | **RULED: run-level environment requirement.** If down, the live item reverts to BLOCKED — **never mock-substituted.** Satisfied at demo time |
| OPEN-10 | `main` moved outside Stage C; concurrent queue active | **RESOLVED — clean fence ratified and implemented** (`de63f3a`). See §5 |
| OPEN-11 | Guardrail 4 ("all egress through `redact.py`") vs provider-directed TI/OEM traffic | **NARROWED** — see §4 |
| OPEN-12 | Who ratifies an out-of-allowlist diff caused by the orchestrator's own card | **RULED** — authority split by blast radius, plus a binding pre-dispatch card check. See §4 |
| OPEN-13 | `shell.test.tsx` order-dependence | **CLOSED BY ATTACK** (`c9a7107`) |
| OPEN-14 | Integrated C4 suite order-dependence | **CLOSED** (`30e4f7c`) — load-induced timing, not a state leak |
| OPEN-14b | Per-test `it()` timeouts overrode the global head-room | **CLOSED** (`bbf4a82`) — caps removed, not raised |

---

## 4. Guardrails — delta from this run

The guardrails did not survive the run unchanged. Three were amended and one was added; all four are binding going forward.

**Unchanged and never relaxed:**
- `anomaly_detector.py` is FROZEN. New formats are sibling modules feeding `{n, ts, level, host, msg, raw}`.
- `raw` is the real log line, **never fabricated** — including for a dropped, truncated, or unparsed event.
- Rules own severity and correlation. The LLM explains; it is advisory and never a control signal.
- Credentials never in CLI args or logs; key **paths** only in config, never key values. **The owner's local profile passphrase is the production step-up identity and is never requested.**

**AMENDED — Guardrail 4, "all egress through `redact.py`" (OPEN-11).**
Narrowed. Provider-directed TI/OEM traffic is a legitimate exception because the queried indicator *is* the request — redacting it would make the call meaningless. The exception is bounded: connectors default **off**, carry an honest egress label at the enable control, and the disclosure now lives in one shared `EGRESS_DISCLOSURE` constant so two copies cannot diverge (`9c226a2`).

**AMENDED — out-of-allowlist authority (OPEN-12).**
Split by blast radius. A worker may proceed on a non-behavioural edit *inside the card's stated intent* and record it; anything behavioural, security-relevant, or outside intent stops for the orchestrator. Paired with a **binding pre-dispatch check**: the orchestrator must verify the card's own allowlist covers everything the card's instructions imply. This rule exists because *the orchestrator's card wording caused the violation* three separate times.

**AMENDED — environment requirements (OPEN-9).**
A missing environment (Docker daemon) makes a live item **BLOCKED**. It is never mock-substituted. A benchmark or gate run against a mock measures nothing and is worse than a skipped one.

**ADDED — verification standard.**
Nothing is accepted on a green run alone:
- A **test** is accepted only after a *watched* mutation makes it fail, **and** a fix makes it pass. A test that always fails is exactly as useless as one that can never fail.
- A **timeout increase** is accepted only after a defect injection proves failures still fail *loudly and fast*.
- An **audit** is checked by grepping the sha it claims to have examined.
- A **report containing a ratio** is checked for whether numerator and denominator measure the same thing.

---

## 5. OPEN-10 — the clean fence (implemented `de63f3a`)

**The premise carried for most of the run was false.** OPEN-10 was tracked as "foreign work committed to shared `main` — keep or revert". `git log --all` returns **zero commits** for `tools/attack_generator.py` and `tools/efficacy_score.py`. They were never committed to any branch or ref, and nothing in the codebase imports them. **There was nothing to revert.**

The actual cause of the recurring drift was underneath: **`web/dist` was a tracked build artefact.** Vite gives its files content-hashed names, so every branch regenerated different filenames and every merge collided — 36 commits touched it. `serve.py:1541-1557` and `test_console.py:2509-2512` already degrade cleanly when it is absent, which is what made untracking it safe rather than merely desirable.

Implemented:
- `web/dist` untracked (`git rm -r --cached`) and ignored.
- Foreign efficacy workspace **moved outside the checkout** to `../log-analyzer-foreign/` and ignored here.
- `8a13e6e` **KEPT** — it is the RFC 5424 and JSON-line parsers plus eval cases P18/P19, untangled from the foreign tools. Reverting it would have regressed eval 19 → 17. A blanket revert would have destroyed real work; the entanglement analysis is what made a surgical answer possible.
- `tools/attack_generator.py` deliberately **left in place and not ignored**, as the owner's inspection copy.

  **Closed 2026-08-30.** Owner: keep as a dev tool, gitignored. Promotion bar lives next to the ignore rule. See `docs/POST_C_CHECKLIST.md`.

---

## 6. Defects found in pre-existing code

### Fixed

| Defect | Where | Resolution |
|---|---|---|
| **Priority chip painted priority with the SEVERITY ramp** (`.is-chip--p1` = `var(--crit)`) | `itsoc.css:629-641` | Emphasis ladder (fill + border opacity), locked by two independently authored source-level assertions (`47fd17e`, `9a8d79f`) |
| Advisory timeout borrowed `var(--high)` | `itsoc.css:612-616` | → `var(--warn)`, identical value, zero pixel change |
| Latent severity reference on the bare `.note-timeout` base rule | `itsoc.css:228` | → `var(--warn)`; the lock was widened to cover the **class wherever declared**, not only its current location |
| **`mttdSeconds` published a metric we cannot compute** | `console/soc.py` | Renamed to `mttaSeconds` across 10+ sites. **No estimated MTTD substituted** — absent data renders `n/a` with its reason |
| **Silent kernel UDP drops with no counter** | `console/syslog_collector.py` | Bounded queue, single drain worker, drops counted *and* surfaced in the UI. Conservation identity: `received = ingested + dropped + lagging + dedupes` |
| Cross-file test isolation (OPEN-8/13), integrated-suite flake (OPEN-14), per-test timeout overrides (OPEN-14b) | `web/src/test/` | Fixed; caps **removed** rather than raised |
| Duplicated egress disclosure literal | `OemEngine.tsx` | One shared `EGRESS_DISCLOSURE` constant + identity test |
| Battlecard citations pointed at wrong lines/paths | `docs/BATTLECARD_TORQ.md` | All citations converted to **exported symbol names**; line numbers rot, symbols survive |

### Parked — deliberately not fixed

| Defect | Why parked |
|---|---|
| **Three pre-C4 hardcoded shadow literals** — `CopilotRail.tsx:311`, `itsoc.css:370`, `itsoc.css:385`. Real: a hardcoded dark shadow renders wrong in light theme; a `--shadow` token exists | **Fixed 2026-08-30**, merged `c2f7e75` (`fix/shadow-tokens`). Pixel-pass caveats filed as FU-1 / FU-2, not reopened as C4 work. |
| **`#000` approval scrim** — `itsoc.css:242` | Ruled acceptable. Modal scrims are conventionally theme-blind and no scrim token exists; inventing one is unnecessary scope |
| `test_console.py:4978` migration gate | Environmental — needs a real `console/.soc/soc_history.db`. Passes in a populated tree, reported as **NOT TESTED** elsewhere rather than allowed to read as a pass |

**The lesson that generalises:** the priority-chip defect passed *every* structural check we had — "is it a hardcoded literal?" (no), "is the token defined in both themes?" (yes), "is the value token-driven?" (yes). `var(--crit)` on a priority chip is a legitimate, correctly-defined token referenced from a syntactically proper place. **Tokenisation audits verify PROVENANCE; they never ask SEMANTICS — is this the *right* token for this surface.** Add that question to any design audit.

---

## 7. The demo timing, and how it must be quoted

**Measured, from genuinely fresh stores, on a live container:**
- Benchmark run 1: **1,397.70 ms** · Benchmark run 2: **1,947.95 ms**
- All **six** executions disclosed in `docs/C5_DEMO_RESULTS.md`, including the four exploratory ones — not the best two.
- Real incident id `inc-1f4f5d4074b3` throughout. `INC-4a7f` is design-kit shorthand and was **never seeded**.
- Live `nft` element insertion verified **on the container**, not inferred from the API response. Audit chain verified to genesis. `console/.soc/auth.json` survived both wipes — a reset that destroys step-up would break the demo's most important gate silently.

**The scope sentence, which must travel with the number:**

> This benchmark measures only the machine-speed backend pipeline on localhost. It does not measure human think time, UI rendering, or WAN network transit. A like-for-like comparison against human-paced SOC workflow benchmarks requires measuring a human-operated run, which has not been performed here. These timings establish pipeline feasibility and determinism from a fresh store, and **must not be used as a competitive speed claim** without a human-paced measurement.

The first draft of that document concluded ">150x safety margin" against the 5-minute target. Every individual number in it was true and the sentence built from them was not: it compared a machine-speed pipeline against a target that means a human-paced workflow. **That is the subtlest defect found in the entire stage, and it was found by reading the conclusion, not the data.**

---

## 8. What a reader should distrust

- **One unexplained gate failure.** `console/test_console.py` returned exit=1 once during the final gate. **The cause is unknown because the gate command redirected its output to `/dev/null`** — an orchestrator process failure: a gate must never discard the evidence it exists to produce. Four subsequent runs are exit 0, including one under deliberate concurrent load. A plausible but **unverified** match is the timing-sensitive `(a) bounded parallelism` check. Recorded rather than rounded down to green.

  **Follow-up (`fix/gate-hygiene`).** The hygiene defect is fixed — `scripts/gate.sh` is now the canonical gate and cannot discard its own output (tees to `gate-logs/<stamp>/`, recovers the true status via `PIPESTATUS[0]`, runs every gate, never rounds a skip to a pass). **The original failure itself was NOT reproduced and its evidence is gone permanently**; nothing below should be read as identifying it.
  - 32 further runs (20 idle, 12 under full-core CPU saturation) produced **no intermittent failure**.
  - The `(a) bounded parallelism` hypothesis is **weakened, not excluded**: under full-core load it completed in 65–66 ms against its 140 ms threshold — a comfortable margin, in the exact condition it was suspected to fail.
  - Two *deterministic* environmental exit=1 causes were found instead, both artefacts of an unpopulated tree rather than product defects. (1) **Missing `web/dist`** (an untracked build artefact) made `check_soc_overview`'s unguarded `get("/")` raise an uncaught `HTTPError: 503` that **aborted the suite mid-run** — every later check went untested behind a bare exit=1, which is precisely the shape of an "unexplained" failure when output is discarded. Now guarded to report `NOT TESTED`, matching `check_serve_react`. (2) The **`soc_history.db` migration gate** (§ above) proved unsatisfiable by any tree available: with no db it fails `NOT TESTED`; with a real, already-migrated db copied from the live checkout it fails as `the migration ADDS exactly audit_index — []`, because the schema already carries `audit_index` and the migration has nothing to add. **It can only pass against a db predating the migration** — so `console/test_console.py` cannot currently reach exit 0 anywhere. Left open deliberately rather than papered over; see `docs/PROJECT_STATUS.md`.
- **Structural conformance is not visual verification.** Stage C had no browser. A headless Chromium pixel pass ran 2026-08-30 on `fix/shadow-tokens` (Antigravity); it is screenshot evidence, not a designer sitting next to the mockup. Caveats FU-1 / FU-2. See `docs/POST_C_CHECKLIST.md`.
- **`INC-4a7f` appearing anywhere as a real id** would be a fabrication. Real ids are `inc-<hash[:12]>`.
- **The arXiv 2604.19533 figure** (best frontier LLM flagged ~3.8% of malicious events; no model passed 50% per-tactic) is a **literature citation, never an in-repo measurement.** Never round it. Never invert it into "LLMs miss 96%".

---

## 9. Next

1. ~~**Live light/dark pixel pass**~~ — done 2026-08-30 (headless Chromium). Caveats: FU-1, FU-2.
2. ~~**The three parked shadow literals**~~ — merged `c2f7e75`.
3. ~~**`test_console.py` gate hygiene**~~ — merged `eec463d`: `scripts/gate.sh` preserves all output. The original failure was **not** reproduced in 32 runs; see §8.
4. ~~`tools/attack_generator.py`~~ — kept as a gitignored dev tool; promotion bar in `.gitignore`.
5. Filed, not started: `docs/followups/FU-1-banner-stale-run.md`, `docs/followups/FU-2-copilot-footer-copy.md`.
6. `feat/redesign-integration` stays parked; bar is `PARKED.md` on that branch.
7. Stage D waits on an owner-written scope doc.
