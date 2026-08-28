# ITSOC Stage C — Execution Log

_Written by the Stage C orchestrator. Autonomous mode: each phase's stop-and-report is appended here
as a log entry rather than a pause. Hard stops still stop and go to the owner._

**Standing substitution (logged once, per owner ruling):** `pytest` is not installed on this machine and
is NOT installed mid-run. Wherever the orchestrator prompt says "pytest", the green-bar is the repo's
canonical suites per CLAUDE.md §6: `tests/eval/run_eval.py`, `console/test_console.py`,
`tests/test_intake.py` (unittest, run directly), `web` vitest, and `npm run build`.

**Push policy:** Q1 = (c) never. Nothing is pushed. All work is local on `stage-c/c0-foundations`,
which stacks on a local `main` that is itself 2 commits ahead of `origin/main` (owner-acknowledged).

---

## Phase C0 — Foundations

Branch `stage-c/c0-foundations`. Opening commit `c5249b2` (build doc + orchestrator prompt + kickoff
sheet + `docs/STAGE_C_ANSWERS.md`) per the autonomous-mode first action.

### C0-T0 · intake / run() reconciliation — **ACCEPTED** (commit `c963b20`, Claude Code worker)

Owner-authorized pre-C0 repair (Blocker 1, ruling (A)).

**Finding — `run()` was NOT honest by default; the owner's branch (3) was the correct path.**
`log_analyzer.run()` ingested via `log_analyzer.load_log_file()`, whose documented behavior is that it
"NEVER converts a readable file into 'unsupported format'": when `normalize.load()` recognized 0
records it fell through to `detect_input_format()` -> `"text"` -> `parse_text_stream()`, which accepts
every non-blank line as a record. Measured pre-fix on `neg_unrecognized_format.log`:
`Format: generic_text — 11/11 line(s) parsed`, `lines_parsed=11`, `findings=0`. Because
`console/adapter.py:448-451` derives `unrecognized` as `lines_parsed == 0 and lines_unparsed > 0`,
that produced a **fake-green "0 findings / 11 lines parsed"** report on a file no rule understood —
a direct guardrail-4 violation. Empty input was worse: `run()` returned rc 2 and wrote **no report at
all**, so intake then died reading a `report.json` that never existed.

**Fix (minimal, seam-reusing).** `formats_universal.py` already implemented
`load_log_file(path, mode="honest"|"force")` with exactly the required semantics and was already
covered by `console/test_console.py` — but was an orphan, never wired into `log_analyzer`. The change
is one import, one optional parameter (`unrecognized_mode: str = None`), one empty-file carve-out, and
one dispatch. `scripts/intake.py` and `tests/test_intake.py` needed **no edit** — the call site was
already correct; only the callee was missing. Default `None` keeps every existing caller on the
historical loader byte-for-byte.

Post-fix, measured: `neg_unrecognized_format` -> `Format: unknown — 0/11 parsed, 11 unparsed`;
`neg_empty` -> `Input log is empty … (this is NOT an all-clear)`, `Format: empty — 0/0 parsed`.

**Hard constraint honored.** god read the full diff: ingestion only. No rule, severity, correlation or
verdict path is touched. `tests/eval/manifest.json` diff is empty. No severity change occurred, so the
STOP condition did not trigger.

**Diff:** `log_analyzer.py` only — 1 file, +24 / -4.

| # | Acceptance | Result (god-verified independently, not claimed) |
|---|---|---|
| a | `tests/test_intake.py` | **PASS** — `Ran 4 tests` / `OK` (was 3 errors) |
| b | `tests/eval/run_eval.py` | **PASS** — 17 passed / 0 failed; 0 FP, 0 FN; p/r/f1 = 1.000 |
| c | `console/test_console.py` | **PASS** — all 27 check groups green |
| d | vitest | **PASS** — 26 files, 107/107 |
| e | `npm run build` | **PASS** — built in 5.40s (only the pre-existing >500 kB chunk advisory) |
| f | detector sha | **PASS** — `364577c5…a4a876` unchanged |
| g | diff inside allowlist | **PASS** — `log_analyzer.py` only |
| h | `manifest.json` untouched | **PASS** — empty diff |

### Environment gate re-run — **8 / 8 GREEN** (owner-required before C0-T1)

`main`-equivalent branch state ✓ · clean tree ✓ · detector `364577c5…a4a876` ✓ · `npm run build` ✓ ·
vitest 107/107 ✓ · `run_eval` 17/17 f1 1.000 ✓ · `console/test_console.py` PASSED ✓ ·
`tests/test_intake.py` 4/4 ✓ — the check that failed at pre-flight is now green.

### Findings carried forward (NOT auto-absorbed — recommended follow-up cards, no tripwire fired)

1. **The dishonest ingestion default still ships.** C0-T0 made honesty *available*, not default.
   `run()` still force-parses unrecognized input for any caller that does not pass
   `unrecognized_mode="honest"` — currently only `scripts/intake.py` passes it; `tools/model_ab.py:146`
   does not. *Orchestrator correction to the worker's report:* `console/serve.py` does **not** call
   `log_analyzer.run()` (its line 898 is only a comment referencing it), so the console is not affected
   *via run()*; the console hydrates through `adapter.load_console_records` -> `log_analyzer.load_log_file`,
   which is the same force-parsing loader — so an equivalent gap does exist on the console path, by a
   different route. Flipping the default repo-wide would move eval/console expectations and is out of
   C0-T0's allowlist. **Recommend a dedicated card; owner decision.**
2. **`formats_universal.DEFAULT_MODE` contradicts its own docstring.** Line 47 resolves to `"force"`
   when `LOG_ANALYZER_UNRECOGNIZED_MODE` is unset, while lines 24/35/592 twice state the default is
   `"honest"` and call it "the repo guardrail". Latent today (intake passes `mode` explicitly), but it
   is an inconsistency inside a guardrail-bearing module. **Recommend a ticket.**
3. Honest mode makes `run()` return `None` rather than `2` for an empty file (it now writes a report,
   which is what the test demands). Scoped to `unrecognized_mode == "honest"`, so no existing exit-code
   contract changed.
4. Pre-existing `ResourceWarning: unclosed file` noise from `normalize.py:226/229/251/254`. Not
   introduced here, outside the allowlist.

### C0-T1 · Runbook schema + eligibility engine — **ACCEPTED** (commit `0e7af92`, Claude Code worker)

**Schema.** `console/runbooks.py`: `id`, `name`, `trigger{rule_ids, entity_types}`,
`preconditions{required_evidence}`, `steps[{type: action|notify_draft, connector, params_template,
rollback}]`, `severity_floor`. Every field required; unknown fields rejected; `rollback` must be a
mapping or an **explicit null** (absent != safe). Shipped `rb-block-ip` and `rb-draft-notify`.

**Standing invariant — "no LLM parameter in `eligible()`'s signature" — VERIFIED BY god INDEPENDENTLY**
(live `inspect.signature`, not the worker's claim):
```
SIG: (runbook, incident, findings)
VAR_ARGS PRESENT: []          # no *args, no **kwargs — nothing can be smuggled in under any name
LLM-ISH PARAM NAMES: []
```
Ineligibility is structural twice over: (1) signature closure as above; (2) **data closure** —
`_rule_facts()` projects incident + member findings through `RULE_OWNED_*_KEYS` allowlists before any
predicate runs, so `llmSev`/`llmWhy`/`explanation` are *absent* from what the engine sees rather than
filtered afterward. `ADVISORY_KEYS` is asserted disjoint from both allowlists.

**god adversarial test (beyond the card).** Poisoned an incident and all member findings with
`llmSev: CRITICAL`, `llmWhy`, `explanation`, `advisory` in every plausible slot:
- advisory could **not force** eligibility -> still `False`
- advisory could **not suppress** an otherwise-identical verdict -> `missing` list byte-identical to baseline
- the engine *did* respond to the rule-owned `severity` field (INFO -> "below the HIGH floor"), i.e. it
  honors rule data and ignores advisory data. Correct on both sides.

**god non-vacuity check (beyond the card).** A guarantee that always returns `False` would make every
test above pass vacuously. Confirmed the positive path is reachable:
`eligible -> {'eligible': True, 'missing': []}` on a well-formed brute-force incident.

**Test-weakening check.** The 2 deletions in `test_console.py` are only the main() aggregation
condition and the summary string, both replaced by extended versions including `runbooks`. No existing
check modified or weakened (verified by god via `git diff -U0 | grep '^-'`).

**Diff:** 4 files, +696 / -2 — `console/runbooks.py` (384), `rb-block-ip.yaml` (50),
`rb-draft-notify.yaml` (44), `console/test_console.py` (+220/-2). Allowlist-clean.

| # | Acceptance | Result (god-verified) |
|---|---|---|
| a | eligibility units + `inspect.signature` no-override property | **PASS** — 43 checks; signature re-verified live by god |
| b | missing-evidence -> structural `missing: [...]` | **PASS** — names each absent key individually |
| c | both runbooks load/validate; violations rejected honestly | **PASS** — 8 rejection cases all raise `RunbookError` |
| d | `console/test_console.py` | **PASS** — `… + runbooks checks green` |
| e | `tests/eval/run_eval.py` | **PASS** — 17/17, f1 1.000 |
| f | `tests/test_intake.py` | **PASS** — 4/4 OK |
| g | vitest / build | **PASS** — 26 files, 107/107; built in 6.32s |
| h | detector sha | **PASS** — `364577c5…a4a876` |
| i | diff inside allowlist | **PASS** — the 4 files above only |

**Honesty spot-check (forced empty/failure states).** Incident with no matching runbook ->
`match_runbooks -> []`; empty is genuinely empty, no fallback runbook, no default-to-eligible path,
and `evaluate_all` still explains *why* each declined. Preconditions entirely unmet -> 8 named misses,
nothing invented; severity reported as *unknown* rather than assumed. Absent runbook directory -> `{}`,
not an invented default. Unparseable file -> loud `RunbookError`, not a silently-skipped file.

### Findings carried forward from C0-T1 (logged, not absorbed)

5. **PyYAML is not installed; no dependency was added.** The two runbooks keep the `.yaml` extension
   the build doc mandates but are written in the **JSON subset of YAML** (valid YAML 1.2, parsable by
   stdlib `json`). The loader prefers `yaml.safe_load` when PyYAML is importable, so installing it
   later is a no-op. Cost: no YAML comments or block style. **Not a build-doc deviation** (the files
   are `console/runbooks/*.yaml` as specified), but block YAML would need an owner dependency decision.
6. **`console/runbooks.py` and `console/runbooks/` coexist** — both mandated by the build doc's own
   paths. The module currently wins Python's import order (verified), but dropping an `__init__.py`
   into the directory would shadow it. Fragile adjacency; worth a rename in a later card.
7. **Nothing calls `eligible()` in production yet** — correct for C0 scope (C0-T2 owns the store), but
   it is proven by tests only, not yet by a live incident path. C1/C3 must wire it.
8. `match_runbooks()`/`evaluate_all()` re-read and re-validate from disk on every call when no dict is
   passed. Fine at two runbooks; whoever wires this into a request path should pass a cached dict.
9. `required_evidence` vocabulary is closed but unvalidated: a typo'd key (`record_ref`) would validate
   and then be permanently ineligible. Fails **safe** (never falsely eligible) but fails quietly.
   Worth a key-vocabulary check in a follow-up.

### C0-T2 · Audit chain + fsafe recovery — **ACCEPTED** (commit `4ba2530`, Claude Code worker)

**Deviation resolution (build doc, recorded per owner instruction):**
> build doc assumed `fsafe.py` existed; it was archive-only; resolved by owner-authorized **port**.

**PART A — path (A), zero adaptation.** god verified port fidelity directly:
`diff <(git show c36d03d:console/fsafe.py) <(head -102 console/fsafe.py)` -> **IDENTICAL, zero changes**.
Not one import needed adapting, exactly as the pre-assessment predicted; fallback (B) did not trigger.
Archived API preserved: `locked(path)` (flock with an O_EXCL spin-lock fallback) + `atomic_write_text`.

**Durable APPEND (the gap the archive did not cover).** `atomic_write_text` is a whole-file rewrite —
O(n) per entry and it puts already-committed history back on the write path, which is wrong for a
ledger. The worker added a separate append path on the same `locked()` primitive (fsafe.py:103-165):
`append_line_holding_lock()` (O_APPEND + `fsync`, + directory fsync on create; caller already holds the
lock because `locked()` is **not** reentrant — flock is per-fd, and the chain must read its tail and
append its successor inside ONE critical section) and `durable_append_line()` (lock-taking form).
Existing bytes are never reopened for writing, truncated, or replaced.

**god independent verification of the chain (not trusted from the report):**
```
a) CLEAN VERIFY        -> {'ok': True, 'count': 4, 'break': None, 'head': 'c092f765…'}
b) TAMPER MIDDLE (i=1) -> {'ok': False, 'break': {'index': 1,
                            'reason': "entry_hash does not match the entry's contents…",
                            'expected': '8ccbbfae…', 'found': '112b78c2…'}}
   idempotent (no self-heal): True   |   file bytes unchanged: True
c) APPEND-ON-BROKEN    -> break STILL reported at index 1; earlier entries NOT rewritten; count 4->5
```
So the D4 requirement "never silently re-chain" holds under direct attack: a break is reported at the
correct index, re-reading does not heal it, and appending afterward does not launder it.

**No auto-repair path.** Worker proved it structurally against `audit.py`'s real AST (no
`write_text/atomic_write_text/replace/truncate/unlink/rename/open` among called names; the only ledger
mutation is one `fsafe.append_line_holding_lock`). god confirmed by grep and by reading
`rebuild_index()`, which **refuses** on a broken chain and returns the verification verdict instead of
laundering corruption into the index.

**god independent additive-migration proof, on a `shutil.copy2` COPY of the live 7.9 MB store:**
```
BEFORE : assets, connectors, events, investigations, iocs, settings, sqlite_sequence, vulnerabilities
AFTER  : … + audit_index
ADDED  : ['audit_index']      DROPPED: []
ROW CHANGES ON PRIOR TABLES: NONE     (events stayed 2500)
>>> ADDITIVE: True            >>> LIVE DB UNTOUCHED: True (mtime unchanged)
```
`CREATE TABLE IF NOT EXISTS` only; no `ALTER`, no `DROP`. **Retention can never reach audit evidence** —
god confirmed `audit_index` is absent from both `HISTORY_TABLES` and `ALL_DATA_TABLES` (so `cleanup()`
and `purge()` cannot touch it) while present in `_QUERYABLE` for the eventual UI. Migration tripwire
did NOT fire.

**Diff:** 5 files, +1009 / -2 — `audit.py` (291), `fsafe.py` (165), `store.py` (100),
`test_console.py` (+254/-2), `test_fsafe.py` (201). Allowlist-clean. The 2 deletions are again only the
runner-wiring line and the banner string (god-verified via `git diff -U0 | grep '^-'`).

| # | Acceptance | Result (god-verified) |
|---|---|---|
| a | clean chain verifies | **PASS** — `ok: True`, count 4, head hash present |
| b | tamper middle -> correct index, no repair | **PASS** — break at index 1; bytes unchanged; idempotent. Deleting a middle entry reports index 2 "prev_hash does not match" |
| c | sqlite derived + rebuildable from JSONL alone | **PASS** — table wiped, `rebuild_index()` reconstructs; refuses on a broken chain |
| d | additive migration on a COPY | **PASS** — god re-ran independently, see above |
| e | atomic write survives interrupt | **PASS** — deterministic swap-point interrupt + **12 real SIGKILLs**; target always complete-old or complete-new |
| f | concurrent append, real concurrency | **PASS** — 8 processes × 25 × 60 KB lines -> 200/200 whole, none interleaved; 5 concurrent `audit.append()` processes -> chain still verifies |
| g | `console/test_console.py` | **PASS** — `… + runbooks + audit-chain checks green` |
| h | `tests/eval/run_eval.py` | **PASS** — 17/17, f1 1.000 |
| i | `tests/test_intake.py` | **PASS** — 4/4 OK |
| j | vitest / build | **PASS** — 26 files, 107/107; built in 4.14s |
| k | detector sha | **PASS** — `364577c5…a4a876` |
| l | diff inside allowlist | **PASS** |

Bonus: `python3 console/test_fsafe.py` -> `PASSED — 10 fsafe checks green`.

### Findings carried forward from C0-T2 (logged, not absorbed)

10. **`console/test_fsafe.py` is not wired into any runner** — nothing invokes it automatically, so
    acceptance (e) and (f) are proven once but not *enforced* going forward. **Orchestrator action:**
    god has added it to the standing Stage C gate and runs it every phase. A permanent fix (wiring it
    into the canonical runner) is a follow-up card, as it is outside every current allowlist.
11. **`append()` deliberately extends an already-broken chain** rather than refusing. Rationale: refusing
    would let one corrupted byte silently stop the ledger from recording the next action. god verified
    it links to the real tail and the earlier break stays reported at its own index — appending is not
    repairing, and D4 is not violated. **This is a judgement call on underspecified behavior and is
    cleanly reversible if the owner prefers refuse-on-broken.**
12. **Stale `.tmp` debris after SIGKILL.** A SIGKILLed writer cannot clean up, so `atomic_write_text` can
    leave a `*.tmp` sibling (10 across 12 kills). The target is never torn and no reader ever opens a tmp
    file, so this is debris, not corruption. No reaper exists. Flagged, not hidden.
13. **`test_fsafe.py` kill test is timing-sensitive** (sleeps 4-45 ms to land inside a write). On a very
    fast/slow machine some kills may land outside the write window; the assertion still holds, but the
    test could weaken silently rather than fail loudly.
14. `store.index_audit_entry` failure is **non-fatal** in `append()` (the JSONL is already committed, so a
    derived-index error is surfaced on the returned entry as `_index_error` rather than raised). Surfaced,
    not swallowed — but a caller ignoring the return value would miss it.
15. `audit_index` is queryable via `store.query()` but **not** exposed over HTTP — `serve.py` has its own
    `_STORE_TABLES` map, untouched. Correct for C0 (no UI); C4 must wire it.
16. **`graphify update .` was not run.** CLAUDE.md asks for it after code changes, but it writes
    `graphify-out/`, outside every allowlist. Deferred to whoever owns that step.

### C0-T3 · TI severity cap + TAXII token/cert auth — **BUILT, NOT ACCEPTED — HALTED FOR OWNER SIGN-OFF** (commit `cbd3099`)

Code is committed and the security work is sound, but C0 **cannot auto-gate**: one build-doc deviation
and one out-of-allowlist regression both require the owner. Autonomous mode: "any deviation needing
sign-off -> halt, write the report, ask the owner." Halted. C0-T4 NOT dispatched.

**New severity mapping (the substance is good).** Two steps. Rule policy sets a CEILING from locally
corroborable evidence (`RULE_SEVERITY_POLICY`, keyed on known-malicious label × ATT&CK technique
actually resolved): corroborated -> high, labelled_only -> medium, technique_only -> medium,
uncorroborated -> low. The feed's declared level then applies **only if strictly lower** — the feed may
de-escalate, never escalate. `TI_SEVERITY_CEILING = "high"` makes **CRITICAL unreachable from threat
intel alone**, so it stays with the rule engine. Findings carry `severity_tier`, `severity_ceiling`,
`feed_declared_severity`, `severity_source` so a rule assignment can never be mistaken for feed data.
A numeric `confidence: 95` deliberately yields no severity word rather than inventing one.

**No eval-measured severity moved.** `run_eval.py` scores `anomaly_detector.py`; TI severity is out of
its scope. 17/17, f1 1.000, `git diff -- tests/eval/manifest.json` **empty** (god-verified). The
owner's severity STOP therefore did not trigger for the eval suite. TI-internal severities did move by
design (demo bundle CRITICAL -> HIGH).

| # | Acceptance | Result (god-verified) |
|---|---|---|
| a | no `--password`/`taxii_password` in `threat_intel/` | **PASS** — grep exit 1, no output |
| b | severity units incl. feed-critical capped lower | **PASS** — 14 checks; "CRITICAL is unreachable from threat intel" |
| c | no credential in CLI arg or log, proven by test | **PASS** — 46 checks |
| d | `threat_intel/test_threat_intel.py` | **FAIL — PRE-EXISTING, zero delta (god-verified)** — see below |
| e | `run_eval.py` + empty manifest diff | **PASS** — 17/17, f1 1.000, manifest diff empty |
| f | `console/test_console.py` | **PASS** — ti-oem not regressed |
| g | `tests/test_intake.py` | **PASS** — 4/4 OK |
| h | vitest / build | **PASS** — 26 files, 107/107; built 4.71s |
| i | detector sha | **PASS** — `364577c5…a4a876` |
| j | diff inside allowlist | **PASS** — 4 files, +900/-71 |

**god independent proof that (d) is pre-existing.** Built a throwaway worktree at the parent commit
`b88304d` and diffed the failure sets:
```
BASELINE (b88304d, WITHOUT the change): FAILED — 16 check(s)
HEAD     (cbd3099, WITH the change):    FAILED — 16 check(s)
diff of the two failure lists -> IDENTICAL FAILURE SET, delta from C0-T3 is ZERO
```
The 16 are stale `~/.cache/mitre_attack` data (e.g. official 'Service Exhaustion Flood' vs table
'Service Exhaustion'; 'Network Service Scanning' vs 'Network Service Discovery'; `T1070.001` -> None)
plus 3 `rule_mitre_map`/`ioc_observed` checks. `mitre_attack.py` and `rule_mitre_map.py` were outside
the allowlist. Likely fixed by `python3 threat_intel/mitre_attack.py --refresh`, which needs network.
**Recommend a dedicated card; this is not C0-T3's failure.**

---

## ⛔ HALT — two items require the owner before C0 can close

**HALT-1 · Build-doc deviation: `--taxii-token` was NOT shipped.**
Build doc §C0.3 (line 49) says verbatim: *"replace `--taxii-password` with token/cert auth
(`--taxii-token` / client-cert paths)"*. The worker did **not** ship `--taxii-token`; it is in the
**reject** list. What shipped instead is path-only: `--taxii-config`, `--taxii-token-file`,
`--taxii-client-cert`, `--taxii-client-key`, plus `$ITSOC_TAXII_TOKEN_FILE` / `$ITSOC_TAXII_TOKEN`.

*The worker's reasoning, which the orchestrator judges correct:* a value-taking `--taxii-token` puts
the secret in `argv`, visible to any user via `ps`. That contradicts §4 guardrail 4 ("connector
credentials are token/cert, **config-file only**") and this card's own acceptance (c). The build doc
contradicts itself here, and the prompt states §4 guardrails are **binding** — so the worker resolved
toward the guardrail. It also hardened the path: `reject_secret_bearing_argv()` runs *before* argparse,
because argparse's own "unrecognized arguments" error would echo the secret value; the guard names only
the flag and prints "(the value you passed has NOT been echoed here)". `TaxiiCredentials.__repr__` and
`_BearerAuth.__repr__` render `***redacted***`.

**This is a deviation from the build doc's literal text and is never silently absorbed.**
> **Owner decision:** (A) ratify the deviation — keep path-only auth, amend the build doc line; or
> (B) require the literal `--taxii-token` flag as written, accepting the `ps` exposure.
> Orchestrator recommends **(A)**.

**HALT-2 · Regression outside the allowlist: `itsoc_mcp/test_mcp.py`.**
god-verified by running both revisions:
```
BASELINE b88304d : 93 passed, 0 failed
HEAD     cbd3099 : 92 passed, 1 failed
```
`itsoc_mcp/test_mcp.py:436` hardcodes
`check("severity from threat_detector (critical)", m["severity"] == "critical")`. That assertion is now
**correct-by-design to fail** — TI can no longer emit `critical`, which is the entire point of the cap.
`itsoc_mcp/` was outside C0-T3's allowlist, so the worker correctly did not touch it and flagged it
instead. It is not in the canonical green-bar suites, so no listed acceptance criterion caught it; the
worker ran it deliberately because it imports `severity_for`.
> **Owner decision:** (A) authorize a one-line follow-up card updating that assertion to `"high"`
> (allowlist `itsoc_mcp/test_mcp.py` only); or (B) reconsider the cap. Orchestrator recommends **(A)**.

### Findings carried forward from C0-T3

17. **Live TAXII is unexercised.** `taxii2client` is not installed and was not installed. The
    `_conn_kwargs()` handoff (`auth=` callable, `cert=` tuple) is written to the requests/taxii2client
    contract but never round-tripped against a real server; the `auth=` kwarg is the worker's read of
    the signature, unverified. Same class of gap as C3's OPNsense VM.
18. **Docs outside the allowlist are now stale**: `docs/`, `RUNBOOK.md`, `CONTRIBUTING.md`,
    `PROJECT_HANDOFF.md` still describe `--taxii-password` and the "flattens to CRITICAL" behavior.
    Worth a docs sweep card (could fold into C0-T4's sweep if the owner widens that allowlist).
19. `threat_intel/test_threat_intel.py`'s 16 pre-existing failures need an owner. Likely a
    `mitre_attack.py --refresh` (needs network), but the ATT&CK table rename
    ('Network Service Scanning' -> 'Network Service Discovery') may be a real content update.

### Orchestration note (logged for the owner)

The named hive roster (Toby, Pam, Jim, Oscar, Meredith) is **not reachable**. A liveness probe to
`toby-mtcnvnwu` returned *"No agent named 'toby-mtcnvnwu' is reachable"*, and `ListAgents` shows only
this session plus an idle peer session and one offline Remote Control session — none of the five. They
appear in `fleet.json` with 0 tokens and `lastTool: null` but are not addressable. Every C0 card was
therefore dispatched to a Claude Code worker under kickoff Q4's unavailable-tier rule (route up, log
the substitution, no stop). C0-T0/T1/T2/T3 were each built by a separate dispatched worker; the
orchestrator wrote the cards, verified every result independently, and kept the board.

---

## Deviation register

### D-1 · Build doc self-contradiction (§0/§2 C0.3 line vs §4 guardrail 4) — **RESOLVED TOWARD THE GUARDRAIL, OWNER-RATIFIED 2026-08-28**

**The contradiction.** Build doc line 49 (Phase C0, item 3) instructed: *"replace `--taxii-password`
with token/cert auth (`--taxii-token` / client-cert paths)"*. A value-taking `--taxii-token <secret>`
places the credential in `argv`, where any user can read it via `ps`. That directly contradicts §4
guardrail 4 — *"connector credentials are token/cert, **config-file only**"* — and defeats the purpose
of the TAXII fix itself, which exists precisely to stop credentials travelling in the clear.

**Resolution.** The C0-T3 worker implemented the §4-honoring form: **path-only auth**
(`--taxii-config`, `--taxii-token-file`, `--taxii-client-cert`/`--taxii-client-key`, plus
`$ITSOC_TAXII_TOKEN_FILE` / `$ITSOC_TAXII_TOKEN`), and placed `--taxii-token` on the **reject** list
rather than shipping it. It did not silently absorb the difference — it reported the deviation, and the
orchestrator halted C0 for ratification rather than auto-gating.

**Owner ruling (2026-08-28): RATIFIED.** The owner's words: *"`--taxii-token <value>` was a defect in
my build doc — a value-taking flag puts the secret in argv, visible to any `ps`, which contradicts §4
guardrail 4 and the very TAXII fix's purpose. Path-only auth is the correct shape."*

**Build doc amended in-branch.** Line 49 now reads: *"replace `--taxii-password` with token/cert auth
via **file-path or env references only** (`--taxii-config`, `--taxii-token-file`,
`--taxii-client-cert`/`--taxii-client-key`); secret values never appear in argv or logs."*

**Precedent, now explicit for all workers** (written into
`hive/stage-c/GUARDRAILS.md`, which every worker reads before its first commit):
> Where the build doc's letter contradicts §4, **§4 wins**. Implement the guardrail-honoring form —
> but do NOT silently absorb the difference: stop, report the contradiction naming both the build-doc
> line and the guardrail, and wait for owner ratification. The contradiction halts the phase for
> ratification, exactly as happened here. Reporting a contradiction is never treated as failure to
> complete the card.

**Status of C0-T3 acceptance:** HALT-1 is CLEARED. **HALT-2 (the `itsoc_mcp/test_mcp.py` 93->92
regression) remains OPEN** — C0-T3 is still not accepted and C0 is still not closed.

### C0-T4 · Runbook terminology sweep — **ACCEPTED WITH AN ORCHESTRATOR CORRECTION** (commit `141db71`, worker Toby; correction `<this commit>`)

Worker Toby (named hive agent, dispatched via the outbox channel) swept "playbook" -> "runbook" per D5.
Genuine sweep sites were correct: `rules_syslog.py` and `console/test_console.py`, both the same
analyst-guidance string ("…contain according to the incident runbook."). Zero behavioral change.

**DEFECT CAUGHT IN VERIFICATION — the sweep edited the governing spec.** Toby also rewrote the
build doc's own §0 decisions-log entry:
```
- | D5 | Terminology | … Sweep any "playbook" strings. |
+ | D5 | Terminology | … Sweep legacy references. |
```
That line legitimately contains the word *because it names the term being swept* — a meta-occurrence.
Rewriting it to satisfy the sweep's own grep destroyed the specificity of a **binding** §0 decision.
The orchestrator has **restored the original D5 text**.

**Root cause is the orchestrator's card, not the worker.** C0-T4's allowlist read "only files a fresh
`grep -rli playbook` reports at dispatch time" — and `docs/ITSOC_STAGE_C_BUILD.md` genuinely matched,
so Toby stayed inside the letter of its allowlist. The card failed to exclude the spec that *defines*
the sweep. **Lesson recorded: a terminology-sweep card must always exclude the governing spec and the
execution log, which necessarily quote the term.** Future sweep cards will carry that exclusion.

**Correct end state (god-verified):** `grep -rli playbook` across `*.py/*.ts/*.tsx/*.html/*.css`
(excluding node_modules, `__pycache__`, `web/dist`) -> **exit 1, no matches**. The only remaining hit
repo-wide is `docs/ITSOC_STAGE_C_BUILD.md`'s D5 line, which is correct and must stay.

Also confirmed: Toby's commit landed *before* the D-1 amendment (`c2418fb`), which applied cleanly on
top — **line 49's ratified path-only-auth wording is intact**, not clobbered.

| # | Acceptance | Result (god-verified) |
|---|---|---|
| a | sweep clean in code | **PASS** — grep exit 1 after the D5 restoration |
| b | `run_eval.py` | **PASS** — 17/17, f1 1.000 |
| c | `console/test_console.py` | **PASS** |
| d | `console/test_fsafe.py` | **PASS** — 10 checks |
| e | `tests/test_intake.py` | **PASS** — 4/4 OK |
| f | vitest / build | **PASS** — 107/107; clean build |
| g | detector sha | **PASS** — `364577c5…a4a876` |
| h | diff inside allowlist | **PASS by the letter; card was under-specified** — see defect above |

### Diagnostic · 16 pre-existing `test_threat_intel.py` failures — **worker Pam, READ-ONLY, delivered**

Pam **corrected the orchestrator's framing**, which is exactly what the card asked for. My "stale
cache" hypothesis was wrong for most of the set. The 16 split into **three independent causes**:

- **Group 1 (10 failures) — the TABLE is genuinely stale; the cache already holds the CORRECT modern
  name, so `--refresh` fixes NOTHING here.** `T1499.002` table says 'Service Exhaustion' vs real
  'Service Exhaustion Flood' (8 rules, `rule_mitre_map.py` L6,7,8,40-44); `T1046` says 'Network Service
  Scanning' vs the real upstream rename 'Network Service Discovery' (L22); `T1136.001` parent:sub vs
  bare-sub naming mismatch (L38).
- **Group 2 (3 failures) — the CACHE FIXTURE IS DOCTORED and the table is CORRECT.** The local
  `~/.cache/mitre_attack` has **no `defense-evasion` tactic at all**; real 'Defense Evasion' has been
  renamed into two invented tactics **'Stealth'** and **'Defense Impairment'**, and `T1070.001` is
  marked `revoked: True` with a **fabricated modified date of 2026-04-14**. Pam's warning is important:
  **do NOT "fix" these by writing 'Stealth' into the production table** — that would corrupt real data
  to match a bad fixture.
- **Group 3 (3 failures) — code/test drift, entirely cache-independent.** `techniques_for_rule`
  (L46-48) returns the table's OWN list/dict objects so callers can mutate the table (real defect, fix
  = deepcopy); an `'ioc_observed': []` sentinel (L12) fails a well-formedness check; and the test's
  "unmapped rules" examples (L111-115) are stale because the table has since grown to map all three.

**Answering the owner's question directly: `mitre_attack.py --refresh` would fix only 3 of 16**, it
requires **network** (urllib against raw.githubusercontent.com/mitre/cti), and it mutates the 48 MB
cache in place — a network dependency Stage C's offline posture otherwise avoids. Pam did not run it.

**Scope safety confirmed:** `test_threat_intel.py` is not a canonical green-bar suite, and the only
canonical-suite consumer of the cache is `console/soc.py:769` — a boolean `attackCacheWarm` that reads
no technique names. So this is genuinely non-gating for Stage C.

### C0-T5 · Align `itsoc_mcp` severity assertion with the ratified cap — **ACCEPTED** (commit `261f226`, worker Jim)

Owner-ratified fix for HALT-2. Exactly one line, exactly one file:
```
- check("severity from threat_detector (critical)", m["severity"] == "critical")
+ check("severity from threat_detector (high)",     m["severity"] == "high")
```
`itsoc_mcp/test_mcp.py` -> **93 passed, 0 failed** (was 92/1). god-verified.

**The security-relevant check:** the card forbade weakening the cap to make the test pass.
`git diff --stat cbd3099..HEAD -- threat_intel/` is **EMPTY** — the TI severity cap is untouched. The
worker aligned the stale assertion rather than eroding the ratified behavior, which is the correct
resolution.

---

## PHASE C0 — COMPLETE. Awaiting the owner's merge gate.

Branch `stage-c/c0-foundations`, **11 commits**, local only (Q1 = (c) never push). Detector frozen at
`364577c5…a4a876` across every commit.

| Card | Commit | Worker | Outcome |
|---|---|---|---|
| C0-T0 intake/`run()` reconciliation | `c963b20` | Claude Code | ACCEPTED — env gate 7/8 -> 8/8 |
| C0-T1 runbook schema + eligibility | `0e7af92` | Claude Code | ACCEPTED |
| C0-T2 fsafe port + audit chain | `4ba2530` | Claude Code | ACCEPTED — deviation D-1's sibling resolved on path (A) |
| C0-T3 TI severity cap + TAXII auth | `cbd3099` | Claude Code | ACCEPTED (after D-1 ratified + HALT-2 cleared) |
| C0-T4 runbook terminology sweep | `141db71` | **Toby** (hive) | ACCEPTED with orchestrator correction `649aea4` |
| C0-T5 MCP assertion alignment | `261f226` | **Jim** (hive) | ACCEPTED |
| — mitre diagnosis (read-only) | n/a | **Pam** (hive) | DELIVERED — corrected the orchestrator's framing |

### C0 exit gate — god-run, not claimed

| Check | Result |
|---|---|
| `tests/eval/run_eval.py` | 17/17 · precision 1.000 · recall 1.000 · **f1 1.000** |
| `console/test_console.py` | PASSED (incl. new `runbooks` + `audit-chain` groups) |
| `console/test_fsafe.py` | PASSED — 10 checks |
| `tests/test_intake.py` | 4/4 OK *(was 3 errors at pre-flight)* |
| `itsoc_mcp/test_mcp.py` | 93 passed, 0 failed |
| vitest | 26 files, **107/107** |
| `npm run build` | clean |
| detector sha | `364577c5…a4a876` unchanged |
| working tree | clean |

### Standing invariants for C0, grep/test-verified

- **No LLM parameter in `eligible()`'s signature** — live `inspect.signature` -> `(runbook, incident,
  findings)`, no `*args`/`**kwargs`, no advisory-ish names. Reinforced by data-closure projection,
  adversarial poisoning, and a non-vacuity check.
- **`--taxii-password` gone** — `grep -rn "taxii.password\|taxii_password\|--password" threat_intel/`
  returns nothing. No credential can reach argv or logs.
- **Audit chain honest under attack** — tamper reported at the correct index, no self-heal, no laundering.
- **Migration additive** — `+audit_index` only, zero drops, zero row changes, live DB untouched.

### The one item NOT green — owner decision required

`threat_intel/test_threat_intel.py` fails **16 checks**. god PROVED these pre-existing (identical
failure set at parent `b88304d`, delta ZERO), and Pam's read-only diagnosis established they are **three
independent causes**, not one stale cache: 10 = genuine table staleness fixable OFFLINE; 3 = the local
ATT&CK cache fixture is **doctored** (invented 'Stealth'/'Defense Impairment' tactics, `T1070.001`
revoked with a fabricated 2026-04-14 date) and the table is CORRECT; 3 = code/test drift including a
real defect (`techniques_for_rule` returns the table's own mutable objects).

It is **non-gating** for Stage C — not a canonical suite, and the only canonical consumer of that cache
is `console/soc.py:769`, a boolean `attackCacheWarm` that reads no technique names. But under the
autonomous-mode rule "every acceptance item passes (run, not claimed)", this item does not pass, so
**C0 does NOT auto-gate. Halting for the owner's merge decision.**

> **Owner decisions outstanding:**
> 1. Merge `stage-c/c0-foundations` into local `main`? Exact command below.
> 2. The 16 `test_threat_intel` failures — dedicated offline card, or documented known-red?
> 3. Kickoff **Q2** (OPNsense VM) and **Q3** (step-up identity) are still unanswered and are needed
>    before C3. Not blocking C1.

### Exact merge command the owner would run

```sh
cd ~/Projects/log-analyzer
git checkout main
git merge --no-ff stage-c/c0-foundations -m "Stage C phase C0: foundations (runbooks, audit chain, TI fixes)"
# NOT pushed — Q1 push authority is (c) never.
```

---

## PHASE C0 — MERGED to local `main` (owner-gated 2026-08-28)

```
git checkout main
git merge --no-ff stage-c/c0-foundations -m "Stage C phase C0: foundations (runbooks, audit chain, TI fixes)"
```
Merge commit **`18b03dd`**. NOT pushed (Q1 = (c)). `main` is now **17 commits ahead of `origin/main`**
(2 pre-Stage-C + 14 C0 + the merge).

**Post-merge gate on `main`, god-run:** eval 17/17 f1 1.000 · `console/test_console.py` PASSED ·
`console/test_fsafe.py` PASSED · `tests/test_intake.py` 4/4 OK · `itsoc_mcp/test_mcp.py` 93/0 ·
detector `364577c5…a4a876` · tree clean. (Run on principle: pre-gated work has previously exposed
latent bugs only real on-`main` state reveals.)

### D-2 · Reference write-connector changed from OPNsense to nftables-over-SSH — **OWNER-INITIATED AMENDMENT, RATIFIED**

Unlike D-1 (a worker-found self-contradiction), D-2 is an **owner-initiated** scope amendment: a
provisioning-effort trade that preserves swappability by construction.

**Old D1:** OPNsense firewall via REST API, key/secret over HTTPS, running in a VM for demos.
**New D1:** **iptables/nftables-over-SSH** (`console/actions/ssh_firewall.py`) against a local **Docker
demo target** — stock Debian/Alpine container running sshd + nftables with `NET_ADMIN`, **SSH key
auth** (satisfies the cert/token principle), disposable between runs. First action: block/unblock IP
via a **dedicated nft chain, rules tagged for clean revoke**.
`console/actions/opnsense.py` is now the **designated follow-on** adapter behind the same abstract
interface — out of scope this run. Because runbooks bind connectors **by name**, it can land later with
**zero changes to approvals, audit, eligibility, or UI**.

**Amended in the same manner as D-1**: the owner's revised build doc was synced into
`docs/ITSOC_STAGE_C_BUILD.md` (D1 line 12, C3 heading line 73, action layer line 76, C3 acceptance line
81, C5 demo line 105, §3 routing line 122), and the **ratified D-1 line 49 was re-applied on top** —
verified present after the sync, so the path-only TAXII auth wording was not reverted.

**Consequences now binding:**
- **C3 acceptance amended** — end-to-end against the **live Docker target**: block -> `nft list` shows
  the rule + the audit entry carries **verbatim command output** -> revoke removes it.
- **C5 demo line amended** — live block of `203.0.113.44` shown via `nft list`.
- **Provisioning is the orchestrator's, inside C3** — a `demo/target/` Dockerfile or run-script in the
  repo, plus a fresh SSH keypair generated locally into a **gitignored** path (e.g.
  `console/.soc/keys/`). Only the key **path** enters local config; the key value never appears in
  argv, logs, commits, or reports.
- **"BLOCKED — VM required" is RETIRED.** C3's live end-to-end item is no longer blockable on external
  provisioning.

### Q3 answered: (a) — existing Phase-6 local profile

The existing local profile's passphrase is the step-up approver identity; its **verified profile name**
is what lands in audit entries. The passphrase never appears in chat, answers, cards, logs, or audit
entries.

### Autonomous-mode gate semantics restated (owner, 2026-08-28)

A phase whose acceptance is **fully green** with zero tripwires and zero **unratified** deviations
**auto-merges to local `main` and proceeds without asking**. The C0 ask was justified by a non-green
acceptance item plus open kickoff questions; clean gates will not wait from C1 onward.

---

## Orchestration record — worker stall, liveness doctrine, phase-order audit (2026-08-28)

### Meredith stalled — card reassigned (owner-ratified)

`meredith-mtconud5` never activated: **0 tokens, `lastTool: null`, `lastActiveSecAgo: null`, empty
`memory.md`**, and **two `Circuit breaker: steer` notices** queued in its inbox alongside its card.
Its card (`prep-c1-sources-nav`, read-only) was **reassigned to Toby**, who already produced the
read-only C5 inventory covering the collector *backend*, so the frontend half pairs naturally.

Per the documented lesson from an earlier effort, **no replacement agent was spawned** — respawning on
a stall produced reassignment churn historically. Owner ratified.
**Standing rule:** if Meredith's slot recovers it takes a **new** card from the queue; the moved card
does not move back.

### Liveness doctrine — STANDING, not a footnote

> **Delivery is the liveness signal. `fleet.json` token counts and `lastTool` are unreliable and must
> NEVER be the basis for declaring a worker stalled or alive.**

Evidence: Toby and Oscar both read `tokens: 0, lastTool: null` in `fleet.json` while having each
delivered four and three completed cards respectively.

**Required diagnostic sequence before declaring any stall** (this is what was actually done for
Meredith): (1) check whether the agent has ever **delivered** a message; (2) read its
`agents/<id>/memory.md`; (3) read its `agents/<id>/inbox/` for queued work and breaker notices. Only
then may a stall be declared. Recorded in `hive/stage-c/GUARDRAILS.md` for all workers.

### PHASE-ORDER AUDIT — no breach. Prep-only confirmed.

The owner flagged a possible phase-ordering breach based on orchestrator wording. **Audited; no breach.**

**Orchestrator wording correction.** "Toby already owns the collector backend from C5" was sloppy and
is withdrawn. The accurate statement: *Toby produced a **read-only prep inventory** of the collector
backend in preparation for C5.* No C5 work has executed. Likewise "delivered three completed cards"
meant three cards **of which the post-C0 ones were all read-only inventories** — it did not mean three
phases of implementation.

**(a) Cards delivered, by id and phase:**

| Worker | Card | Phase | Type | Evidence |
|---|---|---|---|---|
| Toby | `C0-T4` terminology sweep | **C0** | EXECUTION | commit `141db71` (+ god fix `649aea4`) |
| Toby | `prep-c1-intel-network` | C1 prep | **READ-ONLY** | no commit |
| Toby | `prep-c2-seams` | C2 prep | **READ-ONLY** | no commit |
| Toby | `prep-c5-backpressure` | C5 prep | **READ-ONLY** | no commit |
| Toby | `prep-c1-sources-nav` (reassigned) | C1 prep | **READ-ONLY** | in flight |
| Oscar | `C0-T6` offline TI repair | **C0** | EXECUTION | commit `7db891b` |
| Oscar | `prep-c4-designsystem` | C4 prep | **READ-ONLY** | no commit |
| Oscar | `prep-c3-mcp` | C3 prep | **READ-ONLY** | no commit |
| Pam | `mitre-cache-diagnosis`, `prep-c1-cases` | C0/C1 | **READ-ONLY** | no commit |
| Pam | `prep-c3-auth` | C3 prep | **READ-ONLY** | in flight |
| Jim | `C0-T5` MCP assertion | **C0** | EXECUTION | commit `261f226` |
| Jim | `prep-c3-target` | C3 prep | **READ-ONLY** | in flight |

**Every execution card is phase C0. Every post-C0 card is read-only inventory.**

**(b) Has any C2+ card begun executing? NO.** Proof:
```
$ ls console/investigate.py console/org_context.py console/actions/ console/approvals.py
ls: console/investigate.py:  No such file or directory
ls: console/org_context.py:  No such file or directory
ls: console/actions/:        No such file or directory
ls: console/approvals.py:    No such file or directory
```
None of the C2/C3/C4 implementation surfaces exist. And every file touched since Stage C began
(`git diff --name-only e8ca0b7..HEAD`) is C0-scope: `console/audit.py`, `console/fsafe.py`,
`console/runbooks.py` + the 2 runbook yaml, `console/store.py`, `console/test_console.py`,
`console/test_fsafe.py`, `docs/*`, `itsoc_mcp/test_mcp.py`, `log_analyzer.py`, `rules_syslog.py`,
`threat_intel/*`. Nothing from C1's screen merges, C2's investigation engine, C3's action layer, C4's
components, or C5's back-pressure.

### FINDING — foreign uncommitted work in the tree (NOT Stage C)

The audit did surface something real: the working tree is **not clean**, and the changes are **not
ours**. See **OPEN-4** in `docs/STAGE_C_OPEN_ITEMS.md`. Summary: an independent task queue lives at
`log-analyzer/inbox/` (untracked, **not gitignored**), and uncommitted edits implementing its card
`006-asset-risk-weight.md` — sourced from `ITSOC_REDESIGN_SPEC.md` §Phase 4, **not** Stage C — appeared
at 11:20-11:22, after the C0 merge at 11:01. No Stage C card allowlist includes those files. The C0
exit gate and post-merge gate both ran **before** they appeared, so **no Stage C result is
contaminated**. Not reverted or committed — not Stage C's to touch. Owner decision requested.

### Process correction adopted (owner instruction)

`docs/STAGE_C_OPEN_ITEMS.md` is now maintained as the open-items register. **Every future gating ask
stands alone** and is quoted **verbatim** from that register, answerable without reference to prior
conversation.

### C0-T7 · MITRE mapping data-and-hygiene repair — **ACCEPTED** (commit `3998f06`, worker Oscar)

Owner-approved product-code allowlist (OPEN-1, approved as re-scoped). Diff: `rule_mitre_map.py` only,
+53/-43. **This clears the last known-red — C1 now has its zero-known-red baseline.**

Applied: `T1499.002` 'Service Exhaustion' -> **'Service Exhaustion Flood'** (8 rules); `T1046`
'Network Service Scanning' -> **'Network Service Discovery'**; `T1136.001` parent:sub resolved to
'Local Account'; `techniques_for_rule` now returns **`copy.deepcopy`** (line 68); the malformed
`'ioc_observed': []` sentinel removed.

**god-verified independently, not claimed:** `threat_intel/test_threat_intel.py` -> **0 failures, exactly
3 reasoned skips** (each carrying the visible doctored-cache reason string). `run_eval.py` 17/17
f1 1.000 with an **empty `manifest.json` diff — zero severity shift**, so the owner's hard-stop condition
did not trigger. `console/test_console.py`, `console/test_fsafe.py`, `tests/test_intake.py` 4/4,
`itsoc_mcp/test_mcp.py` 93/0 all green. Detector `364577c5…a4a876`. Foreign uncommitted files untouched.

**god adversarial test of the defensive-copy fix** (beyond the card): mutated the returned list in place
and appended to it, then re-read the table — `table intact after caller mutation: True`. The
guardrail-bearing table can no longer be corrupted by a caller, which was the owner's stated concern
("the same disease as the DEFAULT_MODE finding").

**Follow-up C0-T7a dispatched** — the version anchor is not yet pinned. Owner: *"a repo URL is a moving
target … 'correct' drifts the moment MITRE ships the next release."* god extracted the hard facts from
the actual bundle: id `bundle--6198013c-6f02-42a4-9713-38ea1301a1aa`, `spec_version "2.0"`,
`x_mitre_attack_spec_version "3.3.0"`, cache mtime 2026-08-14, and **no `x-mitre-collection` object**, so
a release number (vX.Y) is genuinely not recorded — to be stated plainly rather than guessed. Two
additions god caught: the header's **"STIX 2.1" claim is wrong** (the bundle says 2.0), and the header
must disclose that this cache is a **known-doctored fixture** (no `defense-evasion` tactic; invented
'Stealth'/'Defense Impairment'; `T1070.001` revoked with a fabricated 2026-04-14 date) so a reader can
tell how far to trust the anchor.

## Ops notes — hook error frequency log (owner-requested)

Owner: *"a flaky hook that ever silently fails on a real stop is a liveness hazard of the same genus as
the fleet.json counters."* Tracking occurrences here.

| # | Timestamp | Error | Blocking? |
|---|---|---|---|
| 1 | 2026-08-28 (this session) | `hive-node: Interrupted system call` on stop hook | No — flagged as local infra noise; work unaffected |

If this recurs, the count above grows and it is escalated as a liveness hazard rather than noise.

## Standing instruction recorded — open-items quoting

Owner: *"OPEN-5 exists only as a name to me. Fine while non-gating — but the moment it gates, its full
text comes inline in the same message."* Adopted: any `STAGE_C_OPEN_ITEMS.md` entry that becomes gating
is quoted **in full, inline, as plain flowing prose** — no box-drawing, no columns (owner's relay
corrupts those). Prose summaries remain fine for non-gating items.

### C0-T7a · ATT&CK version anchor pinned — **ACCEPTED** (commit `538e414`, worker Oscar)

Comment-only change, god-verified (`git show 538e414` contains no non-comment lines; +14/-4 in
`rule_mitre_map.py` alone). The anchor now pins concretely instead of pointing at a moving repo URL:
bundle id `bundle--6198013c-6f02-42a4-9713-38ea1301a1aa`, `spec_version "2.0"` (the earlier "STIX 2.1"
claim was wrong and is corrected), `x_mitre_attack_spec_version "3.3.0"`, retrieval date 2026-08-14, and
an explicit statement that **the ATT&CK release number is not recorded in this bundle** because it holds
no `x-mitre-collection` object — stated plainly rather than guessed, which was the point.

It also carries the honesty disclosure: the local cache is a **known-doctored fixture** (missing
`defense-evasion`, invented 'Stealth'/'Defense Impairment', `T1070.001` revoked with a fabricated
2026-04-14 date), and that this is what the three reasoned test skips correspond to. A reader can now
tell exactly how far to trust the anchor. Suites still green: threat_intel 0 failures / 3 skips,
`run_eval` 17/17 f1 1.000.

### C1-T1 · IN FLIGHT — orchestrator intervention before commit (not a defect in the work)

Two mechanical problems caught by a routine progress check, **before** anything was committed:

1. **Work was on `main`, not the phase branch.** `stage-c/c1-consolidation` existed but sat at `df60f81`
   with zero commits, while C1's allowlist files were being modified on `main`. Phase work must never
   land on `main` — the owner gates every merge.
2. **`console/soc.py` held the foreign hunk mixed with C1 work.** The foreign `metrics()` edit
   (`assetsAtRisk`/`usersAtRisk` severity weighting, from the separate `inbox/` queue) sits in the same
   file C1-T1 legitimately edits, so `git add console/soc.py` would have committed the owner's reserved
   work along with ours.

An exact, non-improvised procedure was issued: back up the file first; restore the foreign hunk to its
HEAD form (both forms quoted verbatim in the message); `git checkout -B stage-c/c1-consolidation` to
repoint the branch and switch **while keeping the working tree**; commit only allowlist files by
explicit path; verify the other three foreign files are still listed as modified; then re-apply the
foreign hunk so the owner's pending work is preserved uncommitted. Stop-and-ask if any step deviates —
losing someone else's uncommitted work is worse than a delay.

**The work itself is sound.** Pam correctly identified the silent-killer tripwire and is carrying
`origin` and `cases` across every re-derivation in the preserve block, with a comment naming exactly why.
One code note raised: `_try_absorb_cases()` appears twice in the current diff — flagged as a possible
duplicate insertion to check before it ships.

---

## PHASE C1 — COMPLETE. Auto-merged to local `main` (owner standing rule: clean gates do not wait).

Merge commit **`09f73f0`**, plus `2a743ff` rebuilding `web/dist`. `main` is now **49 commits ahead of
`origin/main`**, all local (Q1 = (c) never push). Detector `364577c5…a4a876` unchanged throughout.

| Card | Commit | Worker | Outcome |
|---|---|---|---|
| C1-T1 Cases->Incidents migration | `a8fa7ae` | Pam | ACCEPTED |
| C1-T2 Incidents merged screen (TEMPLATE) | `069ff19` | Pam | ACCEPTED |
| C1-T3 Intel (ThreatIntel + Enrichment) | `dec8c27` | Toby | ACCEPTED |
| C1-T4 Network (Discovery + Vulnerabilities) | `67d16cf` | Oscar | ACCEPTED after C1-T4a |
| C1-T5 Sources (Collectors folded in) | `0b2c4f9` | Pam | ACCEPTED |
| C1-T6 nav reduction + Cmd-K aliases | `5154d19` | Toby | ACCEPTED |

**Phase gate, god-run on the integrated branch and again on `main`:** vitest **30 files / 138 tests**
(from 107 at phase start) · `npm run build` clean · `run_eval` 17/17 f1 1.000 · `console/test_console.py`
PASSED · `console/test_fsafe.py` PASSED · `tests/test_intake.py` 4/4 · `itsoc_mcp/test_mcp.py` 93/0 ·
`threat_intel/test_threat_intel.py` 0 failures / 3 reasoned skips · detector frozen · tree clean.

### The honesty surfaces C1 actually delivered

- **Manual incidents cannot masquerade as rule verdicts.** Proven by asserting *absence*:
  `expect(document.querySelector(".is-tag--crit, .is-tag--high, .is-tag--med, .is-tag--low")).toBeNull()`,
  alongside the MANUAL badge and analyst-assigned labelling, with a distinct detail composition carrying
  no RCA/evidence rail to fabricate.
- **Intel keeps TWO DISTINCT egress labels.** Feeds is offline ("Surfaced, not generated — offline STIX
  bundle"); Live Enrichment genuinely calls out ("Real provider responses — never fabricated"). A single
  shared label would have claimed egress that does not happen or hidden egress that does.
- **Network consolidates three scanning notices into one** while preserving the authorization wording
  verbatim — a safety notice, not decorative copy — and re-points the formerly dangling `/discovery` link.
- **Sources keeps the honest `host:port` bind display**, asserted including the null path, with the suite
  checking the literal string `undefined` appears nowhere.
- **Old names still work.** Cmd-K aliases Cases->Incidents, Threat Intel/Enrichment->Intel,
  Discovery/Vulnerabilities->Network, Collectors->Sources — each asserted to *navigate*, not merely exist.
- **Approvals holds a nav slot only**, labelled "Not built yet — the page says so honestly". Its screen is C4.

### Integration notes

All three fan-out branches merged with **zero conflicts** despite each touching `App.tsx`,
`AppShell.tsx` and `CommandPalette.tsx` — worktree isolation plus tight allowlists kept them in
disjoint regions. Workers were forbidden from committing `web/dist`; regenerating it at integration is
the orchestrator's step (`2a743ff`).

**One defect caught pre-merge by diff inspection rather than by trusting a report:** C1-T4 had committed
five `web/dist` build files outside its allowlist and had tab markup missing `role="tablist"`,
`role="tab"` and `aria-selected`. Its report said ".is-tabs styling", which was true but incomplete.
Reconciliation card C1-T4a fixed both.

### Carried into C2

C2 opens with its **fixture obligation** as the first card: seed the **INC-4a7f** brute-force scenario
(203.0.113.44 -> server-01) as deterministic sample data, before the investigation-engine cards run
against it. Also carried: **OPEN-8**, the pre-existing `shell.test.tsx` order-dependence — recommended
fix during C2 with `--sequence.shuffle` added to the standing gate afterwards.

---

## PHASE C2 — COMPLETE. Auto-merged to local `main` (`b231163`).

Detector `364577c5…a4a876` unchanged throughout. `main` is now **67 commits ahead of `origin/main`**,
nothing pushed (Q1 = (c)).

| Card | Commit | Worker |
|---|---|---|
| C2-T0 seed the INC-4a7f scenario | `1d02663` | Pam |
| C2-T1 deterministic engine + D2 LLM split | `00af9c8` | Pam |
| C2-T2 parallel grounded advisory agents | `b397efb` | Jim |
| C2-T3 org-context priority rules | `1ec6721` | Oscar |
| C2-T4 Incidents investigation-file section | `f53785f` | Pam |
| C2-FIX `_correlation` guard (audit finding) | `1e23d65` | Oscar |

**Phase gate, god-run on the integrated branch and again on `main`:** web **144/144 shuffled** ·
`npm run build` clean · `run_eval` **19/19** f1 1.000 · `console/test_console.py` PASSED ·
`console/test_fsafe.py` PASSED · `tests/test_intake.py` 4/4 · `itsoc_mcp/test_mcp.py` 93/0 ·
`threat_intel/test_threat_intel.py` 0 failures / 3 reasoned skips · detector frozen.
(The eval suite grew 17 -> 19 cases via the concurrent non-Stage-C queue's parser work; f1 still 1.000.)

### What C2 actually guarantees

**D2 is honoured structurally, not by convention.** `investigate.assemble()` makes **zero model calls** —
proven adversarially by patching both transport functions to throw *and* to sleep, running the advisory
route concurrently, and counting attempts. It returns in **~2.5 ms** against a 120,000 ms target. The
`serve.py` rca route no longer waits on `la.chat_completion`.

**Advisory content cannot fabricate.** Three agents, bounded concurrency 3, 45s each, every block
guard-checked. Measured grounding ratio **1.000** against the ≥0.95 bar. Hallucinated IPs, hostnames,
record numbers and a string citation were all intercepted and stripped. On model failure the block shows
`ADVISORY · timed out — retry` — visible, never silent, never replaced by prose.

**Fact and hypothesis are distinguishable at a glance**, asserted structurally rather than styled. An
unresolvable citation renders as a `.miss` so an ungrounded claim cannot masquerade as cited.

**Priority never mutates severity** — a second rule-owned axis, asserted byte-identical across all three
criticality tags.

### Independent adversarial audit

A separate worker attacked all six guarantees on the integrated branch and reported them holding, naming
each attack attempted. It surfaced one real defect — `_correlation` indexing `e["n"]` unguarded while its
three siblings guarded — which was fixed by its finder with a regression test and a clean sweep for the
same pattern elsewhere. **C2 was deliberately not completed until that landed**, though it was a
robustness finding rather than a failed acceptance item.

### Incident during integration — orchestrator error, caught and repaired

The first C2 merge landed on the **wrong branch**. The concurrent non-Stage-C queue switched the shared
integration checkout to `feat/efficacy-harness` between commands, and the merge went there instead of
`main`. Detected immediately by checking `git merge-base --is-ancestor` rather than trusting the merge
output. Repaired: nothing had built on the stray merge, `feat/efficacy-harness` was restored to `8a13e6e`
(its pre-merge tip), and the merge was redone on `main` **with an explicit branch guard that aborts if
HEAD is not `main`**. That guard is now standard for every integration merge.

This is the second time the shared integration checkout has caused a real incident (see OPEN-10). Worker
worktrees are isolated and were unaffected both times; the exposure is entirely in the orchestrator's own
checkout.

## Phase C3 — Gated response (in progress)

### C3-T1 · Action connector layer + nftables-over-SSH + demo target — ACCEPTED
- Commit `e646ac8` on `stage-c/c3-gated-response`. Worker: Toby.
- Verified by the orchestrator by running, not by reading the report:
  - Redaction: `preview()` for `203.0.113.44` renders
    `nft add element inet itsoc blacklist '{ [IP-1] comment "itsoc:appr-a1" }'`;
    the raw IP is absent from the whole preview dict. Unredacted values reach only the SSH pipe.
  - Private-key-as-text is rejected at `console/actions/ssh_firewall.py:140`, inside `execute()`.
  - Container: `--cap-add=NET_ADMIN` only, `-p 127.0.0.1:<port>:22`, default seccomp,
    no `--privileged`, no `--net=host`, no Docker socket mount.
  - Gate: eval 19/19 f1 1.000; all python suites green; web 144/144; detector sha unchanged.
- **BLOCKED acceptance item:** live end-to-end nftables block. Docker daemon is not running (OPEN-9).
  Recorded as BLOCKED, not as passed.

### Ops notes on C3-T1
- Orchestrator error, self-corrected: private-key rejection was first probed against `preview()`,
  which never touches the key, and was nearly reported as a security gap. The check was wrong,
  not the code.
- Worker report imprecision: "no host filesystem mounts" — `run.sh` performs a single-file
  read-only bind of the **public** key. Design is sound; the claim was not exact.
- Guardrail refined rather than enforced as written: the host-mount prohibition targets socket
  mounts, host directory mounts, and writable mounts. A read-only public-key file bind is
  permitted and preferred over baking a key into the image.

### In flight
- **C3-T2** (Pam) — approvals API + per-action step-up auth per D3, on `stage-c/c3-gated-response`.
- **C3-T2b** (Jim) — `console/ti_oem.py` egress redaction gap (OPEN-5), on `fix/c3-tioem-egress-redact`.
- Held pending T2's API: C3-T3 gated MCP `propose_block_ip`, C3-T4 copilot recommendation.

### C3-T2b · TI/OEM observable egress sanitized (OPEN-5) — ACCEPTED, merge HELD
- Commit `5694f6e` on `fix/c3-tioem-egress-redact`. Worker: Jim. 2 files, +235/-11.
- Diff exactly on allowlist (`console/ti_oem.py`, `tests/test_ti_oem_egress.py`); `redact.py` untouched;
  detector sha unchanged.
- **Verified by an independent orchestrator probe the worker never saw** — a novel header
  `X-Totally-New-Token`, a novel body field `x-vendor-quirk-secret`, a raw IP and a username, with the
  stubbed transport echoing every raw field back in its exception:
  - wire retained the marker, the raw IP, the auth header and the body (functionality preserved —
    non-vacuous);
  - the propagated error carried `[REDACTED]` for all three secret-named fields, `[IP-1]` for the
    address and `[USER-1]` for the username;
  - marker, raw IP and username all absent from the exception, stdout and stderr.
- `raise ... from None` correctly suppresses the chained transport exception, which is the usual leak.
- Only two egress sites exist in the module (`ti_oem.py:381,384`), both inside `_http_request` — no bypass.
- Green: console suite fully green (35 check groups incl. ti-oem and the migration check once the
  copied `.soc` fixture was supplied); eval 19/19, precision/f1 1.000; egress tests 3/3.
- **MERGE HELD, deliberately.** This commit embodies interpretation A of OPEN-11, which narrows the
  literal text of Guardrail 4 and is awaiting owner ratification. Merging first would bake an
  unratified guardrail narrowing into `main`. The code is accepted; the merge waits on OPEN-11.

### C3-T2 · Approvals API + per-action step-up auth (D3) — ACCEPTED
- Commit `a4e9178` on `stage-c/c3-gated-response`. Worker: Pam. 4 files, +886.
  `console/auth.py`, `console/serve.py`, `console/soc.py`, `tests/test_approvals.py`.
- Allowlist extended mid-card, by the orchestrator, to `console/serve.py` for route delegation only:
  the original card named `soc.py (API routes)`, but all `/api/*` dispatch lives in `serve.py` and
  `soc.py` has no HTTP handler, so the endpoints were unreachable as scoped. The worker raised this
  rather than guessing, and built the soc.py functions HTTP-agnostic so no ruling could waste work.
- Orchestrator verification, by running:
  - Suite `tests/test_approvals.py` — 14 tests, OK.
  - **Mutation test 1** — forced `verify_stepup_passphrase` to always return true: **4 tests failed**.
    The step-up guarantee is genuinely bound by the suite, not merely accompanied by it.
  - **Mutation test 2** — disabled the re-evaluation branch: **3 tests failed**. The owner-ratified
    re-evaluation guarantee is likewise bound.
  - **Independent fail-closed probe** of the step-up primitive: empty string, `None`, a wrong value,
    and — the interesting cases — the stored `hash` and the stored `salt` submitted as the passphrase.
    All returned `(False, None)`. `_sessions` byte-identical before and after, so zero session
    creation holds. `approve_approval` with an empty and with a `None` passphrase both returned 401
    with the spy connector at zero calls.
  - `BaseAuthProvider` gained an abstract method; confirmed `LocalDemoAuth` is its only subclass, so
    nothing else became uninstantiable.
  - serve.py diff is three delegation hunks and nothing else; POST routes sit after the
    `_api_authorized` gate (serve.py:1581), so step-up is additive to the bearer check, not a
    substitute for it.
- Gate: console suite fully green (35 groups incl. `action-layer-ssh-firewall`); approvals 14/14;
  MCP 93/0; fsafe 10; intake 4/4; eval 19/19 f1 1.000; `npm run build` clean; detector sha unchanged.
- Design notes recorded: a *pending* create is deliberately NOT audited (creating a proposal is not a
  consequential act; `audit.STATUSES` covers approved/rejected/executed/failed), and approvals persist
  to `.soc/approvals.json` via `soc._save`, leaving the SQLite store schema untouched.

### C3-T3 · Gated MCP `propose_block_ip` + docs honesty correction — ACCEPTED
- Commits `adf236d` (initial), `19fcbf8` (repair C3-T3a), `73167a5` (repair C3-T3b) on `stage-c/c3-mcp`.
  Worker: Toby. Two repair rounds; both defect classes were found by the orchestrator, not by the suite.
- **Defect 1 (C3-T3a): advertised-but-ignored parameters.** The input schema declared `ip`
  ("Optional IPv4 address to verify against incident entity") and `note`; the function read neither.
  A caller could supply an address, believe they had constrained which IP gets blocked, and be wrong —
  the same failure mode as the "read-only" claim the same commit was correcting. Also
  `state: resp.get("state", "pending")` fabricated a backend fact when the backend returned none.
  Resolved by removing both parameters and the default. Verified through the registered handler:
  a call carrying `ip`/`note`/`approve`/`passphrase` sends `{incidentId, runbookId}` only, and a
  no-state backend now yields `state: None`.
- **Defect 2 (C3-T3b): the honesty correction stopped one file short of the published manifest.**
  `itsoc_mcp/server.json:4` and `PUBLISHING.md:22,26` still said "read-only" / "Tools (all read-only)".
  `server.json` is the description published to the MCP registry — correcting the in-repo files while
  leaving the public manifest false would have left the honest statement in the one place nobody
  outside the repo reads. Also unmet at that point: the build doc's C3 item 3 requirement to
  "Document in `itsoc_mcp/PUBLISHING.md` provenance". Both now done; `grep -rEi "read.only" itsoc_mcp/`
  returns zero matches; package version deliberately not bumped.
- Negative authority verified independently: payload carries only `incidentId`/`runbookId`; the registry
  contains no `approve_*`/`reject_*`/`execute_*`/`revoke_*`/`remediate_*` tool; `tools.py` imports
  neither `subprocess` nor `socket` nor the connector module.
- Gate: MCP 131/131, console suite PASSED, approvals 14/14, fsafe 10, eval 19/19 f1 1.000, detector frozen.

### Deviation register addition — D-3 (ratified by the orchestrator, disclosed to the owner)
`73167a5` touched five files outside its card's allowlist (`client.py`, `server.py`, `tools.py`,
`test_mcp.py`, `requirements-mcp.txt`). Every hunk is a comment, docstring or description string
removing a stale "read-only" claim; there is no executable change. The cause was the orchestrator's
card, whose definition of done required that no inaccurate claim survive anywhere in `itsoc_mcp/`
while its allowlist named only three files. Ratified on that basis. This is the sixth card in this run
whose wording caused a worker to breach or question its own allowlist — see OPEN-12.
