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
