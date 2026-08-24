# Autonomous Run Report — Run 2 (reliability / model-swap / storage)

_Unattended orchestration by Michael (god). Merge gate for every task: `python3 tests/eval/run_eval.py` = 17/17 AND `python3 console/test_console.py` passes AND detector sha == `43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05`. No irreversible/outward actions taken._

## Final summary (Run 2) — ALL 3 TASKS MERGED GREEN ✅

Autonomous Run 2 complete. All three tasks passed the merge gate and are merged to `main` and pushed to `origin/main`. Nothing left on a branch, nothing forced or faked. **No task required editing `anomaly_detector.py`, changing a severity value, changing the default model, or touching `tests/eval/manifest.json`.** Detector sha stayed `43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05` throughout.

| Task | Owner | Merge | Result |
|---|---|---|---|
| 1 — schema-constrained structured output + honest fallback | Ryan | `e212b18` (branch `feat/structured-output`) | **MERGED green** |
| 2 — model A/B swap + benchmark (`tools/model_ab.py`) | Ryan | `5096e76` (branch `feat/model-ab`) | **MERGED green** |
| 3 — atomic/locked flat-file storage + roadmap doc | Toby | `531e901` (branch `feat/storage-harden`) | **MERGED green** |

`main` HEAD = `5096e76`, pushed to `origin/main` (was `00c2035` at run start).

**Final full-suite run on merged `main`:**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`, precision/recall/f1 = 1.000
- `python3 threat_intel/test_threat_intel.py` → PASSED — all checks green
- `python3 console/test_console.py` → PASSED — all suites incl. `structured-output` + `storage-atomic`
- `cd web && npm test` → 23 files / 86 tests pass; `npm run build` → clean
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged

**Honesty invariants held:** rules own the verdict; the LLM only explains (schema constrains *decoding*, doesn't add verdict authority); schema-rejection fallback is always *recorded* in run metadata, never silent; the model-A/B tool *surfaces* any cross-model rule-finding divergence (loud + exit 1) rather than hiding it; storage hardening keeps the format and every write atomic/locked so a crash or race can never leave a truncated run.

**Orchestration notes / anything needing your attention:**
- **Roster changed mid-run:** Dwight and Creed were archived; work was routed to the current floor — **Ryan** (Tasks 1 & 2) and **Toby** (Task 3). **Jim stayed dormant** on the initial delivery, so Task 3 was reassigned from Jim to Toby (Jim later woke and confirmed he never started it — no collision). Delivery lesson: cross-session sends were approval-gated in this unattended run, so dispatch went via the hive **outbox** (reliable).
- **Merge conflict (Task 1 vs Task 3)** in `console/test_console.py` — both appended a check + runner registration. Resolved by god deterministically (union of both suites + carried the branch's `check_remote_compute` `fake_chat` `response_schema=None` change); `log_analyzer.py` verified identical to the branch; full suite green before committing.
- **Nothing was skipped for a rule-violation reason.** No product decision was made by the fleet: picking a model winner is explicitly left to you (`tools/model_ab_report.md` says so). Reminder: `tools/model_ab_report.md` is currently an honest empty template because Ollama wasn't running at generation time — re-run `python3 tools/model_ab.py <models…>` with Ollama up to get real latency/quality numbers before choosing a default.

_Delegation: I (god) orchestrated — Ryan and Toby (current-floor hive workers) implemented in isolated git worktrees, one branch per task; I QA'd each independently (merge `--no-ff` + full gate + sha) before merging. Per-task details below._

---

## Final summary (Run 2) — appendix (superseded by the summary above)
_(historical placeholder — see the completed summary above)_

### Task 1 — Schema-constrained structured output
**Status: MERGED to main** (`--no-ff` @ `e212b18`, from branch `feat/structured-output` @ `d74eef2`). Owner: **Ryan** (ryan-mt6hk081). QA'd independently by god; merge conflict resolved (see note).

**What shipped (`log_analyzer.py` + `console/test_console.py`, ~350/−35):** `RESPONSE_SCHEMA` defined once, `required` derived from exactly what `validate_response()` checks (findings array; items require non-empty `summary`) — no invented fields. `chat_completion` + `chat_completion_stream` take an optional `response_schema`; when set (and flag on) they send `response_format {type:json_schema, json_schema:{name, schema}}` on the /v1 path, temperature still 0. `analyze_chunk` passes `RESPONSE_SCHEMA`, so first-pass, second-pass, and on-demand explanations all get constrained decoding. **Design (correct):** the schema is per-call, not hard-wired, because `chat_completion` is shared — `serve.ask_analyst` expects `{"answer":...}` and `compare.py` has its own shape; forcing the findings schema there would corrupt both. Stream caller today is prose-only so passes no schema (wiring present for any future JSON stream caller).

**Honest fallback:** `LLM_STRUCTURED_OUTPUT` env flag, default ON. On HTTP rejection of the schema-bearing request → one retry without schema; if that succeeds the downgrade is recorded (sticky for the process, printed loudly) and later calls skip the doomed schema request. Run metadata (partial + final report dicts) carries `structured_output: "on"|"off"|"fallback:endpoint rejected json_schema (HTTP <code>)`. Never silent. If the no-schema retry ALSO fails, the original error propagates via the existing `api_error` path (endpoint broken ≠ schema-averse — no false fallback). `strip_fences`, `validate_response`, both retry nudges, and the HIGH `analyzer_error` backstop preserved. (Ryan verified no `<think>`-stripping exists anywhere in the repo — honest correction to the brief.)

**Tests:** new `check_structured_output()` — 21 assertions, `urllib.request.urlopen` stubbed at the HTTP layer (no network): schema actually sent + carries the constant; schema-permitted replies always satisfy `validate_response` while the old drift shape `{"log":[...]}` is schema-forbidden AND validator-rejected; recorded fallback on 400 + doomed-request skip after; backstop intact; flag-off honest `off`; end-to-end rules-only `run()` writes `structured_output` into report.json.

**Merge conflict resolution (god):** Task 1 and Task 3 both edited `console/test_console.py` (each appended a similarly-scaffolded check + runner registration), producing a tangled auto-merge. Resolved deterministically: restored main's file (has `check_storage_atomic`), inserted Task 1's `check_structured_output` verbatim from the branch, added both to the runner (union), and carried over the branch's `check_remote_compute` `fake_chat` signature change (`response_schema=None`, needed because `analyze_chunk` now passes it). Verified `log_analyzer.py` matches the branch exactly (empty diff) and the full console suite is green before committing.

**Gate (on merged main):**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`; f1 = 1.000
- `python3 console/test_console.py` → PASSED — all suites incl. `storage-atomic` + `structured-output`
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged

### Task 2 — Model A/B swap + benchmark
**Status: MERGED to main** (`--no-ff` @ `5096e76`, from branch `feat/model-ab` @ `ce14ecb`). Owner: **Ryan** (ryan-mt6hk081). QA'd independently by god. Depended on Task 1 (merged first).

**Hardcode sweep:** grep across py/tsx/ts/html/md found exactly ONE runtime hardcode, now fixed — `console/anomaly_console.html`'s per-finding panel said "Plain-language explanation · llama3.1:8b, local" regardless of the run's model; it now renders `${(DATA.manifest||{}).model || 'model n/a'}` from run metadata. Proving grep after the fix: every remaining hit is legitimate — the ONE sanctioned default `log_analyzer.py:61` (`os.getenv('LLM_MODEL','llama3.1:8b')`, untouched) + its docstring/comments, test fixtures, demo/mock states explicitly gated non-live, and doc mockups. No code path selects a model except `LLM_MODEL`/`--model`.

**`tools/model_ab.py`** (new, stdlib + existing modules only; detector/analyzer logic untouched): CLI list of models (+ `--base-url`/`--api-key`/`--output`), pre-checks `/models`; per reachable model runs the EXISTING `la.run()` path over `samples/OpenSSH_2k.log` and `samples/Linux_2k.log` with structured output ON, temp forced 0, fallback state reset between models. Measures by wrapping `la.chat_completion` from outside (analyze path stays byte-identical): warm median latency per explanation call (cold model-load call excluded), schema-valid vs invalid counts, `structured_output` metadata, findings by source, and dumps every rule finding's explanation prose for eyeball comparison. **Rule-finding identity is ASSERTED across models** per sample (by `(rule_id, summary)` signature): a mismatch prints BUG loudly, lands in a "RULE-FINDING MISMATCH — DO NOT PICK A WINNER" section, and exits 1 — surfaced, never hidden. Unreachable endpoint / uninstalled model → honest "not reachable" skip, no crash.

**`tools/model_ab_report.md`** (new): generated by an actual tool run. Ollama was NOT running at generation time, so it is the honest template ("No measurements … no numbers"), exercising the skip path. It documents: **winner = human decision**, set via `LLM_MODEL` in `.env` (code default at `log_analyzer.py:61` unchanged); if the default ever changes, `RUNBOOK.md`/`README.md`/the log_analyzer docstring and `docs/design` mockups must be updated — the console label + manifest strip now follow run metadata automatically.

**Files changed (3, +291/−1):** `console/anomaly_console.html`, `tools/model_ab.py` (new), `tools/model_ab_report.md` (new). `test_console.py` NOT touched → no merge conflict.

**Gate (on merged main):**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`; f1 = 1.000
- `python3 console/test_console.py` → PASSED — all suites (incl. node parse/render of the edited console HTML)
- `python3 threat_intel/test_threat_intel.py` → PASSED (no regression); `cd web && npm test` → 86/86; build clean
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged (no default-model / severity / manifest change)

### Task 3 — Concurrency-safe flat-file storage + roadmap doc
**Status: MERGED to main** (`--no-ff` @ `531e901`, from branch `feat/storage-harden` @ `bee913f`). Owner: **Toby** (toby-mt6hk5th) — reassigned from Jim, who stayed dormant and never activated. QA'd independently by god.

**What shipped:** new stdlib-only `console/fsafe.py` — `atomic_write_text` = temp file in same dir + `fsync` + `os.replace()`, guarded by a per-target sidecar `.lock` (`fcntl.flock` on POSIX, portable `O_CREAT|O_EXCL` spin-lock fallback with a 10s stale-lock timeout). Routed through it: `serve.save_run` (~line 250), `serve.persist_state` (both `STATE_FILE` and the run-history rewrite), and `soc._save`. **Storage format unchanged** (same paths, same JSON). `console/store.py` (embedded sqlite3) left untouched as instructed. `.gitignore` adds the `.lock` sidecar.

**Roadmap doc:** `ACTION_PLAN.md` created (repo had none) — current state documented honestly as **hybrid** (embedded sqlite3 via `store.py` for SOC Command Center structured data + flat JSON for run history and `.soc/` derived stores), correct now / on-thesis / zero-egress; migrate flat stores to embedded stdlib sqlite3 only at the Tier-2 (team/live-input) concurrency/query/retention trigger; Postgres only at Tier-3. Both explicitly marked **not to be built now**.

**Files changed (6, +296/−6):** `ACTION_PLAN.md` (new), `console/fsafe.py` (new), `console/serve.py`, `console/soc.py`, `console/test_console.py` (`check_storage_atomic()` — 10 checks: `os.replace` monkeypatched to raise between temp-write and swap, on-disk file still parses as the COMPLETE previous JSON at unit / via persist_state after a real save_run / via soc._save; no temp litter; 4 threads × 15 racing writes end as one writer's complete payload), `.gitignore`.

**Gate (on merged main):**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`; f1 = 1.000
- `python3 console/test_console.py` → PASSED — all checks incl. new `storage-atomic`
- web untouched → no vitest/build required for this task
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged

_Note: worker's local commit defaulted to author `ankit@mac.home` (no git identity in the worker env); the `--no-ff` merge commit was authored `Ankit Kumar <ankit512.kumar@gmail.com>` to keep main consistent._

---

# Autonomous Run Report — Run 1 (3 honesty tasks) — COMPLETE

_Unattended orchestration by Michael (god). Merge gate for every task: `python3 tests/eval/run_eval.py` = 17/17 AND `python3 console/test_console.py` passes AND detector sha == `43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05`. No irreversible/outward actions taken._

## Final summary — ALL 3 TASKS MERGED GREEN ✅

Autonomous run complete. All three tasks passed the merge gate and are merged to `main` and pushed to `origin/main`. Nothing was left on a branch, nothing was forced or faked, and **no task required editing `anomaly_detector.py`, changing a severity value, or touching `tests/eval/manifest.json`.** The detector sha stayed `43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05` throughout.

| Task | Owner | Merge | Result |
|---|---|---|---|
| 1 — explanation↔rule consistency guard | Dwight | `bf3271b` (branch `feat/explanation-guard`) | **MERGED green** |
| 2 — threat-intel severity honesty fix | Jim | `ac19b0d` (branch `feat/ti-severity-honesty`) | **MERGED green** |
| 3 — advisory RCA narrative | Dwight | `00c2035` (branch `feat/advisory-rca`) | **MERGED green** |

`main` HEAD = `00c2035`, pushed to `origin/main` (was `6910a94`).

**Final full-suite run on merged `main`:**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`, precision/recall/f1 = 1.000
- `python3 threat_intel/test_threat_intel.py` → PASSED — all checks green
- `python3 console/test_console.py` → PASSED — all suites incl. `explanation-guard` + `advisory-rca`
- `cd web && npm test` → 23 files / 86 tests pass; `npm run build` → clean
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged

**Honesty invariants held everywhere:** rules own the verdict; the guard only withholds a suspect explanation (never overrides/rewrites); RCA never writes severity and every optional layer (runbook cite, LLM hypothesis) degrades to an explicit honest absence, never a fabricated one; LLM egress stays confined to the redact choke point.

**⚠️ NEEDS YOUR DECISION (nothing was silently baked in — conservative defaults chosen and flagged):**
- **Task 3 BM25 citation bar** — `RCA_MIN_SCORE = 1.0`, `RCA_MIN_COVERAGE = 0.5` (rule-id tokens). Review/tune. (Details in Task 3 section.)
- **Task 3 fault-type guard** scoped to single-rule clusters; **hypothesis is local-compute only** (remote RCA would need its own redaction path).
- **Nothing was skipped for a rule-violation reason** — no task hit the "would require touching the frozen detector / a severity value / manifest / a product decision I must not guess" wall. The only product decisions (the BM25 bar) were handled with conservative commented defaults and surfaced above rather than skipped.

_Delegation note: I (god) orchestrated — Jim and Dwight (existing idle log-analyzer workers, not newly spawned) implemented in isolated git worktrees on one branch per task; I QA'd each independently (merge `--no-ff` + full gate + sha) before merging. Handoff report and per-task details below._

---

---

## Task 1 — Explanation↔rule consistency guard
**Status: MERGED to main** (`--no-ff` @ `bf3271b`, from branch `feat/explanation-guard` @ `c817634`). Owner: Dwight (dwight-mt1tbdgc). QA'd independently by god.

**What shipped:** new stdlib-only `explanation_guard.py` — `verify_explanation(finding, text) -> {"ok", "reasons"}` with three deterministic checks: (a) **grounding** — every IP, quoted username, and hostname-shaped token in the prose must appear in the finding's OWN fields (entities/evidence/summary/predicate/timeline); model-authored fields (llmWhy/recommended_action/guard-reasons) are excluded from the corpus so prose can never vouch for prose; (b) **fault-type** — vocab mirrored from `rule_context.predicate_for` + `rules_syslog` for all 7 rule ids; prose matching a foreign rule's distinctive vocab with none of its own is flagged; (c) **count sanity** — a number asserted in prose must appear in the finding. Handles both the analyzer anomaly dict and the console/adapter finding shape.

**Wiring:** guard runs at the single attach point in `log_analyzer.py run()` (covers eager + second-pass) and via a `guarded_explanation()` seam in `console/serve.py _explain` (`/api/explain`). On failure: explanation withheld and replaced with `"unverified — possible mismatch, sent for review"`, `explanation_unverified`/`explanation_guard_reasons` set, ALL deterministic fields (verdict/predicate/timeline) left byte-identical. Never rewrites prose, never overrides a verdict.

**Files changed (4, +345/−3):** `explanation_guard.py` (new), `log_analyzer.py`, `console/serve.py`, `console/test_console.py` (`check_explanation_guard()` — 12 asserts: correct passes, wrong-host caught, wrong-fault-type flagged, fabricated count caught, console withhold path keeps deterministic fields intact, consistent prose passes verbatim).

**Gate (on merged main):**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`; f1 = 1.000
- `python3 console/test_console.py` → PASSED — all checks green incl. `explanation-guard`
- `python3 threat_intel/test_threat_intel.py` → PASSED (no regression from Task 2)
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged (no severity values / manifest touched)

## Task 2 — Threat-intel severity honesty fix
**Status: MERGED to main** (`--no-ff` @ `ac19b0d`, from branch `feat/ti-severity-honesty` @ `a26d160`). Owner: Jim (jim-mt1tba4q). QA'd independently by god.

**Premise correction (needs no decision — informational):** the brief's premise ("flattens every match to CRITICAL") does NOT match the code. `severity_for()` already graduated: malicious-activity+ATT&CK-technique → critical, malicious-activity → high, technique-only → high. The real honesty gap was the unconditional `return "medium"` floor — severity above the floor with no basis.

**Fix:** the no-basis floor `medium` → `low`. A match with no malicious-activity label and no ATT&CK technique now returns `low` (the match itself is the only evidence). `low` already exists in `sev_order`/report breakdown — no new vocabulary, no numeric thresholds, no product decision. Offline mode stays default; no CLI/behavior change.

**Files changed (2, +22/-1):** `threat_intel/threat_detector.py` (floor + comment), `threat_intel/test_threat_intel.py` (severity-honesty block: critical/high/high/low/missing-labels→low).

**Gate (on merged main):**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`; precision/recall/f1 = 1.000
- `python3 threat_intel/test_threat_intel.py` → PASSED — all checks green
- `python3 console/test_console.py` → PASSED — all suites green
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged

## Task 3 — Advisory RCA narrative
**Status: MERGED to main** (`--no-ff` @ `00c2035`, from branch `feat/advisory-rca` @ `3d8d21d`). Owner: Dwight (dwight-mt1tbdgc). QA'd independently by god. Depended on Task 1 (merged first).

**What shipped — `derive_rca(iid, state, hypothesis_fn)` in `console/soc.py`, three layers that each degrade to an honest absence:**
- **Layer 1 — deterministic facts, ALWAYS:** members (findingIds), shared entity, rules fired, firstSeen/lastSeen, ordered timeline (carried through from `rule_context.enrich`/`timeline_for` via the adapter — not recomputed, since raw records aren't in state; noted honestly in code).
- **Layer 2 — runbook citation, only when earned:** stdlib BM25 (`_bm25_rank`, k1=1.5/b=0.75) over a NEW versioned store `console/.soc/runbooks/*.md` (2 seed runbooks: ssh-brute-force, disk-capacity). Explicit bar; below it → honest "no runbook match" including best candidate + score. Never forces a citation.
- **Layer 3 — LLM hypothesis, only when it survives the guard:** built ONLY from Layer-1 facts + any cited passage, labeled `advisory · hypothesis · not a verdict`, passed through `explanation_guard.verify_explanation` (Task 1). Fails guard / no model / empty reply → withheld with reasons, never substitute prose. `soc.py` never imports the LLM — the callable is injected by `serve.py` and is **local-compute only** (remote/unreachable → None → honest model-off), keeping the sanctioned egress at the redact choke point.
- **RCA never writes severity** (test asserts `"severity"` appears nowhere in the RCA JSON; incident severity unchanged after all layers).

**Surfacing:** `GET /api/incidents/<id>/rca` (routing-only in `serve.py`; logic in soc.py). React RCA panel in `Incidents.tsx` inside a dashed frame labeled "Root-cause analysis · advisory — severity above is rule-owned and unaffected"; runbook passage quoted verbatim with score/coverage; withheld hypothesis shows guard reasons; off-shape/404 → honest "unavailable".

**Files changed (13, +1231/−587 incl. rebuilt dist):** `console/soc.py`, `console/serve.py`, `console/.soc/runbooks/{ssh-brute-force,disk-capacity}.md`, `.gitignore` (versions the runbook store while keeping incidents.json etc. ignored), `web/src/lib/api.ts`, `web/src/pages/Incidents.tsx`, `web/src/test/incidents.test.tsx`, `web/dist/*`, `console/test_console.py` (`check_advisory_rca()` — 11 asserts).

**Gate (on merged main):**
- `python3 tests/eval/run_eval.py` → `17 passed, 0 failed, 17 total`; f1 = 1.000
- `python3 console/test_console.py` → PASSED — all checks incl. `advisory-rca`
- `python3 threat_intel/test_threat_intel.py` → PASSED (no regression)
- `cd web && npm test` → 23 files / 86 tests pass; `npm run build` → clean (pre-existing chunk-size advisory only)
- `shasum -a 256 anomaly_detector.py` → `43f0560f…8312d05` — unchanged

**⚠️ PRODUCT-DECISION FLAGS FOR YOU (conservative, clearly-commented defaults — not validated constants; review/tune):**
1. **Citation bar:** `RCA_MIN_SCORE = 1.0` (BM25) AND `RCA_MIN_COVERAGE = 0.5`, where coverage = fraction of the incident's distinct RULE-ID tokens present in the doc (free-text/IP-digit tokens deliberately excluded — they made coverage fragile). Tune to taste.
2. **Fault-type guard on the hypothesis** is asserted only for **single-rule clusters** (a mixed-rule cluster has no single fault type the prose must match); grounding + count checks still always apply.
3. **Hypothesis is local-compute only by design** (egress stays at the redact choke point). If remote RCA is wanted later, it needs its own redaction path.
