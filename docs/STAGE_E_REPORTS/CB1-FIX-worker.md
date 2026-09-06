# CB-1-FIX — worker report

Two CodeRabbit Major findings against the merged CB-1. Both reproduced, both fixed,
both demonstrated with exact before/after. CB-1's design is unchanged; these are two
specific defects inside it.

## Provenance

| | |
|---|---|
| branch | `Ankit512/cb1-fix` (card names `feat/cb1-fix`; name is a warning only) |
| base | `a1a72f9` — *fix: apply CodeRabbit auto-fixes* |
| head at start | `a1a72f9` (worktree was exactly at base) |
| base check | `git merge-base --is-ancestor a1a72f9 HEAD` → **OK**. The reverse also succeeded, which means HEAD **equals** base — at base, not stale. |
| detector sha256 before | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` ✅ |
| detector sha256 after | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` ✅ unchanged, never opened for write |
| `web/node_modules` | **was missing** → ran `npm --prefix web install` (exit 0). Recorded per the card. |

### Files changed (allowlist audit)

```
 M console/copilot.py
 M console/serve.py
 M console/soc.py                      <- narrowly open: ADDED read accessors only
 M console/test_console.py
 M web/src/test/copilot-learned.test.tsx
 A docs/STAGE_E_REPORTS/CB1-FIX-worker.md
```

All inside the allowlist. Nothing on the forbidden list was touched: `anomaly_detector.py`,
the rules, the eval corpus, `console/runbooks.py`, `console/triage_model.py`,
`tools/train_triage.py`, `tools/attack_generator.py`, `tools/efficacy_harness.py`, and
every eligibility path are byte-identical. The advisory guard was **not** widened —
`copilot._assert_fenced` / `runbooks.ADVISORY_KEYS` are untouched. No CB-1 test was
weakened or deleted (see "the one test change" below).

---

## FINDING 1 — the learned router over-captured generic model questions

### Reproduced at base, exactly as filed

`console/copilot.py`'s `_LEARNED_WORDS` contained the generic phrases `"the model"`,
`"this model"` and `"model's"`. Verbatim output of `copilot.learned_question(q)` at base:

```
('disagreements', None)   ||CTX> ('opinion', 'inc-abc123')  <- why did the model return no explanation for this finding
('disagreements', None)   ||CTX> ('opinion', 'inc-abc123')  <- explain the model behind this page
None                      ||CTX> None                       <- what model are you using
None                      ||CTX> None                       <- which model produced this summary
None                      ||CTX> None                       <- what ATT&CK technique does this map to
None                      ||CTX> None                       <- explain this page
('provenance', None)      ||CTX> ('provenance', None)       <- how was this model trained
('opinion', 'inc-abc123') ||CTX> ('opinion', 'inc-abc123')  <- what does the learned model say about inc-abc123
('disagreements', None)   ||CTX> ('disagreements', None)    <- where does the model disagree with the rules
```

(`||CTX>` is the same question with `{"selectedIncidentId": "inc-abc123"}`.)

Both filed hijacks reproduce. The `||CTX>` column is the severe one: with an incident
selected in the rail, a question about *anything* containing "the model" was answered as
an opinion about whatever was selected.

### Why this was Major and not cosmetic

CB-1 also made the learned answer **terminal** — `serve.py` never hands it to the LLM, on
either the JSON or the streaming path. That decision is correct and stays (a paraphrase of
a stored confidence would be a second, drifting number). But it removes the fallback: a
mis-routed question does not degrade to a mediocre LLM answer, it returns a confident,
cited, ADVISORY-labelled answer about the **wrong subject** with no path to recovery. The
two changes are individually sound and interact badly.

### The fix — two tiers, and the provenance gate the card warned about

The card's warning was load-bearing: `learned_question()` checked `_PROVENANCE_WORDS`
only **after** `mentions_model` succeeded, so simply deleting `"the model"`/`"this model"`
would have silently broken `"how was this model trained"`. It is now restructured, not
merely pruned:

- **Tier 1 `_LEARNED_WORDS`** — phrases that *name* the learned second opinion
  (`learned model`, `learned second opinion`, `second opinion`, `triage model`, `aitriage`,
  `ml model`, `learned classifier`, `learned triage`, `learned model's`). Nothing else in
  the product answers to these, so any one is sufficient on its own to route — including to
  the bare per-incident / selected-incident fallback.
- **Tier 2 `_MODEL_REF_WORDS`** — a generic reference to *a* model (`the model`,
  `this model`, `model's`). **Never sufficient on its own, and can never reach the
  selected-incident fallback.** It qualifies only alongside an intent word that is
  unambiguous in this product: a provenance word (only the learned model has a provenance
  sidecar) or a disagreement word (rules are the only verdict producer, so the only thing
  that can "disagree with the rules" is the learned second opinion).

The gate ordering is now explicit: the provenance and disagreement branches accept either
tier, and the fallthrough to `opinion`/selection requires tier 1. **The comment above
`_LEARNED_WORDS` was rewritten to state what the code does** — the old one claimed the
router "only fires on a phrase that names the LEARNED second opinion", which was false.
That comment-asserts-a-property-the-code-lacks pattern is the exact defect family Stage E
closed four times.

### After — the full routing table

```
--- NEGATIVE (must be None in BOTH columns) ---
None                       None                       <- why did the model return no explanation for this finding
None                       None                       <- explain the model behind this page
None                       None                       <- what model are you using
None                       None                       <- which model produced this summary
None                       None                       <- what ATT&CK technique does this map to
None                       None                       <- show me the MITRE techniques involved
None                       None                       <- explain this page
None                       None                       <- what should I do next?
None                       None                       <- the model output looks odd on this row
--- POSITIVE (must route) ---
('opinion', 'inc-dis0001') ('opinion', 'inc-dis0001') <- what does the learned model say about inc-dis0001
('disagreements', None)    ('disagreements', None)    <- what does the learned model disagree with the rules about?
('disagreements', None)    ('disagreements', None)    <- where does the model disagree with the rules
('provenance', None)       ('provenance', None)       <- how was this model trained
('disagreements', None)    ('opinion', 'inc-abc123')  <- what is the second opinion for this run
('provenance', None)       ('provenance', None)       <- what is the learned model provenance
```

**The provenance question still routes — verified, not assumed.** Per-incident,
cross-incident and provenance all still route, with and without a selection. The one
remaining case that legitimately consumes the selection is a bare tier-1 phrase
("what is the second opinion here?"), which names the learned model and asks for no
specific behaviour — that is the fallback working as designed, and it is asserted as such.

### Tests added — the negative space

`console/test_console.py` section **(j)** was replaced by a real table. Nine questions that
must **not** route, each asserted **three** ways: `learned_question(q) is None`, the same
with `{"selectedIncidentId": "inc-abc123"}`, and end-to-end through `copilot.investigate()`
asserting `source != LEARNED_SOURCE`. Then five positives asserted with and without a
selection, plus the bare-phrase fallback, plus a check that **every follow-up the copilot
suggests is one it can actually route** — 34 new checks in (j), all PASS.

### Prompt updates — and one self-consistency bug this surfaced

The card asked for the CB-1 prompts around 7541/7581 to say "the learned model". Eleven
prompt sites inside `check_cb1_learned_copilot()` were updated (all `investigate()` inputs;
answer-text assertions such as `"I will not say what the model would have said"` were left
alone). This is a **phrasing** change to exercise the phrasing the router now owns — no
assertion was weakened.

Doing so surfaced a real bug the card did not name: `copilot.py` **suggests** follow-up
questions to the analyst (`"What does the model disagree with the rules about?"`,
`f"What does the model say about {inc['id']}?"` at lines 1862/1964/1969/2154/2188). Under the
narrowed router the per-incident suggestion would no longer route — the copilot would have
been offering a question it could no longer answer. Those five suggestion strings were
updated to "the learned model", and test (j) now pins the invariant so it cannot regress.

`web/src/test/copilot-learned.test.tsx` prompts were updated for the same reason. Those
tests mock the API response entirely (the rail is a pure consumer), so routing is not
exercised there — the change is corpus honesty, not a behavioural dependency.

---

## FINDING 2 — a store WRITE on the copilot read path

### Reproduced at base

`_copilot_extras()` gained `"incidentsAdvisory": soc.list_incidents(state)`.
`list_incidents()` calls `sync_incidents()` whenever a run is loaded, and `sync_incidents()`
ends in `_save("incidents.json", store)`. Every non-idle copilot request therefore performed
an unconditional disk write. Asking a question is a **read**; guardrail 5 is read-only
posture. Confirmed CB-1-introduced, not pre-existing.

### The fix

`console/soc.py` — **additive only**, exactly as the card scoped it:

- `_merge_incidents(state)` — the merge half of `sync_incidents()`, extracted verbatim
  with the `_save()` left behind. Pure extraction, no logic change.
- `_project_incidents(store, state_filter)` — the tail of `list_incidents()` (sort, dedupe,
  filter, `_public_incident()`), extracted verbatim and shared.
- `sync_incidents()` is now `_merge_incidents()` + `_save()` + return — **identical
  behaviour for every existing caller**, and still the only writer.
- `list_incidents()` is now `sync_incidents()` (or `_load`) + `_project_incidents()` —
  **identical behaviour for every existing caller**; every writing surface keeps the sync.
- **`list_incidents_readonly(state, state_filter)`** — new, read-only. Same merge, same
  projection, no `_save()`.

`console/serve.py` — `"incidentsAdvisory": soc.list_incidents_readonly(state)`.

### The property the original comment was protecting is preserved

There remains **exactly one** computation of severity / label / confidence / agreement.
`list_incidents_readonly()` reaches the *same* `_public_incident()`, which attaches
`aiTriage` via `_incident_ai_triage()` → `triage_model.predict()`. Nothing is recomputed,
re-derived or reconstructed at the copilot seam, and **agreement is not re-derived by
comparing severities** — that exclusion is standing owner doctrine and is still honoured
(see the no-re-derivation probe below). The comment in `serve.py` was rewritten to describe
what the code now actually does rather than what it wished were true.

### Does the fix change which incidents the copilot can see? No.

Asserted mechanically, not asserted by argument:

```
[PASS] and the two return exactly the same list, so nothing the copilot can see changed — only the write is gone
```

— a full `json.dumps(..., sort_keys=True)` equality between `list_incidents_readonly(STATE)`
and `list_incidents(STATE)`. Both run the same merge over the same deterministic ids and the
same projection; the only difference is persistence. So **ids still resolve**: an id the
copilot cites in `/incidents?sel=<id>` is the same id the incidents route produces when the
analyst follows the link (that route still syncs, and the merge is idempotent). Also pinned
directly:

```
[PASS] every id the copilot can cite resolves on the incidents route
```

### Write-count / mtime evidence

New check function `check_cb1fix_copilot_read_only()` (registered in the runner). It counts
`soc._save` calls and pins `incidents.json` bytes **and** `st_mtime_ns`:

```
CB-1-FIX — the copilot read path writes nothing:
  [PASS] the publishing path still writes incidents.json
  [PASS] the seeded run produced real incidents to reason about
  [PASS] soc.list_incidents() — what CB-1 called — DOES write incidents.json, which is the defect
  [PASS] soc.list_incidents_readonly() — what the copilot now calls — writes NOTHING
  [PASS] and the two return exactly the same list, so nothing the copilot can see changed — only the write is gone
  [PASS] a copilot request performs ZERO store writes
  [PASS] incidents.json is byte-identical after the copilot request
  [PASS] incidents.json was not even touched (mtime unchanged)
  [PASS] no analyst-visible CASE is opened as a side effect of asking
  [PASS] the copilot still receives the advisory incident list
  [PASS] every advisory incident still carries its aiTriage block — the single producer is unchanged, only the write is gone
  [PASS] every id the copilot can cite resolves on the incidents route
  [PASS] a genuine publish after the question still persists
```

Probe 1 is unconditional and shows the defect and the fix side by side in the same run:
`list_incidents()` writes `['incidents.json']`, `list_incidents_readonly()` writes `[]`.

### Something the investigation turned up — read this before accepting

The first version of this test asserted `saves == []` across the **very first**
`_copilot_extras()` call and **failed**, reporting `soc._save called for: ['cases.json',
'incidents.json']`. `incidents.json` was still being written. I traced it rather than
retuning the assertion:

```
serve._copilot_extras -> soc.list_cases()
                      -> soc.ensure_incident_cases()
                      -> soc.create_case()            -> _save("cases.json")
                      -> soc._try_absorb_cases()
                      -> soc.migrate_cases_to_incidents() -> _save("incidents.json")
```

So `list_cases()` can write **incidents.json**, not just `cases.json` — a longer chain than
the card's description implies. It is nonetheless the **pre-existing conditional** write the
card correctly characterises: it fires only when a case is actually opened, and is silent
once every incident has one. It is not CB-1's, and it is out of this card's scope.

The test therefore settles the store first (one `list_cases()`), which is precisely what
isolates the unconditional write CB-1 *did* introduce, and then asserts zero writes of any
kind across two full copilot requests. The settling step is documented in the test body so
nobody later mistakes it for a fudge.

**On the card's second-order effect: the fix removes it, in the right direction.** The
concern was that a copilot question syncing incidents to disk lets a *later* request's
`list_cases()` open analyst-visible cases as a side effect of someone having asked a
question. After this fix a copilot question can no longer seed `incidents.json` at all, so
`ensure_incident_cases()` only ever sees incidents that a genuine publish persisted. Pinned
by `[PASS] no analyst-visible CASE is opened as a side effect of asking`.

---

## Acceptance — green outputs

| check | result |
|---|---|
| `console/test_console.py` | **PASSED** — all suites incl. `cb1-copilot-learned-triage` + new `cb1fix-copilot-read-only` |
| `tests/test_stage_e_wall.py` | **126/126 checks passed. Stage E wall intact.** rc=0 |
| `tests/eval/run_eval.py` | **f1 1.000, false positives by rule type: (none)** |
| `tests/test_e7a_feature_contract.py` | **Ran 10 tests — OK** rc=0 |
| `tools/efficacy_harness.py` sklearn **present** | rc=0 |
| `tools/train_triage.py` sklearn **present** | rc=0, folds 1–5 macroF1 1.0 |
| `tools/efficacy_harness.py` sklearn **absent** | honest `UNAVAILABLE — scikit-learn is not installed …` |
| `tools/train_triage.py` sklearn **absent** | rc=0, `Nothing was written. The console keeps working and renders the honest 'model unavailable' advisory state.` |
| `npm --prefix web test` | **44 files, 313 tests passed** |
| `npm --prefix web run build` | **✓ built in 1.46s** |
| detector sha256 | unchanged ✅ |
| `git diff --check` | clean |
| allowlist audit | clean (above) |

### The four CB-1 attacks still pass

```
[PASS] (f) the poison is rendered as a QUOTED value, not as prose
[PASS] (f) the answer says out loud that it refused it as an instruction
[PASS] (f) the poison did NOT become an action, an approval or a runbook      <- actions == []
[PASS] (f) the rule verdict is UNCHANGED by the poisoned block
[PASS] (f) the unavailableReason vector is quoted and refused too
[PASS] (f) a poisoned SIDECAR value is quoted and refused as an instruction
[PASS] (g1) per-incident says UNAVAILABLE and names the reason
[PASS] (g1) it refuses to speculate what the model WOULD have said
[PASS] (g2) the disagreement list says UNAVAILABLE, not 'no disagreements'
[PASS] (g2) it refuses to render an empty list as agreement
[PASS] (g3) provenance says there is no sidecar, from nothing generated
[PASS] (g4) honest absence — every killed answer is still ADVISORY-labelled
[PASS] (g4) no killed answer contains a fabricated number
[PASS] (e) the uncited claim is REJECTED with a named reason
[PASS] (e) an unresolvable incident citation is REJECTED
[PASS] (e) an unrecorded sidecar citation is REJECTED
[PASS] (e) the guard reports what it refused rather than hiding it
```

Zero approve affordances:
`npx vitest run src/test/approvals.test.tsx -t "SELECTOR-NULL"` →
`✓ src/test/approvals.test.tsx (12 tests | 10 skipped)`, **2 passed**, including
*SELECTOR-NULL — the advisory Copilot rail carries NO approve control (vice versa)*.

### The no-re-derivation probe

Stored `agrees: True` with severities **diverging** (rules HIGH, model INFO):

```
PROBE stored agrees=True, rules HIGH vs model INFO:
  learned.agrees = True
  reports agreement?  True
  disagreement list items = [] -> len 0
  facts = {'scored': 1, 'unavailable': 0, 'disagreements': 0}
NO-RE-DERIVATION PROBE: PASS
```

The stored fact wins. Nothing re-derives agreement by comparing severities.

### Known pre-existing failures — confirmed identical at base

Verified by stashing the working tree (unique tag, `apply` by SHA, then dropped by tag) and
re-running at `a1a72f9`:

| test | at base | with my changes |
|---|---|---|
| `tests/test_battlecard_efficacy.py` | `Ran 3 tests … FAILED (failures=1)` | identical |
| `console/test_auth_security.py` | `assert status == 401 … AssertionError: 200` | identical |

Not mine, not fixed, per the card.

---

## Deviations

1. **The card named two prompt sites (~7541, ~7581); eleven were updated.** All eleven are
   `investigate()` inputs inside `check_cb1_learned_copilot()` and all needed the change for
   the tests to exercise the phrasing the router now owns. Answer-text assertions were not
   touched.
2. **Five suggestion strings in `console/copilot.py` were changed** (lines 1862, 1964, 1969,
   2154, 2188). Not requested, but required: without it the copilot would suggest a
   per-incident follow-up the narrowed router can no longer answer. Test (j) pins it.
3. **`web/src/test/copilot-learned.test.tsx` prompt strings updated** — cosmetic; those
   tests mock the response and never exercise the router.
4. **`console/soc.py` got two private helpers as well as the public read accessor**
   (`_merge_incidents`, `_project_incidents`). Both are verbatim extractions of existing
   code so the read-only path and the writing path cannot drift apart. No severity, verdict,
   correlation, lifecycle or `aiTriage` computation was modified, and `sync_incidents()` /
   `list_incidents()` behave identically for every existing caller.
5. **The write-count test settles the store before asserting zero writes** — necessary to
   isolate CB-1's unconditional write from the pre-existing conditional case-opening chain
   documented above. Probe 1 needs no settling and pins the defect unconditionally.
6. **No CB-1 test was weakened or deleted.** Section (j) was *expanded* from 3 checks to 37.
