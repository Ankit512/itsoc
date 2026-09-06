# CB-1-FIX — ACCEPTED

**Card:** CB-1-FIX · two CodeRabbit Major findings on merged CB-1. **Worker head:** `feacbcf`.
**Base:** `a1a72f9` (CB-1 + CodeRabbit's docstring-only autofix) — verified ancestor, no reset.
**Detector:** `364577c5…4876` — verified before and after the merge.

Both defects were found by CodeRabbit **after** the coordinator accepted CB-1. Both were real.
This is the honest follow-up, kept as commits on top rather than folded into the CB-1 merge, so
the record shows what review caught rather than implying acceptance caught it.

## Finding 1 — router over-capture

**The fix is two-tiered, and the tiering is the right shape.** Tier 1 (`_LEARNED_WORDS`) is
phrases that *name* the learned second opinion; any one routes on its own. Tier 2
(`_MODEL_REF_WORDS` — `the model`, `this model`, `model's`) is never sufficient alone and **can
never reach the selected-incident fallback**; it qualifies only beside a provenance or
disagreement word, each of which is unambiguous in this product — only the learned model has a
provenance sidecar, and rules are the only verdict producer, so only the learned model can
"disagree with the rules."

Verified by the coordinator, independently of the worker's table:

```
MUST NOT ROUTE                                          no ctx    +selected incident
why did the model return no explanation for this...     None      None
explain the model behind this page                      None      None
what model are you using                                None      None
which model produced this summary                       None      None
what MITRE techniques are involved                      None      None
explain this page / what should i do next?              None      None

MUST ROUTE
what does the learned model say about inc-2c97…   ('opinion', 'inc-2c9769961239')
how was this model trained                        ('provenance', None)
what does the model disagree with the rules about ('disagreements', None)
show me the second opinion                        ('disagreements', None)
```

The provenance gate survived, which was the trap in this fix: `_PROVENANCE_WORDS` is checked
only after a model reference matches, so naively deleting the generic phrases would have broken
`"how was this model trained"`. It still routes.

**The worker found a real bug the card did not name.** `copilot.py` *suggests* follow-up
questions to the analyst — `"What does the model say about {id}?"` at five sites. Under the
narrowed router the copilot would have been offering a question it could no longer answer. Those
suggestions were updated and test (j) now pins the invariant. That is exactly the class of defect
this project keeps finding: a surface that asserts a capability the behaviour no longer has.

## Finding 2 — the write on the copilot read path

`console/soc.py` was opened narrowly for a read-only accessor. What landed is a **pure
extract-method refactor**, which is more than the card asked for and better than what it asked
for:

- `_merge_incidents(state)` — the merge half of `sync_incidents()`, with the `_save()` left behind.
- `_project_incidents(store, filter)` — the tail of `list_incidents()`, shared verbatim.
- `sync_incidents()` = `_merge_incidents()` + `_save()`. `list_incidents()` = unchanged branch +
  `_project_incidents()`. **Behaviour for every existing caller is identical**, which was the
  constraint.
- `list_incidents_readonly()` — same merge, same projection, same `_public_incident()` reaching
  the same `triage_model.predict()`. One producer, no drift, no write.

Verified by the coordinator with a `_save` interceptor:

```
list_incidents          writes: ['incidents.json']
list_incidents_readonly writes: []
outputs identical: True   (4 incidents)
```

**The worker also traced the write chain further than the card did:** `list_cases()` →
`ensure_incident_cases()` → `create_case()` → `_try_absorb_cases()` → `migrate_cases_to_incidents()`
can also reach `incidents.json`. That is the pre-existing conditional write, correctly left in
place and documented rather than opportunistically changed.

## CB-1's properties, re-verified after the fix

The point of re-running these is that a fix must not quietly cost what acceptance bought.

- Prompt injection through `aiLabel`, `aiSeverity`, the sidecar, and the cross-incident list —
  all still quoted as data, all marked refused, `actions == []`, advisory label intact.
- The newline / fake-system-turn payload still flattens to one line.
- Model kill still degrades honestly across all four behaviours, with the same refusals verbatim.
- **The no-re-derivation probe still holds**: stored `agrees: True` with severities diverging
  (rules `HIGH`, model `INFO`) still reports *agrees*, and the disagreement list holds zero items.
- `SELECTOR-NULL` — 2 passed.

## Gates — all re-run by the coordinator

console/test_console.py PASSED (new `cb1fix-copilot-read-only` block) · wall **126/126** ·
eval 20/20, **FP 0**, f1 1.000 · e7a contract OK · harness OK · train_triage OK · web **313/313** ·
build clean · `git diff --check` clean · allowlist clean (6 files, all in scope) · detector sha256
unchanged.

Pre-existing failures re-confirmed at this base: `tests/test_battlecard_efficacy.py` and
`console/test_auth_security.py`. Neither touched.

## What the coordinator found that neither worker did

**The shipped CB-1 evidence screenshots use a prompt that no longer routes.**
`behaviour1-per-incident-{light,dark}.png` show *"What does the model say about
inc-2c9769961239?"* — which, under the narrowed router, now returns `None` and falls through to
the LLM. The images are still honest about every behaviour they depict; only the prompt wording
is stale. The worker updated the code's suggestion strings and the test prompts and did not
notice the images, which it could not have re-shot anyway.

Handled by annotating the evidence directory (`CB1-evidence/README.md`) rather than by a
re-shoot, which would need a trained artefact and a live run. Recorded here so the trade-off is
visible rather than silent.

## Standing note

CodeRabbit found two Major defects in code the coordinator had accepted after reproducing four
attacks by hand. The attacks were the right test of the *wall*; neither of them touched the
*router's negative space* or the *write path*, and no acceptance criterion asked about either.
The lesson is narrow and worth keeping: **verifying that a surface does the right thing on the
inputs it was built for says nothing about what it does on the inputs it was not.** CB-1-FIX's
negative-space table is now the standing shape for routing changes.
