# E6 — Extend the Stage E wall (tests before features)

**Branch:** `feat/e6-stage-e-wall` (verified with `git branch --show-current` before the
first edit; output was exactly `feat/e6-stage-e-wall`, so work proceeded)
**Head at start of work:** `5978d719d59807a6e626e919df15468160b30e16` (`docs: update Stage E action cards`)
**Worker:** Claude Code (sole eligible model for this card — guard / eligibility-adjacent contract)
**Date:** 2026-09-02

## Freeze check

| when | sha256 of `anomaly_detector.py` |
| --- | --- |
| before any edit | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |
| after all edits | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |

Unchanged, and matches the CLAUDE.md pivot-baseline freeze. The detector was never opened
for writing.

## Allowlist compliance

Allowed by the card, and exactly what changed:

| path | state | what |
| --- | --- | --- |
| `console/runbooks.py` | modified | Stage E advisory keys; widened advisory word guard; `assert_advisory_disjoint()` |
| `console/precedent.py` | new | minimal deterministic ranking interface + `assert_no_advisory_input()` |
| `tests/test_stage_e_wall.py` | new | the executable stdlib wall test |
| `docs/STAGE_E_REPORTS/E6-worker.md` | new | this report |

`git status --short` after the work shows only these four paths. Nothing else was touched;
no orchestrator ruling was needed. The commit uses explicit paths — never `git add -A`.

## What was built

**1. `ADVISORY_KEYS` gains the Stage E fields.** `similarityNote`, `precedentOpinion` and
`proposalDraft` are listed *before* their producers (E1 precedent panel, E7 second-opinion
model, E4 proposal drafts) exist. The guard meets those cards on the day they land rather
than after. `_ADVISORY_WORD_RE` widened by `similarity|precedent|opinion|proposal|draft`, so a
near-miss variant of a Stage E key (e.g. `precedentOpinion2`) is caught by shape even if
nobody remembers to enumerate it.

**2. Disjointness protection extended.** `runbooks.assert_advisory_disjoint()` asserts two
properties against the live constants: the `RULE_OWNED_*` allowlists never intersect
`ADVISORY_KEYS`, **and** no rule-owned key merely *reads* as advisory under the word guard.
The second half is the new protection — previously a not-yet-enumerated advisory field could
be added to an allowlist and silently become an eligibility input.

**3. `console/precedent.py` — interface only.** Per the card, this file carries only the
minimal deterministic ranking interface needed to establish the guard contract; **E1 owns the
real index implementation** and the file says so in its own docstring. `rank(incident,
candidates)` is pure set overlap over `RULE_OWNED_PRECEDENT_KEYS`, ordered by
`(-overlap, id)` so the result is total and reproducible. No model, no network, no
randomness. Advisory fields are dropped by `_facts()` before any comparison.

**4. The executable test — `tests/test_stage_e_wall.py`, stdlib only, no pytest.** Run as
`python3 tests/test_stage_e_wall.py`; exits nonzero with the decisive line printed. Four parts:

- **A** — `ADVISORY_KEYS` names each Stage E field, and each reads as advisory to the word guard.
- **B** — disjointness by name *and* by behaviour: every `ADVISORY_KEY` set on both an incident
  and its finding leaves `eligible()`'s verdict byte-identical, and advisory fields on either
  side of `precedent.rank()` cannot reorder it.
- **C** — the precedent ranking signature, checked on the live `inspect.signature`: exactly
  `(incident, candidates)`, no `*args`, no `**kwargs`, no advisory-reading parameter name.
  There is no parameter through which a model signal can enter the ranking.
- **D** — the import/grep guard over the eligibility and severity paths
  (`anomaly_detector.py`, `rules_syslog.py`, `rule_context.py`, `console/runbooks.py`).
  Implemented by parsing each file's **AST** — imports, call targets, and the *qualifier* of a
  qualified call — rather than a raw source grep, so a comment that says "LLM" is not a
  finding while an actual `import precedent` or `precedent.rank(...)` is. The only
  seam-shaped names permitted are the wall's own vocabulary, enumerated in
  `GUARD_OWNED_NAMES`.

**No decision path was introduced.** `precedent.py` is imported by nothing outside the test;
the guard in part D is what keeps it that way.

## Red-test acceptance (mandatory)

Three mutations, one per protected seam. Each was run on this branch, each drove
`python3 tests/test_stage_e_wall.py` to a nonzero exit, and each was restored.

### Mutation 1 — drop `precedentOpinion` from `ADVISORY_KEYS`

```
console/runbooks.py:
-    "similarityNote", "precedentOpinion", "proposalDraft",
+    "similarityNote", "proposalDraft",
```

```
$ python3 tests/test_stage_e_wall.py
  [FAIL] ADVISORY_KEYS contains 'precedentOpinion'
         -> present keys: ['advisory', 'aiConfidence', 'aiSeverity', 'aiTriage', 'explanation', 'hypothesis', 'llm', 'llmSev', 'llmWhy', 'modelFindings', 'narrative', 'proposalDraft', 'prose', 'rca', 'similarityNote', 'summary']
29/30 checks passed
FAILED:
  - ADVISORY_KEYS contains 'precedentOpinion' -- present keys: ['advisory', 'aiConfidence', 'aiSeverity', 'aiTriage', 'explanation', 'hypothesis', 'llm', 'llmSev', 'llmWhy', 'modelFindings', 'narrative', 'proposalDraft', 'prose', 'rca', 'similarityNote', 'summary']
EXIT=1
```

### Mutation 2 — open the ranking signature to advisory kwargs

```
console/precedent.py:
-def rank(incident, candidates):
+def rank(incident, candidates, **advisory):
```

```
$ python3 tests/test_stage_e_wall.py
  [FAIL] rank() signature is exactly (incident, candidates)
         -> (incident, candidates, **advisory)
  [FAIL] rank() declares no *args and no **kwargs — nothing can be smuggled in
         -> (incident, candidates, **advisory)
  [FAIL] no rank() parameter name reads as an advisory/model input
         -> ('incident', 'candidates', 'advisory')
  [FAIL] precedent.assert_no_advisory_input() agrees
         -> rank() must take exactly ('incident', 'candidates'); got ('incident', 'candidates', 'advisory') — (incident, candidates, **advisory)
26/30 checks passed
FAILED:
  - rank() signature is exactly (incident, candidates) -- (incident, candidates, **advisory)
  - rank() declares no *args and no **kwargs — nothing can be smuggled in -- (incident, candidates, **advisory)
  - no rank() parameter name reads as an advisory/model input -- ('incident', 'candidates', 'advisory')
  - precedent.assert_no_advisory_input() agrees -- rank() must take exactly ('incident', 'candidates'); got ('incident', 'candidates', 'advisory') — (incident, candidates, **advisory)
EXIT=1
```

### Mutation 3 — an eligibility-path file reaches for the precedent seam

```
console/runbooks.py:
+import precedent
 ...
 def eligible(runbook, incident, findings):
     have = evidence_keys(incident, findings)
+    hint = precedent.rank(incident, [])
```

```
$ python3 tests/test_stage_e_wall.py
  [FAIL] console/runbooks.py imports no advisory/model/LLM/precedent module
         -> offending imports: ['precedent']
  [FAIL] console/runbooks.py calls no advisory/model/LLM/precedent helper
         -> offending calls: ['precedent']
28/30 checks passed
FAILED:
  - console/runbooks.py imports no advisory/model/LLM/precedent module -- offending imports: ['precedent']
  - console/runbooks.py calls no advisory/model/LLM/precedent helper -- offending calls: ['precedent']
EXIT=1
```

Mutation 3 is also where the test got stronger. On the first pass only the *import* check
fired: `precedent.rank(...)` presents its call name as `rank`, which reads innocent. The
call-target collector now also records the qualifier of a qualified call, so the seam is
caught at both the import and the call site — as shown above. That hardening is part of the
greening implementation, not a workaround.

### Restoration and residue proof

All three mutations were reverted from byte-identical backups. After restoration:

```
$ git status --short
 M console/runbooks.py
?? console/precedent.py
?? tests/test_stage_e_wall.py

$ grep -n "\*\*advisory\|import precedent\|hint = precedent" console/runbooks.py console/precedent.py tests/test_stage_e_wall.py
console/precedent.py:32:  import precedent
tests/test_stage_e_wall.py:23:     and an actual `import precedent` is.
tests/test_stage_e_wall.py:41:import precedent  # noqa: E402
```

Zero attack residue. The three surviving hits are legitimate and pre-date the mutations: the
usage example in `precedent.py`'s docstring, the sentence in the test's docstring describing
what part D catches, and the test's own import of the module it inspects. `git diff` on
`console/runbooks.py` shows only the two intended hunks (the ADVISORY_KEYS/word-guard block
and `assert_advisory_disjoint()`) — no mutation line survives in the tracked diff. The
mergeable commit contains the greening implementation only.

## Green outputs (the acceptance the reviewer will run)

```
$ python3 tests/test_stage_e_wall.py
Stage E wall — advisory keys, disjointness, precedent signature, seam guard

A. ADVISORY_KEYS names the Stage E advisory fields (guard before feature):
  [PASS] ADVISORY_KEYS contains 'similarityNote'
  [PASS] ADVISORY_KEYS contains 'precedentOpinion'
  [PASS] ADVISORY_KEYS contains 'proposalDraft'
  [PASS] 'similarityNote' also reads as advisory to the word guard
  [PASS] 'precedentOpinion' also reads as advisory to the word guard
  [PASS] 'proposalDraft' also reads as advisory to the word guard

B. the rule-owned projection stays disjoint from the advisory vocabulary:
  [PASS] no rule-owned key is an advisory key
  [PASS] no rule-owned key merely *reads* as advisory
  [PASS] runbooks.assert_advisory_disjoint() agrees
  [PASS] precedent's projection is disjoint from ADVISORY_KEYS too
  [PASS] every ADVISORY_KEY set on the incident and finding changes nothing
  [PASS] advisory fields on either side cannot reorder precedent.rank()

C. precedent.rank() admits no advisory/model/LLM input (live signature):
  [PASS] rank() signature is exactly (incident, candidates)
  [PASS] rank() declares no *args and no **kwargs — nothing can be smuggled in
  [PASS] no rank() parameter name reads as an advisory/model input
  [PASS] precedent.assert_no_advisory_input() agrees
  [PASS] runbooks.assert_no_llm_input() still agrees for eligible()

D. no eligibility/severity-path file imports or calls a precedent/LLM seam:
  [PASS] anomaly_detector.py exists to be guarded
  [PASS] anomaly_detector.py imports no advisory/model/LLM/precedent module
  [PASS] anomaly_detector.py calls no advisory/model/LLM/precedent helper
  [PASS] rules_syslog.py exists to be guarded
  [PASS] rules_syslog.py imports no advisory/model/LLM/precedent module
  [PASS] rules_syslog.py calls no advisory/model/LLM/precedent helper
  [PASS] rule_context.py exists to be guarded
  [PASS] rule_context.py imports no advisory/model/LLM/precedent module
  [PASS] rule_context.py calls no advisory/model/LLM/precedent helper
  [PASS] console/runbooks.py exists to be guarded
  [PASS] console/runbooks.py imports no advisory/model/LLM/precedent module
  [PASS] console/runbooks.py calls no advisory/model/LLM/precedent helper
  [PASS] precedent.py itself imports no model/LLM seam

30/30 checks passed
Stage E wall intact.
$ echo $?; 0
```

```
$ python3 console/test_console.py
  [PASS] CASE_STATUSES is the 6-state machine

PASSED — render + routing + log360 + logcat + iso8601-syslog + auth-csv + loghub-formats + remote-compute + dashboard-data + layout + all-runs + soc-overview + soc-subsystems + stream + export + serve-react + store + efficacy-api + syslog + discovery + ti-oem + evtx + validate-real + formats-universal + rules-parity + explain-stream + structured-output + redesign-phase4 + auth + ask-view + copilot-investigate + bruteforce-series + runbooks + audit-chain + cases->incidents-migration + inc-4a7f-scenario + investigation-engine + parallel-advisory + org-context-priority + action-layer-ssh-firewall + sigma-ingest-triage-case-lifecycle checks green
(exit 0)
```

```
$ python3 tests/eval/run_eval.py
  false positives : 0   
  precision       : 1.000
  recall          : 1.000
  f1              : 1.000
  false positives by rule type:
    (none)
(exit 0 — 20/20, FP=0)
```

```
$ shasum -a 256 anomaly_detector.py
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876  anomaly_detector.py
```

### Source/import inspection of the eligibility and severity paths

Part D of the test *is* this inspection, run mechanically. Reproduced by hand:

```
$ python3 -c "import ast,sys
for f in ['anomaly_detector.py','rules_syslog.py','rule_context.py','console/runbooks.py']:
    t=ast.parse(open(f).read())
    mods=set()
    for n in ast.walk(t):
        if isinstance(n,ast.Import): mods|={a.name for a in n.names}
        elif isinstance(n,ast.ImportFrom): mods.add(n.module or '')
    print(f, sorted(mods))"
anomaly_detector.py ['argparse', 'collections', 'datetime', 'json', 'pathlib', 're', 'sys']
rules_syslog.py ['collections', 're']
rule_context.py ['anomaly_detector', 'datetime', 'pathlib', 're', 'sys']
console/runbooks.py ['inspect', 'json', 'pathlib', 're', 'yaml']
```

Every import is stdlib or a frozen-detector sibling. No LLM/model seam, no `copilot`, no
`triage`, no `log_analyzer`, no `precedent` anywhere on either path.

## Deviations and judgment calls

1. **Guarded-file set.** The card says "eligibility and severity paths" without enumerating
   them. Chosen: `anomaly_detector.py`, `rules_syslog.py`, `rule_context.py` (severity is
   owned by the frozen detector and its rule siblings) and `console/runbooks.py`
   (eligibility). Deliberately **excluded**: `console/triage.py`, which is advisory by
   declaration and whose whole job is to produce `aiTriage`; and `console/adapter.py`, which
   legitimately imports `log_analyzer` for multi-format loading. Guarding either would have
   made the test either false or vacuous. If the orchestrator wants a wider set, the constant
   `GUARDED_FILES` at the top of the test is the single edit.
2. **AST instead of a literal grep.** The card says "import/grep guard". A raw `grep` over
   these files hits 6 seam-words in `anomaly_detector.py`'s comments and 19 in
   `runbooks.py`'s own guard prose — a grep-based test would have to be either
   permanently-failing or riddled with exemptions. The AST walk answers the same question
   (does this file *reference* a seam?) without the false positives, and is strictly harder
   to evade. Recorded as a deviation because it is a change in mechanism, not in intent.
3. **`precedent.py` scope held to the card.** It carries the ranking interface, the
   rule-owned projection, and the signature assertion — nothing else. No store query, no
   ATT&CK join, no disposition surface, no API route, no UI. E1 owns those. The file's
   docstring states the boundary so a later card does not accidentally inherit E6's scope.
4. **Widened `_ADVISORY_WORD_RE`.** Adding `similarity|precedent|opinion|proposal|draft` to
   the shared word guard also constrains `eligible()`'s parameter names. Verified: no current
   rule-owned key and no current parameter name matches, so the widening is free today and
   binding tomorrow.
5. **Not done, by instruction:** no push, no merge, no `git add -A`.
