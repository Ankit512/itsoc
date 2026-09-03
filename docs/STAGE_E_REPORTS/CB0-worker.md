# CB-0 — close the advisory guard's family gap

| | |
|---|---|
| Branch | `Ankit512/cb0-advisory-family-guard` (card named `feat/cb0-advisory-family-guard`; name is a warning only, no rename made) |
| Base | `8436df98b53c22acfd510f4f21a888313ee308b0` |
| Head | `ed975f1` — *guard: fence the ai\<Something\> model-output family by class, not by name* |
| Base check | `git merge-base --is-ancestor 8436df9 HEAD` → exit 0 (**BASE_OK**), run before the first edit |
| Detector sha256 before | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |
| Detector sha256 after | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — unchanged, never opened for edit |
| Files changed vs base | `console/runbooks.py`, `console/test_console.py`, `tests/test_stage_e_wall.py` (+ this report) — all on the allowlist |
| Tree | clean |

## What changed

The guard in `console/runbooks.py` fenced advisory fields two ways — the enumerated
`ADVISORY_KEYS` denylist and the `_ADVISORY_WORD_RE` pattern behind it. The model's own
output fields `aiAgrees` and `aiLabel` were in **neither**. Nothing reads them from an
eligibility path today, so there was no live defect; it was an uncovered surface, and the
whole class of `ai<Something>` names was uncovered with it.

1. **Enumeration** — `ADVISORY_KEYS` now names `aiAgrees` and `aiLabel`, alongside the
   already-listed `aiTriage` / `aiSeverity` / `aiConfidence`. This stays as the explicit record.
2. **Class-level pattern** — `_ADVISORY_WORD_RE` gains one clause:

   ```python
   r"(?-i:\bai[A-Z]|\bai_)"
   ```

   so the model-output family is covered **by class**, not by enumeration. The next
   `aiWhatever` nobody thought to list is refused on the pattern alone.
3. **Both mechanisms kept.** No name was removed from `ADVISORY_KEYS`, no existing pattern
   alternative was narrowed, and neither `assert_advisory_disjoint` nor `assert_no_llm_input`
   was weakened. The fence is strictly stricter.

### Why the scoped `(?-i:...)`, and the over-match verification I ran

`_ADVISORY_WORD_RE` is compiled with `re.IGNORECASE`. A bare `ai[A-Z]` inside it therefore
**degrades to the substring `ai`** and over-matches ordinary words. I checked this rather
than assuming it:

```
NAIVE ai[A-Z] under IGNORECASE (the trap):
  'maintainer' -> True   'chain' -> True
```

So the clause is written case-**sensitive** via the scoped group `(?-i:...)` (Python 3.11+;
this box runs 3.13.3), and `\b`-anchored to a name start. The `\bai_` alternative covers the
snake_case spelling of the same family. Verified over-match surface — **zero hits** on every
rule-owned name and every closed parameter list:

| Set | Size | Caught by the new clause |
|---|---|---|
| `RULE_OWNED_INCIDENT_KEYS` (`id`, `entity`, `entityKind`, `severity`, `findingIds`, `firstSeen`, `lastSeen`) | 7 | `[]` |
| `RULE_OWNED_FINDING_KEYS` (`id`, `type`, `ruleSev`, `sev`, `host`, `occurrences`, `lines`) | 7 | `[]` |
| `precedent.RULE_OWNED_PRECEDENT_KEYS` | 10 | `[]` |
| `ELIGIBILITY_PARAMS` (`runbook`, `incident`, `findings`) | 3 | `[]` |
| `precedent.RANK_PARAMS` | 2 | `[]` |

Negative probes, all `False`: `maintainer`, `chain`, `airflow`, `aid`, `said`, `plain`,
`trail`, `domainId`, `contains`, `available`, `entityKind`, `findingIds`.
Positive probes, all `True`: `aiAgrees`, `aiLabel`, `aiTriage`, `aiSeverity`, `aiConfidence`,
`aiMadeUpField`, `ai_label`.

I also swept every `ai`-shaped identifier in `console/triage_model.py` — the clause matches
**exactly** the five advisory model-output fields (`aiAgrees`, `aiConfidence`, `aiLabel`,
`aiSeverity`, `aiTriage`) and nothing else. A repo-wide sweep also finds `aiOpen`, `aiPanel`,
`aiSection`, `aiInput`, `aiBtnS`, `aiLog`, `aiClosed` — all DOM element ids and local
variables in `console/overview.html`, `web/src/test/c4-themes.test.tsx` and the design
reference HTML. None is a record key, none reaches an allowlist or a signature, so the
pattern (which is only ever applied to rule-owned key names and `eligible()` parameter names)
cannot see them.

## Attack 1 — a NOVEL, UNLISTED field, on BOTH an incident and a finding

`aiMadeUpField` is in no enumeration anywhere. The attack makes it *projectable* by adding it
to **both** rule-owned allowlists (the incident side and the finding side), which is the only
way an unknown field can reach a predicate at all.

```
$ python3 -c "import sys; sys.path.insert(0,'console'); import runbooks;
              print('aiMadeUpField in ADVISORY_KEYS?', 'aiMadeUpField' in runbooks.ADVISORY_KEYS);
              runbooks.assert_advisory_disjoint()"
aiMadeUpField in ADVISORY_KEYS? False
AssertionError: rule-owned key(s) read as advisory: ['aiMadeUpField'] — name them in
ADVISORY_KEYS or drop them from the allowlist
exit=1
```

Refused on **pattern alone**, with the enumeration answering `False`. Both suites bite:

```
$ python3 tests/test_stage_e_wall.py
  [FAIL] no rule-owned key and no eligibility parameter is caught by the clause
         -> ['aiMadeUpField']
  [FAIL] no rule-owned key merely *reads* as advisory
         -> ['aiMadeUpField']
  [FAIL] runbooks.assert_advisory_disjoint() agrees
         -> rule-owned key(s) read as advisory: ['aiMadeUpField'] — ...
123/126 checks passed
FAILED

$ python3 console/test_console.py
  [FAIL] no rule-owned key or eligibility parameter is caught by the clause
FAILED
```

Counterfactual — the **pre-CB-0** pattern would have missed all three of them:

```
  pre-CB-0 pattern catches 'aiMadeUpField'?  False
  pre-CB-0 pattern catches 'aiAgrees'?       False
  pre-CB-0 pattern catches 'aiLabel'?        False
```

That is the whole card: adding two names would have left `aiMadeUpField` exactly as open as
`aiAgrees` was. **Restored** afterwards (`git checkout -- console/runbooks.py`), tree clean.

> Deviation, disclosed: on the first pass of this demonstration the CB-0 edit was still
> uncommitted, so the `git checkout --` restore reverted the fix along with the poison. I
> re-applied the patch, re-verified 126/126 + 0 `[FAIL]`, committed `ed975f1`, and re-ran the
> attacks against the committed state so every restore lands on CB-0 rather than on the base.
> The transcripts above are from the post-commit runs. No work was lost.

## Attack 2 — do the existing guards still BITE?

**2a — `assert_no_llm_input`, signature weakened** (`**llm_hint` smuggled onto `eligible()`):

```
$ python3 -c "... runbooks.assert_no_llm_input()"
AssertionError: eligible() must take exactly ('runbook', 'incident', 'findings');
got ('runbook', 'incident', 'findings', 'llm_hint') — (runbook, incident, findings, **llm_hint)
exit=1

$ python3 tests/test_stage_e_wall.py   → part_c raises the same AssertionError, suite aborts
$ python3 console/test_console.py
  [FAIL] eligible() signature is exactly (runbook, incident, findings)
  [FAIL] eligible() declares no *args and no **kwargs — an advisory argument cannot be smuggled in under any name
  [FAIL] no eligible() parameter name reads as an LLM/advisory/narrative input
  [FAIL] runbooks.assert_no_llm_input() agrees (same signature, checked at runtime)
  [FAIL] runbooks.eligible has exactly three closed params — no *args/**kwargs
FAILED
```

**2b — `assert_advisory_disjoint`, enumeration branch** (the newly-enumerated `aiLabel`
pushed into `RULE_OWNED_FINDING_KEYS`):

```
AssertionError: rule-owned projection overlaps ADVISORY_KEYS: ['aiLabel'] — an advisory
field would reach an eligibility predicate
exit=1

$ python3 tests/test_stage_e_wall.py
  [FAIL] no rule-owned key and no eligibility parameter is caught by the clause -> ['aiLabel']
  [FAIL] no rule-owned key is an advisory key                                   -> ['aiLabel']
  [FAIL] no rule-owned key merely *reads* as advisory                           -> ['aiLabel']
  [FAIL] runbooks.assert_advisory_disjoint() agrees -> rule-owned projection overlaps ...
122/126 checks passed
```

Both branches of `assert_advisory_disjoint` (overlap **and** pattern) and
`assert_no_llm_input` still fail when they should. **Restored** after each;
`git status --porcelain` → 0 modified files both times.

## Tests added (locking the class-level rule)

- `tests/test_stage_e_wall.py` — new **A2** block: the enumerated family, four NOVEL names
  (`aiMadeUpField`, `aiWhatever`, `aiVerdict`, `ai_label`) refused *on pattern alone with
  `key not in ADVISORY_KEYS` asserted*, nine non-matches proving no over-match, and the
  rule-owned/param sweep. Plus a behavioural check in **B**: the four novel fields set on
  **both** the incident and the finding leave `eligible()` byte-identical to baseline.
- `console/test_console.py` — the same four properties beside the existing disjointness check.

Check count on the wall went 118 → **126**.

## Green outputs

| Gate | Result |
|---|---|
| `python3 console/test_console.py` | **0 `[FAIL]`**, exit 0, all checks green |
| `python3 tests/test_stage_e_wall.py` | **126/126 checks passed** — "Stage E wall intact." |
| `python3 tests/eval/run_eval.py` | **20 passed, 0 failed, 20 total**; FP 0, FN 0, precision/recall/f1 = 1.000 |
| `python3 tests/test_e7a_feature_contract.py` | **OK** — 10 tests |
| `python3 -m tools.test_efficacy_harness` (sklearn **absent** — system py3.13.3 has none) | **OK** — 69 tests |
| same, sklearn **1.7.2 present** (`e7b-r2-triage-modifier/.venv/bin/python`) | **OK** — 69 tests |
| `console/test_console.py` + wall under that sklearn venv | 0 `[FAIL]`, exit 0 / 126/126 |
| `npm --prefix web install` | exit 0 (standing setup — `web/node_modules` was missing) |
| `npm --prefix web test` | **43 files, 301 tests passed** |
| `npm --prefix web run build` | **✓ built in 1.45s** (only the pre-existing chunk-size advisory) |
| `git diff --check` (worktree and `HEAD~1..HEAD`) | clean, no whitespace errors |
| Detector sha256 | unchanged, matches the freeze |
| Allowlist audit | 3 code files + this report; nothing forbidden touched |

**Known pre-existing failure, not mine:** `tests/test_battlecard_efficacy.py` → `FAILED
(failures=1)` of 3 — the stale-assertion failure that is already on `main`. Unrelated to
`_ADVISORY_WORD_RE`; not investigated, not touched.

## Deviations

1. The uncommitted-restore incident in Attack 1, disclosed in full above. Resolved; the
   committed state is correct and every transcript here is from a post-commit run.
2. Branch is `Ankit512/cb0-advisory-family-guard`, not `feat/…` — pre-existing checkout, the
   card flags the name as a warning only.
3. sklearn is absent from the system interpreter, so the "with sklearn" run borrows the
   read-only venv at `../e7b-r2-triage-modifier/.venv`. No file in this worktree was involved.
4. Commit made locally with explicit paths (`git add <path> <path> <path>`, never `-A`).
   No push, no merge.
