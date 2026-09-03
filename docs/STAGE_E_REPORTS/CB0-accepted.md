# CB-0 accepted — the advisory guard's family gap, closed by class

**Accepted:** 2026-09-03. **Task:** `task_2e9d679fc130`. **Dispatch:** `ctx_1d545b7f2895`.
**Worker commits:** `ed975f1`, `a8a6c74` (base `8436df9`). **Local merge:** `9d5ec4a`. **Push:** none.
Worker report: `docs/STAGE_E_REPORTS/CB0-worker.md`. Owner-authorized engine change.

## What was wrong

The advisory guard fences advisory fields out of eligibility two ways: the enumerated `ADVISORY_KEYS`
denylist, and `_ADVISORY_WORD_RE` as a pattern safety net. The model's own output fields **`aiAgrees`
and `aiLabel` were in neither** — and the whole `ai<Something>` family was uncovered, so closing it
by adding two names would have left the next `aiWhatever` equally unfenced. Nothing read them from an
eligibility path, so there was no live defect: an uncovered surface, found only because a card's
strict constraint collided with it.

## The fix, at class level

`aiAgrees` and `aiLabel` added to `ADVISORY_KEYS` as the explicit record, and `_ADVISORY_WORD_RE`
extended with **`(?-i:\bai[A-Z]|\bai_)`** — the family covered by class, in both camelCase and
snake_case spellings. Both mechanisms retained: enumeration as the record, pattern as the net.

## The worker corrected the coordinator

The dispatch told the worker `ai[A-Z]` over-matches nothing, **and told it to verify rather than take
that on trust.** It did, and found the coordinator's check was methodologically wrong:
`_ADVISORY_WORD_RE` is compiled with `re.I`, so the clause would have been installed inside a
module-wide IGNORECASE regex where `[A-Z]` also matches lowercase and `ai[A-Z]` collapses to a bare
`ai` substring — over-matching `maintainer`, `chain`, `airflow`, `aid`, `said`, `captain`. The
coordinator had tested a fresh case-sensitive pattern, not the one that would ship.

The conclusion happened to hold — none of the 13 rule-owned keys contain `ai` — but the pattern was
latently wrong, and a future key like `maintainerId` would have been falsely fenced. Note the failure
direction: **fail-closed**, breaking eligibility rather than leaking into it. Wrong either way, and it
would have surfaced later as a baffling eligibility bug. The scoped `(?-i:...)` group is the fix.

## Coordinator verification — reproduced, not read

Tested against the **installed** pattern, not a fresh one:

| | Result |
|---|---|
| Family fenced (`aiSeverity`, `aiConfidence`, `aiAgrees`, `aiLabel`, `aiTriage`, `aiMadeUpField`, `ai_label`, `aiAnythingAtAll`) | **all 8 fenced** |
| Over-match across rule-owned keys and innocent words (`maintainer`, `chain`, `airflow`, `aid`, `said`, `captain`, all 13 rule-owned) | **none** |
| `aiAgrees`/`aiLabel` now in `ADVISORY_KEYS` | yes |

**The attack, reproduced independently.** A novel unlisted `aiMadeUpField` made projectable on
**each** allowlist is refused on pattern alone:

> `rule-owned key(s) read as advisory: ['aiMadeUpField'] — name them in ADVISORY_KEYS or drop them`

Caught on `RULE_OWNED_INCIDENT_KEYS` and on `RULE_OWNED_FINDING_KEYS`; restored clean afterwards.
**Control:** the pre-CB-0 pattern does **not** match `aiMadeUpField` — it would have missed it. The
guard is strictly stronger than before, demonstrated rather than asserted.

The worker additionally showed the existing guards still bite: `llm_hint` on `eligible()` trips
`assert_no_llm_input` with 5 `[FAIL]`s, and `aiLabel` in the finding allowlist trips the overlap
branch — both restored.

## Gates on merged main

Stage E wall **126/126** (was 101 — CB-0 added 25 checks); `console/test_console.py` 0 FAIL;
`tests/eval/run_eval.py` 20/20 F1 1.000 FP 0; `tests/test_e7a_feature_contract.py` 10 passed / 67
subtests; harness 69/69 with sklearn and without; web 301/301 across 43 files; build green; detector
sha256 `364577c5…577a4a876` unchanged; allowlist clean; branch never pushed. The known pre-existing
`tests/test_battlecard_efficacy.py` stale assertion is unchanged.

## Deviation, disclosed by the worker

An early restore reverted the then-uncommitted fix; the worker re-applied it, re-verified, committed,
and **re-ran both attacks against the committed state** rather than relying on the earlier run.
Disclosed unprompted in its own report.

## Consequence for CB-1

CB-1's constraint — *the copilot may read fields the guard fences* — is now satisfiable. `aiSeverity`,
`aiConfidence`, `aiAgrees` and `aiLabel` are all fenced, so all four required behaviours are
expressible without an exception.
