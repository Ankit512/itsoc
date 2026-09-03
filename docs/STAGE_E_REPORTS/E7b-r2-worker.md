# E7b round 2 — worker report

**Branch:** `Ankit512/e7b-r2-triage-modifier` (the dispatch named `feat/e7b-r2-triage-modifier`;
the worktree was already on this branch — name only, no behavioural difference).
**Base:** `944c47e30d8e7cf3fb1d3137e3818e5a3fdb4f46`.
**Task:** `task_c4c9cf449f9e`. **Dispatch:** `ctx_573da9d1477e`.
**Worker commit:** `f029c5d`. **Not pushed. Not merged.**

## Result in one line

**Finding-level learned recall 0.9444 (85/90) → 1.0000 (90/90); learned false positives 0 → 0 in
all four formats.** Recall rose to the rules' own ceiling and suppression was not touched. The
`criticality_rank` label proxy is **halved but not eliminated** (importance 0.4146 → 0.2026); what
it would have cost to eliminate it is measured below and was refused.

## Base check and freeze

    git merge-base --is-ancestor 944c47e3... HEAD   → BASE_OK

First probe of this worktree reported `BASE_FAIL` **and** the reverse as an ancestor — the stale
signature from guardrail 9. It was not stale: the worktree was mid-checkout. Re-checked seconds
later, HEAD was `944c47e3`, tree clean, and the base check passed. No edit was made before it passed.

`anomaly_detector.py` sha256 **before and after**:
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — unchanged.

## Allowlist audit

Four files, all inside the allowlist:

    M console/triage_model.py       M tools/attack_generator.py   (ADDITIVE ONLY)
    M tools/train_triage.py         M tools/test_train_triage.py

`git diff --stat HEAD` over `tools/efficacy_harness.py`, `tools/test_efficacy_harness.py`,
`anomaly_detector.py`, `rules_syslog.py`, `rule_context.py`, `tests/eval/`,
`console/efficacy_api.py`, `web/` and `docs/` is **empty** — the frozen referee is untouched. The
model artifact lives under gitignored `console/.soc/models/` (confirmed via `git check-ignore`), so
it is retrained, not committed. `git diff --check` clean.

## Chosen direction, and why

**(b) re-encode the confounded feature — plus one additive scenario from (c).** Not (a), and not (c)
alone. The reason is a measurement neither round 1 nor the dispatch had.

I dumped all 434 baseline training rows with their labels and vectors. The five dropped findings are
all `ioc_observed` on the crown-jewel host, predicted `benign-expected` at 0.73–0.99 confidence. But
**`ioc_observed` never appears with the `benign-expected` label anywhere in training** — 42 rows, 28
`confirmed`, 14 `false-positive`, zero `benign-expected`. The model was inventing a class the rule
had never been shown.

The cause is in `features()`, not in the corpus. `ioc_observed` matched **none** of the five family
regexes, so it fell into `rule_family_other` — the same bucket as every `infra_unknown_*` rule. In
that bucket the two rules are literally indistinguishable:

    family=other, rule_count=1, detector_owned=1, occurrences=N,
    entity_host_count=1, entity_distinct_count=1, timeline_step_count=1, events_per_minute=N

`infra_unknown_high` on the crown-jewel host is `benign-expected` in training (28 rows, from
`benign-maintenance`, occurrences 6–10). A crown-jewel `ioc_observed` finding with occurrences 6–11
therefore landed on `infra_unknown_high`'s label. **The rule identity was being thrown away, and
`criticality_rank` was doing the work the rule family should have done.**

The fix names the family the rules already name. `rule_context.py:303` groups
`atype.startswith("threat_") or atype in ("ioc_observed", ...)` — the repo's own taxonomy already
says IOC is threat family. `_THREAT_RE` now matches `ioc` as a token (and `indicator`). One regex.
**No feature was added, removed or reordered: `FEATURE_KEYS` is still the same 21 keys in the same
wire order.**

Round 1's diff was not read before this approach was formed.

## Before / after on the frozen referee

Same referee, same three frozen benchmark seeds `(20270302, 20270303, 20270304)`, same four
formats, six scenarios named **explicitly** (see the leak note below).

| | Before (E7a, reproduced) | After (r2) | |
|---|---|---|---|
| Finding-level learned recall | 0.9444 (85/90) | **1.0000 (90/90)** | **+0.0556** |
| Finding-level rules recall | 1.0 (90/90) | 1.0 (90/90) | ceiling |
| `learned_total_dropped_true_findings` | 5 | **0** | eliminated |
| Learned line-level misses | 0 | 0 | unchanged |
| Rules false positives, all formats | 84 | 84 | unchanged |
| **Learned false positives, all formats** | **0** | **0** | **suppression HELD** |
| — canonical | rules 21 / learned 0 | rules 21 / learned 0 | |
| — rfc3164 | rules 24 / learned 0 | rules 24 / learned 0 | |
| — rfc5424 | rules 18 / learned 0 | rules 18 / learned 0 | |
| — jsonlog | rules 21 / learned 0 | rules 21 / learned 0 | |
| `criticality_rank` importance | 0.4146 (rank 1/21) | 0.2026 (rank 1/21) | halved, still first |
| Counterfactual flips, true detections | 28 / 85 | 30 / 90 | see below |
| Counterfactual flips, suppressions | 33 / 84 | 33 / 84 | unchanged |

`dropped_true_findings` **after**, verbatim: `[]` — `learned_total_dropped_true_findings: 0`.

`dropped_true_findings` **before**, verbatim (all five, prose fields as emitted):

    {"confidence": 0.992,  "label": "benign-expected", "rule_id": "ioc_observed", "severity": "MEDIUM",
     "summary": "Potential IOC observed on bnch-server-01",
     "evidence": "Aug 30 02:16:41 bnch-server-01 attack-generator: WARN Failed password for bnch-admin from 198.18.222.151 port 33356 ssh2"}
    {"confidence": 0.9318, "label": "benign-expected", "rule_id": "ioc_observed", "severity": "MEDIUM",
     "summary": "Potential IOC observed on bnch-server-01",
     "evidence": "<134>1 2026-08-30T02:16:41Z bnch-server-01 attack-generator - - - WARN Failed password for bnch-operator from 198.18.24.47 port 33052 ssh2"}
    {"confidence": 0.9318, "label": "benign-expected", "rule_id": "ioc_observed", "severity": "MEDIUM",
     "summary": "Potential IOC observed on bnch-server-01",
     "evidence": "<134>1 2026-08-30T02:16:41Z bnch-server-01 attack-generator - - - WARN Failed password for bnch-root from 198.18.50.168 port 33659 ssh2"}
    {"confidence": 0.7262, "label": "benign-expected", "rule_id": "ioc_observed", "severity": "MEDIUM",
     "summary": "Potential IOC observed on bnch-server-01",
     "evidence": "Aug 30 02:16:41 bnch-server-01 attack-generator: WARN Failed password for bnch-operator from 198.18.127.5 port 33740 ssh2"}
    {"confidence": 0.7262, "label": "benign-expected", "rule_id": "ioc_observed", "severity": "MEDIUM",
     "summary": "Potential IOC observed on bnch-server-01",
     "evidence": "<134>1 2026-08-30T02:16:41Z bnch-server-01 attack-generator - - - WARN Failed password for bnch-svc-deploy from 198.18.111.41 port 33238 ssh2"}

### criticality_sensitivity, after, verbatim

    `criticality_rank` feature importance: 0.2026 (the largest of 21 features)
    domain forced across ['low', 'standard', 'crown-jewel']
    true_detections: 90 total — 60 robust, 30 flip in at least one band
      kept at each band: {'low': 90, 'standard': 90, 'crown-jewel': 60}
    suppressions: 84 total — 51 robust, 33 flip in at least one band
      kept at each band: {'low': 33, 'standard': 33, 'crown-jewel': 0}

**State this plainly: recall rose, suppression held, and the criticality proxy was only halved.**
The flip counts did not improve — 30/90 versus 28/85 is the same 33% of a larger kept set, because
the five recovered findings are themselves crown-jewel `ioc_observed` findings that flip. The
inverted direction the coordinator named is still present. What it costs to remove it is next.

## Direction (c): measured in full, and refused

Generator diversity is the right diagnosis and I implemented it, but the corpus-level fix does not
come free. Four training corpora, one referee, everything else identical:

| Training corpus | Recall | Learned FPs | `criticality_rank` | Suppression flips |
|---|---|---|---|---|
| six scenarios, no re-encode (shipped E7a) | 0.9444 (85/90) | 0 | 0.4146, rank 1/21 | 33/84 |
| six scenarios, re-encode only | 1.0000 (90/90) | 0 | 0.3449, rank 1/21 | 33/84 |
| **seven: + `near-miss-auth-crown`  (SHIPPED)** | **1.0000 (90/90)** | **0** | **0.2026, rank 1/21** | 33/84 |
| seven: + `benign-maintenance-standard` | 0.9111 (82/90) | 0 | 0.0465, rank 8/21 | **0/84** |
| eight: both of the above | 0.9111 (82/90) | 0 | 0.0339 | 0/84 |
| seven: + `benign-authorised-scan` | 0.9778 (88/90) | 0 | 0.0952, rank 5/21 | 27/84 |

(All rows below the first carry the re-encoding. Recall is finding-level learned, denominator 90.)

**`near-miss-auth-crown` — a false positive ON the crown jewel — is free and is shipped.** It breaks
`false-positive ⟹ standard`, halves the criticality importance, and costs nothing.

**`benign-maintenance-standard` — an authorised patch window on a standard host — is refused.** It
dissolves the proxy almost completely (importance 0.4146 → 0.0465, rank 8/21; suppression flips
33/84 → **0/84**) but drops eight true `infra_unknown_high` detections on `error-burst`, all
predicted `benign-expected`. Recall 1.0000 → 0.9111. That is the regression round 1 was failed for,
and I am not absorbing it to improve a secondary metric.

**These are the same eight drops round 1 measured, reached by a completely different intervention.**
Round 1 deleted `criticality_rank`; I left it in the schema and removed its discriminative power by
decorrelating the corpus. Two independent routes, identical cost. That converges on a structural
claim, and I can state the mechanism rather than assert irreducibility:

> An authorised maintenance burst and an attack burst reach `features()` as the **same vector**. I
> measured `infra_unknown_high` over the 14 training seeds with `criticality_rank` excluded: 84
> rows, 9 distinct vectors, **50 rows (60%) on a vector carrying both `benign-expected` and
> `confirmed`**. Every ambiguous pair differs only in `occurrences` (6–10). The fact that actually
> separates them — `maintenance window CHG-#### opened by change management`, which is right there
> in the log — reaches no finding: no rule matches it, so it is in no `rule_id`, no `entities` dict
> and no `timeline`. `criticality_rank` is therefore not merely a label proxy for this rule; under
> the current record projection it is the **only** thing that makes the third class learnable.

Two footnotes on the dispatch's corrected figure. It is directionally right and round 1's
"irreducible" was wrong. My count differs in detail — 60% ambiguous, not 45%, and 9 vectors over 84
rows rather than 42 — because I measured all rows the trainer actually builds (2 formats × 14 seeds)
rather than one format. The separable 40% is separable **by occurrence count alone**, which is a
distribution artefact of the two templates' `randint` ranges, not a signal an analyst would trust.

**I did not manufacture separability.** Widening the maintenance template's error range so
`occurrences` stops overlapping `error-burst` would have bought back all eight drops. It would also
have been fitting the generator to the referee, so it was not done.

`benign-authorised-scan` (an authorised vulnerability scan, a benign-expected class in a rule family
no positive template occupies) was the most promising escape and still cost two detections. Refused.
Neither refused scenario ships: no dead code, and no extra surface leaking into the benchmark
default. Their numbers above are the deliverable.

**Actionable for the next card:** give the record projection a way to observe authorisation — a
rule that fires on a declared change window, or a run-level observed fact carried onto the finding.
With that, `benign-maintenance-standard` should land at zero recall cost and take the criticality
proxy to ~0.04 and 0/84 suppression flips. Without it, the proxy is load-bearing.

## Generator: byte-identical proof

`tools/attack_generator.py` is **ADDITIVE ONLY**. One scenario appended — `near-miss-auth-crown`,
class `false-positive`, host `server-01`, zero malicious lines. The six existing builders,
`SCENARIOS` ordering, `SCENARIO_CLASS`, `SCENARIO_HOST` and every seed are untouched.

Proof, run before and after the change, importing each revision's `attack_generator.py` directly:
the **six original scenarios × 4 formats × 18 seeds** (unseeded fixture + the 3 frozen benchmark
seeds + the 14 training seeds), hashing both the `.log` and the `.manifest.json` of each —
**864 artefacts**:

    BEFORE (base HEAD):      artefacts=864  AGGREGATE_SHA256=c30551f05c9e0be93d0b91219598ac3e845f827acbc374972fb7323fbdd6198b
    AFTER  (working tree):   artefacts=864  AGGREGATE_SHA256=c30551f05c9e0be93d0b91219598ac3e845f827acbc374972fb7323fbdd6198b
    diff of the per-artefact hash lists: IDENTICAL — 0 differing artefacts

### The benchmark-leak warning is real, and observed

`efficacy_harness.py:1610` is `scenarios = args.scenarios or list(generator.SCENARIOS)`, so a
generator addition **does** enter the referee's default sweep until E8m2 lands. Every referee run in
this report therefore names the six scenarios explicitly on the command line. Independent
confirmation: `tests/test_battlecard_efficacy.py` reads that default, and its actual list grew from
six to seven entries with my change — see the gates section.

To make training immune to the same leak, `train_triage.py` now pins `DEFAULT_SCENARIOS` by name
(the six plus `near-miss-auth-crown`) instead of taking `generator.SCENARIOS`. The corpus a
published number was measured against should be a decision, not a default.

## Feature contract

**No amendment was needed and none was made.** `tests/test_e7a_feature_contract.py` is byte-unchanged
and passes 10 tests / 67 subtests. The pre-authorisation under guardrail 10 was not used: the
direction re-encodes a regex, it does not change the feature schema. `FEATURE_KEYS` is the same 21
keys in the same order, `criticality_rank` is still present, and no `FORBIDDEN_KEYS` or leakage
assertion was touched.

I did check the alternative and rejected it on measurement: adding an explicit
`rule_family_infra_telemetry` key (22 keys, which *would* have required the amendment) produced
**identical** referee numbers — recall 1.0000, 0 learned FPs — with criticality importance slightly
*worse* (0.3787). It bought nothing and cost graded surface area, so it was reverted.

### New regression pins (`tools/test_train_triage.py`, 23 → 35 tests)

The family encoding had **no test anywhere** — the defect could recur silently. Added, all additive:

- `RuleFamilyEncodingTests` — `ioc_*` is threat family and not the residual bucket; `ioc_observed`
  and `infra_unknown_{low,medium,high,critical}` **share no family**; `ioc` matches as a token so
  `generic_socket_error` / `biocheck_failed` do not fire; the five pre-existing family mappings are
  unchanged; and `len(FEATURE_KEYS) == 21` pins that this card changed no schema.
- `CriticalityIsNotALabelProxyTests` — the corpus is pinned by name, and `false-positive` is no
  longer confined to one criticality band.
- `AdditiveGeneratorTests` — the original six keep their order, class and host; the added scenario
  declares zero malicious lines and is byte-deterministic per seed.

**Both new guards were verified non-vacuous by negative control.** Against the base
`triage_model.py`, `RuleFamilyEncodingTests` fails 8 assertions
(`'rule_family_malware_or_threat' not found in {'rule_family_other'}`). Against the original
six-scenario corpus, the false-positive band test fails (`false-positive: ['standard']`).

One of these started out vacuous and was rewritten. My first version asserted "no criticality band
maps to exactly one class" — which **passes on the defective corpus**, since crown-jewel already
carried both `confirmed` and `benign-expected`. The direction that actually bites is class → band.
It is now asserted that way, and the half I did **not** fix is pinned honestly as
`test_benign_expected_is_still_confined_to_one_band_KNOWN_RESIDUAL`, with the measured cost of
fixing it in the docstring, so no reader mistakes it for solved.

## Retraining budget

Well inside ten minutes. Fresh clean-environment run, `console/.soc/models/` deleted first:

- **Duration 44.81 s** (`trainDurationSeconds`; 16–27 s on warm repeats).
- **476 rows** — `{'benign-expected': 84, 'confirmed': 224, 'false-positive': 168}`; 196 logs
  ingested, 476 findings seen. 0 incident-disposition rows and 0 event-store rows on this machine
  (honest zero, recorded in the sidecar).
- **14 seeds** `20260902…20260915`; 7 scenarios × 2 formats (`canonical`, `rfc3164`).
- **Cross-validation** 5 stratified folds, balanced sample weights: macro-F1 mean/min/max **1.0**,
  accuracy 1.0 on every fold.
- scikit-learn 1.7.2, Python 3.13.3, 21 features.

**On the perfect cross-validation — do not read it as a generalisation claim.** It is in-sample on
seeded synthetic data from seven templates; once the rule family is encoded faithfully, every
(family × occurrence) cell in the corpus is separable, so 1.0 is what a fitted tree should score.
The number that carries evidence is the referee's, on three disjoint seeds with every entity
remapped and disjointness asserted. Reported as measured, including that it is uninformative.

## Gates

| Gate | Result |
|---|---|
| `tests/test_e7a_feature_contract.py` | **OK** — 10 tests / 67 subtests, file unchanged |
| `tests/test_stage_e_wall.py` | **101/101** — "Stage E wall intact." |
| `tools/test_efficacy_harness.py`, sklearn **present** | **OK** — 57 tests |
| `tools/test_efficacy_harness.py`, sklearn **absent** | **OK** — 57 tests |
| `tools/test_train_triage.py` | **OK** — 35 tests (was 23) |
| `console/test_console.py` | **PASSED** — 0 FAIL, 44 check groups green |
| `tests/eval/run_eval.py` | **20 passed / 0 failed**, precision 1.000 recall 1.000 F1 1.000, FP none |
| `npm --prefix web test` | **290 passed / 43 files** |
| `npm --prefix web run build` | **built in 1.38s**, exit 0 |
| `git diff --check` | clean |
| detector sha256 before/after | `364577c5…577a4a876` unchanged |
| allowlist audit | 4 files, no forbidden path; referee byte-unchanged |

`tools/test_efficacy_harness.py` must be run as `PYTHONPATH=. python3 -m tools.test_efficacy_harness`
— run as a plain script it dies on `ModuleNotFoundError: No module named 'tools'`. Pre-existing,
not caused by this branch.

### Deviations

1. **Orca setup did not install the web dependencies** — `npm --prefix web test` first exited 127
   with `sh: vitest: command not found`. Ran `npm --prefix web install` (exit 0) and re-ran, as the
   card directs. Recorded here.
2. **scikit-learn was not present in the environment.** Created `.venv` and installed
   `requirements.txt` (scikit-learn 1.7.2). `.venv/` is gitignored and not committed.
3. **`tests/test_battlecard_efficacy.py` fails — pre-existing, and I confirmed it by stashing.**
   Same single assertion (`test_canonical_harness_scenario_totals_appear_in_battlecard`, line 66)
   fails on the pristine base and on my branch. It expects three scenarios while the harness default
   sweeps them all; on base the actual list is 18 entries, on my branch 21, because my added
   scenario enters that default. **No new failure mode — the same assertion, already red, with one
   more entry in an already-wrong list.** The file is outside my allowlist and was not edited. It is
   direct evidence for E8m2: pin the benchmark's scenario list.
4. **The referee's importance line reads "the largest of 21 features" as fixed prose**
   (`efficacy_harness.py:1569-1570`) — it is not a computed rank. It happens to be true for this
   model (0.2026, genuinely rank 1/21), but it printed the same phrase for the rejected
   `benign-maintenance-standard` model where `criticality_rank` was 0.0465 and rank **8/21**. Worth
   a fix in a card that owns the referee; I did not touch it. True ranks in this report come from
   `criticality_sensitivity.feature_importance.by_feature` in the JSON.

## Standing guardrails

Rules still own severity. The model is advisory: `console/triage_model.py` writes no `sev`,
`ruleSev`, severity, priority, eligibility or execution state, and the Stage E wall's 101 checks
including the mutation-based leakage proof are green. `raw` is untouched — the only generator change
appends a scenario whose lines are its own real log text, and the manifest carries zero malicious
lines because none of them are. No number in this report is invented; the honest failures are here
with the successes.
