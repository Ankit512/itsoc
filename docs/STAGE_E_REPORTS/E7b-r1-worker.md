# E7b Round 1 — the triage modifier against the frozen referee

**Branch** `Ankit512/e7b-r1-triage-modifier` (worktree naming convention; the card's
`feat/e7b-r1-triage-modifier` was a warning only)
**Head at report time** `f5fe072` + the working commit described below
**Base** `f5fe072858bbdbc3cb0d186db10686e86df72e80`

---

## 1. Base check — and a stop-and-ask that mattered

The card required `git merge-base --is-ancestor f5fe072… HEAD` before the first edit,
and a STOP on failure. **It failed**, and no edit was made.

The diagnosis was that the worktree was **stale, not divergent**. The reverse test
distinguishes the two, and it is the one worth keeping:

```
git merge-base --is-ancestor f5fe072… HEAD    # FAILED  — base not behind HEAD
git merge-base --is-ancestor HEAD f5fe072…    # SUCCEEDED — HEAD is an ANCESTOR of base
```

A base that is *not present* can mean either a safe fast-forward or a genuinely wrong
tree that must halt; only the reverse test tells them apart. HEAD was `b836114`, strictly
behind `main`, and every file the card names — `console/triage_model.py`,
`tools/train_triage.py`, `tests/test_e7a_feature_contract.py`, the frozen referee —
did not exist at that commit. The work was impossible there, not merely misaligned.

Escalated with zero edits. The coordinator reset the worktree to `f5fe072`. **Re-verified
after the reset:**

```
$ git rev-parse HEAD
f5fe072858bbdbc3cb0d186db10686e86df72e80
$ git merge-base --is-ancestor f5fe072858bbdbc3cb0d186db10686e86df72e80 HEAD && echo OK
BASE_ANCESTOR_OK
$ grep -c finding_level_recall tools/efficacy_harness.py
7
```

**Detector freeze, before and after all work — unchanged:**

```
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876  anomaly_detector.py
```

---

## 2. Allowlist audit

Every file modified, and nothing else:

```
 M console/triage_model.py            # allowlisted
 M tests/test_e7a_feature_contract.py # THE ONE pre-authorised amendment (§6)
 M tools/test_train_triage.py         # allowlisted ("their tests")
```

`tools/train_triage.py` was modified during the investigation and then **reverted to
byte-identical with base** — see §5, the rejected direction. It carries no diff.

**The frozen referee is untouched:**

```
$ git diff --quiet tools/efficacy_harness.py tools/test_efficacy_harness.py && echo UNMODIFIED
FROZEN REFEREE UNMODIFIED
$ grep -n 'BENCHMARK_SEEDS = ' tools/efficacy_harness.py
204:BENCHMARK_SEEDS = (20270302, 20270303, 20270304)
```

Not touched: `anomaly_detector.py`, rules, the eval corpus, `console/efficacy_api.py`,
the web surface, `docs/STAGE_E_REPORTS/E8*.md`.

---

## 3. What the measurement said before I changed anything

The BEFORE run reproduces the published E8m benchmark **exactly** — same recall, same
false-positive totals, same importance, same flip counts — so the baseline is faithful
and the comparison is like-for-like.

### The two defects share one cause

All five dropped `ioc_observed` findings were re-scored with `criticality_rank` forced
across its domain, every other feature held as measured:

```
DROPPED ioc_observed INC-4a7f/rfc3164/20270302  low:KEEP(confir,0.9986) standard:KEEP(confir,0.9986) crown-jewel:DROP(benign,0.992)
DROPPED ioc_observed INC-4a7f/rfc5424/20270302  low:KEEP(confir,0.9997) standard:KEEP(confir,0.9997) crown-jewel:DROP(benign,0.9318)
DROPPED ioc_observed INC-4a7f/rfc5424/20270303  low:KEEP(confir,0.9997) standard:KEEP(confir,0.9997) crown-jewel:DROP(benign,0.9318)
DROPPED ioc_observed INC-4a7f/rfc3164/20270304  low:KEEP(confir,0.9999) standard:KEEP(confir,0.9999) crown-jewel:DROP(benign,0.7262)
DROPPED ioc_observed INC-4a7f/rfc5424/20270304  low:KEEP(confir,0.9999) standard:KEEP(confir,0.9999) crown-jewel:DROP(benign,0.7262)
```

**Every one is `confirmed` at ≥0.9986 confidence at `low` and `standard`, and flips to
`benign-expected` only at `crown-jewel`.** Defect 1 is not a second defect. It is defect 2
firing on five specific findings.

### The cause is a confound in the data, not a bad encoding

Criticality is resolved per host. `server-01` is the **only** crown-jewel asset configured,
and exactly two scenarios sit on it — `INC-4a7f` (confirmed) and `benign-maintenance`
(benign-expected). Measured over the 434-row training set:

| criticality | confirmed | false-positive | benign-expected | total |
|---|---|---|---|---|
| standard | 154 | 126 | 0 | 280 |
| crown-jewel | 70 | 0 | 84 | 154 |

**Every benign-expected row is crown-jewel; every false-positive row is standard.**
P(benign-expected \| crown-jewel) = 0.5455 against a 0.1935 base rate. `criticality_rank`
was the highest-purity split available, so the model took it and learned *"crown-jewel is
where benign-expected lives."*

That is why **no re-encoding fixes it.** One-hot, a binary crown-jewel flag and the ordinal
all carry the identical joint distribution — the confound is in the data, not the
representation. The only other route, decorrelating criticality from class, means editing
the generator's scenario-to-host pinning, which would move the benchmark the referee grades
against. So the feature is removed.

### The second thing the measurement showed

`rule_family_other` was not a family. It was five rules with contradictory meanings scoring
as one indistinguishable feature:

| rule_id | confirmed | false-positive | benign-expected |
|---|---|---|---|
| `infra_unknown_high` | 28 | 28 | 28 |
| `ioc_observed` | 28 | 14 | 0 |
| `generic_service_failed` | 0 | 0 | 28 |
| `infra_unknown_low` | 0 | 14 | 0 |
| `infra_unknown_medium` | 0 | 14 | 0 |

A threat-intel hit, a pure-benign service event and two pure false-positive passthroughs
were the same feature. The model could not separate them on rule identity, so it separated
them on the host's configured criticality. **The garbage bucket is what created the demand
for the confounded feature.**

---

## 4. The direction taken, and why

Two changes to `console/triage_model.py`, both arguing from the measurement above:

1. **Remove `criticality_rank` from the feature schema.** An org-config value must not
   drive dismissal advice against log evidence, and in this dataset it provably does.
2. **Split `rule_family_other` into three real families** — `rule_family_threat_intel`
   (this is the card's "feature-mark `ioc_observed`-backed findings"),
   `rule_family_infra_passthrough`, `rule_family_service_state` — giving the model back on
   *rule identity*, a rule-owned observed fact, the discrimination it had been buying from
   org config. `other` remains as the true residual.

**Severity-blind by construction.** `infra_unknown_high` / `_medium` / `_low` differ only by
the severity band inside the rule id. `_INFRA_PASSTHROUGH_RE` matches the **prefix only**,
never the band — a family that separated them would smuggle `sev` back in through the rule
name, and a second opinion that can see the first one is not a second opinion. Asserted:

```
feature_vector({'rule_id':'infra_unknown_high'}) == feature_vector({'rule_id':'infra_unknown_low'})  ->  True
```

`FEATURE_KEYS` 21 → 23. `train_triage.py` still resolves and passes `criticality` on the
record, deliberately: that keeps the referee's `_ForcedCriticality` counterfactual seam
live, so the fix is *proved by measurement* rather than made unmeasurable.

---

## 5. A direction tried and rejected — the frontier is real

To recover the residual recall I added a declared, a-priori cost-sensitive weighting to
`tools/train_triage.py` (`MISS_COST_RATIO = 2.0` on `confirmed` rows: one miss is worth two
false alarms). Measured on the same seeds:

| | finding recall | learned FP (all formats) |
|---|---|---|
| with cost weighting | **0.9444 (85/90)** | **7** |
| without | 0.9111 (82/90) | **0** |

It bought recall **by trading suppression away**, which the card names as not-success. It is
**reverted**; `tools/train_triage.py` is byte-identical with base.

It also proved *why* the residual is irreducible. The 7 false positives it created were
6 `infra_unknown_high` + 1 `infra_unknown_low` — **the same rule as the 8 dropped true
detections.** `infra_unknown_high` is 28/28/28 across the three classes, and for that rule
**every feature the frozen record projection can carry is identical across all three
labels** except `occurrences` (confirmed 8.71, benign 8.04, false-positive 1.82 — heavily
overlapping):

```
label / scenario                          occurrences  evidence_lines  entities  timeline_steps  span  has_time
('benign-expected','benign-maintenance')         8.04            0.00      1.00            1.00  0.00      0.00
('confirmed','error-burst')                      8.71            0.00      1.00            1.00  0.00      0.00
('false-positive','near-miss-errors')            1.82            0.00      1.00            1.00  0.00      0.00
```

The two findings are byte-identical apart from host name, occurrence count and timestamps.
The three routes to separating them are all closed: the distinguishing text lives in
`evidence`/`summary` **prose, which is in `FORBIDDEN_KEYS`**; the real discriminator in the
log (`maintenance window CHG-#### opened by change management`) is a **run-level** fact the
per-finding record cannot reach, and the frozen referee fixes the projection signature
`record_from_report_finding(finding, manifest, org)` so it cannot be plumbed — while reading
anything further from `manifest` would be **ground-truth leakage**, since the manifest
carries `scenario_class` and `malicious_lines`; and `host` → criticality **is the confound
just removed**. Any decision rule that keeps more `infra_unknown_high` keeps proportionally
more false ones. The frontier is forced by the data, not chosen by the model.

I did not sweep the cost ratio against the referee to find a value that scores well. That
would be fitting to the benchmark that grades me.

---

## 6. The contract amendment (pre-authorised, guardrail 10) — called out explicitly

`tests/test_e7a_feature_contract.py` line ~233 asserted as a **non-vacuity control** that
moving `criticality` moves the feature vector. Removing `criticality_rank` makes that control
pass vacuously in the one direction it was written to catch, so under the single pre-authorised
allowlist expansion it is **substituted, not weakened** — same `INCIDENT` record, same
assertion shape, moved onto another **permitted observed fact** (`techniques` →
`mitre_technique_count`):

```python
self.assertNotEqual(
    triage_model.feature_vector(INCIDENT),
    triage_model.feature_vector(dict(INCIDENT, techniques=[])),
)
# And the removal itself is locked down, so it cannot silently return.
self.assertNotIn("criticality_rank", triage_model.FEATURE_KEYS)
self.assertEqual(
    triage_model.feature_vector(INCIDENT),
    triage_model.feature_vector(dict(INCIDENT, criticality="low")),
)
```

The check still bites, and the amendment **adds** two assertions pinning the removal so it
cannot silently regress.

**No `FORBIDDEN_KEYS` entry and no leakage assertion was weakened, deleted or loosened,
anywhere.** `FORBIDDEN_KEYS` is pinned to an exact set by
`test_e7a_feature_contract.py:276`; I deliberately did **not** add `criticality` to it, so
the leakage wall is byte-for-byte as strict as it was. This is the only control amended.

`tools/test_train_triage.py` (plain allowlist, not the expansion) had one assertion on the
removed key; it now asserts the incident shape still scores its observed facts **and** that
criticality is inert.

---

## 7. Before / after, on the same frozen seeds `(20270302, 20270303, 20270304)`

Both runs: all four formats, freshness asserted `True`, 434 rows, training seeds
`20260902…20260915` (unchanged, disjoint from the benchmark).

| | BEFORE | AFTER | |
|---|---|---|---|
| run_id | `efficacy-59132e4cff9c` | `efficacy-f5acc3b73ded` | |
| model sha256 | `0eb19182b45a…` | `da97bf4917b7…` | |
| featureCount | 21 | 23 | |
| **finding-level recall (learned)** | **0.9444 (85/90)** | **0.9111 (82/90)** | ▼ regressed |
| line-level recall / misses | 0 missed | 0 missed | held |
| **learned FP, all 4 formats** | **0** (rules 84) | **0** (rules 84) | **held** |
| `criticality_rank` importance | **0.4146**, largest of 21 | **n/a — feature removed** | **fixed** |
| true_detections flipping | **28 of 85** | **0 of 82** | **fixed** |
| suppressions flipping | **33 of 84** | **0 of 84** | **fixed** |
| dropped `ioc_observed` | **5** | **0** | **fixed** |
| dropped `infra_unknown_high` | 0 | 8 | ▼ new |

**Format-scoped false positives** (no bare count is publishable):

| format | rules BEFORE | learned BEFORE | rules AFTER | learned AFTER |
|---|---|---|---|---|
| canonical | 21 | 0 | 21 | 0 |
| jsonlog | 21 | 0 | 21 | 0 |
| rfc3164 | 24 | 0 | 24 | 0 |
| rfc5424 | 18 | 0 | 18 | 0 |
| **all formats** | **84** | **0** | **84** | **0** |

**`criticality_sensitivity` populations, verbatim:**

```
BEFORE  true_detections: total=85 robust=57 flipping=28 kept_at={'low':85,'standard':85,'crown-jewel':57}
        suppressions:    total=84 robust=51 flipping=33 kept_at={'low':33,'standard':33,'crown-jewel':0}
        criticality_rank feature importance: 0.4146 (largest of 21 features)

AFTER   true_detections: total=82 robust=82 flipping=0  kept_at={'low':82,'standard':82,'crown-jewel':82}
        suppressions:    total=84 robust=84 flipping=0  kept_at={'low':0,'standard':0,'crown-jewel':0}
        criticality_rank feature importance: n/a (unavailable — the feature no longer exists)
```

**Where the importance mass went** — from an org-config value to parser-observed facts:

```
BEFORE                                AFTER
criticality_rank        0.4146        timeline_step_count           0.1876
rule_family_auth        0.1476        events_per_minute             0.1785
events_per_minute       0.1216        observed_span_seconds         0.1715
occurrences             0.0908        rule_family_service_state     0.1160
observed_span_seconds   0.0767        occurrences                   0.0981
timeline_step_count     0.0578        has_observed_time             0.0889
```

### `dropped_true_findings` AFTER — verbatim, all 8

All eight are `infra_unknown_high`, severity HIGH, `benign-expected`, on `bnch-api-01`.
**No `ioc_observed` finding is dropped any more, and nothing is dropped on the crown-jewel
host.**

```
1. infra_unknown_high HIGH benign-expected conf=0.9118  Unknown high alert on bnch-api-01
   line 2: 2026-08-30T04:00:01Z ERROR bnch-api-01 upstream request failed with status 504 attempt=1
   why:  part of a concentrated application error burst
2. infra_unknown_high HIGH benign-expected conf=0.6209  Unknown high alert on bnch-api-01
   line 2: {"host":"bnch-api-01","level":"ERROR","message":"upstream request failed with status 504 attempt=1","timestamp":"2026-08-30T04:00:01Z"}
   why:  part of a concentrated application error burst
3. infra_unknown_high HIGH benign-expected conf=0.611   Unknown high alert on bnch-api-01
   line 2: Aug 30 04:00:01 bnch-api-01 attack-generator: ERROR upstream request failed with status 500 attempt=1
   why:  part of a concentrated application error burst
4. infra_unknown_high HIGH benign-expected conf=0.6718  Unknown high alert on bnch-api-01
   line 2: 2026-08-30T04:00:01Z ERROR bnch-api-01 upstream request failed with status 500 attempt=1
   why:  part of a concentrated application error burst
5. infra_unknown_high HIGH benign-expected conf=0.9118  Unknown high alert on bnch-api-01
   line 2: {"host":"bnch-api-01","level":"ERROR","message":"upstream request failed with status 504 attempt=1","timestamp":"2026-08-30T04:00:01Z"}
   why:  part of a concentrated application error burst
6. infra_unknown_high HIGH benign-expected conf=0.6209  Unknown high alert on bnch-api-01
   line 2: Aug 30 04:00:01 bnch-api-01 attack-generator: ERROR upstream request failed with status 500 attempt=1
   why:  part of a concentrated application error burst
7. infra_unknown_high HIGH benign-expected conf=0.8708  Unknown high alert on bnch-api-01
   line 2: 2026-08-30T04:00:01Z ERROR bnch-api-01 upstream request failed with status 503 attempt=1
   why:  part of a concentrated application error burst
8. infra_unknown_high HIGH benign-expected conf=0.9118  Unknown high alert on bnch-api-01
   line 2: Aug 30 04:00:01 bnch-api-01 attack-generator: ERROR upstream request failed with status 503 attempt=1
   why:  part of a concentrated application error burst
```

### Did each named defect move? Plainly.

**Defect 2 — backwards criticality gradient: ELIMINATED, completely.** Importance 0.4146 →
feature gone. Flipping true detections 28/85 → **0/82**. Flipping suppressions 33/84 →
**0/84**. The keep/drop decision is now identical at all three bands for **every finding in
both populations**. No org-config value can move dismissal advice, because the model can no
longer see one. The referee's own counterfactual measures this, so it is proved, not asserted.

**Defect 1 — crown-jewel IOC dismissals: the named class is ELIMINATED; the aggregate metric
regressed.** All five `ioc_observed` dismissals on the crown-jewel host are gone — 5 → **0**,
and nothing is dropped on that host at all. But eight `infra_unknown_high` findings on
`bnch-api-01` now drop that did not before, so aggregate finding-level recall fell
**0.9444 (85/90) → 0.9111 (82/90)**, a **0.0333 regression against an 85/90 baseline**.

**Cost: none paid in suppression.** Learned false positives remain **0 against rules 84**
across all four formats, and 0 in every single-format subset. Line-level recall and misses
are unchanged at 0.

**Against the stated success bar, this is an honest partial, not a pass.** The bar was that
finding-level recall *regain ground* while suppression holds. Suppression held exactly;
recall lost 3 findings net. I am not going to present that as success. What was bought for it
is that the model's largest feature is no longer an inverted org-config confound, and the
specific failure the card named — evidence-backed IOC findings dismissed at 0.992 confidence
because the asset was important — cannot happen any more. The residual 8 sit on a rule that
is 28/28/28 with an identical feature vector across all three labels; §5 shows recovering
them costs roughly twice as many false positives.

---

## 8. Retrain provenance

Well inside the ten-minute budget.

| | |
|---|---|
| duration | **14.37 s** (baseline retrain 20.34 s) |
| rows | **434** — confirmed 224, false-positive 126, benign-expected 84 |
| base seed | `20260902`, 14 variants → `20260902…20260915` (**unchanged**, disjoint from `BENCHMARK_SEEDS`) |
| formats | canonical, rfc3164 |
| estimator | `sklearn.ensemble.GradientBoostingClassifier(random_state=20260902)` |
| sklearn / python | 1.7.2 / 3.13.3 |
| cross-validation | StratifiedKFold(shuffle=True), 5 folds, balanced sample weights on every fit |
| macro-F1 | mean **0.9381**, min 0.9071, max 0.9615 (per fold: 0.9615, 0.9494, 0.9071, 0.9377, 0.9349) |

**CV fell from 0.9568 to 0.9381, and that is expected rather than hidden.** Cross-validation
is measured on the same confounded distribution the benchmark was built to see past:
`criticality_rank` was a near-perfect in-distribution split, so removing it *must* cost CV.
The referee, on fresh seeds in a remapped entity space, is the arbiter — and there the
suppression result held exactly while the gradient went to zero.

---

## 9. Acceptance gates — all run, all green

| gate | result |
|---|---|
| fresh clean-env train (new `.venv`, `requirements.txt`) | **exit 0**, 14.37 s |
| frozen referee, all 4 formats, frozen seeds | **exit 0** |
| `tools/test_efficacy_harness.py` — **sklearn PRESENT** | **exit 0** — Ran 57 tests, OK |
| `tools/test_efficacy_harness.py` — **sklearn ABSENT** | **exit 0** — Ran 57 tests, OK |
| `console/test_console.py` | **exit 0** — PASSED, all check groups green |
| `tests/eval/run_eval.py` | **exit 0** — precision 1.000, recall 1.000, f1 1.000, false positives **(none)** |
| `tests/test_e7a_feature_contract.py` | **exit 0** — Ran 10 tests, OK |
| `tests/test_stage_e_wall.py` | **exit 0** — **101/101 checks passed**, "Stage E wall intact." |
| `tools/test_train_triage.py` | **exit 0** — Ran 23 tests, OK |
| wall + contract with **sklearn absent** | **exit 0** — 101/101, OK |
| `npm --prefix web test` | **exit 0** — **43 files, 290 tests passed** |
| `npm --prefix web run build` | **exit 0** — built in 1.42 s |
| detector sha256 | **unchanged**, `364577c5…b577a4a876` |
| allowlist audit | 3 files, all permitted; frozen referee unmodified; `BENCHMARK_SEEDS` unmoved |
| `git diff --check` | **clean** |

### The known pre-existing failure — verified pre-existing, and not masking anything

`tests/test_battlecard_efficacy.py` fails on my tree. I confirmed it is **not mine** by
stashing my changes and running it on the pristine base — **byte-identical assertion, same
single failing test, same counts**:

```
on my tree:      AssertionError: Lists differ: ['INC[35 chars]urst'] != ['INC[35 chars]urst', 'near-miss-auth', ... ]
                 Ran 3 tests — FAILED (failures=1)
on base f5fe072: AssertionError: Lists differ: ['INC[35 chars]urst'] != ['INC[35 chars]urst', 'near-miss-auth', ... ]
                 Ran 3 tests — FAILED (failures=1)
```

Not fixed, per the card. It is a stale scenario-list assertion and it is not concealing a
regression of mine: the failure text is identical before and after, and it is the only
failing test in that file.

---

## 10. Standing guardrails

- **Rules own severity and correlation.** Nothing here writes `sev`, `ruleSev`, incident
  severity, priority, runbook eligibility or any execution state. The change is confined to
  the advisory feature schema; `tests/test_stage_e_wall.py` passes 101/101 and
  `tests/eval/run_eval.py` is unchanged at 20/20, FP=0 — **no rule finding or severity moved.**
  A changed advisory label changed no verdict.
- **Real data or an honest n/a.** `criticality_rank` importance now renders **`n/a
  (unavailable)`** rather than a fabricated zero, through the referee's existing
  `by_feature.get()` path — which `tools/test_efficacy_harness.py:917` already asserted must
  be `None` when absent. The web Reports surface reads
  `sens.feature_importance?.criticality_rank ?? null` and renders the honest empty; no web
  file was edited and all 290 web tests pass.
- **`raw` is always the real log line.** Untouched; every line quoted above is the referee's
  own `raw`, verbatim.
- The counterfactual seam was deliberately left live so the fix is measured by the frozen
  referee rather than merely claimed.

## 11. Deviations

1. **Base check failed on first run** — escalated with zero edits; coordinator reset the
   worktree; re-verified green (§1). No work was done on the stale tree.
2. **`web/node_modules` was missing** (Orca setup step had failed). Ran
   `npm --prefix web install` (exit 0) before the web gates, as the coordinator instructed.
3. **No `.venv` existed.** Created one from `requirements.txt` (`scikit-learn==1.7.2`) — this
   is also the "fresh clean-environment train" the acceptance list asks for.
4. **`tools/test_efficacy_harness.py` must be run as `python -m tools.test_efficacy_harness`**
   from the repo root; invoking it by path fails on `ModuleNotFoundError: No module named
   'tools'`. Pre-existing, unrelated to this change.
5. **A direction was tried and reverted** (§5). `tools/train_triage.py` carries no diff.
