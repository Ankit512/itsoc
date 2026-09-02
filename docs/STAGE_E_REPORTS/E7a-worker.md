# E7a — Second-opinion model v1: train + render (worker report)

Branch: `feat/e7a-model-v1`, cut from local `main` at `e7f6831`. Verified before
any edit: `git merge-base --is-ancestor main HEAD` true and
`git diff --stat main..HEAD` empty — the branch was byte-identical to `main`.

## What shipped

A small, **local, per-installation** learned triage model that gives an advisory
second opinion beside the rule verdict — rendered on Findings and Incidents,
provenanced, and provably unwired from every decision.

The deterministic pseudo-AI in `console/triage.py` is **gone**. It matched
keywords in a finding's prose and returned a band that looked like an opinion
without being one; that is exactly the thing this product refuses to ship. What
replaces it either answers with a real model or says out loud that it cannot.

## Dependency pin

`requirements.txt` (new, the repo's only dependency file):

```
scikit-learn==1.7.2
```

Verified installing and training on **Python 3.13.3** (the repo interpreter); it
pulls numpy 2.5.2 / scipy 1.18.1 / joblib 1.6.0, deliberately unpinned so the
resolver picks platform-matching wheels. **Optional at runtime**: nothing in the
engine, console, exporters or any test in this repo needs it. `import sklearn`
happens lazily inside `triage_model.load_model()`, never at module import — the
Stage E wall asserts that on the AST (part F).

## Label mapping

The classes are **E0's disposition vocabulary verbatim**, so a generated
ground-truth row and a real closed incident are the same kind of label with no
translation layer:

| label | from the generator | from the store |
|---|---|---|
| `confirmed` | a finding citing ≥1 manifest-labelled malicious line in a positive scenario | `incident.disposition == "confirmed"` |
| `false-positive` | every finding in a **near-miss** scenario (zero malicious lines by construction), and any finding in a positive scenario that cites none of its malicious lines | `disposition == "false-positive"` |
| `benign-expected` | every finding in the **benign-maintenance** scenario (authorised patch window: the rules *should* fire, and the honest outcome is not "false positive") | `disposition == "benign-expected"` |

An incident with **no** disposition is skipped, never guessed
(`disposition_rows()` counts them as `undispositionedSkipped`).

A predicted class becomes the rendered **severity opinion** through a fixed,
published mapping applied *outside* the model — the model itself never emits a
severity:

* `confirmed` → the rule's own band → **agrees**
* `false-positive` → `INFO` → disagrees
* `benign-expected` → `LOW` → disagrees

The mapping can only ever downgrade, so the model cannot escalate anything, even
on screen.

## Feature schema

One function, `console/triage_model.py:features(record)`, called by **both**
train and inference (`tools/test_train_triage.py` asserts
`train.triage_model.features is triage_model.features` and that the CLI defines
no `features()` of its own). 21 numeric keys, in `FEATURE_KEYS` wire order:

| group | keys |
|---|---|
| rule hits | `rule_family_auth`, `rule_family_scan_or_exposure`, `rule_family_malware_or_threat`, `rule_family_error_or_resource`, `rule_family_windows`, `rule_family_other`, `rule_count`, `rule_is_detector_owned`, `occurrences`, `evidence_line_count`, `mitre_technique_count` |
| observed entity counts | `entity_ip_count`, `entity_user_count`, `entity_host_count`, `entity_port_count`, `entity_distinct_count` |
| timing | `timeline_step_count`, `observed_span_seconds`, `events_per_minute`, `has_observed_time` |
| asset criticality | `criticality_rank` |

One function, two record shapes: a report/console **finding**
(`rule_id`/`type`, `entities`, `timeline`, `host`) and a stored **incident**
(`ruleIds`, `entityValues`, `entity`/`entityKind`, `firstSeen`/`lastSeen`,
`techniques`). Both are rule-owned projections. Criticality is resolved through
`console/org_context.py` on both sides (`enrich.py` for findings, the stored
`criticality` for incidents), so train and inference agree on the same host.

**`FORBIDDEN_KEYS`** names everything `features()` must never read: the four
disposition keys, model/advisory output (`aiTriage`, `aiSeverity`, `llmSev`,
`similarityNote`, `precedentOpinion`, `proposalDraft`, …), prose (`title`,
`summary`, `evidence`, `rationale`, `ruleWhy`, `explanation`, `predicate`, …),
severity and severity override (`sev`, `ruleSev`, `severity`,
`severityOverride`, `analystSeverity`), priority, eligibility, and execution
state.

**Deliberate decision: the rule verdict itself is excluded.** A second opinion
that can see the first one is not a second opinion — excluding `sev`/`ruleSev`
is what makes `agrees`/`disagrees` carry information. The wall asserts this
directly ("the rule verdict itself is invisible to features()").

## Generator extension (only as far as the training set needed)

`tools/attack_generator.py` gains:

* an optional **seed** on `generate()`. `seed=None` reproduces the promoted
  fixtures **byte-for-byte** (asserted line-by-line in
  `test_unseeded_output_is_unchanged_by_the_e7a_extension`), so the efficacy
  harness is untouched; an integer seed produces a deterministic variant —
  same seed, same bytes, forever;
* three scenarios beside the three positives: `near-miss-auth` and
  `near-miss-errors` (benign, just under a rule threshold — zero malicious lines
  in the manifest) and `benign-maintenance` (authorised patch window; the rules
  legitimately fire and the honest outcome is `benign-expected`);
* `SCENARIO_CLASS` and `SCENARIO_HOST`, and `scenario_class` / `host` / `seed`
  in every manifest.

Eval isolation is preserved and re-tested: seeded output is still refused under
`tests/eval/` (`test_seeded_output_is_refused_inside_the_eval_corpus`), and the
pre-existing test that the eval corpus mentions neither `attack_generator` nor
`efficacy_` still passes.

## Data pipeline — and what it never touches

```
attack_generator (seeded manifests)
  → log_analyzer.py --rules-only  [SUBPROCESS — the only seam]
  → report.json findings
  → triage_model.features()
  ⊕ console/.soc/incidents.json rows carrying a REAL analyst disposition
```

`tools/train_triage.py` imports **no** `anomaly_detector`, `log_analyzer`,
`rules_syslog`, `rule_context` or `normalize` — asserted on its AST in
`test_train_cli_never_imports_the_detector_or_the_analyzer`, which also asserts
it does use `subprocess` and `--rules-only`. Training output is refused anywhere
under `tests/eval/`.

The local **event** store (`console/.soc/soc_history.db`) is read as **observed
context only**: a row count written into the provenance sidecar, `usedForTraining:
false`. Not one unlabelled event becomes a training row, and no label is ever
inferred for one.

## Actual store and dataset counts (as measured, not as hoped)

**Local store, at the training run recorded in the shipped sidecar:**

| store | count |
|---|---|
| `console/.soc/incidents.json` | **absent** (`storePresent: false`) → 0 incidents, 0 dispositioned, 0 rows contributed |
| `console/.soc/soc_history.db` | **absent** → `events: 0`, `usedForTraining: false` |

This worktree had no `console/.soc/` at all, so the "2,500-event-class store"
contributed **nothing** to this model. That is the honest number, not a gap
papered over: the E1 2,500-incident store is a synthetic fixture built inside
`console/test_console.py`, and this machine holds no real analyst history. The
disposition-join path is proved instead by
`tools/test_train_triage.py::DispositionJoinTests` against a temp store
(3 incidents → 2 labelled rows, 1 undispositioned skipped, and the disposition
proven inert as a feature). After my later live-API probes the local store now
holds 8 rule-derived incidents, **0 of them dispositioned**, and 0 events — so a
retrain today would still contribute 0 real rows.

**Dataset actually trained on: 434 rows.**

| | |
|---|---|
| scenarios | all 6 (`INC-4a7f`, `failure-success`, `error-burst`, `near-miss-auth`, `near-miss-errors`, `benign-maintenance`) |
| formats | `canonical`, `rfc3164` (2 of 4 — the record a finding produces is format-independent by construction, so the other two multiply subprocesses without adding a distinguishable row) |
| variants | 14 |
| logs ingested through the real analyzer | **168** |
| findings seen | **434** |
| rows by origin | `generated: 434`, `incident-disposition: 0` |
| rows by label | `confirmed: 224`, `false-positive: 126`, `benign-expected: 84` |

## Seeds

Base seed **20260902** (`--seed`, default). 14 consecutive variant seeds, all
recorded in the sidecar as `seedsUsed`:

```
20260902 20260903 20260904 20260905 20260906 20260907 20260908
20260909 20260910 20260911 20260912 20260913 20260914 20260915
```

Each generated log's RNG is seeded from `f"{scenario}|{format}|{seed}"`, so a
seed reproduces the same bytes per scenario/format independently. `random_state`
for `StratifiedKFold` and for both the fold models and the final model is the
same base seed. Two from-scratch trains produced the **identical artifact
sha256** `0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765` and
identical fold scores.

## Cross-validation (reported as measured)

`StratifiedKFold(n_splits=5, shuffle=True, random_state=20260902)`;
`compute_sample_weight("balanced")` applied on **every** fit — training folds and
the final model alike.

| fold | rows | accuracy | macro-F1 | balanced macro-F1 |
|---|---|---|---|---|
| 1 | 87 | 0.9425 | 0.9377 | 0.9628 |
| 2 | 87 | 0.9655 | 0.9615 | 0.9778 |
| 3 | 87 | 0.9310 | **0.9121** | 0.8926 |
| 4 | 87 | 1.0 | **1.0** | 1.0 |
| 5 | 86 | 0.9767 | 0.9726 | 0.9848 |

macro-F1 mean **0.9568**, min **0.9121**, max **1.0**; accuracy mean 0.9631.
Fold 3 is the worst fold and is printed exactly as measured — it is not averaged
away. **Scope**: these numbers are over synthetic ground-truth scenarios drawn
from the same attack classes the rules were written for. They are not a claim
about production traffic, and E8 is the card that benchmarks the model against
the rules honestly.

**Known limitation, stated rather than hidden:** the training scenarios cover
auth, error-burst and maintenance shapes only. A Sigma-sourced finding
(`sigma_itsoc_failed_logon`) is out of distribution, and in the live probe below
the model called it `benign-expected` at 0.80 — a visible disagreement on a
class it was never trained for. That is the advisory block doing its job (a
prompt to look), and it is also the strongest argument for E8's measurement.

## Train duration

**13.23 s** from scratch on a clean model directory (an earlier run: 19.23 s).
Budget is 10 minutes; both runs are ~1–2 % of it.

```
$ rm -rf console/.soc/models
$ .venv/bin/python tools/train_triage.py --quiet
Trained in 13.23s.
  rows 434  {'benign-expected': 84, 'confirmed': 224, 'false-positive': 126}
  CV   5 stratified fold(s), macro-F1 mean=0.9568 min=0.9121 max=1.0
```

## Artifact + sidecar schema

`console/.soc/models/` (already covered by the `console/.soc/` line in
`.gitignore` — nothing model-related is committed):

* `triage_v1.pkl` — the pickled `GradientBoostingClassifier`
* `triage_v1.provenance.json` — top-level keys:

| key | value in the shipped run |
|---|---|
| `card` | `"E7a"` |
| `model` / `modelFile` | `sklearn.ensemble.GradientBoostingClassifier` / `triage_v1.pkl` |
| `modelSha256` | `0eb19182b45abbf…837765` — checked on every load |
| `trainedAt` / `startedAt` / `trainDurationSeconds` | `2026-09-02T09:01:47+00:00` / `…09:01:33+00:00` / `13.23` |
| `seed` / `seedsUsed` / `variants` | `20260902` / 14 seeds / `14` |
| `featureKeys` / `featureCount` | the 21 keys, in wire order / `21` |
| `labels` / `labelSource` | the three E0 classes / how each origin was labelled |
| `datasetRows` / `dataset` | `434` / the full counts block (`generated`, `incidentDispositions`, `observedEventStore`, `byLabel`, `byOrigin`) |
| `crossValidation` | strategy, folds, weighting, every fold's scores, mean/min/max |
| `pipeline` | `attack_generator -> log_analyzer.py --rules-only (subprocess) -> triage_model.features()` |
| `sklearnVersion` / `python` | `1.7.2` / `3.13.3` |
| `wall` / `scope` | the advisory-only statement and the scope sentence |

A load is refused — with the reason named — when scikit-learn is missing, the
artifact is missing, the sidecar is missing or unreadable, the recorded sha256
disagrees with the file (corrupt or swapped), the feature schema does not match
this build, or the pickle does not load.

## Mutation probe — the new guards were SEEN to fail

### Probe 1 — leak a forbidden key into `features()`

Added `+ (3.0 if record.get("disposition") == "confirmed" else 0.0)` to
`criticality_rank`, ran the wall (exit **1**):

```
100/101 checks passed

FAILED:
  - no single forbidden key changes one feature, whatever it is set to -- leaked through: ["disposition='confirmed'"]
```

and `python3 -m unittest tools.test_train_triage` also failed:

```
   1.0,
-  5.0]
+  2.0]
 : disposition='confirmed' leaked into the features
FAILED (failures=1, skipped=2)
```

Restored → `101/101 checks passed / Stage E wall intact.`

### Probe 2 — put a model import on the PRIORITY path

Added `import triage_model` to `console/org_context.py` (which owns
`derive_incident_priority`), ran the wall (exit **1**):

```
FAILED:
  - console/org_context.py imports no advisory/model/LLM/precedent module -- offending imports: ['triage_model']
  - console/org_context.py cannot reach a learned-model module at ANY import depth --
    reached: ['sklearn', 'triage_model'] (full closure: ['__future__', 'datetime', 'hashlib',
    'json', 'os', 'pathlib', 'pickle', 're', 'sklearn', 'triage_model'])
```

Note the transitive part: the guard reported `sklearn` too, two hops away.
Restored → `101/101 checks passed`; `git diff` on both files is empty.

## Kill-the-model — live, against the real server

Three real `serve.py` runs over the same rules-only report of a generated
brute-force log.

**A. no scikit-learn (system python3), artifact present on disk**

```
GET /api/triage/model -> {"available": false,
  "reason": "scikit-learn is not installed — the learned second opinion is optional…",
  "sklearn": null, "provenance": null}
finding auth_bruteforce  RULE sev=HIGH ruleSev=HIGH
  aiTriage {modelAvailable:false, status:"unavailable", aiSeverity:null, confidence:null, agrees:null}
incident  severity=HIGH priority=P1 state=new
```

**B. scikit-learn 1.7.2, trained model loaded**

```
GET /api/triage/model -> available=true sklearn=1.7.2
  provenance {trainedAt:…, seed:20260902, datasetRows:434, trainDurationSeconds:19.23, featureCount:21}

auth_bruteforce           RULE sev=HIGH   | MODEL disagrees   aiSeverity=INFO   conf=0.5273 label=false-positive
generic_auth_failure      RULE sev=MEDIUM | MODEL agrees      aiSeverity=MEDIUM conf=0.9998 label=confirmed
sigma_itsoc_failed_logon  RULE sev=HIGH   | MODEL disagrees   aiSeverity=LOW    conf=0.8021 label=benign-expected

INCIDENT severity=HIGH priority=P1   aiTriage {status:"disagrees", aiSeverity:"INFO", confidence:0.9026}
GET /api/copilot/triage -> modelAvailable=true count=3 disagreements=2 unavailable=0
```

The model disagreed with the rules on two of three findings, loudly, and
`sev`, `ruleSev`, incident `severity` and `priority` are **identical to run A**.

**C. KILL THE MODEL — scikit-learn present, artifact moved away**

```
GET /api/triage/model -> available=false
  reason="no trained model at …/triage_v1.pkl — run `python3 tools/train_triage.py` to train one locally."

linesParsed=9 findings=3
auth_bruteforce           RULE sev=HIGH   ruleSev=HIGH   occ=1 lines=3 | MODEL unavailable aiSeverity=None conf=None agrees=None
generic_auth_failure      RULE sev=MEDIUM ruleSev=MEDIUM occ=7 lines=1 | MODEL unavailable aiSeverity=None conf=None agrees=None
sigma_itsoc_failed_logon  RULE sev=HIGH   ruleSev=HIGH   occ=4 lines=4 | MODEL unavailable aiSeverity=None conf=None agrees=None

INCIDENT severity=HIGH priority=P1 ruleIds=['auth_bruteforce'] techniques=['T1110']
POST /api/cases -> case created: case-5 "E7a kill-model probe"
GET  /api/cases -> cases stored: 8
```

Every rule verdict, severity, priority, occurrence count, evidence-line count,
rule id and technique is byte-identical across all three runs; case files create
and list normally; and the UI/API says **model unavailable** with the reason.
(The probe case was removed from the local gitignored store afterwards.)

The same kill is exercised in-suite by
`console/test_console.py::check_sigma_ingest_triage`: no artifact, orphan
artifact with no sidecar, and corrupt artifact (hash mismatch), each refused
rather than scored.

## Rendering

`web/src/pages/Alerts.tsx` exports `AiTriageBlock`, and
`web/src/pages/Incidents.tsx` imports and renders **the same component** — one
contract, two surfaces, no drift. Caption: **AI TRIAGE · LEARNED, ADVISORY**.
`data-status` is `agrees` / `disagrees` / `unavailable`.

* **agrees** — the opinion band, a `%` confidence, the class chip, and the note
  that the rule verdict is unchanged.
* **disagrees** — the block turns to `--warn`, the chip reads "Disagrees with
  the rule verdict", and a line states that this is *a prompt to look, not a
  reason to change the verdict*.
* **unavailable** — "Model unavailable", the reason printed verbatim, and **no**
  severity, confidence or agreement element in the DOM at all (asserted with
  `queryByTestId(...)).not.toBeInTheDocument()`).

CSS lives in `itsoc.css` section 24, token-only, and deliberately never borrows
the severity ramp (`--crit/--high/--med/--low`) — an advisory opinion may never
look like a rule verdict. `web/src/test/c4-themes.test.tsx` asserts that, plus
that every token used is defined in **both** theme blocks and that all three
state classes exist.

**E4:** the E1 Precedents panel keeps its deterministic numeric/labelled overlap
display beside the AI block, unannotated. No model prose was added — the E4
copilot-prose part is interview-gated and not in this card.

## Command results

| command | result |
|---|---|
| `python3 -m unittest tools.test_attack_generator` | **OK**, 5 tests |
| `python3 -m unittest tools.test_train_triage` (no sklearn) | **OK**, 23 tests (2 skipped: the two that need an estimator) |
| `.venv/bin/python -m unittest tools.test_train_triage` (sklearn 1.7.2) | **OK**, 23 tests, 0 skipped |
| `.venv/bin/python tools/train_triage.py` (from scratch) | **Trained in 13.23 s**, 434 rows, macro-F1 mean 0.9568 |
| `python3 tests/test_stage_e_wall.py` | **101/101 checks passed — Stage E wall intact** |
| `python3 console/test_console.py` (no sklearn) | **PASSED** — all suites green |
| `.venv/bin/python console/test_console.py` (model loaded) | **PASSED** — all suites green |
| `cd web && npm test` | **43 files / 278 tests passed** |
| `cd web && npm run build` | **built in 1.36 s** (`dist/assets/index-*.css` 90.46 kB, `index-*.js` 659.41 kB) |
| `python3 tests/eval/run_eval.py` | **20/20 passed, FP=0**, precision 1.000 / recall 1.000 / F1 1.000 |
| `shasum -a 256 anomaly_detector.py` | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — **freeze intact** |

## Deviations and judgement calls

1. **The local 2,500-event-class store contributed 0 rows** — it does not exist
   on this machine. Reported as an honest zero rather than substituted with a
   synthetic stand-in; the disposition-join path is unit-proved against a temp
   store instead.
2. **Two formats, not four**, in the default training set. The record a finding
   produces is format-independent by construction (the parser normalises before
   the rules run), so `rfc5424`/`jsonlog` would multiply 168 subprocess runs
   without adding a distinguishable row. All four remain available via
   `--format`.
3. **`sev`/`ruleSev` are excluded from the features.** The card's forbidden list
   names "severity override"; I read the verdict itself as forbidden too, on the
   grounds that a second opinion able to see the first is not one. Stated here
   because it is a design decision, not a mechanical reading.
4. **`predict_with()` is split out** from `predict()` so the rendering contract
   can be tested with a stub estimator without a trained artifact on disk. The
   stub lives in the test, never in shipped code.
5. **An estimator with no calibrated probability is refused**, not scored — a
   class without a confidence would have to be rendered with a made-up number.
6. **`aiTriage` on an incident is computed on the API projection and never
   stored**, so no model output can survive into `incidents.json` and be re-read
   later as a fact.
7. **Guarded set widened** beyond the card's letter: the wall now guards
   `console/org_context.py` (priority) and `console/actions/*` (execution)
   alongside severity and eligibility, and checks the **transitive** closure.

## Files changed

```
requirements.txt                     (new)
tools/attack_generator.py            seeded variants + 3 scenarios + class/host manifests
tools/test_attack_generator.py       unchanged (still green — fixtures byte-identical)
tools/train_triage.py                (new) the train CLI
tools/test_train_triage.py           (new) 23 unittest cases
console/triage_model.py              (new) shared features() + honest loader/predictor
console/triage.py                    pseudo-AI removed; learned inference
console/enrich.py                    resolves asset criticality for the feature
console/soc.py                       advisory block on the incident projection
console/serve.py                     GET /api/triage/model
console/test_console.py              E7a advisory + kill-the-model + eligibility parity
tests/test_stage_e_wall.py           parts F (import graph) and G (leakage)
web/src/lib/api.ts                   AiTriage type, incident field, triageModel()
web/src/pages/Alerts.tsx             AiTriageBlock (exported)
web/src/pages/Incidents.tsx          incident-ai-triage panel
web/src/styles/itsoc.css             section 24, token-only, both themes
web/src/test/{alerts,incidents,c4-themes}.test.tsx
docs/soc_subsystems.md               section 1c
docs/STAGE_E_REPORTS/E7a-worker.md   (this file)
```

`tools/test_attack_generator.py` and `console/enrich.py` are listed for the
record; no file outside the allowed set was touched, and
`anomaly_detector.py`, rules severity logic, runbook eligibility/execution,
`tests/eval/` and `manifest.json` were not edited.
