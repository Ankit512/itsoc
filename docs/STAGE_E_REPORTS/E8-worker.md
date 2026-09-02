# E8 — Frozen referee: the paired rules-vs-learned efficacy benchmark (worker report)

Branch: `feat/e8-frozen-referee`, cut at exactly `e46d974559f8cda1a513fe918f6d580b85633abf`.
Both verified before any edit (`git branch --show-current`, `git rev-parse HEAD`,
clean tree).

## What shipped

`tools/efficacy_harness.py` is now a **frozen referee**. It scores **two named
systems** — the rules, and the trained learned triage model — over **fresh,
seeded, entity-disjoint** generator scenarios, and it owns every choice that
could flatter either of them: the benchmark seeds, the freshness assertion, and
all metric logic. The console and the UI are pure pass-throughs.

The rules run is unchanged in kind: it is still the real
`log_analyzer.py --rules-only` subprocess. The frozen detector is never
imported; the subprocess is still the only seam.

## The two systems, and what "the model found something" means

Both systems go through the **same** `score()` and the **same** `diff()`. There
is exactly one implementation of the metric arithmetic in the file, and a test
asserts that by counting it (`def score(` ×1, `def _ratio(` ×1, `def diff(` ×1,
`2 * precision * recall` ×1). The learned system is not a second metric — it is
a **different finding collection handed to the identical scorer**:

* **RULES findings** — every finding the analyzer produced.
* **LEARNED findings** — that same collection after the model has given its
  opinion on each one. A **`confirmed`** prediction is a **model-positive**
  finding and is kept. A **`false-positive`** or **`benign-expected`** prediction
  is **model-negative** and is dropped.

So dropping a finding that cited real malicious lines costs the learned system
recall and puts those lines, verbatim, in its own miss list; dropping a finding
that cited none earns it precision. This interpretation is not folklore — it is
carried in the artefact as `interpretation`, printed by `render()`, and shown on
Reports.

Inference uses the **shipped contract only**: the record projection is
`tools/train_triage.py:record_from_report_finding` (the exact function training
used) and the prediction is `console/triage_model.py:predict_with`. Neither is
re-implemented in the harness.

## Freshness: seeds, and then the part seeds cannot fix

**Benchmark seeds are frozen in the referee:**

```python
BENCHMARK_SEEDS = (20270302, 20270303, 20270304)
E7A_TRAINING_SEEDS = tuple(range(20260902, 20260916))   # 20260902 .. 20260915
```

They are wholly disjoint from the E7a training sidecar's window. The binding
check never trusts that constant: `assert_fresh()` reads the seeds the model's
**actual** provenance sidecar recorded and fails hard on any overlap.

**Seed choice alone is not enough, and pretending otherwise would have been the
easy lie.** `attack_generator` pins each scenario to a fixed host
(`server-01`, `server-02`, `api-01`), draws usernames from fixed four-value
vocabularies, and hard-codes some ports (`51000+offset`, `51100`). Fourteen
training seeds exhaust all of them — and `triage_model.features()` counts
`entity_host_count`, `entity_user_count` and `entity_port_count`. A
"fresh-seed" benchmark would therefore have re-shown the model entities it
trained on, in features it actually reads.

So the referee applies a **benchmark-only, deterministic token remap** to the
generated logs **and to the manifest ground truth**, before the analyzer
subprocess ever runs:

| kind | source | benchmark space |
|---|---|---|
| host | `server-01`, `api-01`, … | `bnch-server-01`, `bnch-api-01`, … |
| user | `admin`, `carol`, … | `bnch-admin`, `bnch-carol`, … |
| ip (public) | `203.0.113.x`, `198.51.100.x` | `198.18.0.0/15` (RFC 2544 benchmarking) |
| ip (private) | `10.10.x.y` | `172.31.0.0/16` (RFC 1918, unused by the generator) |
| port | `40000–60000`, `51xxx` | `33000–33999` |
| change window | `CHG-1000…1999` | `CHG-7000…7998` |

Every replacement is a pure function of the source token (sha256, with linear
probing), so the same seed produces the same bytes forever, and any candidate
landing on a value derived from the training sidecar is refused.

Four properties make this safe rather than convenient, and each is tested:

1. **Ground truth cannot drift.** The log is rewritten line by line, then each
   manifest `raw` is re-read *out of the rewritten log at the line number the
   manifest itself records*. Alignment is by construction, not by a parallel
   substitution. Asserted for every malicious line of every scenario.
2. **The rules behave identically.** Rule ids, severities, occurrence counts and
   timeline lengths are byte-identical pre- and post-remap for all six scenarios
   (`test_the_remap_does_not_change_what_the_rules_do`, and independently
   verified across all 18 scenario/seed pairs of the acceptance run: **0
   differences**). Freshness did not buy itself a different detector.
3. **Criticality is preserved, not quietly dropped.** `org_context` looks
   criticality up by exact host name, so a remapped host would have fallen back
   to `standard` and silently moved the feature vector. `benchmark_org_context()`
   copies each tagged asset's own entry onto its benchmark name into a file in
   the isolated workdir and loads it through the shipped
   `load_org_context(path)` seam — `bnch-server-01` is `crown-jewel` because
   `server-01` is. `console/org_context.json` is untouched.
4. **Nothing upstream changed.** No edit to `tools/attack_generator.py`,
   `tools/train_triage.py`, `console/triage_model.py`, any detector, rule, eval
   fixture, manifest, or `requirements.txt`.

### Deriving the training entity inventory

The E7a sidecar records the training **seeds, scenarios and formats** but **no
entity inventory**, so there is no recorded list to compare against. As the card
allows, the referee derives one from the sidecar's own generator provenance,
without touching training code. The exact method, also carried verbatim in the
artefact as `freshness.entityDerivation`:

> For every `(scenario, format, seed)` triple in
> `provenance["dataset"]["generated"]` (`scenarios` × `formats` × `seedsUsed`),
> call `tools/attack_generator.py:generate()` into an isolated temp directory and
> extract entity values from the generated log text and manifest with
> `efficacy_harness.log_entities()`. `generate()` is a pure function of
> `(scenario, format, seed)`, so these are bit-for-bit the logs training
> ingested; the values are observed, never guessed.

The assertion is then **every entity kind `features()` can count**, with zero
tolerance, and **cross-kind**: a benchmark *host* that equalled a training
*username* is still a leak and is caught.

```
ASSERTED_ENTITY_KINDS = ("ip", "user", "host", "port", "change_window")
```

## Isolation: scoring the model cannot move a rule number

* Each system gets a **deep-independent** finding collection
  (`copy.deepcopy`), and the rules system is scored from its own copy.
* `score_manifests(pairs, model)` is the seam: the same ingested
  `(manifest, report)` pairs can be scored with a model and then with the model
  killed. Serialised rule-system numbers and miss lists must be **byte-identical**
  both times — asserted twice, once with a stub model and once with a real
  `LearnedSystem.load()` failure against an empty model dir.
* The ingested reports and manifests are asserted unmutated after scoring.

## Honest unavailable

Missing scikit-learn, missing artifact, missing or mismatched provenance: the
shipped `triage_model.load_model()` raises its own named reason, and the
benchmark publishes **no learned number at all** — `totals: null`, `misses:
null`, `learned_total_misses: null`, plus the reason. Never zeros, never a
fabricated score. The rules half stays fully measured.

Separately, a scenario with **no malicious lines** has no recall to measure, and
a system with **no findings** has no precision to measure. The frozen scorer
still returns `0.0` there (0/0), so every result now also carries
`precision_defined` / `recall_defined` and every surface renders **`n/a`** —
a `0.0` that reads like a failure is not published as one.

## Acceptance run (recorded)

Clean temporary venv, `requirements.txt` installed, fresh model trained outside
tracked files, benchmark executed at a clean tree.

* venv: `python3 -m venv` + `pip install -r requirements.txt` →
  scikit-learn **1.7.2**, numpy 2.5.2, scipy 1.18.1, joblib 1.6.0, on Python
  **3.13.3**.
* training: `tools/train_triage.py` (defaults) → **434 rows**
  (`confirmed` 224 / `false-positive` 126 / `benign-expected` 84), 5 stratified
  folds, macro-F1 mean **0.9568** (min 0.9121, max 1.0), **48.68 s**.
* model artifact (gitignored, `console/.soc/models/triage_v1.pkl`):
  sha256 **`0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765`**,
  trainedAt **`2026-09-02T09:46:51+00:00`**, training seeds **20260902–20260915**,
  21 features.
* benchmark: `python3 tools/efficacy_harness.py`
  * run id **`efficacy-17286a594e96`**, run date **`2026-09-02T10:25:18+00:00`**
  * commit **`aedd02a76cd06c82152123cb82d3069ffbc4f07e`**, tree
    **`90a2c6a7f24508ed9544ef04b45ae5ef88d8bcb3`**, worktree clean
  * benchmark seeds **20270302, 20270303, 20270304**; format `canonical`;
    all six scenarios; **18 scenario runs**
  * runtime **2.47 s real** (1.73 s user, 0.43 s sys)

**Benchmark entities, post-remap** (asserted disjoint from the derived training
inventory on every kind — overlap `{ip: [], user: [], host: [], port: [],
change_window: []}`):

* host — `bnch-api-01`, `bnch-server-01`, `bnch-server-02`
* user — `bnch-admin`, `bnch-carol`, `bnch-dave`, `bnch-dbadmin`,
  `bnch-deploy`, `bnch-operator`
* ip — `172.31.172.90`, `172.31.219.103`, `172.31.223.176`, `198.18.21.22`,
  `198.18.36.96`, `198.18.39.251`, `198.18.104.204`, `198.18.144.24`,
  `198.18.155.47`
* change window — `CHG-7475`, `CHG-7613`, `CHG-7742`
* port — 49 distinct values in `33064`–`33974`

### Scores

`n/a` = the ratio has no denominator (no malicious lines, or no findings).

| scenario | seed | ground truth | Rule P | Rule R | Rule F1 | Rule FP | Learned P | Learned R | Learned F1 | Learned FP |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `INC-4a7f` | 20270302 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `failure-success` | 20270302 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `error-burst` | 20270302 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `near-miss-auth` | 20270302 | false-positive | 0.0 | n/a | n/a | 1 | n/a | n/a | n/a | 0 |
| `near-miss-errors` | 20270302 | false-positive | 0.0 | n/a | n/a | 3 | n/a | n/a | n/a | 0 |
| `benign-maintenance` | 20270302 | benign-expected | 0.0 | n/a | n/a | 3 | n/a | n/a | n/a | 0 |
| `INC-4a7f` | 20270303 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `failure-success` | 20270303 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `error-burst` | 20270303 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `near-miss-auth` | 20270303 | false-positive | 0.0 | n/a | n/a | 1 | n/a | n/a | n/a | 0 |
| `near-miss-errors` | 20270303 | false-positive | 0.0 | n/a | n/a | 3 | n/a | n/a | n/a | 0 |
| `benign-maintenance` | 20270303 | benign-expected | 0.0 | n/a | n/a | 3 | n/a | n/a | n/a | 0 |
| `INC-4a7f` | 20270304 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `failure-success` | 20270304 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `error-burst` | 20270304 | confirmed | 1.0 | 1.0 | 1.0 | 0 | 1.0 | 1.0 | 1.0 | 0 |
| `near-miss-auth` | 20270304 | false-positive | 0.0 | n/a | n/a | 1 | n/a | n/a | n/a | 0 |
| `near-miss-errors` | 20270304 | false-positive | 0.0 | n/a | n/a | 3 | n/a | n/a | n/a | 0 |
| `benign-maintenance` | 20270304 | benign-expected | 0.0 | n/a | n/a | 3 | n/a | n/a | n/a | 0 |

**Rollup.** Rules: **0 missed malicious lines**, **21 false-positive findings**.
Learned: **0 missed malicious lines**, **0 false-positive findings**.

### Misses, verbatim

**Rule misses: none.** Across all 18 runs the rules detected every
manifest-labelled malicious line — 24/24 (`INC-4a7f`), 22/22
(`failure-success`), 24/24 (`error-burst`).

**Model misses: none.** The model kept every finding that cited a malicious
line, so the learned system's miss list is empty in all 18 runs.

Both empty miss lists are reported as empty, not as an absence of the section.
The machinery that would print them is exercised by
`PairedDifferenceTests.test_a_model_that_rejects_everything_differs_from_the_rules`,
which asserts the verbatim `raw` and `why` of every model miss.

### What the difference actually is

The two systems are identical on the three positive scenarios and differ
entirely on the three negative ones: the rules raise **21 false-positive
findings** across the near-miss and benign-maintenance scenarios, and the model
suppresses **all 21** while suppressing **none** of the true positives. That is
the whole claim, and it is why the learned model is worth rendering — as an
advisory second opinion, next to a rule verdict it never changes.

## Failure exercises (observed, then restored)

1. **Seed overlap.** `python3 tools/efficacy_harness.py --scenario INC-4a7f
   --seed 20260902` (a seed the sidecar records as a *training* seed) →
   **exit 2**:

   > `BENCHMARK REFUSED: benchmark seeds [20260902] were also TRAINING seeds
   > (sidecar recorded [20260902, …, 20260915]) — the benchmark would be scoring
   > the model on its own training data. Refusing to run.`

   Control at the frozen seed `20270302`: exit 0, entity overlap empty on every
   kind, rules and learned both 1.0/1.0/1.0.

2. **Rule invariance.** Mutated `score_pair()` so the learned pass could reach
   the rules scoring path (`_rules_input = learned_findings(...)[0]`) →
   `RuleInvarianceTests` **2 failures**:
   `test_rule_numbers_are_byte_identical_with_and_without_a_model` (serialised
   rules blocks differ) and
   `test_the_learned_pass_cannot_write_into_the_rules_findings`
   (`AssertionError: 0.0 != 1.0` — rule recall moved). Source restored; 3/3 pass.

## Test and gate results

| gate | result |
|---|---|
| `tools/test_efficacy_harness.py` (venv, with sklearn) | **37 passed** |
| `tools/test_efficacy_harness.py` (stdlib-only `python3`) | **37 passed** |
| `console/test_console.py` — efficacy API section | all `[PASS]` |
| `console/test_console.py` — full suite | **0 `[FAIL]`**, exit 0, "checks green" |
| `web` focused `efficacy-surface.test.tsx` | **13 passed** |
| `web` full `npm test` | **43 files, 282 tests passed** |
| `web` `npm run build` (`tsc --noEmit && vite build`) | ✅ built |
| `tests/test_stage_e_wall.py` | **101/101 checks passed — wall intact** |
| `tests/eval/run_eval.py` | **20/20 cases, precision 1.000, recall 1.000, F1 1.000, FP 0** |
| detector sha256 | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — **unchanged** |
| `git diff --check` | clean (exit 0) |
| allowlist audit | see below |

### Allowlist audit

Files changed on this branch, all within the card's allowlist:

```
console/efficacy_api.py
console/test_console.py
docs/BATTLECARD_TORQ.md
docs/STAGE_E_REPORTS/E8-worker.md
docs/research/CITATIONS.md
tools/efficacy_harness.py
tools/test_efficacy_harness.py
web/src/lib/api.ts
web/src/pages/Reports.tsx
web/src/test/efficacy-surface.test.tsx
```

Nothing else: no `anomaly_detector.py`, no detector/rule/eval fixture or
manifest, no training or triage-model code, no action/priority/eligibility code,
no `requirements.txt`. No pytest was used (`unittest` and the repo's own
check scripts only). No push, no merge.

### Pre-existing failure fixed in passing

At base `e46d974`, `EndToEndTests.test_all_scenarios_run_through_the_real_pipeline`
already failed (`AssertionError: 0.0 != 1.0`): E7a added three zero-malicious
scenarios whose recall is undefined, and the test asserted `recall == 1.0` for
every scenario. It now asserts a clean sweep where recall is *defined* and
`malicious_lines == 0` where it is not.

## Frozen file paths and hashes

The referee owns all benchmark seed selection and metric logic. A later E7b
grader can detect any modification by re-hashing these files at this commit
(`aedd02a76cd06c82152123cb82d3069ffbc4f07e`):

| path | sha256 |
|---|---|
| `tools/efficacy_harness.py` | `1908315e1cceb0f8aca6a9e1fb0f2b450a923777defb058cf2758958a7918d25` |
| `tools/test_efficacy_harness.py` | `0d46db7b114a60d3e29168879644b2210527a5c5dde3b7394b7b8a13c9b462eb` |
| `console/efficacy_api.py` | `26284365eb2ee6b5e39e0b814e21f2d24417a181e5a34f2d4747d83af0966435` |

Verify with:

```
shasum -a 256 tools/efficacy_harness.py tools/test_efficacy_harness.py console/efficacy_api.py
```

What is frozen inside them, and enforced by test:

* `BENCHMARK_SEEDS` and `E7A_TRAINING_SEEDS` — the only place a benchmark seed
  is named. `console/efficacy_api.py` and `web/src/pages/Reports.tsx` are
  asserted to contain no seed literal and no `seeds=` argument.
* `score()`, `_ratio()`, `diff()` — one implementation each; the F1 arithmetic
  appears exactly once in the file.
* `ASSERTED_ENTITY_KINDS`, the remap constants, `MODEL_POSITIVE_LABELS` /
  `MODEL_NEGATIVE_LABELS`, `SCOPE_SENTENCE`, `CEILING_SENTENCE`,
  `ADVISORY_SENTENCE`.

## Publishing

* **Reports** shows paired per-scenario Rule and Learned precision/recall/F1
  with the seed, both miss lists verbatim and labelled by system, the run id,
  commit, benchmark seeds and full model provenance (name, sha256, trainedAt,
  training seeds), and the honest unavailable state — a per-row
  "learned model unavailable — no score is shown" and `n/a` totals, never a zero.
* The standing scope sentence is **unchanged and still present**:
  *measured against synthetic ground-truth scenarios; not a claim about
  production traffic.*
  The ceiling sentence is preserved. Added beside them, exactly:
  *the learned model is advisory; these numbers are why.*
* `docs/BATTLECARD_TORQ.md` §3.1a and `docs/research/CITATIONS.md` C-2 are
  updated from this real run — no value is invented — and both continue to state
  that these numbers are separate from the `tests/eval` score and must
  not be merged with it.
