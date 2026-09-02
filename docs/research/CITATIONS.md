# External citations — provenance register

**The rule (owner-ruled 2026-08-28):** repo-provable claims get repo evidence; literature claims get
pinned citations; **nothing floats.** Every external number used in a customer- or competitor-facing
document must have an entry here recording the title, identifier, retrieval date, and **the exact
sentence relied on** — so a reader can check whether the document represents the source faithfully.

---

## C-1 · Cyber Defense Benchmark — LLM detection performance

- **Used in:** `docs/BATTLECARD_TORQ.md` (Phase C5)
- **Source type:** External literature. **This is NOT a claim about itsoc** and must never be presented
  as an in-repo measurement. Nothing in this repository computes or contains this figure.
- **Identifier:** arXiv **2604.19533** — Cyber Defense Benchmark
- **Retrieved:** 2026-08-28
- **The claim, stated precisely:** the best frontier LLM flagged **~3.8% of malicious events**, and
  **no model passed 50% per-tactic**.
- **What it is evidence FOR:** the general unreliability of **LLM-owned verdicts** — which is why itsoc's
  architecture keeps rules owning severity, correlation, priority and eligibility, with the LLM advisory
  everywhere and never a control signal.
- **How it MUST be represented — binding:** cite the arXiv id, and state the paper's claim **precisely**.
  Do **not** round it up. Do **not** paraphrase it into "LLMs miss 96%" or any similar inversion — that
  overstates the source and is exactly the failure mode this register exists to prevent. Do not imply
  the benchmark was run here.

---

## C-2 · Synthetic efficacy harness — rules vs. the learned model

- **Used in:** `docs/BATTLECARD_TORQ.md`
- **Source type:** In-repo measurement against synthetic ground truth.
- **How to reproduce:** `python3 tools/efficacy_harness.py` (with a locally trained
  model present; without one the learned column is an honest "unavailable").
- **Identifier:** `tools/efficacy_harness.py` (`evaluate`), benchmark run id
  `efficacy-17286a594e96`, run date `2026-09-02T10:25:18+00:00`, audited tree commit
  `aedd02a76cd06c82152123cb82d3069ffbc4f07e` (tree `90a2c6a7f24508ed9544ef04b45ae5ef88d8bcb3`,
  clean worktree), benchmark seeds `20270302, 20270303, 20270304`.
  Model: `sklearn.ensemble.GradientBoostingClassifier`, sha256
  `0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765`, trained
  `2026-09-02T09:46:51+00:00` on training seeds `20260902`–`20260915`, 434 rows,
  scikit-learn 1.7.2, Python 3.13.3.
- **The claim, stated precisely:** across 18 scenario runs (six scenarios × three
  benchmark seeds, `canonical` format), the RULES system scored precision /
  recall / F1 of `1.0 / 1.0 / 1.0` on each of the three positive scenarios
  (`INC-4a7f` 24/24 malicious lines, `failure-success` 22/22, `error-burst`
  24/24) and raised 21 false-positive findings across the three
  negative scenarios (`near-miss-auth`, `near-miss-errors`,
  `benign-maintenance`), which carry no malicious lines. The LEARNED system,
  scored on the same findings against the same ground truth through the same
  scoring function, matched the rules exactly on every positive scenario and
  suppressed all 21 of those false-positive findings while suppressing none of
  the true positives. Rules: 0 missed malicious lines. Learned: 0 missed
  malicious lines. On a scenario with no malicious lines recall is undefined,
  and for a system with no findings precision is undefined; those cells are
  `n/a`, not `0.0`.
- **What it is evidence FOR:** detector and model behaviour on these generated
  attack-chain scenarios. It is not evidence about production traffic, is not a
  measurement of the arXiv C-1 benchmark, and is not a claim that the model
  improves any verdict — the model is advisory and changes no severity,
  priority, eligibility or action.
- **Freshness — binding:** these numbers may only be published from a run whose
  benchmark seeds are disjoint from the seeds the model's own provenance sidecar
  records, and whose observed entity values (ip, user, host, port, change window)
  are disjoint from the training entities derived from that sidecar. The harness
  enforces both and refuses to run otherwise; a published number without that
  refusal path is not this citation.
- **How it MUST be represented — binding:** always include the exact sentence
  `measured against synthetic ground-truth scenarios; not a claim about production traffic.`
  An all-1.0 / zero-miss result is a **ceiling**. These scenarios are drawn from the same attack classes the rules were written for — the expected result is perfection, and its value is regression proof (any future score below 1.0 is a detected regression), not a general-efficacy claim.
  Always carry the sentence `the learned model is advisory; these numbers are why.`
  beside the scope sentence — it adds to it and never replaces it.
  Never present the result as production efficacy, never merge it with the
  `tests/eval` score, and never use it as a substitute for C-1. Scenario totals do
  not assert that every individual rule had perfect recall. The learned column may
  never be quoted without its model provenance (name, sha256, trainedAt, training
  seeds) and the benchmark seeds, and an unavailable model must be shown as
  unavailable — never as a zero.

---

## C-2a · E8m amendment — finding-level recall, format scope, criticality sensitivity

- **Used in:** `docs/BATTLECARD_TORQ.md` §3.1b
- **Source type:** In-repo measurement against synthetic ground truth. Additive
  amendment to C-2; it supersedes nothing in C-2 and moves no C-2 number.
- **How to reproduce:** the all-format headline is
  `python3 tools/efficacy_harness.py --format canonical --format rfc3164 --format rfc5424 --format jsonlog`
  (with a locally trained model present); the `canonical`-only run of C-2 remains
  `python3 tools/efficacy_harness.py`. Without a model every number here is an
  honest "unavailable" with its reason.
- **Identifier:** `tools/efficacy_harness.py` (`evaluate`, `finding_level_recall`,
  `dropped_true_findings`, `criticality_sensitivity`), benchmark run id
  `efficacy-dc1c67b07dde`, run date `2026-09-02T21:54:36+00:00`, audited tree commit
  `c4ac20d775b35e48a684b4b84baebb2015608b08` (tree `ea43605c28469094759b76fa19d22b2c21d3cc79`, clean worktree), benchmark seeds
  `20270302, 20270303, 20270304`, formats `canonical, rfc3164, rfc5424, jsonlog`.
  Model: `sklearn.ensemble.GradientBoostingClassifier`, sha256
  `0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765`, trained on
  seeds `20260902`–`20260915`, 434 rows, scikit-learn 1.7.2.
- **The claim, stated precisely — three parts:**
  1. **Two recalls, each over a named denominator.** Line-level recall is over
     the manifest's malicious LINES; finding-level recall is over the FINDINGS
     that cite at least one malicious line. Across 72 scenario runs the rules
     score line-level `1.000` and finding-level `1.000` (90/90); the learned
     system scores line-level `1.000` and finding-level **`0.9444` (85/90)**. It
     drops five findings that were citing real malicious lines — all
     `ioc_observed` on the crown-jewel host in `INC-4a7f`, predicted
     `benign-expected` at confidence up to `0.992` — and line-level recall stays
     `1.000` only because kept findings cover the same cited line. On the
     `canonical`-only C-2 run nothing is dropped and finding-level recall is a
     measured `1.000` (21/21) for both systems.
  2. **False-positive totals carry their format scope.** Across all four
     formatters the rules raise **84** false-positive findings and the learned
     system suppresses **all 84**; the `canonical`-only subset is **21**
     (`rfc3164` 24, `rfc5424` 18, `jsonlog` 21). The C-2 figure of 21 is that
     subset and is correct as measured; it is single-format.
  3. **Criticality sensitivity (COUNTERFACTUAL).** `criticality_rank` carries
     `0.4146` of total feature importance, the largest of 21 features. Forcing it
     across `low`/`standard`/`crown-jewel` with every other feature held as
     measured: of 85 true detections, 57 are robust and **28 flip** (kept at
     `low` 85 / `standard` 85 / `crown-jewel` 57); of 84 suppressions, 51 are
     robust and **33 flip** (kept at `low` 33 / `standard` 33 / `crown-jewel` 0).
     Direction: the model is MORE willing to dismiss a finding on a MORE critical
     asset, driven by an org-config value rather than log evidence.
- **What it is evidence FOR:** how the published metrics behave and what they do
  and do not absorb, on these generated scenarios. It is not evidence about
  production traffic and it is not a claim that the model improves any verdict —
  the model remains advisory and writes no severity, priority, eligibility or
  action.
- **How it MUST be represented — binding:**
  - Carry the same C-2 scope, ceiling and advisory sentences verbatim; this entry
    adds to them and replaces none of them.
  - **Never publish a recall without naming its denominator.** Publishing the
    learned system's `1.000` line-level recall without its `0.9444` finding-level
    recall beside it is a misrepresentation of this measurement.
  - **Never publish a false-positive count without its format scope.** The
    all-format total is the headline; a single format is a labelled subset.
  - The criticality figures are **counterfactuals** and must be labelled as such
    every time they appear. The measured numbers stand exactly as measured; the
    counterfactual is never quoted as an observed result.
  - Findings dropped while citing malicious lines must be listed verbatim
    wherever misses are listed. Reporting the count alone is not sufficient.

---

## Entry template (copy for each new external figure)

```
## C-n · <short name>
- Used in: <document>
- Source type: External literature | Vendor documentation | Standard/regulation
- Identifier: <arXiv id / DOI / URL>
- Retrieved: <YYYY-MM-DD>
- The claim, stated precisely: <verbatim or exact-meaning restatement>
- What it is evidence FOR: <the narrow thing it actually supports>
- How it MUST be represented: <constraints — no rounding, no inversion, no in-repo implication>
```
