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
