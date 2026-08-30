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

## C-2 · Stage D efficacy harness

- **Used in:** `docs/BATTLECARD_TORQ.md`
- **Source type:** In-repo measurement against synthetic ground truth.
- **How to reproduce:** `python3 tools/efficacy_harness.py`
- **Identifier:** `tools/efficacy_harness.py` (`evaluate`), harness landing commit `58a73df`, audited
  tree commit `06a7b989996319bc6d0dd421af61d4399d6cdf75`, run date `2026-08-30T17:22:06+00:00`.
- **The claim, stated precisely:** scenario-level precision / recall / F1 were `1.0 / 1.0 / 1.0`
  for each canonical scenario: `INC-4a7f` (7/7 malicious lines detected), `failure-success`
  (6/6), and `error-burst` (6/6). Across those three scenarios the harness reported 0 missed
  malicious lines and 0 false-positive findings.
- **What it is evidence FOR:** detector behaviour on these generated attack-chain scenarios; it is
  not evidence about production traffic and is not a measurement of the arXiv C-1 benchmark.
- **How it MUST be represented — binding:** always include the exact sentence
  `measured against synthetic ground-truth scenarios; not a claim about production traffic.`
  An all-1.0 / zero-miss result is a **ceiling**. These scenarios are drawn from the same attack classes the rules were written for — the expected result is perfection, and its value is regression proof (any future score below 1.0 is a detected regression), not a general-efficacy claim.
  Never present the result as production efficacy, never merge it with the 19-case `tests/eval`
  score, and never use it as a substitute for C-1. Scenario totals do not assert that every
  individual rule had perfect recall.

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
