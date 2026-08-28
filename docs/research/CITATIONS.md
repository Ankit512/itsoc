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
