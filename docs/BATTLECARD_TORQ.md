# Competitive Battlecard: itsoc vs. Torq (SOAR / Hyperautomation)

**Audited Commit:** `06a7b989996319bc6d0dd421af61d4399d6cdf75` (Stage D audited tree; harness landed at `58a73df`)
**Document Purpose:** Grounded technical comparison for security architects and engineering leadership.  
**Provenance & Fact-Checking Standard:** Every quantitative claim is backed by reproducible in-repo code/tests or pinned literature citations in `docs/research/CITATIONS.md`. All unbacked claims have been strictly cut.

---

## 1. Executive Summary & Core Positioning

Security operations teams evaluate automation on two fundamental axes: **ecosystem breadth** (how many third-party SaaS tools can be connected) and **verdict trust & sovereignty** (can automation be trusted without prompt drift, cloud data leakage, or unverified LLM actions).

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                         THE ARCHITECTURAL SPLIT                        │
   ├────────────────────────────────────┬───────────────────────────────────┤
   │       Torq Hyperautomation         │     itsoc (Sovereign Security)    │
   ├────────────────────────────────────┼───────────────────────────────────┤
   │ • Cloud SaaS orchestrator          │ • Local-compute sovereign engine  │
   │ • Broad multi-vendor visual flows  │ • Rules own all verdicts & gating │
   │ • LLMs inside orchestration steps  │ • LLMs strictly advisory & cited  │
   │ • Cloud-hosted event routing       │ • Local store & DORA hash-ledger  │
   └────────────────────────────────────┴───────────────────────────────────┘
```

### Where itsoc Concedes to Torq
- **Orchestration Breadth:** Torq provides hundreds of pre-built cloud integrations, complex graphical visual workflow builders, and expansive SaaS-to-SaaS automation capabilities across enterprise IT/HR/DevOps suites.
- **itsoc is NOT a generic hyperautomation broker.** itsoc is purpose-built for high-integrity log analysis, sovereign threat investigation, and cryptographically verified, step-up gated containment.

### Where itsoc Wins Decisively
1. **Verdict Trust & Rule Determinism:** In itsoc, rules strictly own detection verdicts, severity, entity correlation, priority calculation, and runbook eligibility. Models never author verdicts, escalate severity, or trigger actions autonomously.
2. **Data Sovereignty & Local Boundary:** Log ingestion, investigation assembly, and response coordination execute within the customer's environment (local SQLite, stdlib parsers, local rule engine). Raw log streams are never egressed to third-party cloud LLMs.
3. **Provable Step-Up Authorization:** Destructive actions cannot be dispatched by autonomous model inference. Every action requires human approval with step-up passphrase verification and produces a SHA-256 hash-chained audit ledger.
4. **Epistemic Honesty by Design:** Empty logs report empty (never a false all-clear), unrecognized formats report unrecognized, and absent data renders `n/a` instead of synthetic metrics.

---

## 2. Feature & Architectural Comparison Matrix

| Capability / Architecture | Torq Hyperautomation | itsoc Sovereign SOC | itsoc Technical Provenance |
| :--- | :--- | :--- | :--- |
| **Primary Deployment** | Multi-tenant or dedicated Cloud SaaS | Self-hosted local/on-premise (Docker/VM) | Local SQLite (`console/store.py`: `DB_PATH`, `_SCHEMA`), zero cloud runtime dependency. |
| **Detection & Severity Ownership** | Vendor workflows / AI agent evaluations | Deterministic rule engine (frozen detector) | `anomaly_detector.py` (SHA-256 `364577c5...`), `console/org_context.py` (`PRIORITY_MATRIX`, `calculate_priority`). |
| **Role of Generative AI / LLMs** | Workflow step execution, intent routing, dynamic agent actions | Strictly parallel **advisory** layer; zero control or verdict authority | `console/investigate.py` (`ADVISORY_LABEL`, `dispatch_advisory`), `explanation_guard.py` (`UNVERIFIED_NOTE`). |
| **Fact Grounding & Hallucination Defense** | Prompt engineering & model fine-tuning | Hard citation verification: every claim must cite record `{n}` or get stripped | `explanation_guard.py` (`_sentence_guard`, `_check_grounding`), `console/test_console.py`. |
| **Data Egress Boundary** | Telemetry and events route through cloud infrastructure | Sovereign local boundary by default; raw logs never leave the host | `console/redact.py` (`Redactor.mask`, `redact_case`). |
| **Threat Intel Egress Transparency** | Managed cloud integrations | **Explicitly disclosed:** TI lookups transmit only queried indicators over HTTPS | `web/src/pages/OemEngine.tsx` (`EGRESS_DISCLOSURE`), `console/ti_oem.py` (`enrich_ip`, `poll_connector`). |
| **Containment Action Gating** | Webhook / API trigger, policy-based approvals | Cryptographic step-up authorization with passphrase verification | `console/auth.py` (`BaseAuthProvider.verify_stepup_passphrase`, `LocalDemoAuthProvider`), `console/actions/base.py` (`BaseConnector`). |
| **Audit Trail & Accountability** | Cloud platform execution logs | Tamper-evident, append-only SHA-256 hash-chain ledger (`chain.jsonl`) | `console/audit.py` (`FIELDS`, `append`, `verify_chain`, `GENESIS`). |
| **Honesty Under Missing Data** | Varies by workflow configuration | Hardcoded honesty: unrecognized formats, empty inputs, and null KPIs report `n/a` | `web/src/components/OpsMetrics.tsx` (`fmtDuration`, `OpsMetrics`), `tests/test_intake.py` (`test_unrecognized_format_is_honest`, `test_empty_input_is_honest`). |

---

## 3. Quantitative Claim Fact-Checking & Citation Register

In accordance with repo standards, every numerical figure is verified against in-repo measurements or external literature registered in `docs/research/CITATIONS.md`.

### 3.1 Pinned External Literature Citation (Binding)

> **Citation C-1 (arXiv 2604.19533 — Cyber Defense Benchmark):**  
> *"The best frontier LLM flagged **~3.8% of malicious events**, and **no model passed 50% per-tactic**."*  
> *(Source: `docs/research/CITATIONS.md:10-26`, retrieved 2026-08-28).*
> 
> **Binding Representation Constraints:**
> - This is an **external literature citation**, NOT an in-repo measurement of itsoc.
> - The figure is **never rounded**.
> - The figure is **never inverted into "LLMs miss 96%"** (that represents an unsupported claim).
> - **Evidence Context:** This benchmark substantiates why itsoc forbids LLMs from owning verdicts, severity, or triage decisions, keeping all core security logic deterministic.

---

### 3.1a Synthetic Efficacy Harness — rules and the learned model, scored side by side

**Scope:** measured against synthetic ground-truth scenarios; not a claim about production traffic.

These scenarios are drawn from the same attack classes the rules were written for — the expected result is perfection, and its value is regression proof (any future score below 1.0 is a detected regression), not a general-efficacy claim.

the learned model is advisory; these numbers are why.

Since E8 the harness scores **two explicit systems** over the same fresh scenarios, through the same scoring function and the same ground-truth diff: the **rules** (`log_analyzer.py --rules-only`, subprocess) and the **learned** second-opinion triage model. A `confirmed` model prediction keeps a finding (model-positive); a `false-positive` or `benign-expected` prediction drops it (model-negative). The model never touches a severity, a priority, an eligibility decision or an action — dropping a finding here changes only *this benchmark's* learned column.

The benchmark is proven fresh, not assumed fresh. Seeds are frozen in the harness and disjoint from the training sidecar's recorded seeds; a benchmark-only deterministic token remap makes every observed host, user, IP, port and change-window value disjoint from the training entities derived from that same sidecar, and the run refuses to proceed on any overlap. The remap is verified not to change what the rules do.

Scenario-level totals, all three benchmark seeds. `n/a` = the ratio has no denominator: a scenario with no malicious lines has no recall, and a system with no findings has no precision.

| Scenario | Ground truth | Rule P / R / F1 | Rule FPs | Learned P / R / F1 | Learned FPs | Malicious lines |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| `INC-4a7f` | confirmed | 1.0 / 1.0 / 1.0 | 0 | 1.0 / 1.0 / 1.0 | 0 | 24 / 24 |
| `failure-success` | confirmed | 1.0 / 1.0 / 1.0 | 0 | 1.0 / 1.0 / 1.0 | 0 | 22 / 22 |
| `error-burst` | confirmed | 1.0 / 1.0 / 1.0 | 0 | 1.0 / 1.0 / 1.0 | 0 | 24 / 24 |
| `near-miss-auth` | false-positive | 0.0 / n/a / n/a | 3 | n/a / n/a / n/a | 0 | 0 / 0 |
| `near-miss-errors` | false-positive | 0.0 / n/a / n/a | 9 | n/a / n/a / n/a | 0 | 0 / 0 |
| `benign-maintenance` | benign-expected | 0.0 / n/a / n/a | 9 | n/a / n/a / n/a | 0 | 0 / 0 |

**Rollup across 18 scenario runs (6 scenarios × 3 seeds):** rules — **0 missed malicious lines, 21 false-positive findings**; learned — **0 missed malicious lines, 0 false-positive findings**. The two systems are identical on every positive scenario; the model suppressed all 21 rule false positives on the near-miss and benign-maintenance scenarios and suppressed none of the true positives. **Rule misses: none. Model misses: none.**

Run id: `efficacy-17286a594e96`; run date: `2026-09-02T10:25:18+00:00`; audited commit `aedd02a76cd06c82152123cb82d3069ffbc4f07e` (tree `90a2c6a7f24508ed9544ef04b45ae5ef88d8bcb3`, clean); benchmark seeds `20270302, 20270303, 20270304`; pipeline `log_analyzer.py --rules-only (subprocess)`. Model: `sklearn.ensemble.GradientBoostingClassifier`, sha256 `0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765`, trained `2026-09-02T09:46:51+00:00` on seeds `20260902–20260915`, 434 rows, scikit-learn 1.7.2. Reproduce with `python3 tools/efficacy_harness.py`; provenance and representation constraints are registered as C-2 in `docs/research/CITATIONS.md`. Where scikit-learn or the model artifact is absent, the learned column is an honest "unavailable" with its reason — never a zero.

This harness measurement is separate from the **Evaluation Detection Score** below, which remains the result of `tests/eval/run_eval.py` over its canned cases; the two F1 measurements must not be collapsed.

> **Scope label (E8m).** The 21 false positives above are the **`canonical`-format** total for those 18 runs. Read §3.1b for the all-format headline. No false-positive count in this document appears without its format scope.

---

### 3.1b E8m amendment — what the E8 metrics did not say out loud

**Scope:** measured against synthetic ground-truth scenarios; not a claim about production traffic.

An owner-authorised, **additive** amendment. It moved no benchmark seed, no remap, no freshness assertion and no metric: every number in §3.1a is unchanged and was re-measured byte-identical before and after. What follows is published *beside* those numbers because it was always true of them and was never printed.

#### (a) Finding-level recall, published beside line-level recall

Recall has always had two denominators and only one was published:

* **Line-level recall** is over the manifest's **malicious lines** — how much labelled ground truth the system reached.
* **Finding-level recall** is over the **findings that cite at least one malicious line** — how many of those findings the system still carries.

They diverge whenever a system drops a finding whose cited malicious lines a *kept* finding also covers: the line stays detected, the finding is gone, and line-level recall absorbs the loss silently.

Measured on the frozen seeds across **all four formatters** (72 scenario runs):

| System | Line-level recall (over malicious lines) | Finding-level recall (over findings citing a malicious line) |
| :--- | ---: | ---: |
| rules | **1.000** | **1.000** (90 / 90) |
| learned | **1.000** | **0.9444** (85 / 90) |

The learned system's line-level recall is a true 1.000 and its finding-level recall is **not**. It drops **5** findings that were citing real malicious lines — every one an **`ioc_observed`** finding on the **crown-jewel** host in the flagship `INC-4a7f` scenario, predicted `benign-expected` at confidence up to **0.992**. Line-level recall stays 1.000 only because all five cite malicious line 2, which kept findings also cover.

| Scenario | Format | Seed | Rule | Advisory label | Confidence | Cited malicious line |
| :--- | :--- | ---: | :--- | :--- | ---: | ---: |
| `INC-4a7f` | `rfc3164` | 20270302 | `ioc_observed` | benign-expected | 0.992 | 2 |
| `INC-4a7f` | `rfc5424` | 20270302 | `ioc_observed` | benign-expected | 0.9318 | 2 |
| `INC-4a7f` | `rfc5424` | 20270303 | `ioc_observed` | benign-expected | 0.9318 | 2 |
| `INC-4a7f` | `rfc3164` | 20270304 | `ioc_observed` | benign-expected | 0.7262 | 2 |
| `INC-4a7f` | `rfc5424` | 20270304 | `ioc_observed` | benign-expected | 0.7262 | 2 |

Every finding a system drops while it cites a malicious line is now listed **verbatim** — in the JSON (`dropped_true_findings`), in the harness's own output, and on the Reports surface — with exactly the weight a missed line already had. This class of absorption is never invisible again. On the `canonical`-only run of §3.1a nothing is dropped, and finding-level recall there is a measured **1.000 (21 / 21)** for both systems.

*The advisory is still advisory.* A dropped opinion removes no rule finding and changes no verdict, severity or priority. What it changes is what a metric reports, which is why it is published.

#### (b) False-positive totals, always labelled with their format scope

| Format scope | Rule false-positive findings | Learned false-positive findings |
| :--- | ---: | ---: |
| **all four formatters (headline, 72 runs)** | **84** | **0** |
| subset — `canonical` only (18 runs) | 21 | 0 |
| subset — `rfc3164` only | 24 | 0 |
| subset — `rfc5424` only | 18 | 0 |
| subset — `jsonlog` only | 21 | 0 |

The suppression claim is **stronger** than the one E8 published, not weaker: the model suppressed all **84**, not 21. The published 21 was simply single-format and was not labelled as such. A bare false-positive count with no format scope is not a publishable number in this repository.

#### (c) The criticality sensitivity — a named finding, not a footnote

`criticality_rank` — the asset-criticality band resolved from the **org config by host name** — carries **0.4146 (41.5%)** of the model's total feature importance, the largest of its 21 features by a wide margin. Forcing it across its whole real domain (`low` 0, `standard` 1, `crown-jewel` 2) while holding every other feature exactly as measured:

| Population (all four formatters) | Total | Robust across all three bands | Flips in at least one | Kept at `low` / `standard` / `crown-jewel` |
| :--- | ---: | ---: | ---: | ---: |
| true detections (kept, citing malicious lines) | 85 | 57 | **28** | 85 / 85 / **57** |
| suppressions (dropped, citing nothing) | 84 | 51 | **33** | 33 / 33 / **0** |

**Direction, stated plainly: the model is *more* willing to dismiss a finding on a *more* critical asset.**

* Raising a host from `standard` to `crown-jewel` flips **28 of 85** true detections from KEPT to DROPPED.
* Lowering `crown-jewel` to `standard` or `low` flips **33 of 84** suppressions from DROPPED to KEPT — including all five dropped `INC-4a7f` IOC findings.

That is the opposite of operational intuition, and it is driven by an **org-config value rather than by log evidence**.

**These are counterfactuals.** The benchmark hosts have fixed criticality, so **every published number above stands exactly as measured** — nothing in §3.1a or §3.1b is a projection. The point is that a headline of "0 false positives, 0 line misses" rests substantially on one configuration value, and a buyer is entitled to know which.

The counterfactual is computed **live on every run** (the harness re-scores each finding through the shipped model with the criticality feature forced) and is published marked `kind: "counterfactual"`, never as a measurement.

Reproduce the all-format headline with:

```
python3 tools/efficacy_harness.py --format canonical --format rfc3164 --format rfc5424 --format jsonlog
```

Run id: `efficacy-7588b98a963f`; run date: `2026-09-02T21:52:16+00:00`; audited commit `3960f32197aae12348194f50fdb39e57e7597c94` (tree `7480eb11f42a55bc6d6f09c0234ee8dc4d0e4dae`, clean); benchmark seeds `20270302, 20270303, 20270304`; formats `canonical, rfc3164, rfc5424, jsonlog`. Model: `sklearn.ensemble.GradientBoostingClassifier`, sha256 `0eb19182b45abbf434daa196b3d30dbb3de99c83e15694254af5440103837765` — bit-identical to the model behind §3.1a, so every number here is directly comparable to it. Registered as C-2a in `docs/research/CITATIONS.md`.

Rules still own severity and correlation; the model never writes one. Where scikit-learn or the model artifact is absent, every number in this section is an honest "unavailable" with its reason — never a zero.

---

### 3.2 In-Repo Verified Benchmarks & Guarantees

| Metric / Guarantee | Measured Value | Repository Evidence | Technical Description |
| :--- | :--- | :--- | :--- |
| **Evaluation Detection Score** | $F_1 = 1.000$<br>(Precision 1.000, Recall 1.000) | `tests/eval/run_eval.py` (`evaluate_case`, `score_predictions`) | Measured on the 19 standard deterministic test cases (SSH brute-force, web attacks, port scans, disk alerts). |
| **Deterministic Assembly Speed** | $< 5\text{ ms}$<br>(Target $< 120\text{ s}$) | `console/investigate.py` (`assemble`)<br>`console/test_console.py` | Assembles timeline, IOCs, affected entities, and blast radius from SQLite store without waiting on LLMs. |
| **Advisory Grounding Rate** | $1.000$ ($100\%$ on test scenario)<br>(Target $\ge 0.95$) | `console/investigate.py` (`_run_advisory_agent`)<br>`explanation_guard.py`<br>`console/test_console.py` | Measured on canonical `INC-4a7f` scenario via `explanation_guard.py` verifying every sentence against source `{n}` lines. |
| **Advisory Worker Timeout** | Exactly $45\text{ s}$ | `console/investigate.py` (`ADVISORY_TIMEOUT`)<br>`console/test_console.py` | Per-agent thread pool timeout ensuring advisory queries fail openly without hanging UI. |
| **Rule Severity Mutation** | Exactly $0\%$ | `console/org_context.py` (`PRIORITY_MATRIX`, `calculate_priority`)<br>`console/test_console.py` | Priority weighting rules adjust priority ($P1\dots P4$) based on asset criticality, leaving underlying severity immutable. |
| **Redaction Coverage** | $100\%$ of private IPs/hosts/users | `console/redact.py` (`Redactor.mask`)<br>`tests/test_intake.py` (`test_redacted_by_default`) | Masks sensitive identifiers before LLM advisory dispatch and in command preview dialogs. |

---

### 3.3 The Cut List: Claims Excluded for Lack of Verification

To maintain epistemic honesty, the following candidate claims were **CUT** because they cannot be backed by repository evidence or pinned citations:

1. **CUT: "LLMs miss 96% of attacks" / "96.2% error rate":**  
   *Reason:* Paraphrasing or inverting arXiv 2604.19533 overstates the source. The paper measures event-level detection in a specific benchmark, not overall attack-level failure rates.
2. **CUT: "Mean Time to Detect (MTTD) is reduced to X seconds / X%":**  
   *Reason:* Codebase analysis of `console/soc.py` (`metrics` calculation) established that our stored metrics measure Mean Time to Acknowledge (MTTA), and true MTTD is not computable from heterogeneous raw event logs without universal UTC normalization. Publishing an unmeasurable MTTD claim is prohibited.
3. **CUT: Competitor-specific latency or error rate claims (e.g., "Torq has X% false positive rate" or "Torq takes X hours to configure"):**  
   *Reason:* itsoc does not possess independent, peer-reviewed benchmarks of Torq production environments. Competitor capabilities are characterized by architectural properties (cloud vs. local, AI orchestration vs. rule determinism), not unsourced numbers.
4. **CUT: "Processes up to 100,000 EPS" / "Enterprise-scale throughput":**  
   *Reason:* Vague sizing claims ("up to", "enterprise-scale") without an in-repo load benchmark harness are cut.
5. **CUT: "Incident response completes in under 5 minutes" as a completed fact:**  
   *Reason:* Sub-5-minute execution is a scripted benchmark target (`docs/ITSOC_STAGE_C_BUILD.md`), pending live measurement during Phase C5 runs.

---

## 4. Threat Intelligence Egress Transparency

A foundational principle of itsoc is that sovereignty claims must be transparent regarding edge exceptions:

- **Default State (Zero Egress):** Normal log parsing, anomaly detection, incident correlation, investigation file assembly, and runbook eligibility run entirely locally without network transmission.
- **The Egress Exception:** If an operator explicitly enables external Threat Intelligence connectors (e.g., AlienVault OTX, AbuseIPDB) via `web/src/pages/OemEngine.tsx` (`console/ti_oem.py`: `enrich_ip`, `poll_connector`):
  - Queries transmit **only specific queried indicators** (external IPs, domain names, hashes) and necessary API credentials over outbound HTTPS.
  - **Raw log files and internal host telemetry are NEVER sent wholesale.**
  - An explicit transparency notice is displayed adjacent to connector toggles in the UI (`web/src/pages/OemEngine.tsx`: `EGRESS_DISCLOSURE`).

---

## 5. Summary Battlecard Takeaways for Buyers

```
When to Choose Torq:
  • You need enterprise-wide SaaS workflow orchestration across 100+ non-security apps (Jira, Slack, Workday, Salesforce).
  • Your organizational policy allows raw telemetry and credentials to reside in multi-tenant cloud environments.
  • You prioritize drag-and-drop workflow canvas flexibility over local deterministic verification.

When to Choose itsoc:
  • You operate under strict data sovereignty, defense, or compliance mandates (DORA, NIS2, air-gapped/on-prem).
  • You require guaranteed deterministic verdicts where LLMs cannot mutate severity or trigger unvetted actions.
  • You demand verifiable step-up authorization with cryptographic hash-chained audit trails for all firewall/system changes.
  • You value epistemic honesty — zero fabricated clean bills of health, zero ungrounded AI summaries, and zero fake metrics.
```
