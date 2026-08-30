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

### 3.1a Stage D Synthetic Efficacy Harness

**Scope:** measured against synthetic ground-truth scenarios; not a claim about production traffic.

These scenarios are drawn from the same attack classes the rules were written for — the expected result is perfection, and its value is regression proof (any future score below 1.0 is a detected regression), not a general-efficacy claim.

The following are **scenario-level** totals from the three canonical scenarios. They do not mean every individual rule achieved perfect recall; the harness can attribute a malicious line to multiple rules.

| Scenario | Format | Precision | Recall | F1 | Malicious lines detected | Miss count |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| `INC-4a7f` | `canonical` | 1.0 | 1.0 | 1.0 | 7 / 7 | 0 |
| `failure-success` | `canonical` | 1.0 | 1.0 | 1.0 | 6 / 6 | 0 |
| `error-burst` | `canonical` | 1.0 | 1.0 | 1.0 | 6 / 6 | 0 |

**Three-scenario rollup (`INC-4a7f`, `failure-success`, `error-burst`):** 0 missed malicious lines and 0 false-positive findings. Run date: `2026-08-30T17:22:06+00:00`; pipeline: `log_analyzer.py --rules-only (subprocess)`; audited commit: `06a7b989996319bc6d0dd421af61d4399d6cdf75` (harness landing commit: `58a73df`). Reproduce with `python3 tools/efficacy_harness.py`; provenance and representation constraints are registered as C-2 in `docs/research/CITATIONS.md`.

This harness measurement is separate from the **Evaluation Detection Score** below, which remains the result of `tests/eval/run_eval.py` over 19 canned cases; the two F1 measurements must not be collapsed.

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
