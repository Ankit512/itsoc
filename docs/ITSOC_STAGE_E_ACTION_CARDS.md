# itsoc — Next-Phase Action Cards

_v1 · Sep 2026 · Two tracks. Track A is owner-only and comes first: no build card below the line may claim priority over it. Track B is the Stage E build ("legible intelligence"), derived from the Torq SOC Brain analysis (video + slides, Aug 2026, in the competitive file). All Stage C/D doctrine binds: detector frozen at `364577c5…a4a876`, GUARDRAILS.md applies, delivery is the liveness signal, audits are grepped, security accepted by attack._

**The wall (restated once, binding on every card):** no learned or advisory signal ever touches severity, eligibility, priority, or execution — not as a score, a tiebreaker, a re-ranker of verdicts, or a confidence gate. Torq's architecture feeds a per-org transformer INTO the verdict (Reflex → Auto Triage) and puts an AI model inside retrieval ("Deep Relevance Judgement"). itsoc's architecture is the inversion: verdicts and candidate sets are deterministic; models may only annotate them, labeled ADVISORY, for human eyes.

---

## Track A — Evidence (owner: Ankit; orchestrator not involved)

### A1 · Send the Charles email — TODAY
The drafted email (Techstars opinion + pre-seed intros) with the two-sentence sync line and the repo link. Pre-send check: README reads well as a first impression; phone number filled in.
**Done when:** sent. **Follow-up:** one nudge after 5 days if silent, then stop.

### A2 · Interview script + probe list
One page: 6–8 open questions for a sovereignty-constrained security lead. Must include the three probes this analysis produced:
1. "Torq trains a transformer per organization to help decide what's a true positive. Would your auditor accept that? Would you?"
2. "Would 'shows you the last five times this happened and what you decided' change your triage time?" (validates E2/E3 before building more)
3. "When your team overrides an alert, where does that knowledge go today?" (validates E1/E6)
Plus: current tooling, what logs they cannot send off-site, who signs off on a containment action today, what DORA reporting costs them.
**Done when:** the page exists and has been rehearsed aloud once.

### A3 · Book 3–4 demand interviews
Targets: security leads at Irish/EU BFSI, healthcare, gov, critical infrastructure. Channels: existing network, LinkedIn (already-connected first), Charles's intros if A1 converts. The ask is 30 minutes of their expertise, not a pitch; demo only if they ask.
**Done when:** three calendar invites accepted. **This card is the binding constraint. Everything in Track B is subordinate to it.**

### A4 · Competitive file entry — Torq SOC Brain
File the video summary + both slides in `docs/research/COMPETITIVE.md` with dates, source URLs, and the two architectural facts: Reflex verdict feeds Auto Triage; retrieval re-ranked by an AI model. Add the two battle-card lines (concede: they learn per-org instincts, we are told in reviewable rules; win: their model's self-agreement authorizes eradication, our named human authorizes action). Never claim their production behavior beyond the published material.
**Done when:** committed. May be delegated to the fleet as a docs card if preferred.

---

## Track B — Stage E build: "legible intelligence" (fleet; orchestrator runs it)

Sequencing gate: **E0, E1, E6 start now, then E7 → E8** — the second-opinion model is the MVP centerpiece and is interview-independent (its training data comes from the generator's ground truth, not customers). **E2, E3, E5, and E4's copilot-prose part wait for at least one interview signal** ranking them; a design partner's first request re-orders the track. Build order: E0 + E6 (schema and wall first) → E1 → E7 → E8.

### E0 · Disposition capture (foundation — everything downstream consumes this)
Incident lifecycle gains a rule-owned disposition on close: `confirmed | false-positive | benign-expected`, each with optional free-text reason. (Taxonomy adopted from Torq's TP/FP/Positive-Benign split — their best design decision; the third category keeps "correct rule, expected finding" from poisoning both recall and tuning.) Stored on the incident, exported in reports, shown as a chip in History.
Worker: Claude Code (store schema). Acceptance: disposition is settable only through the lifecycle transition, additive migration, appears in the audit trail when set on a contained incident; no disposition field ever read by `eligible()` (test).

### E1 · Precedent index — deterministic recall
`console/precedent.py`: given an incident, return similar past incidents by overlap of {rule ids, entities (hosts/users/IPs), ATT&CK tags, asset criticality}, ranked by overlap count, each match carrying its explanation ("same rule + same host + T1110"). Pure index query on the store; no model anywhere in the path. Surfaced as a "Precedents" panel on Incidents with dispositions visible (needs E0).
Worker: Claude Code (touches store queries). Acceptance: explanation string per match derivable from the match itself; kill-the-LLM test irrelevant by construction (prove no LLM import); <200ms on the 2,500-event store.

### E6 · Extend the wall — tests before features
Before E4 exists, the guard grows to meet it: `ADVISORY_KEYS` gains the Stage E advisory fields (`similarityNote`, `precedentOpinion`, `proposalDraft`); the disjointness test extends; a new test asserts `precedent.py`'s ranking function signature admits no advisory input; a grep-test asserts no file in the eligibility/severity path imports `precedent` advisory helpers or any LLM seam.
Worker: Claude Code. Acceptance: the tests exist and have been seen to fail (mutate, observe, restore — per doctrine).

### E2 · Day-zero history import (interview-gated)
Import closed-incident history from a CSV/ticket export (generic mapping: title, entities, timestamps, disposition, notes) into the store as `origin: imported` incidents — badged, never confusable with rule-detected ones (C1-T2 selector-null test pattern). Feeds E1 immediately: precedent recall works before itsoc has seen live traffic. This is the honest version of Torq's "inherit the predecessor's brain."
Worker: Claude Code (migration-bearing) + Codex (format mapping tests). Acceptance: import is additive and re-runnable without duplicates; imported incidents excluded from efficacy metrics (test).

### E3 · Org memory as reviewable rules (interview-gated)
`benign-expected` dispositions with reasons can be promoted — by a human, in Settings — to suppression/annotation rules: `{pattern, scope, reason, owner, expiry}`. Expired rules surface for re-review; suppressed findings are counted and visible ("suppressed by rule S-3, owner AK, expires 2026-12"), never silently dropped. This is per-org adaptation an auditor can read.
Worker: Claude Code (rule path adjacency — severity untouched, suppression is display/priority-layer only; if it needs to touch verdict emission, STOP and re-scope).
Acceptance: suppression never deletes or alters a finding record; counts visible; expiry works; `eligible()` unaffected (test).

### E7 · Second-opinion model — train + render (STARTS NOW; needs E0 schema + E6 tests first)
The MVP model-training card. A small, local, per-installation learned triage model whose output is rendered, measured, and never wired.
- **Data:** bootstrap from `tools/attack_generator.py` ground-truth manifests + the 2,500-event store; real dispositions (E0) join the training set as they accrue. A `train` CLI (`tools/train_triage.py`) regenerates the model locally; the model file lives in `console/.soc/models/`, gitignored, with a provenance sidecar (training date, dataset counts, feature list).
- **Model:** feature-vector classifier first (rule hits, entity counts, timing, criticality → scikit-learn gradient boosting); Ollama-embedding + linear head as a variant behind the same interface. Local only — training and inference never leave the machine.
- **Render:** an "AI TRIAGE · LEARNED, ADVISORY" block beside the rule verdict on Findings/Incidents: the model's severity opinion, confidence, and agreement status with the rules (agrees / disagrees — disagreement is information for the human, never a gate). Reuses the `aiSeverity` advisory plumbing; fields registered in `ADVISORY_KEYS`.
- **The wall, enforced:** E6's tests extend to the model fields; `eligible()`, severity, priority, and execution provably unreachable from model output (mutation-proven).
Worker: Claude Code (pipeline + guard integration), Antigravity (UI evidence, both themes). Acceptance: model trains from scratch on a clean checkout in <10 min; kill-the-model test → rule verdicts and case files fully intact, advisory block shows honest "model unavailable"; disagreement renders visibly; no model import anywhere in the verdict/eligibility path (grep + import-graph test, seen to fail).

### E8 · Harness-benchmark the model — publish honest numbers (needs E7 + the harness)
Run the trained model through `tools/efficacy_harness.py` scenarios as a *second scored system* beside the rules: per-scenario precision/recall/F1 for both, side by side, misses listed verbatim for both. Publish in the Reports efficacy section and the battle card with the standing scope sentence plus one more: "the learned model is advisory; these numbers are why." Either outcome is a win: model under rules = the thesis, measured; model strong = a validated advisory signal whose disagreements feed E5's proposal queue.
Worker: Claude Code (harness extension), Gemini (report/battle-card copy). Acceptance: both systems scored by identical code paths; numbers carry run id + model provenance; no shared state between scoring runs (a rules-only run with the model deleted produces identical rule numbers — test).

### E4 · Advisory similarity layer (folded into E7's rendering; interview-gated for the copilot-prose part)
The copilot may annotate the deterministic precedent set (E1) in prose — "the last four like this closed as false positives, reasons cited" — every claim citing incident ids from E1's output only, candidate set always shown unannotated first. The numeric/labeled similarity display ships with E7.
Worker: Claude Code (guard), Antigravity (UI evidence). Acceptance: guard rejects any claim citing an incident not in the candidate set (seen to fail).

### E5 · Rule-change proposal queue (interview-gated; needs E0)
When a rule accumulates N same-reason overturns, a *proposal* appears in a review queue: the pattern, the overturn evidence, a drafted amendment (LLM-drafted, ADVISORY-typed). A human accepts → it becomes a normal, versioned, severity-affecting rule change with its manifest update, halted for owner per standing rules. Their system learns silently into weights; ours learns legibly into reviewed diffs.
Worker: Claude Code. Acceptance: a proposal can never self-apply (no code path exists — prove structurally, not by test-of-absence alone); accepted changes follow the existing manifest discipline; queue empty-state honest.

---

## Routing summary
Claude Code: E0, E1, E6, E7 (pipeline + guard), E8 (harness extension), E3, E5, E4-guard (store/verdict adjacency throughout). Codex: E2 format-mapping fan-out, batch tests against fixed acceptance, E7 feature-extraction unit tests. Antigravity: E7/E3 UI evidence, screenshot-backed both-theme passes. Gemini: E8 report/battle-card copy, empty states, docs (A4 if delegated). Equal-orchestration scoreboard continues for Codex/Antigravity.

## Track F — Utility & legibility (post-E8 unless marked NOW)

### F0 · RB-UX — runbook legibility (NOW; light tier; no engine changes)
Runbooks render as plain-language analyst cards: what it does / fires on / needs / steps 1-2-3 / reversible. Schema vocabulary (severity_floor, params_template) leaves the UI; eligibility machinery collapses behind "why ineligible?" disclosure. Antigravity UI evidence + Gemini copy. Acceptance: a non-builder can state what each runbook does from the card alone; engine files untouched.

### F1 · Connector matrix (interview-gated; Entra-read is the named first candidate)
Read connectors ranked for the EU regulated buyer: M365/Entra sign-in logs → Defender alerts → Google Workspace audit → CloudTrail; SIEM-pull (Sentinel/Splunk) probed as the possible one-integration answer. Write connectors demand-gated only: Entra disable-user/revoke-sessions first, OPNsense per D-2. Notify: Slack/Teams drafts via rb-draft-notify pattern. Every connector ships an honesty spec: what leaves, protocol, auth, redaction. No catalog-chasing — six deep entries cover the story.

### F2 · Multi-step runbooks (interview-gated; pre-draft only)
Runbook = ordered steps with per-step preview, one approval covering the previewed list (per-step approval for destructive steps); declarative `only_if` conditions on rule-owned fields only (eligibility-signature discipline extends — advisory fields structurally excluded). Runbook editor = Settings form composing vetted connector steps; never a freeform canvas, no loops/variables/HTTP steps/free conditionals — each is a gate bypass. Scheduled read-only automations (scans, TI refresh, E9 retrain) allowed ungated with honest run history.

**A2 probe additions:** "What's your stack — Microsoft? What would itsoc need to read for a real trial?" · "Walk me through containing a compromised account today: who does each step, in what tool, who approves?"

## What this phase is NOT
No model output wired into severity, eligibility, priority, or execution — the per-installation model exists (E7) but it advises, measured (E8), never decides. No confidence-gated autonomy tiers. No auto-applied suppressions. No re-ranking of anything by a model outside a labeled advisory block. No cloud training or inference — the model trains and runs locally, full stop. If a card drifts toward any of these, it stops — that drift is the competitor's architecture, not ours.
