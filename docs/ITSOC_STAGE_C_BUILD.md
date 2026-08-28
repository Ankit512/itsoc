# ITSOC_STAGE_C_BUILD.md — Claude Code Execution Document

_v1 · Aug 2026 · Companion to `ITSOC_STAGE_C_SPEC.md` (this doc supersedes it where they differ)._
_Read `CLAUDE.md` first. Every non-negotiable applies. Detector stays at sha `364577c5…a4a876`._

---

## 0. Decisions log (all open questions resolved — build to these)

| # | Question | Decision |
|---|----------|----------|
| D1 | Reference write-connector | **OPNsense firewall** via its REST API (key/secret token auth over HTTPS — satisfies the cert/token principle; runs in a VM for demos). Connector interface is abstract (`console/actions/base.py`) so an iptables-over-SSH adapter can follow without core changes. First action: **block IP / unblock IP** on a named alias. |
| D2 | Advisory latency | **qwen3:8b stays the default narrator** (post-Phase-4 fixes + `reasoning_effort=none` + json_schema). Investigation agents run **parallel, bounded concurrency 3, per-agent timeout 45s**. Deterministic case assembly NEVER waits on the LLM: advisory sections render "ADVISORY · pending" then fill or honestly time out ("ADVISORY · timed out — retry"). Settings gains an optional "fast narration model" field (advisory-path only). |
| D3 | Auth for approvals | **Step-up gate on the Approvals surface only.** App stays ungated (design-v3 decision holds). Approving/rejecting any action requires re-entering the Phase-6 scrypt passphrase (the `auth.ts` swap-seam); the verified identity is stamped into the audit entry. No approval without an authenticated actor, ever. |
| D4 | Audit store | **Append-only hash-chained JSONL** written through `fsafe.py` (`console/.soc/audit/chain.jsonl`; each entry carries `prev_hash`, `entry_hash` = sha256 of canonical JSON + prev). A derived **sqlite index** in `store.py` for querying/UI. The JSONL chain is the source of truth; `verify_chain()` runs on read and any break renders an honest "CHAIN BROKEN at entry N" banner — never silently re-chain. |
| D5 | Terminology | **Runbooks** everywhere (aligns with the existing copilot "runbook engine" citations). Sweep legacy references. |
| D6 | Scope additions | Org-context priority rules (asset criticality), TI severity + TAXII auth fixes, "DORA-ready action trail" export line — all in (phased below). |

---

## 1. Feature consolidation (authorized resize — 16 screens → 12)

Duplicative features become one. Data/back-ends merge; old routes 301 to the new home. Nothing is deleted from storage — screens merge, stores migrate additively.

| Old screens | New screen | Rationale & rules |
|---|---|---|
| **Incidents** + **Cases** | **Incidents** | Cases were CRUD shells around the same objects incidents already are. Incidents absorb the case lifecycle (`new → investigating → pending-approval → contained → closed`), analyst notes, and linkage to runs/actions/audit. Existing case records migrate into incident metadata (additive migration in `soc.py`; keep a read-only legacy export). RCA + the new Investigation file live here. |
| **Threat Intel** + **Enrichment** | **Intel** | Both are external-context surfaces. One screen, two labeled sections: Feeds (TAXII/static) and Live Enrichment (OTX/AbuseIPDB). Honest egress labels on both ("this section calls external services"). |
| **Discovery** + **Vulnerabilities** | **Network** | Same tool (nmap), same egress class (active scanning). Tabs: Discovery / Vulnerabilities. Single "active scanning — not read-only" banner instead of two. |
| **Collectors** | folds into **Sources** | The design-v3 nav already groups Sources; live collectors are just live sources. Sources gets tabs: Uploads / Collectors, keeping the honest bind display (host:port, never `undefined`). |
| *(new)* | **Approvals** | The single authoritative approval surface (see D3, Phase C4). Lives in the main nav under Incidents. |

Resulting nav (design-v3 grouping preserved): Overview · Findings · Incidents · Approvals · Intel · Network · Assets/Users · Sources · History · Reports · Settings · (Experimental: OEM Engine, anything not yet at fidelity). Overview/Findings/Incidents/Sources/Settings remain the core group; Approvals joins it.

---

## 2. Phases

Discipline for every phase: **own branch** (`stage-c/<phase>`), additive commits, `pytest` + `npm run build` green, **stop and report** with a diff summary, human gate before merge. Task routing between Claude Code, Codex, and Gemini follows §3. Never push without an explicit owner decision. A severity-affecting change updates `tests/eval/manifest.json` in the same commit. If a task would touch `anomaly_detector.py` — STOP and ask.

### Phase C0 — Foundations: runbook engine, audit chain, TI fixes
Branch `stage-c/c0-foundations`. Backend only, no UI.

1. **Runbook schema + eligibility engine** (`console/runbooks.py` + `console/runbooks/*.yaml`):
   - Declarative runbook: `id, name, trigger {rule_ids, entity_types}, preconditions {required_evidence}, steps [{type: action|notify_draft, connector, params_template, rollback}], severity_floor`.
   - `eligible(incident) -> {eligible: bool, missing: [...]}` computed **only** from rule verdicts + evidence. No LLM input parameter exists in the signature — make ineligibility structural.
   - Ship two runbooks: `rb-block-ip` (brute-force / compromise trigger) and `rb-draft-notify` (notification draft only).
2. **Audit chain** per D4: `console/audit.py` (append/verify via `fsafe.py`), sqlite index table in `store.py`. Entry fields: `{ts, actor, incident_id, runbook_id, step, eligibility_proof, evidence_refs, request_redacted, response_verbatim, status: approved|rejected|executed|failed, prev_hash, entry_hash}`.
3. **TI fixes (P0.5):** replace `threat_intel/severity_for()`'s flatten-to-CRITICAL with rule-mapped severities (feed-declared level → capped by rule policy); replace `--taxii-password` with token/cert auth via **file-path or env references only** (`--taxii-config`, `--taxii-token-file`, `--taxii-client-cert`/`--taxii-client-key`); secret values never appear in argv or logs. Update tests.
4. **Runbooks terminology sweep** (D5).

Acceptance: unit tests for eligibility (including the no-override property), chain append/verify/tamper-detection, TI severity mapping; all existing tests green.

### Phase C1 — Screen & store consolidation
Branch `stage-c/c1-consolidation`. Implements §1 exactly.

- Backend: additive migrations (cases→incident metadata; no destructive drops), route aliases for old endpoints, honest legacy export.
- Frontend: merged screens at **design-v3 fidelity** (reuse existing `is-*` compositions; the dc TITLES map gains the new/renamed pages), nav reduction, ⌘K entries updated (old names alias to new screens so muscle memory survives).
- Collectors→Sources keeps the live bind fix visible.

Acceptance: every pre-merge capability reachable on the new screens; no data loss (migration test on a copied `.soc/` fixture); build green; screenshots per merged screen in the report.

### Phase C2 — Investigation engine (autonomous, read-only) + org context
Branch `stage-c/c2-investigation`.

1. **Deterministic case assembly** (`console/investigate.py`, extending `soc.derive_rca`): timeline reconstruction, entity/asset correlation, IOC extraction, blast-radius set — all from rule evidence, all citing record `{n}` refs. Fires automatically on incident creation (read-only ⇒ no gate). Target < 2 min on the 2,500-event store.
2. **Parallel advisory agents** per D2 (narrative, ATT&CK mapping, pivot suggestions) through `askStream` + `explanation_guard` + json_schema. Each output block labeled `ADVISORY`; every factual sentence carries a resolvable citation or the guard rejects it. Pending/timed-out states per D2.
3. **Org-context rules** (`console/org_context.py` + Settings-editable `org_context.json`): asset criticality tags (`crown-jewel|standard|low`) weight incident **priority** (a rule-owned, separate field — severity itself is untouched). Replaces the binary "at risk" flag with criticality-aware exposure.
4. Incidents screen: Investigation file section (deterministic block visually distinct from advisory blocks — reuse the verdict/advisory composition).

Acceptance: INC-4a7f case assembles < 2 min; ≥ 95% advisory citation coverage measured by the guard; kill-the-LLM test → deterministic file still complete, advisory shows honest timeout; priority never mutates severity (test).

### Phase C3 — Gated response: approvals + OPNsense connector
Branch `stage-c/c3-gated-response`.

1. **Action layer**: `console/actions/base.py` (abstract connector: `preview()`, `execute()`, `revoke()`), `console/actions/opnsense.py` per D1. All request bodies pass `console/redact.py` before logging/preview. Key/secret from local config — never CLI args, never logged.
2. **Approval flow** (`/api/approvals`): create-on-recommend, approve/reject with **step-up auth** per D3 (server verifies the scrypt passphrase per action; identity stamped into the audit entry). Approve → execute → append `executed|failed` with verbatim connector response. Failed = FAILED state + revoke offered where applicable; never fake-contained.
3. **Gated MCP write tool**: `itsoc_mcp` gains `propose_block_ip` — creates a *pending approval only*; the MCP layer cannot execute. Document in `itsoc_mcp/PUBLISHING.md` provenance.
4. AI copilot may *recommend* among **eligible** runbooks and draft justifications; recommendation payloads are advisory-typed and carry no executable handle.

Acceptance: end-to-end on a live OPNsense VM (block → audit entry with real response → unblock); rejection path audited; step-up required every time (no session grace in v1); tamper test breaks the chain banner; attempting to execute an ineligible runbook via raw API returns 409 with missing-evidence body.

### Phase C4 — UI: Response rail + Approvals screen (design changes)
Branch `stage-c/c4-response-ui`. All at design-v3 fidelity; extend `TOKENS.md`/`itsoc-design-system.css` — do not fork styles.

**New components (`is-*`):**
- `is-runbook-card`: name, trigger rule chips, eligibility badge — `ELIGIBLE` (low-accent outline) / `INELIGIBLE — missing: <evidence>` (muted, never red; ineligibility is information, not alarm). One primary "Request approval" button max per view (accent-button budget holds).
- `is-approval-modal`: redacted request preview (mono block), evidence chain (citation list, same composition as finding evidence), eligible-by rule line, step-up passphrase field, Approve (primary) / Reject. Overlay shadow allowed (design rule: shadows on overlays only).
- `is-audit-timeline`: vertical hash-chain view; each entry mono-timestamped, status-chipped (`approved/rejected/executed/failed` — severity palette only for `failed` using crit `#f26d78`); "chain verified ✓" footer or the CHAIN BROKEN banner.
- `is-advisory-pending` / `is-advisory-timeout` states for investigation blocks.
- Priority chip (org-context) beside — never replacing — the severity chip; tooltip "priority is rule-owned, weighted by asset criticality".

**Screen changes:**
- **Incidents**: right column gains a Response panel (eligible runbooks list → request approval); Investigation file per C2; lifecycle stepper in the header (case states from C1).
- **Approvals** (new, per §1): pending queue (master-detail like Findings), each opening `is-approval-modal`; empty state honest ("No pending approvals" — no illustration filler).
- **Copilot rail**: can surface pending approvals and recommend runbooks — read-only cards with a "Open in Approvals →" link. **No approve control exists in the rail** (verify by grep + test).
- **Reports**: audit export in all 5 formats; add the one line "DORA-ready action trail — every action carries approver, rule eligibility, evidence, and connector response."
- Motion: modal = ⌘K-style scale+fade; timeline entries appear without stagger (design rule).

Acceptance: approval control exists in exactly one component; both themes; keyboard path (J/K queue nav, Esc closes modal, Enter submits only when passphrase non-empty); screenshots vs dc-fidelity bar.

### Phase C5 — Demo hardening + collector back-pressure
Branch `stage-c/c5-demo`.

1. **Torq-comparison scenario**: script the full arc on sample data — brute-force INC-4a7f fires → investigation file assembles → `rb-block-ip` recommended → approve (step-up) → OPNsense blocks 203.0.113.44 → audit export. Target: **under 5 minutes wall-clock with the human gate included**. Record the timing honestly in the demo notes (real number, not the target).
2. **Collector back-pressure**: bounded queue + honest counters (`ingested / dropped / lagging`) surfaced on Sources; drops are counted and shown, never silent.
3. **Battle card** (`docs/BATTLECARD_TORQ.md`): concede orchestration breadth; win on verdict trust, sovereignty, provable gating; cite the Cyber Defense Benchmark ~3.8% figure and the under-5-min-with-approval demo.
4. KPI panel (P1): MTTD/MTTA/time-to-approval/time-to-contain from real timestamps; `n/a` without priors.

Acceptance: scripted demo runs clean twice consecutively from a fresh store; counters visible under a flood test; battle card reviewed by owner.

---

## 3. Worker assignment — who builds what

Three worker tiers execute this document. The owner (or the orchestrating session) routes tasks by weight; when in doubt, route up to Claude Code.

**Claude Code agents — all heavy work.** Anything that is architectural, verdict-adjacent, security-sensitive, cross-module, or migration-bearing:
- All of **C0** (eligibility engine, audit chain, TI severity/auth fixes — trust-model core, no exceptions).
- C1 backend migrations (cases→incidents, store changes) and route aliasing.
- All of **C2** (investigation pipeline, advisory-agent orchestration, `explanation_guard` integration, org-context rules).
- All of **C3** (action layer, OPNsense connector, step-up auth, MCP write tool — everything that can touch the outside world).
- C4 components that carry security semantics: `is-approval-modal`, `is-audit-timeline`, the rail's no-approve constraint and its tests.
- Any change involving `redact.py`, `fsafe.py`, `store.py` schema, `explanation_guard.py`, auth, or anything within one import of `anomaly_detector.py`.

**Codex — medium work, distributable only.** Medium-weight tasks that are parallelizable into independent, identically-shaped units with no shared state and no security semantics — the fan-out tier. A task goes to Codex only when it decomposes cleanly (one unit failing doesn't corrupt another) AND sits below the Claude Code line above:
- C1 per-screen frontend merges fanned out one-screen-per-unit (Intel, Network, Sources) once the first merged screen (built by Claude Code or reviewed as the pattern) exists as the template.
- C4 non-security `is-*` components fanned out one-component-per-unit against the design-system spec (`is-runbook-card` visuals, advisory pending/timeout states, priority chip).
- Batch test-writing against already-fixed acceptance criteria (one test file per unit); batch screenshot/fixture generation across screens and themes.
- Multi-file mechanical transforms bigger than a copy sweep but pattern-fixed: route-alias wiring across old endpoints, ⌘K alias entries across all screens, applying the TITLES map.
- If a "distributable" task turns out to have hidden coupling (shared store, ordering dependency, a restricted file), it stops and re-routes up to Claude Code.

**Gemini — light-to-medium work.** Self-contained, spec-bounded, low-blast-radius, single-unit tasks:
- Singleton screen tweaks and nav reduction where the composition already exists at design-v3 fidelity.
- The D5 runbook terminology sweep; page-subtitle updates; copy changes.
- Presentational polish without security semantics: Reports export line, empty states, both-theme passes on individual screens.
- C5 documentation work: battle card draft, demo notes; KPI panel display wiring (calculation itself is C2/Claude Code).
- Sample-data preparation, honest-state copy review.

**Rules that bind all tiers equally:**
1. Every worker reads `CLAUDE.md` + §4 guardrails before its first commit; the non-negotiables do not scale down with task size.
2. Codex and Gemini work only from written task cards (scope, files allowed to touch, acceptance) derived from this doc — no self-expanding scope. Codex fan-outs additionally get a unit manifest (the list of units, one card each) so no unit invents siblings. Any task that drifts into a restricted file stops and re-routes to Claude Code.
3. Same branch/gate discipline for all: own branch (Codex: one branch per fan-out, one commit per unit), additive, tests+build green, stop-and-report, human merge gate. Reviewer for any Codex or Gemini branch is a Claude Code agent or the owner — never self-merged; Codex fan-out reviews check cross-unit consistency (same pattern applied identically), not just per-unit correctness.
4. The detector-sha CI check and the honesty-surface tests are the tripwire for everyone: a red check halts the branch regardless of who authored it.

## 4. Standing guardrails (verbatim, for every phase)

1. Rules own severity, correlation, priority, and **eligibility**. LLM output is advisory everywhere and is never a control signal, trigger, gate-opener, or eligibility input.
2. Honest surfaces: failed actions fail visibly; empty states are empty; timeouts say so; the audit chain reports its own breaks; no invented data anywhere.
3. Detector untouched; sha check in CI stays.
4. All egress through `redact.py`; connector credentials are token/cert, config-file only.
5. Reuse seams first: `derive_rca`, `explanation_guard`, `askStream`, `store.py`, `fsafe.py`, `redact.py`, the verdict/advisory composition, Phase-6 auth seam.
6. Stop-and-report at every phase end; no merge, no push without the owner's explicit go.
