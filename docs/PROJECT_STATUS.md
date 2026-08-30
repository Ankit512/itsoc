# log-analyzer — Project status

**As of 2026-08-30 (post-C checklist closeout).** Local `main` is ahead of `origin/main` (`da6eb21`): owner-gated merges `c2f7e75` (`fix/shadow-tokens`) and `eec463d` (`fix/gate-hygiene`). Everything below is verifiable in the repo; nothing here is aspirational.

**Gates at time of writing:** web **204/204** across 40 files on `fix/shadow-tokens` before merge · deterministic eval **19/19**, F1 = 1.000 · detector sha `364577c5…` frozen and byte-identical throughout. `console/test_console.py` still cannot reach exit 0 on a current tree — see below; the gate now preserves that evidence.

---

## What this is

A local-first security operations console. It ingests logs, detects incidents by rule, explains them, and offers a gated way to act on them.

One principle runs through every part of it, and most of the engineering effort went into enforcing it rather than describing it:

> **The system advises. A human decides.** A rules engine owns every verdict. The AI copilot explains and never decides. Nothing executes without a person approving it in one specific place.

---

## Achieved

### Detection and ingest
- **Frozen detector** (`anomaly_detector.py`) — sha-pinned and never edited across the entire build. New formats are sibling modules feeding a fixed shape `{n, ts, level, host, msg, raw}`.
- **Multi-format parsing** — syslog, RFC 5424, JSON-line, Android logcat, EVTX history.
- **`raw` is always the real log line**, never fabricated — including for dropped, truncated or unparsed events.
- **Collector back-pressure** — bounded ingest queue, writes moved off the listener thread, and `ingested / dropped / lagging` counters that are **surfaced in the UI, not just recorded**. Conservation identity: `received = ingested + dropped + lagging + dedupes`.

### Investigation
- Event correlation, org context, and asset-criticality weighting.
- **An advisory layer that is structurally separated from fact.** Model hypotheses carry their own visual and DOM identity so a guess can never be read as a finding, and advisory states never borrow the severity palette.
- **Honest advisory states** — "running" and "timed out" are visible states. A timed-out hypothesis never degrades into a blank space.

### Gated response
- Action layer with an SSH-firewall connector (nftables over SSH against a live container).
- **Approvals queue with per-action step-up authentication.** The backend refuses to execute without approval regardless of what the UI does.
- Gated MCP `propose_block_ip` — propose only, never execute.
- **Runbook recommendations** showing eligibility and, when ineligible, exactly what evidence is missing. Ineligibility is presented as information, not alarm.
- **Append-only SHA-256 audit chain** with chain verification to genesis, and a visible CHAIN BROKEN state.

### Honesty surfaces
- **Connectors ship disabled by default**, with an egress disclosure beside the enable control, held in one shared constant so two copies cannot drift.
- **`n/a` with a reason** wherever data does not exist — no fabricated zeros.
- **Competitive battlecard where every claim is checkable**: unsupported claims were cut rather than softened, and citations name exported symbols rather than line numbers, which rot.
- **A demo benchmark that states what it does not measure** and forbids its own numbers being used as a competitive speed claim.

### Verified end to end
A scripted demo run twice from genuinely fresh stores against a live container: real incident id, live `nft` element insertion confirmed on the target, audit chain verified, step-up credentials surviving each reset. **All six runs disclosed, including the four exploratory ones.**

---

## Yet to be done

### Ready — filed cards, not started
- [x] **FU-1 · Banner over a stale dashboard** — merged `93fbd4c`. KPI block says *"showing previous run — latest upload unrecognized"* when the latest ingest is unrecognized and the selected run is still a previous parsed one. When the selected run itself is unrecognized, the existing banner stands and the new line is absent.
- [x] **FU-2 · Copilot footer copy drift** — merged `326b436`. Confirming grep: product, tests, and the incident mockup pin *"I interpret & explain"*; TOKENS.md was amended to that string. Overview mockup still has an older "explain & prioritize" variant (out of this card).

### Ready — small, understood, unblocked
- [x] **Three hardcoded shadow literals** — merged `c2f7e75` (`fix/shadow-tokens`). Elevation is tokenised (`--shadow` / `--shadow-pop` / `--shadow-modal`); a source-level guard stops the literals coming back. Pixel-pass caveats are FU-1 and FU-2, not blockers.
- [x] **`test_console.py` gate hygiene** — merged `eec463d` (`fix/gate-hygiene`). `scripts/gate.sh` is the canonical gate: tees combined output to `gate-logs/<stamp>/<name>.log`, recovers the real exit via `PIPESTATUS[0]`, runs every gate, reports SKIP rather than rounding it to a pass, verifies the detector freeze. **The original intermittent `exit=1` was NOT reproduced** in 32 runs; its evidence is gone. With output no longer discarded, the next occurrence characterises itself.
- [x] **`soc_history.db` migration gate** — owner ruled **pre-migration fixture, not SKIP** (2026-08-30). Merged `721f7e5`. `tests/fixtures/pre-migration-soc/` is the old shape (seven tables, no `audit_index`, plus C1 cases.json). The gate copies it; `console/test_console.py` EXIT=0 with no live `.soc` db. `web/dist` 503 remains guarded as honest NOT TESTED.
- [x] **`tools/attack_generator.py`** — **promoted (D0, `985ff4c`)**. Tests + isolation (output refused under `tests/eval/`). `tools/efficacy_data/` stays gitignored. Not a score.
- [ ] **`feat/redesign-integration`** stays **parked, not killed.** Directionally right (no auto-bootstrap, atomic `0600` writes) but Codex's four findings are disqualifying as-is. Acceptance bar is `PARKED.md` on that branch; it only comes back through that list.

### Stage D (in flight)
- [x] **D0** generator promotion — merged `985ff4c`.
- [x] **D1** efficacy harness — merged `58a73df`. Next: **D2** surface (Antigravity).
- [ ] **D2** Reports/Experimental efficacy table + miss list + scope sentence.
- [ ] **D3** battle-card + CITATIONS provenance.
- [ ] **P4** OPNsense adapter (after D0–D1; live item BLOCKED if no box).

---

## What a reader should distrust

Stated plainly, because a status document that lists only wins is a sales document.

1. **The pixel pass was headless Chromium, not a designer sitting next to the mockup.** It ran 2026-08-30 on `fix/shadow-tokens` (Antigravity). Structural + screenshot evidence; two composition/copy caveats are FU-1 and FU-2. Antigravity also claimed a verbatim footer match that a tree grep disproved — see `docs/POST_C_CHECKLIST.md`.
2. **One unexplained `test_console.py` exit=1** from Stage C closeout is still uncharacterised. The discarding `/dev/null` is gone (`scripts/gate.sh`); the lost failure cannot be recovered. The next occurrence will keep its output.
3. **`INC-4a7f` is design-kit shorthand.** Real incident ids are `inc-<hash[:12]>`. Seeing `INC-4a7f` presented as a real id would indicate fabrication.
4. **The arXiv 2604.19533 figure** (best frontier LLM flagged ~3.8% of malicious events; no model passed 50% per-tactic) is a **literature citation, never an in-repo measurement.** It must never be rounded, and never inverted into "LLMs miss 96%".
5. **The demo timings (~1–2s) measure a machine-speed backend pipeline only** — no human think time, no UI rendering, no WAN transit. They are not a competitive speed claim.

---

## Deeper reading

| Document | What it holds |
|---|---|
| `docs/STAGE_C_CLOSEOUT.md` | **Read first.** Phases with merge commits, deviations and resolutions, the open-items register, guardrail changes, defects fixed vs parked |
| `docs/C5_DEMO_RESULTS.md` | All six demo runs with per-stage timings and the scope boundary |
| `docs/BATTLECARD_TORQ.md` | The competitive comparison, with its cut list |
| `docs/C5_PREP.md` | Fresh-store reset procedure, KPI feasibility, collector reconnaissance |
| `docs/POST_C_CHECKLIST.md` | Owner-gated leftover-list closeout: merges, filed cards, AG stall, audit-accuracy note |
| `docs/followups/FU-1-banner-stale-run.md` | KPI context line when latest ingest is unrecognized over a previous run |
| `docs/followups/FU-2-copilot-footer-copy.md` | One copilot honesty-footer string; grep the tree |
