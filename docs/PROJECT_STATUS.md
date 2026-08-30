# log-analyzer — Project status

**As of 2026-08-30.** `main` = `origin/main` = `e9e96fa`. 326 commits since 2026-08-14. Everything below is verifiable in the repo; nothing here is aspirational.

**Gates at time of writing:** web **201/201** across 39 files (declaration order and shuffled) · python `tests/` **38/38** · `console/test_console.py` exit 0 · deterministic eval **19/19**, F1 = 1.000 · detector sha `364577c5…` frozen and byte-identical throughout.

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

### Blocked — needs a machine we do not have
- [ ] **Live light/dark pixel pass against the mockups.** No browser exists in this environment. Every theme and fidelity claim is *structural* — tokens resolve, no hardcoded colours, palette confined. **Nothing establishes that anything actually looks right.** This is the single largest known gap.

### Ready — small, understood, unblocked
- [ ] **Three hardcoded shadow literals** (`CopilotRail.tsx:311`, `itsoc.css:370`, `itsoc.css:385`). A dark shadow renders wrong in light theme; a `--shadow` token already exists. Deliberately parked so a pre-existing fix would not hold a phase open.
- [ ] **`test_console.py` gate hygiene** — one unexplained `exit=1` whose output was discarded by a `>/dev/null` in the gate command. Not reproduced in four later runs, including one under deliberate load. Fix the gate so it never discards its own evidence, then characterise the failure.
- [ ] **`tools/attack_generator.py`** — left untracked in the checkout awaiting owner inspection; keep or discard.
- [ ] **`feat/redesign-integration`** carries a commit of parked, **unreviewed** work-in-progress (170 lines across auth, serve and tests) preserved during worktree cleanup. Review or delete.

### Not defined
- [ ] **There is no Stage D.** The build document ends at C5. Any further product work needs its scope written before it can be planned.

---

## What a reader should distrust

Stated plainly, because a status document that lists only wins is a sales document.

1. **No visual verification was ever performed.** No browser was available. Structural conformance is not the same as looking correct.
2. **One unexplained test failure** is recorded above and has not been root-caused.
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
