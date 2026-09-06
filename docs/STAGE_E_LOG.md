# ITSOC Stage E — Execution Log

Owner-activated 2026-09-02 via `ITSOC_STAGE_E_ORCHESTRATOR_PROMPT_LEAN.md`.
Build order: E0 + E6 → E1 → E7a → E8 → E7b → E9.

Detector freeze: `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.
Model/advisory output is fenced from severity, eligibility, priority, and execution.

---

## Activation, gate, and first dispatch — 2026-09-02

Report: `docs/STAGE_E_REPORTS/activation-dispatch.md`.

- Step 0: local `main` matched `origin/main` at `b836114`; Stage E register commits then advanced local `main` to `5978d71`. No push.
- Step 1: required inputs present; detector freeze exact; Guardrails already present; Stage E registers created.
- Step 2: all required gates passed. Web 43/43 files, 251/251 tests; eval 20/20, F1 1.000; console, intake, fsafe, MCP, and threat-intel suites green.
- Step 3: Claude Code 2.1.252 and Codex 0.149.1 present. Antigravity and Gemini absent; both tiers route up to Claude Code for this run and are logged here once.
- Owner update: `docs/ITSOC_STAGE_E_ACTION_CARDS.md` replaced byte-for-byte from the 2026-09-02 download (`9e8da0b…cc2c93`), adding Track F and immediate F0. The orchestrator prompt still governs mechanics, including E7a → frozen E8 → independently graded E7b rounds → E9.
- Dispatched: E0 `task_011af4e0ea34` / `ctx_b09c48a3291c`; E6 `task_ae693acfc187` / `ctx_eeeeb1190457`; F0 `task_2da0cfc5cfa8` / `ctx_ca8144f63b88`.

## E6 accepted — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E6-accepted.md`.

- Accepted worker commit `6285a0f` and merged locally as `9a61c0f`; no push.
- Independent gates: Stage E wall 30/30, full console suite green, referee eval 20/20 with F1 1.000, frozen detector hash exact.
- Accepted the AST import/call wall as the precise implementation of the requested grep guard: executable coupling fails without comment/string false positives.
- `graphify update .` succeeded after merge.

## E0 and F0 accepted — 2026-09-02

Reports: `docs/STAGE_E_REPORTS/E0-accepted.md` and `docs/STAGE_E_REPORTS/F0-accepted.md`.

- E0 accepted from worker commits `622f540` and `f8cc279`; merged locally as `684c373`; no push.
- E0 evidence: full console suite including 34 new checks, eval 20/20 with F1 1.000, build green, eligibility unchanged and disposition-blind, frozen detector hash exact.
- F0 accepted from worker commit `4cb5b17`; merged locally as `01c88dc`; no push and no engine/backend changes.
- F0 evidence: runbook and theme coverage green, full console suite, eval 20/20 with F1 1.000, build green, frozen detector hash exact.
- A parallel acceptance run timed out in the same untouched Integrations test on both branches under resource contention; its isolated rerun passed 9/9. The combined-main sequential suite then passed 43/43 files and 266/266 tests.
- `graphify update .` succeeded after both merges.

## E1 dispatched — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E1-dispatch.md`.

- Task `task_4a6f228d1ce6`, dispatch `ctx_c8fdfcc07fbf`, Claude Code.
- Branch `feat/e1-precedent-index` in its own worktree, exact accepted-main base `7bd6796`.
- Contract retains the E6 rank signature and advisory wall; E1 is deterministic recall only. No push or worker merge.

## E1 accepted — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E1-accepted.md`.

- Accepted worker commit `9f34421`; merged locally as `739683f`; no push.
- Independent gates: Stage E wall 48/48, full console green, web 43/43 files and 271/271 tests, build green, eval 20/20 with F1 1.000, frozen detector hash exact.
- 2,500-incident end-to-end query: best 18.1 ms, median 18.7 ms of 7, with a clock-free posting-cost assertion proving the query does not scan the whole store.
- Disposition joins only after deterministic ranking; advisory/disposition poisoning cannot reorder results. Explanations are recomputable from each match's shared facts.
- `graphify update .` completed. Graphify reported one TSX parser warning on `Incidents.tsx`; the authoritative TypeScript build passed.

## E7a dispatched — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E7a-dispatch.md`.

- Existing generator/isolation prerequisite reverified: 5/5 generator tests and 13/13 harness tests.
- Task `task_64d5ccd160ec`, dispatch `ctx_c8ce5df92642`, Claude Code, branch `feat/e7a-model-v1`.
- Exact accepted-main base `e7f6831`. One shared rule-owned feature extractor; seeded provenance; stratified CV; balanced weighting; learned advice only.
- Missing dependency/model must remain an honest visible unavailable state. Mutation and kill-model evidence are mandatory. No push or worker merge.

## E7a implementation merged; independent test card dispatched — 2026-09-02

Reports: `docs/STAGE_E_REPORTS/E7a-worker.md` and `docs/STAGE_E_REPORTS/E7a-codex-dispatch.md`.

- Claude implementation commit `fb24aef` independently audited and merged locally as `8337490`; no push.
- Independent gates before merge: clean Python 3.13 venv installed pinned scikit-learn 1.7.2; 23/23 training tests; fresh 434-row train in 13.03 s with five-fold macro-F1 mean 0.9568; Stage E wall 101/101; full console green; web 43/43 files and 278/278 tests; production build green; eval 20/20 with F1 1.000; detector hash exact.
- PyPI metadata confirms 1.7.2 is production-stable and supports Python 3.13. A newer release exists, but the accepted pin is the release actually reproduced by the implementation and independent training runs.
- `graphify update .` completed after merge, with the known `Incidents.tsx` parser warning; the authoritative TypeScript build passed.
- Codex test-only task `task_ad6e978dc5ba`, dispatch `ctx_9d10053d48fd`, branch `test/e7a-feature-contract`, exact base `8337490`. Only the new adversarial test file and its worker report are allowed.

## E7a accepted — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E7a-accepted.md`.

- Accepted implementation commit `fb24aef`, merged as `8337490`, plus independent Codex test commit `3b5ddf0`, merged as `f43d757`; no push.
- Independent test card changed exactly its two allowed paths and added 10 adversarial contracts covering real generator batches, three labels, feature leakage, shared extraction, artifact failures, protected projections, byte-stable rule/case state, and non-persistence.
- Coordinator gates after both merges: feature contract 10/10; Stage E wall 101/101; full console green; web 43/43 files and 278/278 tests; build green; eval 20/20 with F1 1.000; detector hash exact.
- Fresh training remained under the ten-minute budget at 13.03 s for 434 labeled rows; five-fold macro-F1 mean 0.9568. The local 2,501-event store had zero dispositions, so it contributed provenance context but no invented labels.
- `graphify update .` completed after the test merge: 3,742 nodes, 6,533 edges, 229 communities. The known `Incidents.tsx` partial-parse warning remains; TypeScript build is authoritative and passed.
- E7a is closed. E8 is the next executable card and becomes frozen after acceptance.

## E8 dispatched — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E8-dispatch.md`.

- Task `task_af321cc0bcc3`, dispatch `ctx_e58af9c7a6d8`, Claude Code, branch `feat/e8-frozen-referee`.
- Exact accepted-main base `e46d974`. The card owns the paired-system metric path, fresh disjoint benchmark seeds/entities, provenance, Reports/battle-card publication, and referee tests.
- A real clean-environment train and benchmark plus overlap/model-kill failure evidence are mandatory. No push or worker merge.
- E7b remains gated until this card is independently accepted and its referee paths are frozen.

## E8 accepted — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E8-accepted.md`. Worker report: `docs/STAGE_E_REPORTS/E8-worker.md`.

- Worker commits `aedd02a` (referee) and `11fb797` (publication), merged locally as `e5d9a5f`; no push, and the worker never merged.
- The dispatch survived a host-sleep interruption of the agent turn. The same worker was resumed on the intact worktree rather than replaced, so task `task_af321cc0bcc3` and dispatch `ctx_e58af9c7a6d8` kept their original provenance and settled once with `worker_done`.
- The resume carried a stricter entity rule: disjointness must cover every observed host/user/IP value, not just high-cardinality identifiers. `ASSERTED_ENTITY_KINDS` is now `ip, user, host, port, change_window`, proven with zero tolerance on each kind and cross-kind. Because the generator pins hosts and draws usernames from fixed vocabularies, seed choice alone could not satisfy this; a benchmark-only deterministic token remap of log lines and matching manifest raw values makes it satisfiable, and no generator or training file was touched.
- Coordinator verification, run independently of the worker's own report: detector sha256 `364577c5…577a4a876` unchanged; branch never pushed and absent from every remote; ten changed files all inside the allowlist with no detector, rules, eval-corpus, model/training, or dependency file among them; working tree clean.
- Coordinator gates on merged main: harness tests 37/37 both with sklearn 1.7.2 and with it absent; console suite 0 FAIL; eval 20/20 with precision/recall/F1 1.000 and 0 false positives; web 43/43 files and 282/282 tests; `npm run build` green.
- Both mutation exercises were reproduced by the coordinator, not taken on trust. A benchmark seed drawn from the training set exits 2 with `BENCHMARK REFUSED`, naming the sidecar's real training seeds `20260902–20260915` against the frozen benchmark seeds `20270302–20270304`. Killing the model leaves every rules number and miss list byte-identical and yields `available: false` with a stated reason and `totals: null` — an honest unavailable state, never a scored zero.
- **Amended 2026-09-02** (see `docs/STAGE_E_REPORTS/E8-leakage-interrogation.md`): the false-positive total below is canonical-format only — the all-formatter total is 84, all suppressed. Learned recall of 1.000 is line-level; **finding-level learned recall is 0.9444 (85 of 90)** because the model dropped five `ioc_observed` findings on the crown-jewel host in `INC-4a7f` as `benign-expected` at up to 0.992 confidence, whose cited line other kept findings also covered. "Matches every positive" does not hold at finding level. Rules numbers are unaffected.
- Measured on the frozen benchmark: rules score 1.000 precision/recall/F1 with 0 misses on all three positive scenarios and raise 21 false positives across the negatives; the learned system matches every positive and suppresses all 21, also with 0 misses. Both systems list their misses verbatim and carry one run id plus model provenance.
- Negative scenarios carry `precision_defined`/`recall_defined`, so a 0/0 renders `n/a` rather than a measured zero. The standing synthetic-scope sentence is retained and the learned system stays advisory.
- E8 is closed. The referee logic, its tests, and benchmark seed selection are now frozen; E7b modifiers may not edit them. E7b is unblocked.

## E8 leakage interrogation ruled; E7b held — 2026-09-02

Report: `docs/STAGE_E_REPORTS/E8-leakage-interrogation.md`.

- Leakage **cleared** on four independent grounds: `features()` emits counts and family flags only, so entity values never reach the model and value overlap cannot leak in principle; positive and negative scenarios share the same three hosts, so criticality is not a scenario shortcut; the benchmark org context copies each asset's real criticality and invents nothing; and on five never-used seeds (`20280411–20280415`) the learned system suppressed all 35 rules false positives with zero line-level misses and zero entity overlap. The methodology is ratified. The disjointness-surface note stands as written: the assertion defends a real surface, narrower than its name implies.
- The interrogation surfaced a publication defect and a second finding, both adopted: finding-level learned recall is 0.9444 (85 of 90), not the published line-level 1.000, because five `ioc_observed` findings on the crown-jewel host in `INC-4a7f` were dropped as `benign-expected` at up to 0.992 confidence; and `criticality_rank` carries 41.5% of feature importance with a backwards gradient — raising a host to crown-jewel flips 28 of 85 true detections to DROPPED, lowering it flips 33 of 84 suppressions to KEPT.
- `docs/STAGE_E_REPORTS/E8-accepted.md` is amended in place rather than reworded away; the original paragraph is retained under a correction block.
- **E7b round 1 is HELD.** The metrics amendment lands first as owner-authorized card E8m — finding-level recall published beside line-level with both denominators labelled, false-positive totals labelled with format scope (84 all-formatter headline, canonical 21 as a labelled subset), and the criticality sensitivity recorded as a named finding rather than a footnote. E8m is additive publication only: every currently published value must come out byte-identical and the frozen seeds, remap and freshness assertion may not move. The referee re-freezes on E8m acceptance.
- Round 1 then dispatches against a named target — the crown-jewel IOC dismissals and the backwards criticality gradient — graded on the standing two-run pattern, with success defined as finding-level recall regaining ground without losing the false-positive suppression result.
- F0 was **not** re-dispatched: it is already built, merged (`01c88dc`) and accepted (`7bd6796`). The dispatch-dedup check worked. Its one unmet acceptance bar was screenshot evidence, dispatched as the narrow evidence-only card F0-EV; acceptance bars are not retroactively waived.
- Dispatched: E8m `task_4425dd303a37` / `ctx_4c703b40e9b1`, F0-EV `task_899c657d856c` / `ctx_6eefe7beee5b`, both Claude Code, both local-only.

## F0-EV base near-miss — doctrine hardened, 2026-09-02

- Orca placed the F0-EV worktree at `b836114`, **30 commits behind local main and lacking the F0 merge `01c88dc`**. The runbook legibility code the card existed to photograph was not present at that commit. Uncaught, the card would have produced real screenshots of the pre-F0 UI and reported the acceptance bar unmet — a false negative indistinguishable from a genuine finding.
- **Credit where it belongs: the worker stopped and asked.** Its card told it to stop unless the branch was exactly `feat/f0-evidence`; the branch was `Ankit512/f0-evidence`, Orca's own naming convention. The worker judged this "looks like the Orca workspace naming convention rather than a wrong branch", and rather than proceeding or silently stopping, it asked — and volunteered the base commit unprompted, which is what exposed the real fault. That instinct is worth more than the guard that triggered it.
- **Failure class named:** evidence produced against the wrong tree is the screenshot form of the reconstructed audit — honest-looking, procedurally clean, and false. It is likeliest precisely on evidence cards, because those are the cards where nobody re-checks the tree. Recorded in guardrail 6.
- **The guard was lucky, so it is replaced, not thanked.** The branch-name check fired for a cosmetic reason and caught a substantive problem once; luck is not a control. Guardrail 9 now makes `base:` a standing field on every card, verified twice — by the orchestrator at dispatch from actual worktree provenance, never assumed to land on current main, and by the worker pre-edit via `git merge-base --is-ancestor <base> HEAD`. The base check does the stopping; the branch-name check is demoted to a warning, because a guard that alarms on cosmetics trains workers to override alarms. Evidence-producing cards additionally verify that the specific artefacts they are evidencing exist at HEAD before capturing: grep-the-tree extends to photograph-the-tree.
- Fault ownership: the dispatch, not the worker. The card specified a branch and never specified or verified a base.
- Also handled this dispatch: Orca setup failed on both worktrees, leaving `web/node_modules` missing; both workers were told to `npm --prefix web install` and record the deviation. E8m's base (`9d01bd9`, one coordinator-docs commit behind main, full E8 referee present) was ruled acceptable and it was told explicitly **not** to rebase — a tidiness rebase would have been needless risk against files it may not touch.

## E8m accepted, E7b round 1 dispatched — 2026-09-02

- **E8m accepted** and merged as `5de9511`; report `docs/STAGE_E_REPORTS/E8m-accepted.md`. The referee is **re-frozen**, now including the finding-level recall path, the format-scope path, the criticality counterfactual and their tests.
- The byte-identical constraint was verified by the coordinator independently of the worker's own walker: a detached worktree at the base commit and the amended head, run against the **same model artifact**, flattened to leaf key paths — 3,615 before, 3,861 after, **0 removed, 0 changed** except `provenance.branch` (an artefact of the detached base worktree) and the expected volatile `run_id`/`run_date`/`commit`/`tree`. 246 added paths, all additive.
- All three amendments reproduce the interrogation's ground truth exactly: finding-level learned recall 0.9444 (85/90) with the five `ioc_observed` drops published verbatim at up to 0.992 confidence; false-positive totals scoped by format (84 headline; canonical 21, jsonlog 21, rfc3164 24, rfc5424 18); `criticality_rank` importance 0.4146 with suppressions 84/33 flipping/51 robust and true detections 85/28 flipping/57 robust, direction published per band via `kept_at`.
- **Pre-existing failure confirmed pre-existing:** `tests/test_battlecard_efficacy.py` fails identically at the base commit, at the amended head, and on main. Its assertion is stale — it expects exactly three scenarios from a harness that has returned six across three seeds since the negative scenarios were added. It is not in the standing gate set, which is why it rotted unnoticed. Not fixed: outside E8m's allowlist.
- **F0-EV accepted** and merged; the evidence card found a real defect on its first run — runbook Steps render **unnumbered** because `.is-rb-steps__list{display:flex}` blockifies the `<li>`s of a semantically correct `<ol>`, while `padding-left:17px` still reserves the marker gutter. F0's 15 component tests passed throughout because they assert structure, not rendered markers. Also an accessibility defect: `list-style:none` on an `<ol>` drops list semantics for VoiceOver. Reported, not fixed, per the card's zero-code-change rule. **The fix is not yet queued — awaiting the owner's sequencing call.**
- **E7b round 1 dispatched:** `task_04fa102b33a2` / `ctx_966546338f31`, Claude Code, base `f5fe072`. Named target: the crown-jewel IOC dismissals and the backwards criticality gradient. Success is finding-level recall regaining ground **without** losing the false-positive suppression result; trading one for the other is not success.
- **One pre-authorized allowlist expansion recorded on the card (guardrail 10):** `tests/test_e7a_feature_contract.py` asserts as a non-vacuity control that changing `criticality` moves the feature vector. Removing or re-encoding `criticality_rank` — one of the sanctioned candidate directions — would break it. The worker may amend that one control in the same commit, substituting another permitted fact, and may **not** weaken any `FORBIDDEN_KEYS` or leakage assertion. The amendment is graded.
- **Guardrail 9 justified itself on its first use.** The E7b worktree was again created at `b836114`, 37 commits behind — the same stale commit as F0-EV. Caught by the orchestrator base check before the worker's first edit; the clean worktree was reset to `f5fe072` and the worker notified. The failure is systematic, not a one-off: `worker-start --worktree new-top-level` has landed on a stale ref every time it has been checked. Guardrail 9 now records this as measured fact and makes the orchestrator-side reset standing.

## E7b round 1 base halt — worker's diagnostic folded into doctrine, 2026-09-02

- The E7b R1 worker ran the guardrail-9 base check, found it failed, made **zero edits**, and halted to ask — exactly as carded. By the time it asked, the orchestrator had already reset the worktree to `f5fe072`, so its report described the pre-reset state; the condition was resolved and no fast-forward was needed.
- **Its diagnosis was sharper than the guard it was given.** It ran the check in reverse — `git merge-base --is-ancestor HEAD <base>` **succeeds** — and concluded the worktree was **stale, not divergent**, then proposed a zero-risk `--ff-only` remedy rather than simply reporting a failure. The guard as written only answered "is the base present", which cannot distinguish a safe fast-forward from a genuinely wrong tree that must halt.
- Guardrail 9 now carries that test: a failed base check is **diagnosed, not just reported**. Reverse-ancestor success means stale and safe to fast-forward or reset; neither direction holding means diverged, and work halts for the orchestrator.
- This is the **second** worker stop-and-ask to catch this class of problem (F0-EV was the first), against a worktree tool that has landed on a stale ref on every occasion checked. Both instincts were correct and both are logged with credit.

## E7b round 1 graded; round 2, E8m2 and F0-FIX dispatched — 2026-09-03

- **Round 1 graded an honest partial and NOT merged** (`docs/STAGE_E_REPORTS/E7b-r1-graded.md`, `944c47e`). Merging would have locked a 0.0333 regression into the primary published metric. Its branch is intact for comparison.
- **Logged with credit — the label-proxy diagnosis.** The worker measured that the two named defects were one: `server-01` is the only crown-jewel asset, and in training every `benign-expected` row is crown-jewel while every `false-positive` row is standard, so `criticality_rank` was a label leak wearing a risk-signal costume. That is the finding of the round, and it is better than the brief it was given.
- **Logged with credit — the refused trade.** A declared cost weighting recovered 0.9444 exactly but created 7 false positives on the same rule. The worker rejected and reverted it rather than buy recall with suppression; verified, `tools/train_triage.py` carries no diff.
- **Logged — the coordinator's correction of the stopping claim.** Round 1 justified stopping on "an identical feature vector across all three labels". Measured: 14/14/14 rows, **nine** distinct vectors, **four** ambiguous, 19 of 42 rows — roughly 45% ambiguous and 55% separable. Directionally right, materially overstated. Headroom exists that the round concluded did not.
- **New doctrine line, guardrail 6:** claims that justify STOPPING get measured exactly like claims that justify shipping. "Irreducible", "impossible", "undecidable", "already covered" and "no headroom" are measurable assertions, and they are where verification is easiest to skip because the conclusion is a non-action.
- **A false premise in the round 2 brief was caught before dispatch.** The generator-diversity candidate was authorized on the basis that "the locked benchmark manifest is untouched by construction". There is no stored manifest: `efficacy_harness.py` calls `attack_generator.generate()` at runtime (~line 1250) and takes its default scenario set from `generator.SCENARIOS` (~line 1610). Editing the generator — even purely additively — would therefore change what the frozen benchmark measures and make before/after incomparable. Rather than block the intent, the freeze hole is being closed first.
- **Dispatched, all base-verified and reset by the orchestrator before first edit:**
  - **E8m2** `task_5effc7eaee28` / `ctx_a39adf319191` — third referee amendment, additive only: per-finding-type recall by `rule_id` in the scorecard (so a rule-class loss can no longer hide inside an aggregate, which is exactly how both the five `ioc_observed` drops and the eight `infra_unknown_high` drops hid), plus an explicit frozen benchmark scenario tuple so generator additions cannot leak into the benchmark. Re-freezes on acceptance.
  - **E7b round 2** `task_c4c9cf449f9e` / `ctx_573da9d1477e` — from the same base as round 1, independence preserved: it may read the round 1 grading but not its diff. Carries round 1's measured facts including the corrected 45%-ambiguous figure, and the generator direction is permitted **additively only**, with byte-identical proof required for the existing six scenarios.
  - **F0-FIX** `task_c5347ee3033c` / `ctx_1dd66e0b1d3e` — the steps-numbering defect, framed as the accessibility fix it is (`list-style:none` on an `<ol>` drops list semantics in VoiceOver). The card's stated point is the test: F0's 15 tests passed for the defect's whole life because they assert structure, never rendered result.
- **Guardrail 9 note:** all three worktrees were again created at `b836114` — the fifth, sixth and seventh consecutive occurrences. Each was diagnosed STALE via the reverse-ancestor test contributed by the round 1 worker, confirmed clean, and reset before any edit.

## Systemic rulings — 2026-09-03

- **Doctrine, guardrail 6, extended upward:** an owner's premise is grepped exactly like a worker's claim, before any card is dispatched on it. A ruling resting on a false premise about the tree produces confidently wrong work, and the orchestrator is the last reader positioned to catch it. This was ratified after the round-2 generator premise was checked and did not hold.
- **Correction to the E8 freeze, recorded in `E8-accepted.md` itself rather than only here.** E8's acceptance language froze "the referee logic, its tests, and benchmark **seed selection**" — narrower than the "locked, hash-recorded manifest" it was later remembered as. There was never a stored manifest to lock: the referee generates at runtime and took its scenario set from `generator.SCENARIOS`. The freeze was real **as seed-pinning only**; benchmark *composition* was never frozen, and any added scenario would have silently changed what was measured under correctly-frozen seeds. Nothing had added one, so nothing revealed it. **E8m2 makes the freeze real for the first time** — a new property, not a refinement.
- **Standing setup preamble added to `ITSOC_ORCHESTRATOR_PROMPT.md`:** base check first (with the stale-vs-diverged reverse test), `npm --prefix web install` performed silently as expected setup rather than logged as a deviation eight times, detector freeze verified either side, branch name a warning only.
- **Card HK1 dispatched** (`task_0ca0be461a6b` / `ctx_6a73172e4939`) to root-cause the stale worktree base rather than keep paying the per-dispatch reset tax. Diagnosis before fix; accepted by attack — a fresh dispatch must land on current main with no reset; guardrail 9 stays afterward regardless.
- **HK1 reproduced the defect on its own worktree** — the 8th consecutive placement at `b836114` — recorded it as evidence and continued diagnosing without edits.
- **Root-cause lead, found while capturing HK1's specimen and handed over as a hypothesis to verify:** `refs/remotes/origin/main` **is** `b836114` exactly, while local `main` is 41 commits ahead. Orca appears to resolve a new worktree's base from the remote-tracking ref rather than local `main`. If confirmed, the root cause is an **interaction between the tool's default and this project's own doctrine**: nothing is ever pushed, so `origin/main` is frozen at the last fetch and can never advance, which is why the stale commit is always the same one and why the defect cannot self-heal. The doctrine that protects the repo is what starves the ref.
- **Both halting workers credited.** E8m2 and F0-FIX each ran the reverse-ancestor test, classified STALE rather than DIVERGED, reported instead of self-fixing, and named the concrete consequence: E8m2 that building on `b836114` would reimplement or conflict with the E8m amendment it extends; F0-FIX that commit `4cb5b17` was absent, so it "cannot fix a defect whose code is absent." That second one is the F0-EV failure class — work against a tree lacking the thing being worked on — caught **by design rather than by luck**, which is the difference the doctrine exists to produce.

## E8m2, F0-FIX and HK1 accepted — 2026-09-03

- **E8m2 accepted** (`5bbf4dd`, report `E8m2-accepted.md`). Per-rule finding recall earned itself on its first run: the aggregate 0.9444 resolves to `ioc_observed` at **0.5833 (7/12)** while every other rule sits at 1.0. A rule class at 58% was invisible inside a 94% aggregate, and it is the threat-intel class on the crown-jewel host in the flagship scenario. Byte-identical verified independently — 13,466 to 14,466 leaf paths, **0 changed, 0 removed**, 1,000 added.
- **The benchmark scenario freeze verified BY ATTACK, both directions.** Injecting a rogue scenario into `generator.SCENARIOS` at runtime left the benchmark's resolved set unchanged; removing a frozen scenario raised `BenchmarkProvenanceError` rather than silently measuring less. Guardrail 7 applied to a freeze: a guard never seen to fail is not yet a guard. Referee re-frozen; harness 69/69 with and without sklearn.
- **F0-FIX accepted** (`54a012f`, report `F0-fix-accepted.md`), and **the card's diagnosis was half the cause**. `display:flex` was cause one; the worker found Tailwind's preflight `ol,ul{list-style:none}`, loaded before `itsoc.css`, as cause two — both confirmed by the coordinator at `main.tsx` import order and `preflight.css:308`. Un-flexing alone would have rendered bare AND left the Safari/VoiceOver semantics defect fully intact. A fix addressing only the documented cause would have looked correct and shipped the accessibility half of the bug.
- **The F0-FIX worker caught its own vacuous test.** Its first computed-style assertion on `list-style-type` passed against a deliberately broken partial fix, because jsdom propagates `display` but not `list-style-type`. It found this by reverting against that partial fix, moved cause 2 to a source assertion, and documented exactly what jsdom can and cannot prove. It also measured that the old suite scores **290/290 against the broken stylesheet**, confirming the card's premise by experiment rather than assertion. `RunbookCard.tsx` untouched — CSS was the seam where the damage was done.
- **HK1 accepted** (`e79d73f`, report `HK1-worker.md`, 291 lines). Diagnosis before patching, mechanism from git's own reflog across **seven** historical Orca branches: `branch: Created from refs/remotes/origin/main`. The Orca repo record carried **no base-ref field**, so it fell back to the GitHub default branch. Root-cause moment: `refs/remotes/origin/main@{0}`, `update by push`, **2026-09-02 08:31:11** — the last push this repo ever made, after which the standing do-not-push doctrine guaranteed the base could never move again while local main advanced 41 commits. That is why all eight failures hit the *same* commit rather than drifting: **the doctrine that protects the repo is what starved the ref.**
- **The coordinator's proposed mitigation was wrong and the worker rejected it.** The lead suggested `git update-ref refs/remotes/origin/main main` as a doctrine-safe refresh, on the assumption that `origin/main` was merely unfetched. HK1 ran `git ls-remote origin main` and found the real remote genuinely at `b836114`. The suggestion would have made the remote-tracking ref assert a value the remote does not have — corrupting ahead/behind, undermining `--force-with-lease`, and silently reverting on the next fetch. **An honestly stale ref beats a confidently wrong one**, and the difference was one command the coordinator did not run. Recorded as its own section in the HK1 report.
- **Fix and proof, both verified by the coordinator:** `orca repo show` now records `worktreeBaseRef: main` where the key was absent; a fresh worktree created with no `--base-branch` and no reset landed exactly on current local main with its reflog reading `Created from refs/heads/main`; and `origin/main` remained `b836114` throughout — so the base resolution moved, not the remote. Out-of-repo footprint is exactly one `set-base-ref` call plus a probe worktree, since removed.
- **Guardrail 9 stays in force**, now as the detector rather than the fix: it still covers worktrees created before the fix, other repo registrations, and any future regression in base resolution. Belt after buckle.
- Standing finding across three cards this round: **a suite that asserts structure while the rendered result is broken proves less than its pass rate suggests** — the same shape as line-level recall reading 1.000 while a rule class sat at 0.5833, and as 15 F0 tests passing for a defect's entire life.

## E7b round 2 PASS; gradient parked; Stage E closing — 2026-09-03

- **Round 2 PASSED and is merged as the current model** (`76c8a10`, graded `E7b-r2-graded.md`). Finding-level recall **0.9444 → 1.0000 (90/90)**, `ioc_observed` per-rule **0.5833 → 1.0 (12/12)**, dropped true findings **5 → 0**, learned false positives **0 in every format**, line-level misses 0.
- **The diagnosis, credited:** the model's feature function was **disagreeing with the rules' own taxonomy**. `ioc_observed` matched no family regex, was orphaned into `rule_family_other` alongside every `infra_unknown_*` rule, and inherited a `benign-expected` label it carries on **zero of its 42 training rows**. The fix names the family the rules already name (`rule_context.py:303`). That is legible intelligence in one sentence: *the model got better by being made to agree with the rules about what things are called.* The E7a feature contract is **byte-unchanged** — no amendment where round 1 needed one — which confirms this was a repair, not a renegotiation.
- **E8m2's pin recorded its first live save, same day it was built.** Round 2 appended a generator scenario; the benchmark measured exactly the frozen six, `scenarioSetIsFrozen: true`, and the existing six hashed **72/72 artefact pairs identical** before and after. The worker independently confirmed the hole from the pre-pin side — on its base the new scenario *did* enter the harness default list.
- **The eight-detection trade is a measured property, not an artefact.** Two rounds, different levers — round 1 deleted `criticality_rank`, round 2 added a standard-host benign scenario — converged on the identical cost of closing the gradient: **eight true `infra_unknown_high` detections**. We know the price because we measured it twice.
- **OPEN-15 registered and parked** by owner ruling: the backwards criticality gradient, halved not eliminated, with the measured trade attached. Not an E9 item — E9 is retrain automation; a richer projection is model research. Stated in the E8 interrogation report's sensitivity section so the published record matches reality, and flagged as a better card once real dispositions exist via E0/E2.
- **Coordinator mistake, self-reported and amended:** the grading worktree was created with `git worktree add -f … main`, checking `main` out a second time, so the evaluation merge advanced `main` and desynchronised the primary worktree. Content was correct; the commit message would have read "grade: merge r2 for evaluation" in an accepted card's permanent history. Re-synced with nothing at risk and amended. **Guardrail 9 now requires grading and evaluation worktrees to be `--detach`, never checked out on a live branch.**

## E9 dispatched — 2026-09-03

- **E9** `task_eb719f60d7e0` / `ctx_677ff81e0676`, **Codex**, branch `feat/e9-retrain-automation`, base `6b490ea`. The last Stage E card: `scripts/retrain.sh` — regenerate → train → benchmark → refuse-regressed-install, printing both scorecards and exiting nonzero on refusal.
- **Two additions from this round's learnings, written into the card as first-class requirements.** (1) The regression comparison uses the **amended scorecard** — finding-level *and* per-rule recall — never an aggregate alone; a candidate holding aggregate recall while losing a rule class must be refused, because aggregate-only comparison is precisely the hiding mechanism E8m and E8m2 were built to close. (2) The script **asserts its own preconditions before scoring**: the frozen scenario tuple intact and `scenarioSetIsFrozen` true, and benchmark seeds disjoint from the candidate's recorded training seeds read from its provenance sidecar. If either fails it aborts *before* any number is computed. The E8m2 pin and the E8 sidecar check become the automation's own preconditions — a benchmark that cannot prove its own freshness must not produce a number at all.
- Acceptance is **by attack**, per guardrail 7: four refusals must be demonstrated, not asserted — a deliberately regressed candidate, a per-rule-only regression with the aggregate held, a tampered scenario tuple, and an overlapping seed — with the installed model proven byte-identical after a refused run.
- Card provenance noted honestly on the card itself: no standalone E9 text exists in `docs/`, so the spec is the owner's dispatch instruction; the worker is told to STOP and report if it finds a fuller definition that contradicts it.
- **HK1's fix confirmed working in production on the first dispatch after it landed.** The E9 worktree was created at `6b490ea` — current local main — with **no reset required**, and its reflog reads `branch: Created from refs/heads/main`. Eight consecutive dispatches had previously landed on `b836114` from `refs/remotes/origin/main`. Guardrail 9's base check remains in force as the detector.

## E9 rejected on first report, then accepted on demonstrated evidence — 2026-09-03

- **E9's first `worker_done` said `succeeded` while deferring all four refusal demonstrations "to the review environment".** That is a guard never seen to fail wearing a green label. It was rejected. The stage's own precedents name the family exactly: F0's fifteen structural tests passing for a rendering defect's entire life, and a 1.000 aggregate recall sitting over a rule class at 0.5833.
- The E9 refusal gate is the most load-bearing artifact in the product's future operations — it is the thing that stops a silently-worse model from installing, forever, after the fleet is gone. **That gate, of all gates, gets proven by attack.**
- The blocker was removed rather than accepted: the worker claimed no installed model artifact existed; one did, in the E7b-r2 worktree, and its `console/triage_model.py` was verified byte-identical to current main — so that artifact *is* the current installed model. The same worker was restarted on the same terminal with exact-evidence requirements.
- **Standing doctrine, guardrail 5:** completion labels are honest surfaces. `--outcome succeeded` with the stated acceptance evidence missing is a false label; unmet acceptance ships as `failed` or an explicitly named partial, in the subject line.
- **The line this stage runs on, recorded verbatim: a demonstration that fails is the most valuable outcome available — a real defect found by attack, not a failure of the card.**

## Mini-scope addendum: E4 copilot-prose un-gated; CB-1 dispatch HELD — 2026-09-03

- **Owner decision, logged as such:** E4's **copilot-prose part is un-gated** by owner ruling. E2, E3 and E5 remain interview-gated. This reactivates the fleet for a single card (CB-1), after which it stands down again.
- **CB-1 · Copilot × learned-triage integration** was NOT dispatched. The pre-dispatch premise check (guardrail 6 — owner premises are grepped like worker claims) found the card's own constraint blocks two of its four required behaviours.
- **The contradiction, measured.** The card constrains the integration to `ADVISORY_KEYS` fields and states that a field outside them "is a stop, not an addition". `console/runbooks.py:79` defines `ADVISORY_KEYS` as containing `aiTriage`, `aiSeverity`, `aiConfidence` — but **not `aiAgrees` and not `aiLabel`**, and `_ADVISORY_WORD_RE` does not match either name. Yet the card's per-incident behaviour requires **agreement status** (`aiAgrees`) and its own worked example quotes the **label** ("reads it benign-expected at 0.87" — `aiLabel`), and the cross-incident disagreement list is impossible without `aiAgrees`. Deriving agreement by comparing `aiSeverity` to the rule severity is excluded by the card's own "never recomputing" rule.
- **The more important finding, independent of CB-1: this is a latent gap in the eligibility guard.** `aiAgrees` and `aiLabel` are model-output fields that the runbooks advisory guard neither lists nor pattern-matches. `console/triage_model.py`'s own forbidden-key list does cover them, so the model cannot read them as features — but if any eligibility path ever read `aiAgrees`, the runbooks guard would not catch it. Verified that nothing in `runbooks.py` or `soc.py` reads either field today, so there is **no live defect** — only an uncovered surface.
- Held for owner decision rather than dispatched under an assumption: proceeding either violates the stated constraint or guts half the card.
- **Routing note:** Antigravity is again absent from the available agent tiers (same as at F0), so the rail-UI evidence portion routes up to Claude Code under the standing routing policy, logged as the fallback.

## CB-0 dispatched; owner deviation logged — 2026-09-03

- **Owner deviation, logged as such at the owner's instruction:** the CB-1 card constrained copilot data access to `ADVISORY_KEYS`, which is an **eligibility denylist**, not a data-access allowlist. Using a denylist as an allowlist is a category error, and it is what made the card self-contradictory — it forbade the very fields (`aiAgrees`, `aiLabel`) two of its four behaviours require. Caught by the pre-dispatch premise check; nothing was dispatched on it.
- **CB-1's constraint is restated** by owner ruling: the copilot may read model-emitted advisory fields, defined as **fields the guard fences**. Any field the guard does not fence is a stop. That makes the guard's coverage the definition, which is why the guard is being fixed first.
- **Option 3 (deriving agreement at display time) stays excluded, now for the right reason:** display-time derivation creates a **second computation of a stored fact, and two computations drift.** The earlier reason — "it recomputes" — was correct but shallower.
- **CB-0 dispatched** `task_2e9d679fc130` / `ctx_1d545b7f2895`, Claude Code, base `8436df9`. Owner-authorized engine change to `console/runbooks.py`, fixed **at class level, not instance level**: add `aiAgrees`/`aiLabel` to `ADVISORY_KEYS`, and extend the pattern so the `ai<Something>` model-output prefix is covered **by class rather than by enumeration** — otherwise the next `aiWhatever` is equally unfenced. Both mechanisms retained: enumeration as the explicit record, pattern as the safety net.
- Accepted **by attack**: a novel unlisted `aiMadeUpField` poisoned onto both an incident and a finding must be caught on pattern alone, and the existing guards must be shown still biting on a deliberate violation. Over-match was pre-checked by the coordinator — `ai[A-Z]` matches none of the 13 rule-owned keys and none of the three eligibility params — but the worker is told to verify that itself rather than take it on trust.
- **Antigravity fallback to Claude Code ratified as standing policy.** Antigravity was absent at F0 and is absent again; rail-UI evidence routes up to Claude Code without a per-card decision.
- CB-0's worktree landed on the correct base with **no reset required** — the second consecutive clean placement since HK1's fix, and the first since `origin/main` was pushed current.

## Setup-script root cause; guardrail 13 — 2026-09-03

- **Root cause of every setup failure this stage, found by inspecting a routine status message rather than by design.** Orca's repo record carried `hookSettings.scripts.setup = "pnpm install"` with **`mode: auto`** — auto-detected, not chosen. Three things wrong for this repo: `pnpm` is not installed (`pnpm: command not found`, exit 127), the project uses **npm** (`web/package-lock.json`, no pnpm lockfile), and the script runs at the **worktree root** while the JS project lives in `web/`. Nine worktrees, nine identical failures, one self-install per card.
- `orca project setup-update` exposes setup *policy* and metadata but not the script body, so no worker card could close this — it is a Settings-level field. **Owner is correcting it in the UI to `npm --prefix web install`.**
- **The family, named: auto-detected infrastructure config is unverified config.** This is the same shape as the `worktreeBaseRef` defect HK1 root-caused — both were `mode: auto` guesses that were simply wrong, and **this session found both by paying their tax repeatedly, not by inspection.** Roughly eighteen deviations across the two, against a thirty-second check.
- **Guardrail 13 added** to carry it: anything the tooling inferred rather than a human chose — base ref, setup script, package manager, default branch — gets checked against the repo's actual conventions at stage start, before the first dispatch. And: **a workaround that outlives its cause becomes cargo cult** — when the root cause is fixed, retire the workaround and say so.
- **PENDING RETIREMENT:** on the first dispatch after the UI correction, verify setup succeeds cleanly, then **remove the `npm --prefix web install` self-install step from the standing card setup preamble** in `docs/ITSOC_ORCHESTRATOR_PROMPT.md` and record the retirement here. Until verified, the preamble stays — retiring a workaround before its cause is confirmed fixed is the same error in the other direction.

## CB-1 accepted — the learned second opinion, attacked four ways — 2026-09-06

- **Accepted and merged.** Four behaviours; four attack demonstrations reproduced by the coordinator
  independently of the worker's transcript, plus a fifth vector the card did not name (a newline
  payload forging a fake system turn — flattened, quoted, refused).
- **The option-3 exclusion was tested, not assumed.** Stored `agrees: True` with the severities
  diverging (rules `HIGH`, model `INFO`). A display-time re-derivation would have said *disagrees*. It
  said *agrees*, as stored, and the disagreement list held zero items.
- **The best line in the diff is in `serve.py`:** a learned answer is terminal on both the JSON and
  streaming paths and never reaches the LLM, "because a model paraphrase of a stored confidence is a
  second, drifting number." Unprompted, and the right instinct.
- **Coordinator premise error, guardrail 6.** The card asserted `aiSeverity`, `aiConfidence`,
  `aiAgrees` and `aiLabel` are all fenced. `aiConfidence` and `aiAgrees` **do not exist as leaf keys** —
  `triage_model` emits `confidence`/`agrees` inside `aiTriage`. Not grepped before dispatch. Accepted
  on the containment reading, with the safety property verified rather than assumed (container fenced
  twice, `_assert_fenced()` re-derives at read time, no production code hoists the leaves). Logged as
  **OPEN-16**; the strict-leaf alternative is a cheap rename in a path CB-1 was forbidden to touch.
- **Second pre-existing failure found:** `console/test_auth_security.py` fails identically at base
  (auth gate off unless `ITSOC_AUTH=1`), alongside the known `tests/test_battlecard_efficacy.py`. Both
  outside the standing gate set. That set now has two known holes in it.

## CB-1-FIX accepted — both review findings closed — 2026-09-06

- **CodeRabbit found two Major defects in accepted, merged CB-1.** Both real, both re-verified by
  the coordinator before dispatch: the learned router over-captured generic "the model" prose (and,
  with an incident selected, answered about *that* incident regardless of the question), and
  `_copilot_extras` performed an unconditional `incidents.json` write on every copilot request.
- **Both fixed and demonstrated.** Two-tier router — naming phrases route alone, a generic model
  reference never reaches the selected-incident fallback; and `soc.list_incidents_readonly()`, a
  pure extract-method refactor leaving every existing caller byte-identical. Coordinator probe:
  `list_incidents` writes `['incidents.json']`, `list_incidents_readonly` writes `[]`, outputs
  identical.
- **The worker found a bug the card did not name:** the copilot *suggests* follow-up questions,
  and five of those suggestion strings would no longer have routed under the narrowed router — the
  copilot offering a question it could not answer. Fixed and pinned by test (j).
- **The coordinator found one neither worker did:** the shipped CB-1 evidence screenshots use a
  prompt that no longer routes. Annotated in `CB1-evidence/README.md` rather than re-shot; the
  trade-off is recorded rather than silent.
- **All CB-1 properties re-verified after the fix** — four attacks, the fake-system-turn vector, the
  model kill, and the no-re-derivation probe. Gates green; detector unchanged.
- **The lesson, kept narrow:** the four attacks were the right test of the wall and said nothing
  about the router's negative space or the write path, because no acceptance criterion asked. A
  negative-space table is now the standing shape for routing changes.

## OPEN-16 ratified — containment kept, and pinned — 2026-09-06

- **Owner ruling: keep the containment reading.** A leaf inside a fenced advisory container is
  fenced. No rename in `triage_model.py`; `aiConfidence`/`aiAgrees` stay as denylist entries for
  names nothing currently emits — costs nothing, fails safe.
- **The ruling rested on a once-verified assumption, so it is now an invariant.** Containment is the
  only belt for five of the eight leaves the copilot reads. `tests/test_stage_e_wall.py` gains
  **part H** (126 → **135**): the container is fenced twice over and is not rule-owned; no leaf is
  hoisted out of the live `soc._public_incident()` projection; dropping `ADVISORY_KEYS` removes every
  leaf; and `copilot.LEARNED_LEAVES` must stay a subset of what part H covers.
- **Proven to bite.** A negative control hoisted `confidence` onto the projection: the wall failed
  two checks and exited 1. A guard that cannot fail is not a guard — the F0 lesson, applied before
  the fact rather than after it.
