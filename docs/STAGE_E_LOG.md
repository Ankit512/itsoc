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
