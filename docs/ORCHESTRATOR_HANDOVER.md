# itsoc — orchestrator handover

**Written:** 2026-09-07. **State at handover:** `main` = `f28c954`, `HEAD == origin/main`, tree clean,
detector frozen `364577c5…4876`, `scripts/gate.sh --web` GREEN 23/23.
**In flight:** DEP-1 (see §6). Everything else is stood down.

You are taking over as orchestration coordinator. Read `CLAUDE.md` and `GUARDRAILS.md` first — they
are the contract. This file is what those two do not tell you: the standing posture, the lessons
that were bought expensively, and where the work actually stands.

---

## 1. The one thing to understand before dispatching anything

**Engineering has run ahead of evidence, and the constraint is not yours to fix.**

Every remaining build item — E2, E3, E5, F1, F2 — is *interview-gated*. The gate is Track A in
`docs/ITSOC_STAGE_E_ACTION_CARDS.md`, marked **"owner: Ankit; orchestrator not involved."** The file
says it plainly:

> **A3 · Book 3–4 demand interviews** — *"This card is the binding constraint. Everything in Track B
> is subordinate to it."*

No Track A progress is logged anywhere. Track B, meanwhile, shipped completely plus seven
post-closeout deliverables. **If you find yourself hunting for a card to dispatch, the honest answer
is usually that there isn't one.** A4 (the Torq competitive file) is the only Track A item the doc
marks delegatable; it was offered and the owner chose otherwise. Do not invent work to look busy —
say the queue is empty and stand down.

---

## 2. Standing doctrine you must not relearn the hard way

These are in `GUARDRAILS.md`, but here is *why* each exists.

**A demonstration that fails is the most valuable outcome available.** Owner's words, verbatim, kept
as a standing line. Attack demonstrations are the acceptance, not extras.

**`worker_done --outcome succeeded` with the card's stated acceptance evidence missing is a FALSE
LABEL.** E9's first report claimed success with every refusal demonstration deferred. It was
rejected and the same worker restarted on the same terminal with exact-evidence requirements.
Unmet acceptance ships as `failed` or an explicitly named partial.

**Claims that justify STOPPING get measured exactly like claims that justify shipping.** A worker
that stops must prove the blocker as rigorously as one that ships.

**Owner premises get grepped like worker claims, before dispatch.** This has now caught three false
premises — a "locked benchmark manifest" that did not exist, `ADVISORY_KEYS` used as an allowlist
when it is a denylist, and a card asserting `aiConfidence`/`aiAgrees` are leaf keys when they are
not. Two of those three were the coordinator's own. **Grep the card you are about to send.**

**Guardrail 9 — `base:` verified twice.** Every card carries a base commit; the worker runs
`git merge-base --is-ancestor <base> HEAD` before the first edit, and if that fails but the REVERSE
succeeds the worktree is STALE — report and wait, never rebase. Branch-name mismatches are a WARNING
only. **Grading worktrees must be `--detach`** — a grading worktree on a live branch once advanced
`main` with a misleading merge message.

**A guard that cannot fail is not a guard.** Every guard added must be shown to BITE: break the
thing deliberately, show red, restore, show green. This project shipped the can't-fail-guard defect
four times (fifteen F0 component tests passed for a rendering defect's whole life; line-level recall
read 1.000 while `ioc_observed` sat at 0.5833). Do not accept a new check without a negative control.

**Verifying a surface on the inputs it was built for says nothing about the inputs it was not.**
CB-1 passed four hand-reproduced attacks and still had two Major defects, because nobody asked about
the router's *negative space* or the *write path*. A negative-space table is now the standing shape
for any routing change.

---

## 3. How to run a card (mechanics)

The run is `run_9214da4ebb53`. Agent identity is `claude` (not `claude-code`).

```
orca orchestration task-create --run run_9214da4ebb53 --task-title "..." --display-name "X" \
    --spec "$(cat cardfile.txt)" [--deps '["task_id"]']
orca orchestration worker-start --run run_9214da4ebb53 --task <id> --agent claude \
    --worktree new-top-level --name <slug> --base-branch main --setup run
orca orchestration check --run run_9214da4ebb53 --wait --types worker_done,escalation,question \
    --timeout-ms 3600000
```

**Waiters get their OWN standalone call.** Chaining `check --wait` onto another command, or
backgrounding it with a stray `&`, has produced duplicate waiters twice. Run it in the background as
its own invocation.

Deliveries **replay until acked**, so nothing is lost — but ack them (`--ack <deliveryId>`) or you
will be re-notified forever.

**`--deps '["task_id"]'` is a real queue edge.** Use it to hold a card behind another rather than
holding it in your head.

### The setup failure you WILL see, fifteen-plus times

`hookSettings.scripts.setup` is `pnpm install` with `mode: auto`, pnpm is not installed, and the repo
uses npm in `web/`. **Every dispatch reports "Setup failed."** It is fully absorbed by the standing
card preamble, which tells the worker to run `npm --prefix web install` itself. Ack it and move on.

**Pending:** the owner is correcting the field in the Orca UI. On the first dispatch after that
lands, verify setup succeeds cleanly, then RETIRE the self-install step from
`docs/ITSOC_ORCHESTRATOR_PROMPT.md` and log the retirement. Owner's reasoning: *"a workaround that
outlives its cause becomes cargo cult."* Do not retire it unverified.

---

## 4. How to grade a card

**Do not read the worker's report and merge.** Re-run the evidence yourself. Every acceptance this
session found something the worker's own report did not.

1. Inspect the commit and diffstat; audit the allowlist (`git diff --name-only <base> HEAD`).
2. Verify the detector sha256 before and after.
3. Run `scripts/gate.sh --web` yourself in the worker's worktree. Expect **23 PASS**.
4. **Re-run the card's demonstrations independently**, against the code, not from the transcript.
5. **Add a probe the card did not ask for.** This has paid off every time — a newline/fake-system-turn
   injection vector on CB-1, a hoisted-leaf negative control on OPEN-16, a redaction-disabled control
   on GS-1 that proved a raw IP leaks into a report headed `REDACTED`.
6. Merge with `--no-ff` from the REPO ROOT (`cd` leakage into a worker worktree has twice produced
   "Already up to date"), write an acceptance doc under `docs/STAGE_E_REPORTS/`, append to
   `docs/STAGE_E_LOG.md`, push.

Commit messages end with the session attribution line the harness gives you.

---

## 5. The gate — read this before you trust any green

`scripts/gate.sh` is THE gate (GS-1, 2026-09-06). It runs **all 18 Python suites, 21 checks, ~71s**;
`--web` adds vitest + build for 23. CI runs the same script, so CI cannot be greener than a local
run. `CLAUDE.md` §6 names the gate, not individual suites — **naming suites in the contract doc is
what let two of them rot unnoticed.** Add a new suite to `scripts/gate.sh`, never to that line.

The gate enforces five rules on itself: never discard evidence, never let `tee` mask an exit code,
never stop at first red, never round a SKIP up to a PASS, and **never leave a suite unlisted** —
anything omitted is named with its reason in a DELIBERATELY OUT block it prints every run.

Invocation mode is load-bearing: the two `tools/` suites must run as `python3 -m tools.<name>` from
the repo root, or they die with `ModuleNotFoundError: No module named 'tools'`. That is `sys.path`,
not the tests.

---

## 6. In flight right now

**DEP-1** — `task_e3cfa6c0637c`, dispatch `ctx_27c0200e4063`, worktree `dep1-vitest`, base `f28c954`
(base check passed, no reset).

Closes the vitest CRITICAL (GHSA-5xrq-8626-4rwp, CVSS 9.8). **Minimal scope by owner decision:**
vitest `^2.1.3` → `^3.2.6` only. npm proposes 5.0.0 because it is latest, not because the fix needs
it — the vulnerable range is `<= 3.2.5`, and vitest 3 supports the vite 5 already installed.

Deliberately excluded, and the worker is told not to "helpfully" include them:
`react-router-dom` (production dep, moderate only, a routing major needs its own change) and `vite`
(high, **knowingly accepted**, dev-only, closing it drags the whole build toolchain).

**Grade it on one thing: the suite must still be exactly 44 files / 313 tests.** 313 → 312 is a
failure, not a rounding. If any test file needed changing, that is a stop, not a migration.

---

## 7. Open ledger

| Item | State |
|---|---|
| **OPEN-15** — backwards criticality gradient | `OPEN`, **parked by owner ruling.** Halved (importance 0.4146 → 0.2026), not eliminated; closing it costs **8 true `infra_unknown_high` detections**, measured twice by independent levers. Model research, not automation. Becomes a much better card once real dispositions exist via E0/E2. |
| **OPEN-16** — advisory guard fences names the producer does not emit | `RATIFIED` — owner kept the **containment** reading 2026-09-06. Now enforced, not assumed: wall **part H** (126 → 135) pins that the container is fenced twice over and no leaf is ever hoisted. Proven to bite. |
| **Setup field** | Blocked on the Orca UI. See §3. |
| **`vite` high advisory** | Knowingly accepted, dev-only. Revisit with a build-toolchain card. |
| **`react-router-dom` 6 → 7** | Deferred. Production dependency; needs its own change with UI verification. |
| E2, E3, E5, F1, F2 | Interview-gated. See §1. |

Stage E is closed (`docs/STAGE_E_CLOSEOUT.md`). Reactivating the fleet requires a new scope doc.

---

## 8. Security posture, as of the review

`docs/SECURITY_REVIEW.md` holds the full audit. Two things worth carrying forward:

**The repo is PRIVATE.** Session context had referred to it as public; GitHub reports otherwise.
Confirm before acting on any exposure assumption.

**SEC-1 closed a reproduced CSRF.** `serve.py`'s old comment claimed loopback binding meant
"reachable from this machine alone." Loopback stops other *hosts*, not the *browser on that host* — a
cross-origin `text/plain` POST started a live network listener. `request_guard_reason()` now hooks
`parse_request`, so routes added later inherit the guard automatically. **The residual is
deliberate:** it defends against the browser; a local non-browser process is still unauthenticated,
because the login gate is off by owner decision (2026-08-27) and that decision is not yours to
reopen. `console/test_auth_security.py` now guards that default against being silently flipped.

---

## 9. Things the owner has ruled, that you should not relitigate

- **Option 3 stays excluded:** *"display-time derivation creates a second computation of a stored
  fact, and two computations drift."* Agreement is read from storage, never re-derived by comparing
  severities. There is a wall check and a probe for this.
- **The E8-published model stays current** until a round produces one strictly better on the amended
  scorecard. Two-run grading; regressions reported, never absorbed.
- **`AUTH_REQUIRED` off** is an owner decision with a documented mitigation and restore switch.
- **The graphify label stays declined.**
- **The detector is frozen.** If a task would require editing `anomaly_detector.py`, STOP and ask.

---

## 10. Coordinator errors recorded this session, so you can avoid them

- Proposed a `git update-ref` mitigation on a false assumption; the worker checked the actual remote
  and rejected it. **Check the remote before proposing ref surgery.**
- Created a grading worktree on a live branch, advancing `main` with a misleading merge message.
- Armed duplicate waiters twice.
- `cd` leakage into a worker worktree produced "Already up to date" on a merge, twice.
- Ran a pre-check against a fresh case-sensitive pattern instead of the INSTALLED one; the worker
  caught it. **Test against what is installed.**
- Framed a failing auth test as a silently-failing security test implying a product defect. It was
  neither: the gate is off by a documented owner decision and the *test* was wrong. **Read the code
  and its history before assigning blame.**

None of these lost work — deliveries replay, and every one was caught by a worker or a re-check.
That is the system working. Keep it working by re-checking.
