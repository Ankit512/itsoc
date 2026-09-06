# ITSOC Stage E — Open Items Register

Numbering continues from the Stage C register (last numbered item: OPEN-14; OPEN-14b is retained as its sub-item).

**Status legend:** `OPEN` = awaiting owner · `RATIFIED` = decided, actioned · `RETIRED` = no longer applies.

No Stage E open items at activation.

---

## OPEN-15 — the backwards criticality gradient (PARKED, honestly labelled)

**Status:** `OPEN` — parked by owner ruling 2026-09-03. Not an E9 item.

**What it is.** `criticality_rank` — a value read from org config, not from log evidence — drives the
advisory model's dismissal decisions in the wrong direction: the model is *more* willing to dismiss a
finding on a *more* critical asset.

**Where it stands.** Halved, not eliminated. Feature importance fell **0.4146 → 0.2026** across the two
graded E7b rounds; suppression flips are unchanged at **33/84**, and true-detection flips read 30/90
against a baseline 28/85 — an increase fully accounted for by 2 of the 5 newly-recovered findings being
criticality-sensitive, with no previously-robust detection becoming fragile.

**The measured price of closing it — established twice, independently.** Eliminating the proxy outright
costs **eight true `infra_unknown_high` detections**. Round 1 reached that figure by deleting the
feature; round 2 reached the identical figure by adding a benign-expected scenario on a standard host
(importance would fall to 0.0465, suppression flips to 0/84). Two different levers, same cost. This is
a measured property of the current record projection, not one round's artefact.

**Why parked rather than dispatched.** E9 is retrain automation. A richer projection or a different
lever is model research, not automation work. It becomes a candidate card for a future stage —
plausibly a much better one once **real dispositions** exist via E0/E2, since real analyst labels are a
stronger lever than another synthetic pass.

**Published record.** Stated in `docs/STAGE_E_REPORTS/E8-leakage-interrogation.md` §4 so the public
numbers match reality. Guardrails unaffected: the model remains advisory and never writes a severity.


---

## OPEN-16 — the advisory guard fences container names the producer does not emit

**Status:** `RATIFIED` — **owner ruling 2026-09-06: keep the containment reading.** Raised by CB-1 acceptance the same day. No live defect, and the assumption the ruling rests on is now enforced by test rather than assumed (see *Ruling* below).

**What it is.** `console/runbooks.py` `ADVISORY_KEYS` lists `aiConfidence` and `aiAgrees`. **Neither
exists as a leaf key anywhere in the repo.** `console/triage_model.py` emits them as `confidence` and
`agrees` *inside* the `aiTriage` container. So the guard's denylist names two fields nothing produces,
while the two fields that *are* produced are unfenced under their own leaf names — along with
`status`, `ruleSeverity` and `unavailableReason`.

**Why it is not a live defect.** `aiTriage` is itself fenced twice over (in `ADVISORY_KEYS`, and by
`_ADVISORY_WORD_RE`'s `ai<Something>` class clause from CB-0), so the rule-owned projection drops the
whole subtree before any eligibility predicate sees it. Every leaf is fenced *by containment*. No
production code hoists those leaves to top level — verified by grep at CB-1 acceptance; only test
files reference them there. `console/copilot.py:_assert_fenced()` re-derives the fence from runbooks'
own guard at read time, so un-fencing the container fails loudly.

**The exposure, stated precisely.** If any future code ever flattens an `aiTriage` block onto an
incident or finding, the leaf names `confidence`, `agrees`, `status`, `ruleSeverity` and
`unavailableReason` would land unfenced — and `ruleSeverity` in particular is a severity-shaped name
one rename away from a rule-owned key. Containment is doing real work here; it is not belt *and*
braces, it is the only belt.

**The two readings, and what each costs.**
- *Containment* (accepted for CB-1): a leaf inside a fenced container is fenced. Costs nothing now;
  depends on nothing ever hoisting.
- *Strict leaf*: every leaf must be fenced under its own name. Costs a rename in
  `triage_model.py` — a forbidden path for CB-1, so a card of its own, but a small one.

**Coordinator note, under guardrail 6.** The CB-1 card asserted all four `ai*` fields were fenced.
That premise was not grepped before dispatch, and it was false. This is the second premise in the CB
family about `ADVISORY_KEYS` that did not survive contact — the first was the owner's
denylist-as-allowlist category error. The pattern is worth naming: **`ADVISORY_KEYS` is being reasoned
about from its name rather than from its contents.** Read it before citing it.

### Ruling — 2026-09-06

**Keep the containment reading.** A leaf inside a fenced advisory container is fenced. No rename in
`console/triage_model.py`; `aiConfidence` and `aiAgrees` stay in `ADVISORY_KEYS` as denylist entries
for names the producer does not currently emit, which costs nothing and fails safe if it ever does.

**What the ruling rests on, and why that needed pinning.** Containment is not belt *and* braces here
— it is the only belt. Five of the eight leaves the copilot reads (`confidence`, `agrees`, `status`,
`ruleSeverity`, `unavailableReason`) are unfenced under their own names and are safe *only* because
they travel inside `aiTriage`. That was verified once, by hand, at CB-1 acceptance. A property
verified once and then relied on forever is exactly the shape this project keeps finding defects in.

**So the assumption is now an invariant.** `tests/test_stage_e_wall.py` **part H** (wall 126 → 135)
pins the two facts the ruling depends on:

1. the container is fenced twice over — in `ADVISORY_KEYS` *and* by `_ADVISORY_WORD_RE`'s
   `ai<Something>` class clause — and is not a rule-owned key;
2. no advisory leaf is ever hoisted out of it: the live `soc._public_incident()` projection carries
   every leaf *only* inside the block, and dropping `ADVISORY_KEYS` from that projection removes
   every one of them.

It also pins `copilot.LEARNED_LEAVES` as a subset of the leaves part H covers, so a future reader
that adds a leaf must come back to this check and justify it rather than quietly widening the set.

**Proven to bite, not merely to pass.** A negative control simulated the failure mode — a refactor
hoisting `confidence` onto the incident projection — and the wall failed two checks and exited 1.
A guard that cannot fail is not a guard, which is the lesson from the fifteen F0 component tests
that passed for a rendering defect's entire life.

**What is still true and unchanged.** No production code hoists these leaves today. The strict-leaf
alternative remains available and cheap if it is ever wanted: a rename in `triage_model.py`, outside
every current allowlist. This ruling does not foreclose it — it makes the cost of *not* doing it
visible and monitored.