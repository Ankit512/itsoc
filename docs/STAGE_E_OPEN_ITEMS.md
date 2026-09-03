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

