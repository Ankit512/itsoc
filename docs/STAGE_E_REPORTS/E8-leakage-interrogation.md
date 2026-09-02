# E8 leakage interrogation — the 21 suppressions and fresh-seed confirmation

**Run:** 2026-09-02, coordinator-run, read-only. **Model:** `triage_v1.pkl`, sha256
`0eb19182…03837765`, GradientBoostingClassifier, 434 rows, sklearn 1.7.2.
**Benchmark seeds:** frozen `20270302–20270304`. **Confirmation seeds:** `20280411–20280415`.

No engine, harness, model or test file was modified. Every number below was produced by
instrumenting the shipped `LearnedSystem.opinion` seam from outside and re-running the frozen
referee.

## Verdict

**Leakage: cleared.** **But a separate publication defect was found, and I recommend it gates E7b.**

## 1. Leakage findings — cleared

**Entity values cannot reach the model by construction.** `triage_model.features()` emits 21
features that are counts and family flags — `entity_ip_count`, `entity_user_count`,
`entity_host_count`, `entity_port_count`, `entity_distinct_count` — never a raw identifier. No IP,
username, hostname or change-window string is an input. Entity-value overlap therefore cannot leak
into a decision even in principle; the disjointness work defends a real but narrower surface than
its name suggests.

**The one host-derived feature is the model's most important one.** `criticality_rank` carries
**41.5%** of total feature importance — by far the largest — ahead of `rule_family_auth` (14.8%),
`events_per_minute` (12.2%) and `occurrences` (9.1%). It is resolved from the org config by exact
host name, which is why the remap needed a benchmark-only org context.

**That org context is faithful.** `benchmark_org_context` copies each real asset's own criticality
onto its benchmark name and invents nothing; `console/org_context.json` is untouched. Verified by
reading the generated file.

**Criticality is not a scenario shortcut.** The positive and negative scenarios draw on the **same
three hosts** (`bnch-api-01`, `bnch-server-01`, `bnch-server-02`), and criticality overlaps across
both sides — suppressed findings split 51 at `standard` / 33 at `crown-jewel`, kept findings 60 /
30. The model cannot separate malicious from benign by host band, because host band does not
separate them.

**It generalises to unseen seeds.** On five seeds never used for training or the frozen benchmark
(`20280411–20280415`), the rules raised 35 false positives across the negative scenarios and the
learned system suppressed **all 35 with zero line-level misses**, with entity overlap zero on every
kind and cross-kind. The result is not an artefact of the three frozen seeds.

## 2. Scale correction to the published number

The published "21 false positives" is the **canonical-format** total. Run across all four
formatters the rules raise **84**, and the learned system suppresses all 84. The suppression claim
is stronger than published, not weaker; the figure is simply single-format and is not labelled as
such.

## 3. The defect — finding-level recall is not 1.000

Precision is measured over findings but recall is measured over malicious **lines**. That asymmetry
is documented in the harness. Its consequence is not published, and it hides a real drop:

Of the 90 findings that cite at least one malicious line, the model **drops 5** — every one of them
an **`ioc_observed` finding on the crown-jewel host in `INC-4a7f`**, the flagship attack scenario,
labelled `benign-expected` with confidence up to **0.992**.

- **Finding-level learned recall is 0.9444, not 1.000.**
- Published line-level recall stays 1.000 only because the dropped findings all cite malicious line
  2, which other kept findings also cover.

So "the learned system matched every positive with 0 misses" is true as measured and misleading as
read: the advisory discards the threat-intel IOC hit on the most critical asset in the flagship
scenario, and the published metric absorbs it.

## 4. Robustness — the sensitivity runs backwards

Forcing `criticality_rank` across its real domain (`low` 0, `standard` 1, `crown-jewel` 2) and
holding every other feature fixed:

| Population | Robust across all three bands | Flips in at least one |
|---|---|---|
| 84 suppressions | 51 | 33 (all `benign-maintenance`) |
| 85 true detections | 57 | 28 (`error-burst` 22, `failure-success` 6) |

Direction matters:

- Raising a host from `standard` to `crown-jewel` flips **28 true detections from KEPT to DROPPED**.
- Lowering `crown-jewel` to `standard`/`low` flips **33 suppressions from DROPPED to KEPT**, and
  also flips the 5 dropped `INC-4a7f` IOC findings back to KEPT.

The model is **more** willing to dismiss a finding on a more critical asset. That is the opposite of
the operational intuition, and it is driven by an org-config value rather than by log evidence.

These are counterfactuals: benchmark hosts have fixed criticality, so the published numbers stand
exactly as measured. The point is that a headline result of "0 false positives, 0 misses" rests
substantially on one configuration value.

## 5. Standing guardrails, unaffected

Rules still own severity and correlation. The model never writes a severity, and its output is
advisory. A dropped advisory does not remove the rule's finding or change its verdict, so nothing
here breaches the model wall. The exposure is to how the advisory is *published* and to what E7b
would optimise against.

## Recommendation

1. Publish finding-level recall alongside line-level, and name the 5 dropped `ioc_observed`
   findings explicitly rather than letting line coverage absorb them.
2. Label the false-positive total with its format scope (21 canonical / 84 all-format).
3. Record the criticality sensitivity and its direction as a known property of the model.
4. Hold E7b round 1 until 1–3 land. E7b modifiers tuned against a metric that reports 1.000 where
   the finding-level number is 0.9444 would be optimising against a number that hides a dropped IOC.

**Owner ruling, 2026-09-02:** clearance accepted and this methodology ratified. All four
recommendations adopted. E7b round 1 is HELD pending the metrics amendment (card E8m); round 1 then
dispatches against a named target — the crown-jewel IOC dismissals and the backwards criticality
gradient.

## 6. What this demonstrates architecturally

The benchmark caught the advisory model confidently wrong on the highest-stakes case in the corpus.
On the flagship attack scenario, on the crown-jewel host, the model labelled five threat-intel
`ioc_observed` findings `benign-expected` with confidence up to 0.992 — and it was wrong. Those
findings cite a real malicious line.

Every rule verdict stood untouched. The detector fired, owned its severity, and reported the
finding regardless of what the model thought of it; the frozen hash is unchanged and the rules
numbers are byte-identical whether the model is loaded, wrong, or absent entirely. The model's
error changed an advisory label and nothing else. No verdict moved, no severity shifted, no finding
was suppressed from the record.

This is the wall functioning exactly as designed, observed under adversarial measurement rather
than asserted in a doc. It is also the argument for the wall: a model this confident and this wrong
on the most security-salient case in the benchmark is not a component that should be permitted to
decide anything. It advises, and it never decides — and the reason that separation is worth its
cost is visible here in measured numbers rather than in principle.
