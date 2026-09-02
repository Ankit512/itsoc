# E1 — Precedent index (worker report)

Branch: `feat/e1-precedent-index`, cut from local `main` at `7bd6796` (verified
`git rev-list --left-right --count main...HEAD` = `0 0`, clean tree, before any edit).

## What shipped

A pure deterministic precedent query over the stored incidents, surfaced as a
**Precedents** panel on Incidents. It answers *"have we seen this before?"* and
nothing else — no verdict, no recommendation, no model.

E6 left `console/precedent.py` as an interface-only stub with the note that
**E1 owns the real implementation**. That is what this card grew, keeping the
E6 `rank(incident, candidates)` signature byte-for-byte so the Stage E wall's
part C still closes on the same live signature.

## Schema decisions

### Similarity dimensions (four, all rule-owned)

| dimension | sourced from | why this spelling |
|---|---|---|
| `ruleIds` | `incident.ruleIds` | the rule ids that actually fired |
| `entity` | `incident.entity` **and** `incident.entityValues` | hosts, users and IPs in one dimension |
| `attackTags` | `incident.attackTags` **or** `incident.techniques[].id` | the store already carries `techniques`; both spellings feed one dimension |
| `assetCriticality` | `incident.assetCriticality` **or** `incident.criticality` | the store already carries `criticality` |

`DIMENSION_SOURCES` maps each dimension to every store spelling that feeds it,
so the ranker reads the store as it actually is and E6's canonical names keep
working unchanged.

### Two new DERIVED incident fields (`soc.derive_incidents`)

* `ruleIds` — sorted unique `finding.type` over the cluster's members.
* `entityValues` — sorted unique host / user / IP values the parser **actually
  observed**: IP chips, `hostDerived` hosts, and usernames matched with
  `redact.USER_PATTERNS` (the same vocabulary redaction masks with, so
  precedent and redaction agree on what a username is), plus the primary entity.

Both are derived from the cluster's own real findings — nothing invented — and
are hoisted onto the incident so a *stored* incident can still answer "what was
this about?" after its run's findings are gone. They are rebuilt on every sync
like every other derived field, and a pre-E1 stored incident simply carries
neither key, contributes no overlap on those dimensions, and is never rewritten.
Additive, exactly as E0 is.

### Ranking and tie-breaking

`overlap` = the count of shared fact **values** summed over the four dimensions.
Order: `(-overlap, -dimensionsMatched, id)`. Total, reproducible, and broken by
nothing but the incident id. (E6's stub used `(-overlap, id)`; the added
secondary key is itself deterministic and is documented in the module.)

### Explanation

Each match carries `matched` (shared values per dimension), `because` (one
clause per matched dimension) and `explanation` (the joined sentence).
`explain()` and `because()` are **pure functions of `matched`** — the wall and
`check_precedent_index` both assert `explain(m["matched"]) == m["explanation"]`
and that every value in `matched` is genuinely present in *both* records'
rule-owned facts. So a rendered reason is always fully derivable from the facts
that produced it.

### Disposition: shown, never used

Each match carries the prior incident's E0 disposition verbatim
(`disposition`, `dispositionReason`, `dispositionAt`, `dispositionRecorded`);
`null` reads as "none recorded". It is read from `DISPLAY_ONLY_KEYS` **after**
`rank()` has already fixed the order, and `DISPLAY_ONLY_KEYS` is disjoint from
`RULE_OWNED_PRECEDENT_KEYS`. A precedent's recorded outcome therefore cannot
feed back into which precedents surface — there is no learned loop.

### Honest omissions

The queried incident is never its own precedent, and a zero-overlap incident is
omitted entirely rather than ranked last. Nothing comparable in the store →
`precedents: []`, never a nearest-anything filler.

## Proof there is no LLM / model / network / advisory input in the ranking path

`tests/test_stage_e_wall.py` part E, read off the **AST of the shipped file**:

* `console/precedent.py` imports **only** `{inspect, re}` — an LLM client, an
  HTTP client or a random source cannot be used without first appearing in that
  allowlist, so there is nothing to smuggle through.
* it calls no network / subprocess / clock / randomness / `eval` primitive.
* `rank()`'s live signature is exactly `(incident, candidates)` — no `*args`,
  no `**kwargs`, no advisory-reading parameter name (E6's part C, unchanged).
* every disposition field is absent from `RULE_OWNED_PRECEDENT_KEYS`, and
  `facts()` provably drops them off a real record
  (`assert_no_disposition_input()`).
* behavioural: setting **every** `runbooks.ADVISORY_KEY` plus a disposition on
  both sides cannot reorder `query()`; reversing the candidate order changes
  nothing; repeating the query is byte-identical.

E6's wall is preserved, not replaced: parts A–D are untouched and still pass
(48/48 checks, up from 30/30 — the 18 added checks are part E).

## Performance evidence — 2500-incident synthetic store

Two independent proofs, per the "generous deterministic measurement without
flaky wall-clock assumptions" requirement.

**Deterministic and clock-free** (`Index.cost()` returns exact integers):

* store holds 2500 incidents;
* a single-rule query reads a posting list of exactly **100** entries and
  scores exactly **100** candidates — **4% of the store**, asserted as
  `scored * 25 == N`. That is what makes it an index rather than a scan, and it
  is an equality on integers, not a timing.

**Wall clock, generous**: best-of-7 of the *full end-to-end* call
(`soc.incident_precedents` — load the 2500-incident store from disk, build the
inverted index, rank, decorate), against a 200 ms budget. Best-of-N, not a
single reading, so scheduler noise on a shared machine cannot fail a fast
implementation.

```
end-to-end precedent query over 2500 incidents is under 200 ms
  (best 17.9 ms, median 18.5 ms of 7 reps)
```

~11x headroom. Two further checks stop the budget being met dishonestly: the
timed query must return real, ranked, non-empty results with a non-zero overlap
and a non-empty explanation on every match, and two runs over the same store
must be byte-identical.

## Full test outputs

| command | result |
|---|---|
| `python3 tests/test_stage_e_wall.py` | **48/48 checks passed — Stage E wall intact** (exit 0) |
| `python3 console/test_console.py` | **PASSED**, 1123 `[PASS]`, 0 `[FAIL]`, exit 0 — ends `… + e0-incident-disposition + e1-precedent-index checks green` |
| `npm --prefix web test` | **43 files, 271 tests passed** (exit 0) |
| `npm --prefix web run build` | **✓ built in 3.22s** (exit 0) |
| `python3 tests/eval/run_eval.py` | **20 passed, 0 failed, FP=0, FN=0, precision/recall/f1 = 1.000** (exit 0) |
| `shasum -a 256 anomaly_detector.py` | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — **unchanged** |

`web/node_modules` was absent in this worktree; `npm --prefix web ci` was run
once to install from the committed lockfile before the web commands. No
dependency was added or changed.

## Preservation checks

* **E6 rank signature and wall** — signature identical; wall parts A–D byte-for-
  byte, still passing.
* **E0 migration and lifecycle** — untouched. `check_incident_disposition`
  still green in full, including the pre-E0 additive-migration and
  `sync_incidents` preservation checks. The E1 fields go through the same
  derived-field path; `_strip_disposition` / `_disposition_defaults` are not
  modified.
* **Severity / priority / eligibility / execution / runbook engine** — not
  touched. `check_precedent_index` additionally asserts a precedent query
  writes nothing and changes no stored severity or priority, and that
  `runbooks.eligible()` answers identically with and without the E1 fields.
* **`anomaly_detector.py`, eval fixtures, `manifest.json`** — not touched.
* **No pytest** — both Python suites are plain stdlib, run directly.

## Deviations

None. Every file changed is on the allowed list.

## Files changed

`console/precedent.py`, `console/soc.py`, `console/serve.py`,
`console/test_console.py`, `tests/test_stage_e_wall.py`, `web/src/lib/api.ts`,
`web/src/pages/Incidents.tsx`, `web/src/test/incidents.test.tsx`,
`docs/soc_subsystems.md`, `docs/STAGE_E_REPORTS/E1-worker.md`.
