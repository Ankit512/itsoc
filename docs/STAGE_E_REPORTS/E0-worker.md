# CARD E0 — disposition capture · worker report

## Branch / head

- `git branch --show-current` → **`feat/e0-disposition-capture`** — checked
  **before the first edit**, matched the card exactly, work proceeded.
- Base head at start: `5978d71` ("docs: update Stage E action cards").
- Commit produced by this card: see `git log -1` on the branch (added below at
  commit time); explicit paths only, no `git add -A`, no push, no merge.

## Freeze verification (`anomaly_detector.py`)

| when | sha256 |
| --- | --- |
| before any edit | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |
| after all edits | `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` |

Unchanged, and matches the CLAUDE.md frozen value. The detector was never
opened for edit; nothing in this card touches detection, severity or correlation.

## What was built

Incident lifecycle gains an analyst **disposition** —
`confirmed | false-positive | benign-expected` — captured on close, with an
optional free-text reason (≤ 500 chars).

**Store schema (`console/soc.py`).** Four additive keys on the incident:
`disposition`, `dispositionReason`, `dispositionAt`, `dispositionHistory`
(append-only `set`/`cleared` audit trail with reason, from/to state, timestamp).
`INCIDENT_DISPOSITIONS`, `INCIDENT_DISPOSITION_ALIASES`,
`DISPOSITION_REASON_MAX`, `DISPOSITION_FIELDS` and `normalize_disposition()`
are the vocabulary; `normalize_disposition()` deliberately returns an unknown
token unchanged so the caller rejects it honestly rather than coercing it into a
valid one.

**Single writer.** `set_incident_state(iid, new_state, disposition=None,
reason=None)` is the only function that writes a disposition. It raises
`ValueError` on: an out-of-vocabulary disposition, a disposition on any
transition that is not a close, a reason with no disposition, and an over-long
reason. Closing *without* a disposition stays legal — `null` reads as "none
recorded", never a fabricated default. Re-opening clears the current disposition
(it describes a *closed* outcome, exactly as `resolvedAt` is cleared) while the
history stays append-only.

**Additive preservation.** `_disposition_defaults()` yields the neutral
projection; `_public_incident()` applies it on read so a pre-E0 store answers
honestly *without being rewritten*; `sync_incidents()` carries the stored values
across every re-derivation (in the same preserve block that protects absorbed
case metadata); `_manual_incident_from_case()` carries them too; and
`migrate_cases_to_incidents()` only ever `setdefault`s them, so a captured
disposition is never overwritten by a re-run. `_strip_disposition()` is the
tripwire on the derived path: `derive_incidents()` output is scrubbed before it
reaches the store, so no crafted finding payload can mint a disposition.

**API (`console/serve.py`).** `_incident_state` reads exactly three keys —
`state`, `disposition`, `dispositionReason` (`reason` as alias) — and ignores
every other key in the body. A non-object body is a 400. There is no PATCH/PUT
incident route, so `POST /api/incidents/<id>/state` is the entire write surface.

**Report export (`console/export.py`).** `build(state, incidents=None)` gained an
optional argument; `build_disposition_section()` renders an
`id="analyst-dispositions"` / `data-export="dispositions"` section listing
incident, entity, state, disposition, reason and timestamp — every field
`escape()`d (the reason is analyst free text and must not inject markup) — with an
honest "No incident has been dispositioned yet." when empty.
`soc.generate_report()` passes `soc.dispositioned_incidents()`, which reads the
store **without syncing**, so generating a report has no write side effects. The
plain `/api/export` HTML path passes no incidents and is byte-for-byte unchanged.

**UI (`web/`).** `api.ts` gained `IncidentDisposition`, `INCIDENT_DISPOSITIONS`,
`DISPOSITION_LABELS`, `DispositionEvent`, the four optional `Incident` fields, and
an optional `opts` on `setIncidentState` that omits `disposition` from the body
entirely when absent. In `Incidents.tsx`, clicking **closed** in the lifecycle
stepper opens a disposition form instead of posting immediately; the reason input
is disabled until a disposition is chosen (no orphan reasons); every other step
posts as before. The Incident History & Audit Log panel renders the disposition
chip (`data-testid="disposition-chip"`, labelled *analyst-captured · not a rule
verdict*) and the append-only trail (`disposition-audit-entry`), and renders
nothing when no disposition was recorded.

**Fence (unchanged code, asserted).** Disposition never reaches detection,
severity, priority, runbook eligibility, execution, or any advisory/learned path.
This is structural and pre-existing: `runbooks.eligible()` has a closed
three-parameter signature and projects its incident through
`RULE_OWNED_INCIDENT_KEYS`, which contains no disposition key. `runbooks.py` was
not modified and does not contain the word "disposition".

## Files changed (diff allowlist)

```
console/export.py               |  61 +++++++-
console/serve.py                |  21 ++-
console/soc.py                  | 164 +++++++++++++++++++--
console/test_console.py         | 312 +++++++++++++++++++++++++++++++++++++++-
docs/soc_subsystems.md          |  66 ++++++++-
web/src/lib/api.ts              |  54 ++++++-
web/src/pages/Incidents.tsx     |  87 ++++++++++-
web/src/test/incidents.test.tsx |  91 ++++++++++++
8 files changed, 833 insertions(+), 23 deletions(-)
```

Plus this report (`docs/STAGE_E_REPORTS/E0-worker.md`). Every path is on the
card's allowlist; nothing outside it changed (`git status --porcelain` lists
exactly these files). `anomaly_detector.py` and `console/runbooks.py` are
untouched.

## Acceptance output summaries

**`python3 console/test_console.py`** — PASSED. The new
`check_incident_disposition()` section runs against a **copy** of `.soc/` in a
tempdir (the live store is never touched) and is green on all 34 checks:

- vocabulary is exactly `confirmed | false-positive | benign-expected`;
- a freshly derived incident carries no disposition (honest "not decided");
- closing with a disposition records it (alias `false_positive` normalized) with
  the reason, and the **set action + reason land in the audit/history trail**;
- rejects an unknown disposition, a disposition on a non-close transition, a
  reason with no disposition, and an over-long reason — and a rejected
  transition changes nothing on the stored incident;
- closing without a disposition stays legal; re-opening clears it but the
  append-only trail keeps both the `set` and `cleared` entries;
- **survives `sync_incidents`** (re-derivation never erases it), and
  `_strip_disposition` removes every disposition key from a derived dict;
- **additive old-store migration/resync**: a pre-E0 incident reads as "no
  disposition" *without the file being rewritten*; the cases→incidents migration
  still runs, backfills the keys neutrally, preserves every pre-E0 field
  byte-for-byte, and a re-run preserves a captured disposition;
- **report export**: the generated report carries the section, states the real
  disposition/reason/incident id, labels it as analyst state not a rule verdict;
  the plain export has no such section; an empty set renders the honest empty;
- **API lifecycle-only mutation**: `POST /state` closes with a disposition (200);
  refuses one on a non-close (400) and an unknown value (400); smuggled keys
  (`Disposition`, `dispositionHistory`, `dispositionAt`, `severity`) are ignored
  and the history is not rewritten; `PATCH`/`PUT`/`DELETE /api/incidents/<id>`
  are all ≥400; opening a case does not touch the disposition;
- **eligibility guardrail**: `inspect.signature(runbooks.eligible)` is exactly
  `(runbook, incident, findings)` with no `*args`/`**kwargs`; no disposition key
  is in `RULE_OWNED_INCIDENT_KEYS`; `runbooks.eligible` returns **identical**
  answers across `None` + all three disposition values over every shipped
  runbook, and the eligible set is non-empty so the check is not vacuous;
  `soc.eligible_runbooks` is likewise disposition-blind; `runbooks.py` never
  mentions disposition.

Final line: `PASSED — … + sigma-ingest-triage-case-lifecycle +
e0-incident-disposition checks green`.

**`npm --prefix web test`** — `Test Files 43 passed (43) · Tests 255 passed
(255)`. Four new tests in `web/src/test/incidents.test.tsx`: the close form
captures and posts `{state, disposition, dispositionReason}` (and posts nothing
until confirmed, with the reason input disabled until a disposition is chosen); a
non-close transition posts `{state}` only and opens no form; the **History chip**
plus audit entry render with the label and reason; and no chip renders when no
disposition was recorded.

**`npm --prefix web run build`** — `✓ built in 3.40s`, 1688 modules transformed.
Only the pre-existing >500 kB chunk-size advisory.

**`python3 tests/eval/run_eval.py`** — `20 passed, 0 failed, 20 total`,
TP 16, **FP 0**, FN 0, precision/recall/f1 = 1.000. No severity changed, so no
`tests/eval` or `manifest.json` update was required.

**`shasum -a 256 anomaly_detector.py`** —
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` (unchanged).

No pytest was used anywhere.

## Deviations

None from the card's scope or allowlist. Two judgment calls worth flagging for
the reviewer, both documented in `docs/soc_subsystems.md`:

1. **Closing without a disposition remains legal.** The card makes the reason
   optional but is silent on the disposition itself. Forcing a choice would make
   an undecided analyst invent one, which the honesty guardrail forbids, and
   requiring it would be a breaking change to the existing close transition. `null`
   is rendered as "none recorded" everywhere.
2. **Re-opening clears the current disposition** (the history entry is kept and a
   `cleared` entry appended). A disposition describes a *closed* outcome; leaving a
   stale "confirmed" on an incident that is back in `investigating` would be
   dishonest. This mirrors the existing `resolvedAt` clearing rule.

One incidental fix inside the new test helper: the shared `req()` helper tolerates
a non-JSON error body, because serve.py answers `PATCH`/`PUT`/`DELETE` with a
plain-text `405 read-only`.
