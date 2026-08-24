# ACTION_PLAN

Living plan for cross-cutting engineering decisions that are not visible from
any single module. Code stays the source of truth for behavior; this file
records **direction** — what we deliberately built, what we deliberately
deferred, and the trigger that flips a deferral into work.

## Storage roadmap

### Current state (honest): HYBRID — and that is correct for now

Two storage mechanisms coexist on purpose, both local, both zero-egress:

| Store | Mechanism | What it holds |
|---|---|---|
| `console/store.py` | **embedded sqlite3** (stdlib) | SOC Command Center structured data — events, assets, vulns, IOCs (deduped, queryable, retention-pruned) |
| `console/.runs/*.json` | flat-file JSON | run history — whole analyzer reports, one file per run |
| `console/console_state.json` | flat-file JSON | live console state (debug convenience) |
| `console/.soc/*.json` | flat-file JSON | SOC derived stores — incidents, cases (display aggregations) |

This split is on-thesis: single-analyst, local-first, no daemon, no external
service, nothing leaves the machine. Whole-report blobs and small derived
dicts do not need SQL; structured, deduped, queryable history already has it
via stdlib sqlite3. **Do not migrate ahead of need.**

The flat-file stores are hardened as of `feat/storage-harden`
(`console/fsafe.py`): every write is atomic (temp file + `os.replace()` in the
same directory) and lock-guarded (`fcntl.flock` where available, portable
`.lock` fallback), so a crash mid-write or two racing writers (e.g.
`POST /api/mark` → `persist_state` racing a re-run's `save_run`) can never
leave a truncated or interleaved JSON file. The storage **format** is
unchanged — same paths, same JSON.

### Trigger to move the flat-file JSON stores into SQLite

Migrate `console/.runs/`, `console/.soc/*.json` (and retire
`console_state.json`) into **embedded stdlib sqlite3** — still local, still
zero-egress — only when the **team / live-input (Tier-2) stage** creates real
pressure that flat files cannot absorb:

- **concurrency** — multiple writers beyond what a per-file lock comfortably
  serializes (several analysts, or continuous live ingestion writing while
  reviewers mark);
- **query** — needing cross-run queries ("all incidents for host X across the
  last 90 days") that today would mean parsing every JSON file;
- **retention** — history growth beyond the current `MAX_RUNS`-style pruning,
  needing time- or size-based retention policies.

Until one of those is actually felt, the hybrid stays.

### Explicitly NOT to be built now

- ❌ **SQLite migration of the flat-file stores** — deferred until the Tier-2
  trigger above fires. The atomic+locked writes cover today's risk.
- ❌ **Postgres (or any client/server database)** — reserved for the
  **Tier-3 sovereign control plane** only, if/when a multi-machine deployment
  exists. It contradicts the local/zero-egress posture at every earlier tier.
