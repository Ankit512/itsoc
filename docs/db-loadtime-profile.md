# DB / load-time profile and fixes (conv db-loadtime)

Baseline main `065f75f`. Measured with `perf_counter`/`cProfile` on **real-size
data**: a copy of the live store DB (7.9 MB, 2,500 events) and the live run
history (25 files, 748 KB). Harness: end-to-end GETs against a live
`ThreadingHTTPServer` plus direct function timings. All numbers ms/op,
median-of-batch on an M-series Mac; run-to-run noise ~±10%.

## Ranked hotspots (BEFORE) and what was done

| # | Operation | BEFORE | AFTER | Change | Action |
|---|---|---:|---:|---|---|
| 1 | `runs_summary()` (direct) | 59.96 | 4.27 | **14×** | fixed (`load_run` validation) |
| 2 | `GET /api/overview` | 6.16 | 1.36 | 4.5× | fixed (via 1+4) |
| 3 | `query('events', q=…)` LIKE scan | 6.12 | 6.46 | — | **plan item** (FTS5), not fixed |
| 4 | `GET /api/metrics` | 3.18 | 0.66 | 4.8× | fixed (`list_runs` cache) |
| 5 | `GET /api/runs` | 2.44 | 0.58 | 4.2× | fixed (`list_runs` cache) |
| 6 | `list_runs()` (direct) | 2.12 | 0.13 | 17× | fixed (stat-cache) |
| 7 | `load_run()` (direct) | 2.13 | 0.10 | 21× | fixed (no full-index parse) |
| 8 | syslog `_store()` path (`init_db`+insert) | 0.58 | 0.42 | 27% | fixed (init guard — the dispatched quick win) |
| 9 | `import serve` cold start | ~67 | ~79* | — | left alone (one-time; *noise) |
| 10 | `query('events', limit=100)` | 0.43 | 0.42 | — | already fast, left alone |
| 11 | `store.metrics()` | 0.41 | 0.42 | — | already fast, left alone |
| 12 | `GET /console_state.json` | 0.21 | 0.22 | — | already fast, left alone |

`GET /api/runs-summary` end-to-end: 4.93 ms AFTER (BEFORE not captured over
HTTP — the harness had the route name wrong; the direct figure in row 1 is the
same work minus HTTP framing).

## Root causes (measured, not assumed)

1. **`load_run()` validated its name by calling `list_runs()`**, which parsed
   *every* saved run file. `runs_summary()` calls `load_run` per run →
   **O(N²) full-file JSON parses**: cProfile showed **675 `json.loads` calls
   (26 full-directory parses, ~19 MB of JSON) per summary call**. Fix:
   validate the name against the directory's actual `*.json` filenames (same
   no-blind-join security property), then parse only the requested file.
   AFTER cProfile: 25 parses, pathlib stat noise dominates.
2. **`list_runs()` re-parsed all 748 KB on every call** — and it sits on
   `/api/runs`, `/api/metrics` (labels) and `/api/overview`
   (`_prior_run_state`). Fix: per-file nav-entry cache keyed by
   `(mtime_ns, size)` — unchanged files cost a stat; a rewritten run (reviewer
   marks a finding) re-parses; deleted files drop out; entries copied on
   return so callers can't mutate the cache.
3. **`store.init_db()` re-ran the full DDL script on every call** — 6+
   call-sites per request in `serve.py` and once per datagram in
   `syslog_collector._store()` (0.139 ms each). Fix (the dispatched quick
   win): DDL runs once per DB path per process (0.004 ms after); a repointed
   `DB_PATH` (tests) or a vanished DB file still re-initializes.

## Honest limits of the measurement

- Measured on one machine, warm OS file cache, no concurrent load; absolute
  numbers will differ elsewhere, ratios should hold.
- Startup A-row (67 vs 79 ms) is dominated by interpreter/import variance —
  treat as unchanged; did not pursue import-graph pruning.
- BEFORE HTTP number for `/api/runs-summary` missing (wrong route in the first
  harness run) — the direct-call number stands in.
- The React bundle/browser render cost was not measured (server-side only).

## Plan — recommend-only, for later (aligned with the archived storage roadmap)

The archived `archive/itsoc-main:ACTION_PLAN.md` storage roadmap holds: the
sqlite (structured history) / flat-JSON (whole-run blobs) hybrid is deliberate;
migrate flat stores into sqlite only when the Tier-2 team/live-input trigger
fires; no client/server DB engine before Tier-3. Nothing measured here
justifies pulling that trigger early. Worth doing later, in order:

1. **FTS5 for `q=` free-text search** (hotspot #3, 6.4 ms at 2,500 events,
   linear in table size — will hurt at 100k+ events). Contentless FTS5 table
   over `events(message, raw, host, src_ip)` + triggers; still stdlib sqlite,
   but a schema migration — needs its own gated task.
2. **WAL + `synchronous=NORMAL` pragmas** if sustained syslog ingest becomes
   real: insert is 0.42 ms/op (~2,400 events/s ceiling) on the default
   rollback journal, connection-per-insert. WAL persistently changes the DB
   file's journal mode, so it should be an explicit, documented change — with
   a batched-insert path in `syslog_collector` (per-burst transaction) at the
   same time.
3. **Per-run summary cache in `runs_summary()`** (same mtime/size key as
   `list_runs`) if run histories grow past `MAX_RUNS=25` or files get much
   bigger — at 4.3 ms today it is not worth the machinery.
4. **Do not** move `.runs/*.json` into sqlite for performance reasons — after
   fix #2 the flat files cost a stat each; the roadmap's Tier-2 triggers
   (concurrency, cross-run query, retention) remain the only valid reasons.
