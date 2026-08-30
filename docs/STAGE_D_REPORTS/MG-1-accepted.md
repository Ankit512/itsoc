# MG-1 accepted — pre-migration SOC fixture

**When:** 2026-08-30. **Worker:** Codex `task_88228fcccd15` / `ctx_8081dd574295` / `d5f3da5`.
**Merge:** `721f7e5`. **Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.

Owner ruling: pre-migration fixture, not SKIP. C1-T1 precedent.

## Independent verification

| Check | Result |
|---|---|
| Allowlist | `console/test_console.py`, `tests/fixtures/pre-migration-soc/soc_history.sql`, `cases.json` — no product-module edits |
| Fixture tables | exactly the seven pre-`audit_index` tables; SQL has no `CREATE` for `audit_index` |
| Non-vacuous | one `events` row |
| C1 cases | `case-incident-less` (`incidents: []`) and `case-multi-incident` (two links) |
| `check_audit()` | rc 0 with **no** live `console/.soc/soc_history.db` |
| Full `console/test_console.py` | EXIT=0 on the MG-1 worktree |
| Mutation | second `init_db()` on the migrated copy adds `[]` — exact-`audit_index` would fail |
| Eval | 19/19 |

Gate copies the fixture (`copytree`), materializes sqlite from SQL in the copy, never writes the checked-in files. Live-db dependency is gone.
