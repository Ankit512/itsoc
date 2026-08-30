# D2-API accepted — GET/POST `/api/efficacy`

**When:** 2026-08-30. **Worker:** Claude `task_97782a9db4a7` / `ctx_8ac86e539478` / `53000fa`.
**Merge:** `5d3720b`. **Detector:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`.

## Independent verification

| Check | Result |
|---|---|
| Allowlist | `console/efficacy_api.py`, `console/serve.py`, `console/test_console.py` |
| `check_efficacy_api()` | rc 0 |
| Idle | `{status:idle, run:null, error:null}` |
| POST | 202 running, `run` stays null while in flight |
| Done | exact scope sentence; non-empty scenarios; int miss/FP counts; pass-through of harness totals |
| Error | `status:error`, `run` null, real reason |
| 409 concurrent POST, 400 unknown scenario | pass |
| No `anomaly_detector` import in `efficacy_api.py` (AST) | pass |
| No P/R/F1 computed in serve.py | pass (asserted in the suite) |
| Eval | 19/19 |

D2-UI accepted `22bb8d5` (`docs/STAGE_D_REPORTS/D2-UI-accepted.md`). D2 complete.
