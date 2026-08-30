# D2 live `/api/efficacy` — tested 2026-08-30

**When:** 2026-08-30T17:51:36+00:00. **Tree:** `main` (API `5d3720b` + UI `22bb8d5` + ceiling framing `148352c`).
**Self-ratified.** Detector freeze unchanged.

The D2-UI **NOT TESTED** label existed only because `/api/efficacy` sat on a parallel branch. Both are on `main`. This card ran the live path once.

## Endpoint

| Step | Result |
|---|---|
| GET idle | `{status: idle, run: null, error: null}` |
| POST three canonical scenarios | 202 `{status: running, run: null, error: null}` |
| Poll | `run` stayed null while `running` |
| GET done | `status: done`; `run_date` `2026-08-30T17:51:36+00:00`; exact scope sentence; pipeline `log_analyzer.py --rules-only (subprocess)` |
| Scenarios | `INC-4a7f` / `failure-success` / `error-burst`, all canonical, P/R/F1 1.0, 0 misses, 0 FPs |

JSON saved at `/tmp/itsoc-d2-live/done.json` (not committed).

## SPA

Vite `:5173` proxied `/api/efficacy` to `serve.py :8765`. Reports (`http://localhost:5173/reports`) rendered the live panel:

- scope sentence
- ceiling/regression sentence
- run date `2026-08-30T17:51:36+00:00`
- table rows for the three scenarios
- *no missed malicious lines*

Idle copy *No efficacy harness run yet* was **absent** (honest: a run existed).

## Labels that stay

- `web/dist` 503 is correct-by-design (honest NOT TESTED when the SPA is not built).
- Overview mockup “explain & prioritize” is a design-kit artifact, outside product scope.
- Pixel pass remains “headless, not designer-reviewed” until a human designer looks.
