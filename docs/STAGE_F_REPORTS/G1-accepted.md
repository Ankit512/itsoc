# G1 accepted — information architecture

**Accepted:** 2026-09-10. **Merge:** `--no-ff` of `Ankit512/g1-information-architecture` @ `b94d0e3` into `main`.
**Run:** `run_4ecaacc89bfc`. **Task:** `task_2d228405ba11`. **Base:** `010a50c`.

## Independent coordinator grade

- `git merge-base --is-ancestor 010a50c HEAD`: true.
- Allowlist: `AppShell.tsx`, `itsoc.css`, `nav-aliases.test.tsx`, `shell.test.tsx`, `docs/STAGE_F_REPORTS/G1-*`. CommandPalette and SpotlightTour untouched.
- Detector sha256 `364577c5…a876` unchanged. Package manifests unchanged vs `010a50c`.
- `git diff --check` clean.
- `scripts/gate.sh --web` re-run in the worker worktree: **GREEN 23/23**. Evidence `gate-logs/20260910-084103`. Vitest **45 files / 328 tests** (+5 vs G0, none removed).
- Dead `"Command Center · off"` box is gone (tests assert `queryByText(/Command Center/)` is null). OEM Engine remains on the command palette (`nav-oem`) and `/oem` route.

## Deviation ratified

Context order is **Intel · Network · Assets · Sources**, not the card's Intel/Assets/Network/Sources. Load-bearing reason: flattened `CORE_NAV` stays byte-identical to pre-G1 so `web/src/lib/tour.ts` (out of allowlist) does not need an edit. Outside-in grouping is also a coherent demo argument. Recorded in `G1-worker.md` §1.

## Finding, not a G1 fail

Worker reported 42/48 route-states differ between two capture sessions of an identical tree + identical frozen report (content region). That is capture noise, not a nav bug. It will degrade G2/G3 pixel evidence; carry it into G4 rather than blocking G1.

## Next

Stage F ordering: **H1 (vite 5 → 8) before G2**. Do not dispatch interview-gated engine work.
