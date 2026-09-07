# DEP-1 — close the vitest CRITICAL advisory (worker report)

- **Branch:** `Ankit512/dep1-vitest` (card named `feat/dep1-vitest`; name mismatch is a WARNING only, flagged here, not corrected)
- **Base check:** `git merge-base --is-ancestor f28c954 HEAD` → **PASS**. HEAD at start = `f28c9549dab35c9eea3fc479a04bab7197378d34` (identical to base — worktree was not stale).
- **Detector freeze:** `sha256(anomaly_detector.py)` = `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` **before and after**. Never opened, never edited. Re-confirmed independently by the gate's `detector_freeze` stage.
- **Environment note:** `web/node_modules` was **missing** on arrival. Ran `npm --prefix web install` to establish the baseline (295 packages). Recorded as required.

## The change

One line, one package.

```diff
-    "vitest": "^2.1.3"
+    "vitest": "^3.2.6"
```

Resolved to **vitest 3.2.7** (latest 3.x; vulnerable range is `<= 3.2.5`).

Files changed — exactly two, both on the allowlist:

```
 M web/package.json
 M web/package-lock.json
```

`web/vite.config.ts` was **NOT touched**. The `test:` block (`environment: "jsdom"`, `globals: true`,
`setupFiles`, `css: false`) and the `/// <reference types="vitest/config" />` pragma are all valid
unchanged under vitest 3 — the documented-config-change escape hatch was not needed and not used.
No test file under `web/src/test/` was touched. Nothing was skipped, weakened, deleted, `.skip`-ed
or `.todo`-ed.

## npm audit — BEFORE

```
7 vulnerabilities (5 moderate, 1 high, 1 critical)
```

Per-package (`npm audit --json`):

| package | severity | advisory |
|---|---|---|
| **vitest** | **critical** | **GHSA-5xrq-8626-4rwp — Vitest UI server: arbitrary file read + execute** |
| vite | high | GHSA-fx2h-pf6j-xcff — `server.fs.deny` bypass on Windows alternate paths |
| esbuild | moderate | GHSA-67mh-4wv8-2f99 |
| react-router | moderate | GHSA-wrjc-x8rr-h8h6, GHSA-337j-9hxr-rhxg |
| react-router-dom | moderate | via react-router |
| @vitest/mocker | moderate | via vite |
| vite-node | moderate | via vite |

## npm audit — AFTER

```
# npm audit report

esbuild  <=0.24.2
Severity: moderate
esbuild enables any website to send any requests to the development server and read the response - https://github.com/advisories/GHSA-67mh-4wv8-2f99
fix available via `npm audit fix --force`
Will install vite@8.2.2, which is a breaking change
node_modules/esbuild
  vite  <=6.4.2
  Depends on vulnerable versions of esbuild
  node_modules/vite

react-router  6.0.0 - 7.17.0
Severity: moderate
React Router: Open redirect via backslash in <Link> and useNavigate (CVE-2025-68470 bypass) - https://github.com/advisories/GHSA-wrjc-x8rr-h8h6
React Router: Arbitrary Constructor Injection via deserializeErrors() in React Router SSR Hydration - https://github.com/advisories/GHSA-337j-9hxr-rhxg
fix available via `npm audit fix --force`
Will install react-router-dom@7.18.3, which is a breaking change
node_modules/react-router
  react-router-dom  6.0.0-alpha.0 - 7.17.0
  Depends on vulnerable versions of react-router
  node_modules/react-router-dom


4 vulnerabilities (3 moderate, 1 high)
```

**Critical: 1 → 0.** ✅ That is the card.

Exact remaining counts: **3 moderate, 1 high, 0 critical, 0 low, 0 info — total 4** (down from 7).

Two moderates also cleared as a side effect, not as scope creep: `@vitest/mocker` and `vite-node`
were flagged only because their *old* versions (`<=3.0.0-beta.4` and `<=2.2.0-beta.2`) were in the
advisory range. They moved with vitest to 3.2.7 / 3.2.4, which is expected.

### Knowingly accepted, stated not omitted

- **`vite` HIGH — GHSA-fx2h-pf6j-xcff (`server.fs.deny` bypass on Windows alternate paths), plus the
  `esbuild` moderate underneath it. KNOWINGLY ACCEPTED for now, per owner decision.** It is dev-only
  (vite is a devDependency; the deployed SPA is static `web/dist`), the bypass is Windows-specific,
  and closing it means vite 5 → 7/8, which drags the whole build toolchain. Not fixed here. Not
  silently dropped either — it is the reason the "1 high" remains in the after-count above.
- **`react-router-dom` 6.30.6 (2 moderates). OUT OF SCOPE, untouched.** It is a *production*
  dependency that ships in `web/dist`; a routing major belongs in its own change with its own UI
  verification, not riding along with a test-toolchain fix.

Verified by direct lockfile comparison (`HEAD:web/package-lock.json` vs working tree) that every
out-of-scope package is byte-identical in version:

```
UNCHANGED vite = 5.4.21          UNCHANGED react = 18.3.1
UNCHANGED esbuild = 0.21.5       UNCHANGED react-dom = 18.3.1
UNCHANGED rollup = 4.62.4        UNCHANGED react-router = 6.30.6
UNCHANGED typescript = 5.9.3     UNCHANGED react-router-dom = 6.30.6
UNCHANGED jsdom = 25.0.1         UNCHANGED @vitejs/plugin-react = 4.7.0
UNCHANGED tailwindcss = 3.4.19   UNCHANGED postcss = 8.5.26
```

Everything that *did* move in the lockfile is vitest's own family: `@vitest/{expect,mocker,
pretty-format,runner,snapshot,spy,utils}` 2.1.9 → 3.2.7, `vite-node` 2.1.9 → 3.2.4, and its
transitives (`pathe` 1.1.2 → 2.0.3, `tinyrainbow` 1.2.0 → 2.0.0, `tinyspy` 3.0.2 → 4.0.6,
`@types/chai`, `@types/deep-eql`, `strip-literal` added).

## Nothing moved — the acceptance criterion

**Baseline, before the bump (vitest 2.1.9):**

```
 Test Files  44 passed (44)
      Tests  313 passed (313)
```

**After the bump (vitest 3.2.7):**

```
 Test Files  44 passed (44)
      Tests  313 passed (313)
   Duration  15.91s
```

Same 44 files, same 313 tests, all passing, exit 0. **No test file required a change to run under
vitest 3**, so the STOP condition was never reached.

### Standing advisory-wall check

`npx vitest run src/test/approvals.test.tsx -t "SELECTOR-NULL"`:

```
 ✓ src/test/approvals.test.tsx (12 tests | 10 skipped) 43ms
 Test Files  1 passed (1)
      Tests  2 passed | 10 skipped (12)
```

**2 passed.** (The 10 skipped are the other tests in the file that the `-t` name filter excludes —
that is the filter, not a weakened suite.) The advisory Copilot rail still carries no approve
control; the wall survived the runner change.

### Build

`npm --prefix web run build` (`tsc --noEmit && vite build`) — clean, exit 0:

```
vite v5.4.21 building for production...
✓ 1689 modules transformed.
dist/index.html                   1.10 kB │ gzip:   0.61 kB
dist/assets/index-BxsMmCWf.css   90.77 kB │ gzip:  16.93 kB
dist/assets/index-D8PonEq8.js   679.32 kB │ gzip: 187.85 kB
✓ built in 1.87s
```

(The >500 kB chunk notice is pre-existing and unchanged.)

### `web/dist` output — unchanged, and not merely "in kind"

The card asks for confirmation the shipped output is unchanged in kind. A stronger check was run: a
real A/B. The upgraded manifests were set aside, `web/package.json` + `web/package-lock.json` were
reverted to HEAD, `npm ci` reinstalled the *pre-change* dependency tree, and `dist` was rebuilt from
it. Both trees were hashed with `shasum -a 256` over every file:

```
$ diff dist-before.txt dist-after.txt
(no output)
```

**Byte-for-byte identical — same filenames, same content hashes, no drift even in hashes or
ordering.** This is expected and is the point: vitest is not a build input. `vite build` runs on
vite 5.4.21 / rollup 4.62.4 / esbuild 0.21.5 / typescript 5.9.3, none of which moved. The upgraded
manifests were then restored and `npm ci` re-run before the gate.

## GATE SUMMARY — `scripts/gate.sh --web`

```
================ GATE SUMMARY (20260907-204537) ================
  PASS  run_eval
  PASS  validate_real_selftest
  PASS  threat_intel
  PASS  test_auth_security
  PASS  test_copilot_workspace
  PASS  test_overview
  PASS  test_fsafe
  PASS  test_mcp
  PASS  test_intake
  PASS  test_audit_drift
  PASS  test_ti_oem_egress
  PASS  test_stage_e_wall
  PASS  test_e7a_feature_contract
  PASS  test_battlecard_efficacy
  PASS  test_approvals
  PASS  test_attack_generator
  PASS  test_train_triage
  PASS  test_efficacy_harness
  PASS  test_console
  PASS  test_recommend
  PASS  web_vitest
  PASS  web_build
  PASS  detector_freeze
  evidence: /Users/ankit/orca/workspaces/log-analyzer/dep1-vitest/gate-logs/20260907-204537

  DELIBERATELY OUT of this gate (rule 5 — named, never silently unlisted):
    tests/eval/validate_real.py (full mode) — scores the detector against an
      OPERATOR-SUPPLIED real log plus a hand-labelled ground-truth file, and
      asserts nothing; it reports metrics. Its --selftest, which does assert,
      IS in the gate above.
    web/src/test (vitest) and the web build — in the gate behind --web, since
      they need web/node_modules; absent, they SKIP loudly (never a pass).
=======================================================
GATE GREEN.
```

**23 PASS, 0 FAIL, including `web_vitest` and `web_build`.** Gate exit 0. The `web_vitest` stage
inside that run reported `Test Files 44 passed (44) / Tests 313 passed (313)`.

`detector_freeze` inside the gate:

```
expected 364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876
actual   364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876
```

## Hygiene

- `git diff --check` — clean, no whitespace errors.
- Allowlist audit — `git status --porcelain` shows exactly `M web/package.json` and
  `M web/package-lock.json`. `web/vite.config.ts` and `docs/STAGE_E_REPORTS/DEP1-worker.md` were on
  the allowlist; the config was not needed, this report is the only other file added.
- Nothing on the FORBIDDEN list was opened for writing. No test file, no rule, no eval corpus, no
  `anomaly_detector.py`, no console module, no eligibility path.
- Committed with explicit paths only. No `git add -A`. No push, no merge.

## Deviations

1. **Branch name.** Card says `feat/dep1-vitest`; the worktree is on `Ankit512/dep1-vitest`. The card
   states this is a WARNING only, so the branch was left alone rather than renamed mid-card.
2. **`npm --prefix web install` was required** — `web/node_modules` did not exist on arrival. Recorded
   as the card asks. It did not modify `package-lock.json` (verified: the tree was clean immediately
   after, before the vitest edit).
3. **Resolved to 3.2.7, not 3.2.6.** The range `^3.2.6` was written as the card specifies; npm
   resolved the latest 3.x, which is 3.2.7. Both are outside the vulnerable `<= 3.2.5` range.
4. **No `vite.config.ts` change was needed.** Noting it explicitly since the card pre-authorized one.

Nothing else was changed, and nothing was left undone.
