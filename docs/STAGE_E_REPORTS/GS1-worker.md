# GS-1 — close the gate-set holes

**Branch:** `Ankit512/gs1-gate-set` · **Base:** `5cc5d45` (current `main`) · **Date:** 2026-09-06

**Base check.** `git merge-base --is-ancestor 5cc5d45 HEAD` → **0 (ancestor OK)**. Worktree is not stale.

**Detector freeze.** `shasum -a 256 anomaly_detector.py` before **and** after:
`364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876` — matches CLAUDE.md §1. Never opened for writing.

**Environment.** `web/node_modules` was **absent**; `npm --prefix web install` was run (exit 0). Recorded per the card.

**Files changed (allowlist audit).** All five are on the allowlist; nothing else is touched.

| File | On allowlist |
| :--- | :--- |
| `scripts/gate.sh` | yes |
| `.github/workflows/ci.yml` | yes |
| `tests/test_battlecard_efficacy.py` | yes |
| `console/test_auth_security.py` | yes |
| `CLAUDE.md` | yes — under the stated condition; before/after quoted in §4 |
| `docs/STAGE_E_REPORTS/GS1-worker.md` | yes (this file) |

`git diff --check` → **clean** (no whitespace errors, no conflict markers).

---

## 0. Baseline re-measured at the base

Every suite launched as the card describes, timed. **The coordinator's baseline reproduced exactly** — same 13 passes, same 2 failures, same 2 invocation-mode failures. No difference to report.

| Suite | rc | wall |
| :--- | ---: | ---: |
| `console/test_auth_security.py` | **1** | 0.3s |
| `console/test_console.py` | 0 | 20.4s |
| `console/test_copilot_workspace.py` | 0 | 0.04s |
| `console/test_fsafe.py` | 0 | 0.8s |
| `console/test_overview.py` | 0 | 0.2s |
| `itsoc_mcp/test_mcp.py` | 0 | 0.1s |
| `tests/eval/run_eval.py` | 0 | 0.1s |
| `tests/test_approvals.py` | 0 | 3.5s |
| `tests/test_audit_drift.py` | 0 | 0.1s |
| `tests/test_battlecard_efficacy.py` | **1** | 2.0s |
| `tests/test_e7a_feature_contract.py` | 0 | 1.5s |
| `tests/test_intake.py` | 0 | 0.1s |
| `tests/test_recommend.py` | 0 | 31.3s |
| `tests/test_stage_e_wall.py` | 0 | 0.8s |
| `tests/test_ti_oem_egress.py` | 0 | 0.1s |
| `threat_intel/test_threat_intel.py` | 0 | 0.3s |
| `tools/test_attack_generator.py` | **1** | 0.03s |
| `tools/test_efficacy_harness.py` | **1** | 0.04s |
| `tools/test_train_triage.py` | 0 | 2.5s |

---

## 1. TASK 1 — `tests/test_battlecard_efficacy.py`

### 1a. The stale assertion (as briefed)

**Before:**

```python
self.assertEqual(
    ["INC-4a7f", "failure-success", "error-burst"],
    [scenario["scenario"] for scenario in result["scenarios"]],
)
```

Actual output is 18 entries — the six frozen `BENCHMARK_SCENARIOS` across the three `BENCHMARK_SEEDS`.

**After** — the structural invariant, read from the frozen referee rather than copied out of it:

```python
from tools.efficacy_harness import BENCHMARK_SCENARIOS, BENCHMARK_SEEDS
...
self.assertEqual(
    [(scenario, seed)
     for seed in BENCHMARK_SEEDS
     for scenario in BENCHMARK_SCENARIOS],
    [(run["scenario"], run["seed"]) for run in result["scenarios"]],
)
self.assertEqual({"canonical"}, {run["format"] for run in result["scenarios"]})
```

The seed is now asserted too, not just the name, so the *ordering* contract (scenario tuple in declaration order, once per seed, in seed order) is what is pinned. A legitimate scenario or seed addition now moves this test **with** the referee instead of breaking it the same way. `tools/efficacy_harness.py` and `tools/test_efficacy_harness.py` were read, never edited.

### 1b. A SECOND, LARGER FINDING the brief did not anticipate — the rest of that test was DEAD

Fixing the first assertion unblocked the loop underneath it, which builds a Markdown row per run and asserts it appears in the battle card. **Zero of the 18 rows appear in `docs/BATTLECARD_TORQ.md` — in any form.** Measured:

```
False | `INC-4a7f` | `canonical` | 1.0 | 1.0 | 1.0 | 9 / 9 | 0 |
False | `failure-success` | `canonical` | 1.0 | 1.0 | 1.0 | 6 / 6 | 0 |
... (16 more, all False)
rows found in battlecard: 0 / 18
```

The row shape the test builds — 7 columns with the **format** in column 2 and **per-run** figures — is not the shape §3.1a has. That table is `Scenario | Ground truth | Rule P/R/F1 | Rule FPs | Learned P/R/F1 | Learned FPs | Malicious lines`, aggregated over the three seeds.

**Which side is wrong: the TEST.** Git shows this precisely. At `cc9416c` (the test's own era) the battle card *did* carry exactly that row shape:

```
$ git show cc9416c:docs/BATTLECARD_TORQ.md | grep '| `canonical` |'
82:| `INC-4a7f` | `canonical` | 1.0 | 1.0 | 1.0 | 7 / 7 | 0 |
83:| `failure-success` | `canonical` | 1.0 | 1.0 | 1.0 | 6 / 6 | 0 |
84:| `error-burst` | `canonical` | 1.0 | 1.0 | 1.0 | 6 / 6 | 0 |
```

Commit `11fb797` (*docs(E8): publish the paired benchmark from a real fresh run*) replaced that single-seed table with the six-row, three-seed aggregate and **did not update the test**. Because the assertion above it failed first, the whole loop had been unreachable ever since. Both halves were stale, from the same cause, at the same moment.

### 1c. The published document is CORRECT — verified, not assumed

The card asked me to report loudly if the battle card states a figure the harness does not produce, and **not** to quietly adjust either side. I checked, and the finding is the reassuring direction: **every published §3.1a number reproduces from today's harness.**

| Scenario | Class | Malicious lines (3 seeds summed) | Battle card | Rule FPs | Battle card |
| :--- | :--- | ---: | ---: | ---: | ---: |
| `INC-4a7f` | confirmed | 9+7+8 = 24 | 24 / 24 ✅ | 0 | 0 ✅ |
| `failure-success` | confirmed | 6+9+7 = 22 | 22 / 22 ✅ | 0 | 0 ✅ |
| `error-burst` | confirmed | 9+8+7 = 24 | 24 / 24 ✅ | 0 | 0 ✅ |
| `near-miss-auth` | false-positive | 0 | 0 / 0 ✅ | 3 | 3 ✅ |
| `near-miss-errors` | false-positive | 0 | 0 / 0 ✅ | 9 | 9 ✅ |
| `benign-maintenance` | benign-expected | 0 | 0 / 0 ✅ | 9 | 9 ✅ |

Rollup: harness `total_misses=0`, `total_false_positives=21` — matching both *"0 missed malicious lines, 21 false-positive findings"* and the E8m scope label *"The 21 false positives above are the `canonical`-format total for those 18 runs."*

**No figure was adjusted on either side.** The document was already right; only the test was stale. So the replacement asserts the document's *real* published table, which is what the test's name has always promised:

- ground-truth class, rule P/R/F1 cell, rule FP count and malicious-lines column, per scenario, summed across seeds;
- the P/R/F1 cell must be **identical across the three seeds** — a per-seed divergence is a failure, not something to average, because one published cell cannot honestly stand for three different measurements;
- `n/a` rendering mirrors the referee's own rule (`precision_defined` / `recall_defined`, harness lines 1586-1589), so an undefined recall never prints as a measured `0.0`;
- a new `test_rollup_totals_match_the_harness` pins the rollup sentence and the E8m scope label to `total_misses` / `total_false_positives`, so those two can no longer drift apart.

**Learned column, honestly.** A trained model is gitignored and absent from a fresh checkout, so the learned cells are asserted only when `learned.available`, and otherwise print the harness's own reason. I did **not** leave that path unproven: I ran `tools/train_triage.py` and re-ran the suite with a model present — **5 tests, OK, with no NOTE lines**, i.e. the battle card's learned columns (`1.0 / 1.0 / 1.0`, `n/a / n/a / n/a`, 0 FPs) are verified too. Both paths are exercised.

**Before → after:**

```
$ python3 tests/test_battlecard_efficacy.py          # BEFORE
AssertionError: Lists differ: ['INC[35 chars]urst'] != [... 15 additional elements]
Ran 3 tests in 1.996s
FAILED (failures=1)

$ python3 tests/test_battlecard_efficacy.py          # AFTER
.....
Ran 5 tests in 2.485s
OK
  NOTE: learned column unverified for `INC-4a7f` — no trained model at .../triage_v1.pkl
  (... one per scenario; absent-model path)

$ python3 tools/train_triage.py && python3 tests/test_battlecard_efficacy.py   # AFTER, model present
.....
Ran 5 tests in 2.168s
OK                                                   # no NOTEs — learned columns verified
```

Test count went 3 → 5. **No assertion was deleted or weakened**: the two guardrail tests are untouched, the scenario-list assertion got *stronger* (seeds and format now pinned), the row check went from unreachable to executing against the document's real table, and the rollup check is new.

---

## 2. TASK 2 — `console/test_auth_security.py`

I read `console/serve.py` lines 113-127 and the auth path (`serve.py:1470-1473`, `:2815`) before touching anything.

**Conclusion: the TEST is wrong, not the product.** This is not a STOP. `AUTH_REQUIRED = os.environ.get("ITSOC_AUTH", "").strip() == "1"` is a deliberate, dated (2026-08-27), documented owner decision, with the mitigation stated (127.0.0.1 bind only) and the restore switch given. `console/test_console.py:5306-5411` exercises **both** modes. The defect is that this suite asserted the fail-closed behaviour without enabling the mode that produces it, so it got 200 and failed.

**Before** — asserts 401, never turns the gate on:

```python
def main():
    original = auth.AUTH_PROVIDER
    try:
        ...
            status, _ = request(base, "/api/overview")
            assert status == 401, status
    finally:
        auth.AUTH_PROVIDER = original
    print("auth security regressions: PASS")
```

**After** — the same assertions, now run in the mode they were written for:

```python
def main():
    # The product default is the owner's decision and is NOT touched: assert it
    # is still the documented env-driven switch, so a future "fix" that flips
    # the default on cannot hide behind this suite.
    expected_default = os.environ.get("ITSOC_AUTH", "").strip() == "1"
    assert serve.AUTH_REQUIRED == expected_default, (...)
    print(f"auth security: process default AUTH_REQUIRED={serve.AUTH_REQUIRED} "
          f"(owner decision, 2026-08-27) — pinning it ON for these assertions")

    original = auth.AUTH_PROVIDER
    original_required = serve.AUTH_REQUIRED
    serve.AUTH_REQUIRED = True          # assert the fail-closed gate, not 200
    try:
        ...
    finally:
        serve.AUTH_REQUIRED = original_required
        auth.AUTH_PROVIDER = original
    print("auth security regressions: PASS (fail-closed mode, AUTH_REQUIRED=True)")
```

Three properties worth stating:

1. **No assertion weakened.** Every `assert status == 401` is unchanged. Nothing accepts 200.
2. **The product default is untouched** — and now *guarded*: the suite fails if `serve.AUTH_REQUIRED` stops being the documented `ITSOC_AUTH`-driven switch, in **either** direction. Somebody "fixing" this by flipping the default on cannot hide behind a green run here.
3. **Honest about its own mode**, in its output and in a module docstring naming the owner decision, the mitigation and the restore switch. The pin/restore pattern is the one `console/test_console.py` already uses, so there is one idiom, not two. `console/serve.py` was read only.

**Before → after:**

```
$ python3 console/test_auth_security.py          # BEFORE
Traceback (most recent call last): ... AssertionError: 200
rc=1

$ python3 console/test_auth_security.py          # AFTER
auth security: process default AUTH_REQUIRED=False (owner decision, 2026-08-27) — pinning it ON for these assertions
  127.0.0.1 "GET /api/overview HTTP/1.1" 401 -
  127.0.0.1 "POST /api/auth/signup HTTP/1.1" 201 -
  127.0.0.1 "POST /api/auth/signup HTTP/1.1" 409 -
  127.0.0.1 "POST /api/auth/login HTTP/1.1" 200 -
  127.0.0.1 "GET /api/overview HTTP/1.1" 200 -
  127.0.0.1 "PATCH /api/cases/some-id HTTP/1.1" 401 -
  127.0.0.1 "PATCH /api/cases/some-id HTTP/1.1" 404 -
auth security regressions: PASS (fail-closed mode, AUTH_REQUIRED=True)
rc=0
```

---

## 3. TASK 3 — the gate

### 3a. Complete inventory — 19 entries, every one classified

The card says seventeen suites; the true count is **eighteen runnable Python suites plus one non-asserting tool**. The extra one is the point of the exercise: **`tests/eval/validate_real.py --selftest`** is a real, self-contained, asserting check (`SELFTEST: PASS`, 15 assertions, 0.05s) that appeared on nobody's list — neither the gate's, nor CI's, nor the card's — because it does not match `test_*.py`. It is exactly the kind of thing that rots unseen, and it is now in the gate.

| # | Suite | Invocation | Wall | Classification |
| ---: | :--- | :--- | ---: | :--- |
| 1 | `tests/eval/run_eval.py` | file | 0.1s | **IN-GATE** (was) |
| 2 | `tests/eval/validate_real.py --selftest` | file + flag | 0.1s | **IN-GATE** (newly found) |
| 3 | `threat_intel/test_threat_intel.py` | file | 0.3s | **IN-GATE** (was) |
| 4 | `console/test_auth_security.py` | file | 0.3s | **IN-GATE** (was failing) |
| 5 | `console/test_copilot_workspace.py` | file | 0.1s | **IN-GATE** |
| 6 | `console/test_overview.py` | file | 0.2s | **IN-GATE** |
| 7 | `console/test_fsafe.py` | file | 0.8s | **IN-GATE** |
| 8 | `itsoc_mcp/test_mcp.py` | file | 0.1s | **IN-GATE** |
| 9 | `tests/test_intake.py` | file | 0.1s | **IN-GATE** |
| 10 | `tests/test_audit_drift.py` | file | 0.1s | **IN-GATE** |
| 11 | `tests/test_ti_oem_egress.py` | file | 0.1s | **IN-GATE** |
| 12 | `tests/test_stage_e_wall.py` | file | 0.8s | **IN-GATE** |
| 13 | `tests/test_e7a_feature_contract.py` | file | 1.5s | **IN-GATE** |
| 14 | `tests/test_battlecard_efficacy.py` | file | 2.5s | **IN-GATE** (was failing) |
| 15 | `tests/test_approvals.py` | file | 3.5s | **IN-GATE** |
| 16 | `tools/test_attack_generator.py` | **`-m tools.…`** | 0.1s | **IN-GATE** (was failing as a file) |
| 17 | `tools/test_train_triage.py` | **`-m tools.…`** | 2.5s | **IN-GATE** |
| 18 | `tools/test_efficacy_harness.py` | **`-m tools.…`** | 4.7s | **IN-GATE** (was failing as a file) |
| 19 | `console/test_console.py` | file | 20s | **IN-GATE** (was) |
| 20 | `tests/test_recommend.py` | file | 31s | **IN-GATE** — see §3c |
| — | `tests/eval/validate_real.py` (full mode) | n/a | n/a | **DELIBERATELY OUT** — needs an operator-supplied real log **and** a hand-labelled ground-truth file, and asserts nothing; it reports precision/recall/FP lists for a human. Not a pass/fail suite. Its `--selftest`, which *does* assert, is entry 2. |
| — | `web/src/test` (vitest, 44 files / 313 tests) + `npm run build` | `--web` | 20s | **IN-GATE behind `--web`** — needs `web/node_modules`. Absent, they **SKIP loudly**, never a pass. |

No suite is unlisted. The gate's own summary now prints the DELIBERATELY OUT block on every run, so the classification is visible at the point of use rather than buried in a report.

### 3b. Invocation mode is load-bearing — recorded as a finding

Two suites pass or fail purely by **how they are launched**:

```
$ python3 tools/test_attack_generator.py
ModuleNotFoundError: No module named 'tools'
$ python3 -m tools.test_attack_generator
Ran 5 tests — OK
```

**Cause, established, not guessed.** Both do `from tools import …`, which needs the **repo root** on `sys.path`. Launching as a file puts `tools/` on `sys.path[0]` instead, so the package is invisible. There is no `tools/__init__.py`; `-m` works because the CWD is on `sys.path`. Proof the cause is `sys.path` and not the test bodies:

```
$ PYTHONPATH=. python3 tools/test_attack_generator.py
Ran 5 tests — OK      # same file, same content, now passes
```

So the tests were never broken, and neither needed editing — I did not touch the frozen `tools/test_efficacy_harness.py`. The gate makes the choice **explicit**: `python3 -m tools.<name>`, run from the repo root, under a header comment explaining why. I chose `-m` over `PYTHONPATH=.` because it is self-documenting at the call site — a reader sees the module launch and the comment, rather than inheriting behaviour from an env var set elsewhere.

### 3c. Speed — measured, and nothing omitted for it

Full Python gate: **70.9s** wall for 21 gates. With `--web`: **93.6s** for 23.

`tests/test_recommend.py` (31s) and `console/test_console.py` (20s) are 51s of that — 72%. **Both stay in the default gate, and there is no `--full` flag.** A 70-second gate is comfortably fast enough to actually run before every merge, and splitting the two most expensive suites behind an opt-in flag would recreate the exact hole this card exists to close: the flag would go unpassed, and their coverage would rot the way suites 4 and 14 did. If the gate ever outgrows a developer's patience, the fix is to make those suites faster, not to make the gate blinder. Both are ordered **last** so cheap breaks surface early — while rule 3 still runs everything.

### 3d. The four properties, kept

All four are intact and unmodified: `run_gate` still tees to terminal **and** `gate-logs/<stamp>/<name>.log` (rule 1), still recovers `PIPESTATUS[0]` (rule 2), every gate still runs via `|| true` with a summary exit (rule 3), and `skip_gate` still reports SKIP separately from PASS (rule 4). I added a **rule 5** — *never leave a suite unlisted* — since that is the property whose absence caused this card.

### 3e. CI now runs the gate

`.github/workflows/ci.yml` hand-listed three suites; `scripts/gate.sh` hand-listed the same three. **Two hand-maintained lists of what to test is one too many — whichever is edited less becomes a lie, and both were.** CI now executes `scripts/gate.sh --web`. Adding a suite to the gate adds it to CI for free, and CI can no longer be greener than a developer's local run.

Three deliberate improvements came with it: Node is now set up and `npm --prefix web ci` run, so **CI builds and tests `web/` for the first time**; `gate-logs/` is uploaded as an artifact `if: always()`, honouring rule 1 across the runner boundary; and there is still **no `pip install`**, which turns the job into a standing proof that the optional extras are optional — scikit-learn is absent there, so `test_train_triage` / `test_efficacy_harness` take their honest skip path and `test_battlecard_efficacy` reports the learned column as unverified-with-a-reason rather than fabricating a pass.

**Both optional-dependency states are verified locally**, as the acceptance asks:

```
$ python3 -m tools.test_train_triage                      # sklearn PRESENT (1.7.2) → OK
$ python3 -m tools.test_efficacy_harness                  # PRESENT → OK (69 tests)
$ PYTHONPATH=<stub> python3 -m tools.test_train_triage    # sklearn ABSENT → OK (skipped=2)
$ PYTHONPATH=<stub> python3 -m tools.test_efficacy_harness # ABSENT → OK
$ PYTHONPATH=<stub> python3 tests/test_battlecard_efficacy.py
  OK — NOTE: learned column unverified … scikit-learn is not installed …
```

(ABSENT was simulated with a `sklearn.py` on `PYTHONPATH` that raises `ImportError`; the real package was never uninstalled.)

---

## 4. CLAUDE.md §6 — before and after

My change **does** make the documented command stale: §6 named three suites by hand, which is now a strict subset of a canonical gate that CI also runs, and leaving it would keep pointing every future agent at the same three-suite habit that caused this card.

**Before:**

> 6. **Branch per task** (`feat/<slug>`). Before proposing a merge, run `tests/eval` (`run_eval.py`) + `console/test_console.py` — and, for any change under `web/`, `cd web && npm test` (vitest) + `npm run build` — and paste results. Merge only after green.

**After:**

> 6. **Branch per task** (`feat/<slug>`). Before proposing a merge, run **`scripts/gate.sh`** — and, for any change under `web/`, **`scripts/gate.sh --web`** (it adds vitest + the production build) — and paste the GATE SUMMARY block. Merge only after GATE GREEN. The gate is the single list of what must pass: it runs every Python suite in the repository (`.github/workflows/ci.yml` executes the same script, so CI cannot be greener than your local run), and any suite it deliberately omits is named with its reason in its own summary. Naming individual suites here instead is what let two of them fail unnoticed (GS-1, 2026-09-06); add a new suite to `scripts/gate.sh`, not to this line.

Nothing else in CLAUDE.md is touched; §1 and §7 (the freeze) are unchanged.

---

## 5. THE GATE STILL BITES — two demonstrations

A gate that cannot fail is not a gate. Both breaks were temporary local edits, both fully reverted, both verified reverted by hash and `git status`.

### Demo A — restore the two pre-fix suites → gate goes RED and names both

```
$ git show HEAD:console/test_auth_security.py    > console/test_auth_security.py
$ git show HEAD:tests/test_battlecard_efficacy.py > tests/test_battlecard_efficacy.py
$ scripts/gate.sh ; echo rc=$?
  PASS  test_console
  FAIL  test_auth_security (exit=1, evidence: gate-logs/20260906-125659/test_auth_security.log)
  FAIL  test_battlecard_efficacy (exit=1, evidence: gate-logs/20260906-125659/test_battlecard_efficacy.log)
GATE RED — 2 failing. Output above is preserved in gate-logs/20260906-125659.
rc=1
```

This is the whole card in one run. **Both** failures are reported, not just the first (rule 3 held — `test_console` ran and passed *after* them), each names its evidence file (rule 1), and the script exits 1. These are the exact two suites that had been failing invisibly; the gate now catches them.

### Demo B — a real product defect caught by a suite the old gate never ran

Demo A proves the gate runs the fixed tests. This proves the **new coverage catches product breakage that would previously have shipped green.** I disabled the redaction deep-walk in `scripts/intake.py` — the egress path:

```diff
-            return node if key in SKIP_KEYS else redactor.redact(node)
+            return node  # DELIBERATE GS-1 BREAK: redaction disabled
```

```
$ scripts/gate.sh ; echo rc=$?
  FAIL  test_intake (exit=1, evidence: gate-logs/20260906-125838/test_intake.log)
GATE RED — 1 failing.
rc=1

$ cat gate-logs/20260906-125838/test_intake.log
AssertionError: '198.51.100.20' unexpectedly found in "# Safe intake report (REDACTED) …
  - **Redaction:** ON — 0 IP(s), 0 username(s), 0 hostname(s) masked …
  | Brute-force login attempts for 'admin' from 198.51.100.20 |
  : raw IP leaked into redacted markdown
```

A raw IP leaking into a report labelled *"REDACTED"* and *"safe to share"* — caught **only** by `tests/test_intake.py`, which the old three-suite gate did not run. **Under the previous gate this defect would have passed green.**

**Restored and verified:**

```
$ cp <backup> scripts/intake.py
$ git status --porcelain
 M .github/workflows/ci.yml
 M CLAUDE.md
 M console/test_auth_security.py
 M scripts/gate.sh
 M tests/test_battlecard_efficacy.py
$ git diff --check    # clean
```

`scripts/intake.py` is absent from the list — byte-identical to `HEAD`. The two test files were restored from hash-verified backups (`764bb289…`, `c766690a…`).

---

## 6. Final green — the acceptance runs

### `scripts/gate.sh --web` (final, after everything reverted)

```
================ GATE SUMMARY (20260906-130000) ================
  PASS  run_eval                      PASS  test_e7a_feature_contract
  PASS  validate_real_selftest        PASS  test_battlecard_efficacy
  PASS  threat_intel                  PASS  test_approvals
  PASS  test_auth_security            PASS  test_attack_generator
  PASS  test_copilot_workspace        PASS  test_train_triage
  PASS  test_overview                 PASS  test_efficacy_harness
  PASS  test_fsafe                    PASS  test_console
  PASS  test_mcp                      PASS  test_recommend
  PASS  test_intake                   PASS  web_vitest
  PASS  test_audit_drift              PASS  web_build
  PASS  test_ti_oem_egress            PASS  detector_freeze
  PASS  test_stage_e_wall
  evidence: gate-logs/20260906-130000

  DELIBERATELY OUT of this gate (rule 5 — named, never silently unlisted):
    tests/eval/validate_real.py (full mode) — … asserts nothing; it reports metrics.
      Its --selftest, which does assert, IS in the gate above.
    web/src/test (vitest) and the web build — in the gate behind --web, since
      they need web/node_modules; absent, they SKIP loudly (never a pass).
=======================================================
GATE GREEN.
```

23 PASS, 0 FAIL, 0 SKIP, exit 0, 93.6s. `scripts/gate.sh` (no `--web`) is likewise **GATE GREEN** — 21 PASS, exit 0, 70.9s.

### Standing suites, individually confirmed from the gate's own logs

| Check | Result |
| :--- | :--- |
| `tests/eval/run_eval.py` | `cases: 20 passed, 0 failed, 20 total`; `false positives : 0` — **20/20, FP=0** ✅ |
| `tests/test_stage_e_wall.py` | `135/135 checks passed` · `Stage E wall intact.` ✅ |
| `console/test_console.py` | PASSED — all 45 check groups green (…`cb1fix-copilot-read-only`) ✅ |
| `tests/test_e7a_feature_contract.py` | PASS ✅ |
| harness + train_triage, sklearn **PRESENT** | OK / OK (69 tests) ✅ |
| harness + train_triage, sklearn **ABSENT** | OK (skipped=2) / OK ✅ |
| `npm --prefix web test` | `Test Files 44 passed (44)` · `Tests 313 passed (313)` ✅ |
| `npm run build` | PASS (`tsc --noEmit && vite build`) ✅ |
| `anomaly_detector.py` sha256 | `364577c5…a4876` — unchanged ✅ |

---

## 7. Deviations and judgement calls

1. **Suite count is 18+1, not 17.** `tests/eval/validate_real.py --selftest` was on nobody's list. Added.
2. **A second finding in Task 1** the brief did not anticipate: the row-assertion half of the battle-card test was *dead*, not merely stale — 0/18 rows matched — and `git show cc9416c` proves commit `11fb797` changed the document's table shape without updating the test. Both halves rotted from one cause.
3. **The published document was verified CORRECT.** Nothing was adjusted on either side. This is a negative finding, reported because the card asked for it either way.
4. **Task 2 is not a STOP.** After reading `serve.py`, the test was wrong and the product right. I additionally *pinned* the product default so it cannot be quietly flipped behind a green run.
5. **No `--full` flag**, deliberately, with the 70.9s / 51s-of-it numbers given in §3c. Reasoning stated rather than the omission made silently.
6. **CI points at the gate**, and gained web coverage and evidence upload. CI's no-`pip-install` posture is preserved and reframed as a standing proof that the optional extras are optional.
7. **CLAUDE.md §6 was updated**, before/after quoted verbatim in §4.
8. **A trained model artifact** (`console/.soc/models/triage_v1.pkl`) was created locally to exercise the learned-column path. It is gitignored and is not part of this commit.
9. **Nothing on the FORBIDDEN list was modified.** `scripts/intake.py` was temporarily broken for Demo B **only**, at the card's explicit request, and restored byte-identically (§5).
