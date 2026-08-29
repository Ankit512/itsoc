# OPEN-10 Decision Dossier: Foreign Work & Build Artefact Resolution

**Target**: Resolution of concurrent queue artefacts (`tools/attack_generator.py`, `tools/efficacy_data/`, `tools/efficacy_score.py`), parser commit `8a13e6e`, and `web/dist` churn.  
**Author**: Toby (`toby-mtcnvnwu`)  
**Date**: 2026-08-29  
**Branch**: `prep/open10-dossier` (off `main` at `3c0e6ad`)  
**Status**: Reconnaissance & Decision Dossier (Report-Only — No files reverted or modified outside this document)

---

## Executive Summary & Key Findings

1. **Untracked Foreign Tools are NOT in Git History**:
   The foreign-work inventory (`tools/attack_generator.py`, `tools/efficacy_data/`, `tools/efficacy_score.py`) was **never committed to any branch or ref** in the repository. They are solely uncommitted leftover files in the main checkout from an interactive session on `feat/efficacy-harness`.
2. **Zero Codebase Entanglement for Foreign Tools**:
   Zero production modules (`console/`, `threat_intel/`, `itsoc_mcp/`, `web/`), zero tests (`tests/`, `test_console.py`, `test_mcp.py`), and zero CI scripts import or reference `attack_generator` or `efficacy_score`.
3. **Commit `8a13e6e` Contains Genuine, Non-Tangled Production Parsers**:
   The commit associated with `feat/efficacy-harness` (`8a13e6e`) introduced RFC 5424 and JSON-line log parsers (`console/formats/rfc5424.py`, `console/formats/jsonlog.py`) and 2 evaluation test cases (P18, P19). It is fully green (eval 19/19, F1 1.000, detector SHA unchanged) and is **not tangled** with the untracked generator scripts.
4. **`web/dist` is a Major Source of Repo Churn (37 Commits)**:
   Committing generated Vite bundles was originally done for zero-Node runtime serving (`console/serve.py:94-96`), but content-hashed assets (`index-[hash].js`, `index-[hash].css`) have caused 37 churn commits, binary bloating, and recurring merge conflicts. Both `serve.py` and `test_console.py` already support clean fallback/skip when `web/dist` is absent.

---

## 1. Inventory & Provenance

| Artefact | Git Status | Commit / Ref | Author / Date | Origin / Method |
| :--- | :--- | :--- | :--- | :--- |
| `tools/attack_generator.py` | **Untracked** | None (never committed) | N/A (~2026-08-28 20:24 BST) | Leftover in working directory from `feat/efficacy-harness` session. |
| `tools/efficacy_score.py` | **Untracked** | None (never committed) | N/A (~2026-08-28 20:24 BST) | Leftover in working directory from `feat/efficacy-harness` session. |
| `tools/efficacy_data/` (4 logs + 4 manifests) | **Untracked** | None (never committed) | N/A (~2026-08-28 20:25 BST) | Leftover generated output in working directory. |
| `console/formats/rfc5424.py`<br>`console/formats/jsonlog.py` | **Tracked** | `8a13e6e278` | Ankit (2026-08-28 20:22:50 BST) | Direct commit on `feat/efficacy-harness`, merged directly to `main`. |
| `web/dist/` (HTML + hashed CSS/JS) | **Tracked** | 37 commits (first `365c627`, latest `2a743ff`) | Multiple (2026-08-24 to 2026-08-27) | Direct commits & merges across redesign phases. |

### Details on Provenance
- **`tools/attack_generator.py`** (241 lines, 8.6 KB): Standalone synthetic attack-chain generator for canonical, RFC 3164, RFC 5424, and JSONL formats. Never committed to git history (`git log --all -- tools/attack_generator.py` returns 0 results).
- **`tools/efficacy_score.py`** (222 lines, 7.9 KB): Standalone CLI evaluation tool measuring precision/recall/F1 of `anomaly_detector.detect` against logs in `tools/efficacy_data/`. Never committed to git history (`git log --all -- tools/efficacy_score.py` returns 0 results).
- **`tools/efficacy_data/`** (8 files, 5.7 KB): Contains 4 scenario pairs (`brute_compromise`, `credential_spray`, `error_burst`, `port_scan`). Never committed to git history.
- **`8a13e6e` (`feat(parsers): add RFC 5424 and JSON-line log format support`)**: A clean 7-file commit (+446, -2) that registered two production parsers in `normalize.py:sniff_format()` and added evaluation cases P18 and P19 to `tests/eval/manifest.json`.

---

## 2. Entanglement Analysis

### A. Upstream & Downstream References to Foreign Tools
- **Production Code (`console/`, `threat_intel/`, `itsoc_mcp/`, `web/`, root parsers)**:
  - `grep_search("attack_generator")` -> **0 occurrences**.
  - `grep_search("efficacy_score")` -> **0 occurrences**.
  - `grep_search("efficacy_data")` -> **0 occurrences**.
- **Test Suites (`tests/`, `console/test_console.py`, `itsoc_mcp/test_mcp.py`, `web/src/test/`)**:
  - `grep_search("attack_generator")` -> **0 occurrences**.
  - `grep_search("efficacy_score")` -> **0 occurrences**.
  - `grep_search("efficacy_data")` -> **0 occurrences**.
- **Official Evaluation Harness (`tests/eval/run_eval.py`)**:
  - Does **not** import, call, or reference any script in `tools/`.
  - Operates strictly on `tests/eval/manifest.json` and `tests/eval/cases/`.
- **Documentation**:
  - Mentioned only as foreign items in `docs/STAGE_C_OPEN_ITEMS.md:510` and `docs/STAGE_C_HANDOFF.md:91`.
- **Foreign Tools Internal Dependencies**:
  - `attack_generator.py`: Depends only on Python standard library (`argparse`, `json`, `datetime`, `pathlib`).
  - `efficacy_score.py`: Imports `normalize.py`, `rules_syslog.py`, and `anomaly_detector.detect`. It consumes production modules, but no production module consumes it.

### B. Entanglement of Commit `8a13e6e` (RFC 5424 & JSONL Parsers)
- Registered in `normalize.py:sniff_format()` (lines 173-195).
- Directly exercised by `tests/eval/run_eval.py` via test cases P18 (`pos_rfc5424_bruteforce.log`) and P19 (`pos_jsonlog_bruteforce.log`).
- Evaluated in `console/test_console.py:formats-universal` checks.

### C. Entanglement of `web/dist`
- **`console/serve.py:97`**: Sets `WEB_DIST = HERE.parent / "web" / "dist"`.
- **`console/serve.py:1541-1557`**: If `web/dist/index.html` is absent, returns an honest HTTP 503 HTML page:
  `The web app isn't built yet ... Build it once: cd web && npm install && npm run build`.
- **`console/test_console.py:2509-2512`**: Specifically checks `if not (serve.WEB_DIST / "index.html").exists(): print("  [SKIP] web/dist not built...")`.

---

## 3. Blast Radius of a Revert

### Scenario 1: Deleting / Archiving Untracked Foreign Tools (`tools/attack_generator.py`, `tools/efficacy_score.py`, `tools/efficacy_data/`)
- **Git Impact**: Zero commit history modifications; working directory cleaned.
- **Gate Impact**:
  - `tests/eval/run_eval.py`: 19/19 passed (unaffected).
  - `console/test_console.py`: 31+ subsystems passed (unaffected).
  - `python3 -m unittest discover tests/`: 38/38 passed (unaffected).
  - `itsoc_mcp/test_mcp.py`: 131/131 passed (unaffected).
  - `web` vitest & build: 100% green (unaffected).
- **Isolation Assessment**: **100% isolated**. Can be deleted or moved immediately with zero collateral impact.

### Scenario 2: Reverting Commit `8a13e6e` (`feat/parsers`)
- **Git Impact**: Requires `git revert 8a13e6e`.
- **Gate Impact**:
  - `run_eval.py` will fail unless test cases P18 and P19 are manually deleted from `tests/eval/manifest.json` and `cases/`.
  - Eval test count drops from 19 to 17.
  - Multi-format ingestion support for RFC 5424 (structured syslog) and JSONL is removed.
- **Isolation Assessment**: **Tangled with Eval Gate**. Reverting `8a13e6e` is destructive to valid functionality and is **strongly contraindicated**.

### Scenario 3: Untracking & Gitignoring `web/dist`
- **Git Impact**: One commit running `git rm -r --cached web/dist` and adding `web/dist/` to `.gitignore`.
- **Gate Impact**:
  - `test_console.py` gracefully skips `web/dist` test if not built, or passes if `npm run build` is run prior to testing.
  - `serve.py` serves `web/dist` whenever built, and serves an honest build prompt when absent.
  - Eliminates all future merge conflicts in `web/dist/assets/*.js` and `web/dist/assets/*.css`.

---

## 4. Quantitative Analysis of `web/dist` Churn

A repository-wide audit of commits modifying `web/dist` reveals:
```
Total commits modifying web/dist: 37 total (36 commits in 365c627..HEAD + origin commit 365c627)
First commit: 365c627 (2026-08-24) — feat(serve): serve the built React SOC app at :8765
Latest commit: 2a743ff (2026-08-27) — chore(build): rebuild web/dist after C1 integration
Average diff size per commit: ~1,200 lines of minified JS/CSS churn
```

### Why `web/dist` was Committed vs. Why it Fails
1. **Original Intent (`365c627`)**: Intended to allow running `python3 console/serve.py` immediately after `git clone` without requiring Node.js or `npm install`.
2. **Failure Mode (Vite Content Hashing)**:
   - Every frontend edit generates new asset hashes (`index-B8GWr0A9.css`, `index-rf2du_A6.js`).
   - Merging branches where both authors ran `npm run build` generates insoluble git conflicts across multi-megabyte single-line minified files.
   - Workers in Stage C were repeatedly constrained by `web/dist` conflicts (e.g. `2a743ff`, `fab7af0`, `53a985f`).
3. **Stage C Doctrine**: Stage C cards explicitly forbid committing `web/dist` (`web/dist` allowlist exclusion).

---

## 5. Costed Decision Options & Recommendation

### Option A (RECOMMENDED): Clean Fence — Archive Untracked Tools, Retain Parsers (`8a13e6e`), Gitignore `web/dist`
- **Actions**:
  1. Move `tools/attack_generator.py`, `tools/efficacy_score.py`, `tools/efficacy_data/` into `archive/efficacy_harness/` (or remove them).
  2. Retain commit `8a13e6e` on `main` (preserving RFC 5424 and JSONL parsers + 19/19 eval coverage).
  3. Untrack `web/dist` via `git rm -r --cached web/dist` and add `/web/dist/` to `.gitignore`.
- **Cost / Effort**: 5 minutes; 1 clean commit.
- **Consequence**: **Zero regressions, 100% clean working trees, permanent elimination of `web/dist` merge collisions, and full preservation of format parsers.**

### Option B: Total Revert — Revert `8a13e6e`, Delete Untracked Tools, Retain Committed `web/dist`
- **Actions**:
  1. Revert commit `8a13e6e` on `main`.
  2. Downgrade `tests/eval/` from 19 to 17 test cases.
  3. Delete untracked files in `tools/`.
  4. Continue committing `web/dist`.
- **Cost / Effort**: 30 minutes; risk of merge conflicts with subsequent parser work.
- **Consequence**: **Destroys working RFC 5424/JSONL format support, reduces eval rigor, and leaves `web/dist` merge churn unsolved.**

### Option C: Status Quo — Leave Untracked Files in Root Checkout, Keep Committing `web/dist`
- **Actions**: None.
- **Cost / Effort**: 0 minutes initially; recurring hours lost to future merge incidents.
- **Consequence**: **Repeated risk of dirty checkouts polluting branch integrations (as observed during C2 merge), and ongoing binary merge conflicts.**

---

## Final Recommendation

**Adopt Option A**.  
The untracked tools (`attack_generator.py`, `efficacy_score.py`) do not exist in git history, making their removal completely safe. Commit `8a13e6e` is a high-quality, fully tested format-parser addition that should remain on `main`. Untracking `web/dist` and adding it to `.gitignore` eliminates the primary mechanical friction point in the repository while leaving `serve.py`'s honest fallback behavior fully functional.
