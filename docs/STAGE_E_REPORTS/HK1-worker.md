# HK1 — Orca's stale worktree base: diagnosis, fix, and proof

Card: HK1. Worker branch: `Ankit512/hk1-worktree-base`.
Scope: Orca tooling and local configuration. **No file in this repository's
application surface was read for edit or changed.** The only file this card
writes is this report.

---

## 1. Base check result — the defect reproduced on me

The card predicted this worker would likely land on the stale base. It did.
This dispatch is the **eighth consecutive occurrence**.

```
HEAD                     b83611484233496231aebbfff092ae98cdbee438
                         "docs: add standing Stage E guardrails"  2026-09-02 08:31:09 +0100

git merge-base --is-ancestor e0b739a2… HEAD     -> FAILS
git merge-base --is-ancestor HEAD e0b739a2…     -> SUCCEEDS   => worktree is STALE
```

Consistent with all seven prior occurrences: the worktree was **clean**
(`git status --short` empty) and the branch had **no unique commits** — its
entire reflog was a single line, `branch: Created from refs/remotes/origin/main`.
Nothing was lost. This is a **base-resolution** defect, not lost work.

Freeze verified before and after all work:

```
shasum -a 256 anomaly_detector.py
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876   (unchanged)
```

Diagnosis proceeded without any edit to the stale worktree. It was held as the
specimen for the whole investigation and reset by the coordinator — not by me —
only once the diagnosis, fix and proof were complete. After that reset:

```
HEAD  4d946e310e577546cea4d2e617455a4934148d35
      "docs: accept E8m2; benchmark scenario freeze verified by attack"   (= current local main)

git merge-base --is-ancestor e0b739a2… HEAD   -> SUCCEEDS   => base check PASSES
```

Both readings are recorded deliberately: the failing one is the specimen this
card exists to explain, and the passing one is the state this report is
committed from.

---

## 2. The mechanism, with the evidence that identifies it

**Orca resolves a new worktree's base from the remote-tracking ref
`refs/remotes/origin/main`, not from local `main`.**

This is not inferred from a coincidence of two refs pointing at the same
commit. It is git's own record of the source ref, on every Orca-created branch:

```
$ git reflog show Ankit512/hk1-worktree-base
b836114 …@{0}: branch: Created from refs/remotes/origin/main
```

The same line appears at the tail of every Orca-created branch's reflog —
`Ankit512/e7b-r2-triage-modifier`, `Ankit512/e8m2-scorecard-pin`,
`Ankit512/f0-steps-numbering`, `Ankit512/f0-evidence`,
`Ankit512/e7b-r1-triage-modifier`, `Ankit512/d2-efficacy-surface` — each
`Created from refs/remotes/origin/main`, each starting at whatever
`origin/main` held at the time. The ones that later show a `reset: moving to …`
entry are the orchestrator-side mitigation being applied on top.

**Why `origin/main` was the fallback:** `orca repo show` for repo
`506c3684-fb2e-44d5-924d-a4f5bbaf8a32` (`/Users/ankit/Projects/log-analyzer`)
carried **no base-ref field at all**. With nothing recorded, Orca falls back to
the remote default branch derived from the registration's
`gitRemoteIdentity.canonicalKey = github.com/Ankit512/log-anomaly-detector`.
So the base was never *chosen* — it was defaulted.

### Candidate mechanisms ruled out, not assumed away

| Candidate from the card | Verdict | Evidence |
|---|---|---|
| Cached/mirrored clone never fetched | **Ruled out** | `.git/FETCH_HEAD` mtime `Sep 3 01:31:32 2026` — a fetch ran ~minutes before this dispatch. |
| Stale remote-tracking ref that a fetch would fix | **Ruled out** | `git ls-remote origin main` → `b83611484233496231aebbfff092ae98cdbee438`. The **real GitHub remote genuinely is at b836114.** No fetch could ever help. |
| Template / seed worktree copied on creation | **Ruled out** | Each branch is created by a normal git branch operation from a named ref, per its reflog; no copy step appears. |
| Detached snapshot taken at repo-registration time | **Ruled out** | `origin/main` moved repeatedly *after* registration (`addedAt` 1788093572830) — its reflog has 20+ later entries. The value is live, just frozen since the last push. |
| Pinned/default ref in Orca's repo registration | **CONFIRMED — by absence** | No base-ref key in `orca repo show`; the remote default branch is used as fallback. |

---

## 3. The root-cause moment

`refs/remotes/origin/main` last moved here:

```
$ git reflog show refs/remotes/origin/main
b836114 refs/remotes/origin/main@{0}: update by push      <-- last entry, ever
38efb59 refs/remotes/origin/main@{1}: update by push
6ecf75f refs/remotes/origin/main@{2}: update by push

$ stat -f '%Sm %N' .git/refs/remotes/origin/main
Sep  2 08:31:11 2026 .git/refs/remotes/origin/main
```

**The moment is 2026-09-02 08:31:11 — the last `git push` this repository ever
made.** That push set `origin/main` to b836114 and nothing has moved it since.

The root cause is an **interaction between two individually-correct
behaviours**, not a bug in either half:

- Orca defaults a new worktree's base to the **remote** default branch.
- This project's standing doctrine is **never push**; every card ends
  "Do not push. Do not merge." Work lands on local `main` through local merges.

Local `main` has since advanced **41 commits** past `origin/main`. Because the
doctrine forbids the push that would move `origin/main`, **the defect can never
self-heal** — and that is precisely why every one of the eight occurrences
landed on the *same* commit rather than drifting. The reported spread of 30 /
37 / 40 / 44 commits behind is not the base moving; it is local `main` moving
away from a fixed point.

---

## 4. What I changed

One command, in **Orca's own state only**. No file in this repository was
touched, and no remote was contacted:

```
orca repo set-base-ref --repo path:/Users/ankit/Projects/log-analyzer --ref main
```

The repo record now carries `"worktreeBaseRef": "main"` — a key that was
**absent** from the record beforehand. `orca repo search-refs` confirms Orca
treats `main` and `origin/main` as two distinct refs, so this names local
`main`, resolved at creation time.

This was reported to the coordinator with the exact command and rationale
**before** it was run, per the card's out-of-repo constraint.

---

## 5. The proof — a fresh worktree, same path, no reset

Acceptance bar: create a worktree through the same path that produced the
eight failures and show it lands on current local `main` with **no reset**.

```
$ orca worktree create --name hk1-base-proof \
    --repo path:/Users/ankit/Projects/log-analyzer --no-parent --setup skip
    # note: NO --base-branch passed — the repo default is what is under test

  "baseRef": "main",
  "git": { "head": "c4ee4ed6071560eb80d596d0f2007da4f3309f6d",
           "branch": "refs/heads/Ankit512/hk1-base-proof" }

$ git reflog show Ankit512/hk1-base-proof
c4ee4ed …@{0}: branch: Created from refs/heads/main        <-- was refs/remotes/origin/main

$ git rev-parse main
c4ee4ed6071560eb80d596d0f2007da4f3309f6d                   <-- identical

$ git rev-parse --short refs/remotes/origin/main
b836114                                                    <-- UNCHANGED
```

This is a controlled A/B, and the third line is what makes it one:

- **Before:** created from `refs/remotes/origin/main` → landed on `b836114`.
- **After:** created from `refs/heads/main` → landed on `c4ee4ed`, byte-identical
  to current local `main`.
- **`origin/main` is still `b836114` throughout.** The remote did not catch up.
  What moved is the **base resolution** — which is the claim under test.

No reset was applied to the probe worktree at any point. The probe worktree and
its branch `Ankit512/hk1-base-proof` were removed after the measurement.

---

## 6. A lead that was checked rather than adopted

The coordinator supplied a strong lead mid-investigation — that `origin/main`
had gone stale for want of a fetch — and floated
`git update-ref refs/remotes/origin/main main` as a doctrine-safe mitigation,
explicitly asking that it be verified rather than restated.

Checking it changed the answer. `git ls-remote origin main` returns
`b83611484233496231aebbfff092ae98cdbee438`: the **real remote is at b836114**.
The local remote-tracking ref is not stale — it is *accurate*. Had the lead been
adopted, `update-ref` would have pointed `origin/main` at a commit the remote
does not contain, making the ref confidently wrong rather than honestly behind,
and quietly breaking `--force-with-lease`, whose whole safety model depends on
that ref telling the truth.

The coordinator confirmed the correction and asked that it be recorded here as
part of the finding. It is the same discipline the card is about: a check that
takes one command is worth more than a plausible mechanism, and the failure mode
being fixed here is precisely one of a remembered value never being re-checked
against reality.

---

## 7. Mitigations considered, ranked

**Recommended — adopted: `orca repo set-base-ref --ref main`.**
Declarative, persisted in Orca's repo record, applied once, contacts no remote,
and self-maintains as local `main` advances. It fixes the resolution at the
point where the wrong ref was chosen, rather than correcting the result
afterwards.

**Rejected: `git update-ref refs/remotes/origin/main main`.**
Worth naming explicitly because it touches no remote and so is doctrine-legal,
but it is the wrong instrument. It makes `origin/main` assert a value the actual
remote does not have — corrupting ahead/behind reporting, and undermining
`--force-with-lease`, whose entire safety model is that the remote-tracking ref
tells the truth about the remote. Any genuine fetch silently reverts it, and it
must be re-run forever.

**Kept, but not as the fix: the orchestrator-side reset (guardrail 9).**
It stays. Per the card, the belt remains after the buckle is repaired, and its
removal is out of scope — I am not recommending it. Its standing value is now
different: it was the fix, and it becomes the **detector**. If a worktree ever
again fails the base check, that is now a signal that something has changed in
Orca's repo registration, and it should be investigated rather than routinely
reset past.

---

## 8. Everything touched outside this repository

Complete list:

1. **`orca repo set-base-ref --repo path:/Users/ankit/Projects/log-analyzer
   --ref main`** — Orca repo record `506c3684-fb2e-44d5-924d-a4f5bbaf8a32` now
   carries `worktreeBaseRef: "main"`. Reported to the coordinator before it was
   run. This is the fix.
2. **Transient probe worktree `hk1-base-proof`** — created at
   `/Users/ankit/orca/workspaces/log-analyzer/hk1-base-proof` solely to obtain
   the proof in §5, then removed via `orca worktree rm`; its branch
   `Ankit512/hk1-base-proof` is gone. Nothing remains.

Nothing else outside this repository was modified. No remote was contacted
except the read-only `git ls-remote` used to rule out a stale cache. Nothing
was pushed; nothing was merged.

---

## 9. Residual risk

The fix is a **per-repo** setting. A repo registered in Orca later — or this one
re-registered — starts again with no base ref and inherits the same remote
default. The general behaviour (default to the remote default branch) is inside
Orca's own installation and is not safely user-fixable from here; what is
user-fixable is the per-repo override, which is what was applied. Guardrail 9's
base check remains the standing detector for that case.


---

## 10. Closing — guardrail 9 remains in force

**Guardrail 9's base check stays in place after this fix.** It was never in
scope to remove it, and it is not being recommended for removal.

The buckle is repaired; the belt remains. The check also still covers cases this
fix does not reach:

- worktrees created **before** the fix, which are still sitting on b836114;
- a **differently-registered** repo, or this one re-registered, which starts
  again with no base ref and inherits the remote default;
- any **future regression** in Orca's base resolution.

Its role has changed rather than ended. Before this card the check was the fix,
run on every dispatch as a standing tax. Now it is the **detector**: a worktree
that fails the base check is no longer routine, and should be treated as a
signal that something has changed in Orca's repo registration and investigated,
not simply reset past.

---

### Freeze verification (final)

```
shasum -a 256 anomaly_detector.py
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876
```

Unchanged, before and after. No file in this repository's application surface —
`anomaly_detector.py`, rules, `console/`, `tools/`, `web/`, `tests/`, or the eval
corpus — was modified. The only file this card writes is this report.
