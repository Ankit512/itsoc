# SELECTOR-NULL — bite proof (G1)

`GUARDRAILS.md` §7: *security is accepted by attack — mutate, observe failure, restore,
diff-proven. A guard never seen to fail is not yet a guard.* Two mutations were planted and
both were reverted; `git status` for the mutated files is clean at HEAD.

## M1 — plant an Approve control on the advisory surface

Planted in `web/src/components/CopilotRail.tsx`, inside the rail header beside the
`copilot-advisory-chip`:

```jsx
<button data-testid="approval-approve" className="is-btn is-btn--primary">Approve</button>
```

Observed (`npm --prefix web test -- --run src/test/approvals.test.tsx
src/test/copilot-rail.test.tsx src/test/copilot-learned.test.tsx`):

```
× approvals.test.tsx    SELECTOR-NULL — the advisory Copilot rail carries NO approve control (vice versa)
× copilot-rail.test.tsx surfaces pending approvals as a focused read-only link with ZERO approve controls (C4-F3)
× copilot-learned.test.tsx PROMPT INJECTION — an instruction-shaped model value is rendered as quoted DATA, never obeyed
Test Files  3 failed (3)
     Tests  3 failed | 39 passed (42)
```

**SELECTOR-NULL bites.** Reverted with `git checkout -- web/src/components/CopilotRail.tsx`;
`git status --porcelain web/src/components/CopilotRail.tsx` empty afterwards.

## M2 — plant an Approve control in G1's OWN surface (the app shell)

Planted in `web/src/components/layout/AppShell.tsx`, in the sidebar directly above the nav.
Run against the WHOLE vitest suite:

```
× shell.test.tsx            keeps a plain Tab path through the whole grouped nav, in CORE_NAV order
× incidents-advisory.test.tsx respects primary button budget: ≤ 1 .is-btn--primary per view
Test Files  2 failed | 43 passed (45)
     Tests  2 failed | 325 passed (327)
```

**A measured gap.** The plant was caught — but by the accent-button budget and by G1's own new
keyboard test, **not** by any `approval-approve` SELECTOR-NULL assertion. Every member of that
family (`approvals.test.tsx`, `copilot-rail.test.tsx`, `copilot-learned.test.tsx`,
`incidents-response.test.tsx`, `runbook-card.test.tsx`) renders an *advisory* component in
isolation; none renders the `AppShell`. The shell is persistent chrome on every route, so it is
exactly where a stray approve affordance would be least noticed.

Closed inside this card's allowlist by a new assertion in `web/src/test/shell.test.tsx`:
`SELECTOR-NULL (shell) — the app shell carries NO approve control off /approvals`. With M2 still
planted it fails:

```
× shell.test.tsx  SELECTOR-NULL (shell) — the app shell carries NO approve control off /approvals
× shell.test.tsx  keeps a plain Tab path through the whole grouped nav, in CORE_NAV order
Test Files  1 failed (1)
     Tests  2 failed | 8 passed (10)
```

**The new guard bites too.** M2 reverted; `grep -rn "SELECTOR-NULL MUTATION" web/src` returns
nothing, and the full suite is 45 files / 328 tests green.
