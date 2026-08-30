# P1 · Push the backlog

**When:** 2026-08-30. **Q1 revised:** push now, as backup.
**Force-pushes:** none. No ref was diverged or behind.

## Verify

```
git log origin/main -1
e63b091 merge(chore/post-c-closeout): file follow-ups and close the leftover-list run
```

`git rev-parse main` = `git rev-parse origin/main` = `e63b091568042b5527c0978aa1af96251f3927b9`.

## Pushed this run (new or fast-forward)

| Ref | Before origin | After | Kind |
|---|---|---|---|
| `main` | `da6eb21` | `e63b091` | fast-forward +6 |
| `feat/redesign-integration` | `71782ef` | `134e659` | fast-forward +1 (`PARKED.md`) |
| `fix/shadow-tokens` | (absent) | `7960d5d` | new |
| `fix/gate-hygiene` | (absent) | `f4e157b` | new |
| `fix/auth-atomic-write` | (absent) | `66417b5` | new |

## Already on origin (in-sync, not rewritten)

`oob/at-risk-nuance`, `oob/connector-egress-label`,

`fix/c2-correlation-guard`, `fix/c3-tioem-egress-redact`, `fix/c4-integration-shuffle`, `fix/c4-r1-priority-palette`, `fix/open8-test-isolation`, `fix/open13-shell-flake`, `fix/open14b-upload-timeouts`,

`stage-c/c0-foundations`, `stage-c/c1-consolidation`, `stage-c/c1-fanout-intel`, `stage-c/c1-fanout-network`, `stage-c/c1-fanout-sources`, `stage-c/c1-t6-nav`, `stage-c/c2-advisory`, `stage-c/c2-investigation`, `stage-c/c2-invfile`, `stage-c/c2-org-context`, `stage-c/c3-gated-response`, `stage-c/c3-mcp`, `stage-c/c4-audit-timeline`, `stage-c/c4-fanout-advisory`, `stage-c/c4-fanout-priority`, `stage-c/c4-fanout-runbook`, `stage-c/c4-response-ui`, `stage-c/c4fidelity`, `stage-c/c4theme`, `stage-c/c5-battlecard`, `stage-c/c5-demo`, `stage-c/c5-kpi`, `stage-c/c5-n1-egress-constant`, `stage-c/c5-t2-backpressure`.

33 refs. Confirmed local SHA = `origin/<ref>` after fetch.

## Not in the surviving set (not pushed)

`chore/post-c-closeout` is reachable from `main` (`a8d0c5d` is an ancestor of `e63b091`). Other `feat/*` / `prep/*` / `archive/*` / `test/*` were already on origin from earlier work and were not in the P1 list.

## Force

None. Classification after fetch: NEW 3, AHEAD 2, IN_SYNC 33, DIVERGED 0, BEHIND 0.
