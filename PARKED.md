# PARKED — `feat/redesign-integration`

**Status:** PARKED. Not merged. Not killed.
**Commit:** `71782ef` — *park(redesign-integration): uncommitted work-in-progress preserved at cleanup*
**Owner ruling:** 2026-08-30. Directionally right (no auto-bootstrap, atomic `0600` writes) but disqualifying as-is. This branch only comes back through the acceptance list below.

Codex reviewed `71782ef` as card CD-1. The four findings are copied **verbatim** from that report. Un-parking means every item is fixed and proven, not re-argued.

---

## What is already true (not a pass)

> The backend changes improve the baseline posture by eliminating login auto-bootstrap, forcing the sole profile to `analyst`, refusing a second ordinary signup, writing credentials atomically with mode `0600`, and centrally requiring a valid session after a profile exists.

That is why this is parked rather than deleted.

---

## Acceptance list — all four required

### 1. Fail-open pre-bootstrap

> The central guard is explicitly fail-open before bootstrap: when `hasProfile` is false, every otherwise protected API (including mutating and outside-world-capable endpoints) is allowed without authentication. After bootstrap it fails closed for missing/invalid tokens, but there is no step-up control or role authorization: any valid 24-hour in-memory bearer session authorizes all protected endpoints, including sensitive configuration/egress operations.

**Bar:** make all sensitive APIs fail closed before bootstrap (expose only the minimal bootstrap/status/login surface). Add authorization and recent-auth/step-up requirements for high-impact or egress-capable actions.

- [ ]

### 2. `getMe()` fabricating an analyst identity

> The browser remains fail-open. In `web/src/lib/auth.ts`, `getMe()` fabricates `{username: "analyst", role: "analyst"}` on a non-401 response or network exception and retains the token. The newly added test asserts `null` plus token removal for exactly those cases, but the commit does not change `auth.ts`; therefore the claimed fail-closed behavior is not pinned by passing implementation/tests.

A fabricated authenticated identity is about the worst honesty violation this codebase could ship.

**Bar:** change `getMe()` to clear the token and return unauthenticated on every unverifiable response. The test and the implementation must agree.

- [ ]

### 3. Tests pinning behaviour the commit does not implement

> Other new HTTP assertions also do not match the implementation: `ProfileExistsError` subclasses `ValueError` and `_auth_signup()` maps it to 400, while the test expects 409; the cross-origin signup test expects 403, but this commit adds no Origin/CSRF validation. Thus the tests do not currently pin the claimed takeover and cross-origin behavior.

**Bar:** implement and test the intended 409 mapping; implement an explicit same-origin/CSRF policy if cookies remain accepted. Run the backend plus frontend suites so every newly asserted behaviour is proven rather than merely described.

- [ ]

### 4. Bootstrap check-then-write race

> Bootstrap itself also has a check-then-write race, so two concurrent signups can both pass the existence check and the later atomic replace can overwrite the first profile.

**Bar:** serialize bootstrap creation with exclusive-create or a lock.

- [ ]

---

## Standing constraints

- Do not edit `anomaly_detector.py`.
- Do not merge this branch while any box above is open.
- Owner is the only merge authority.
