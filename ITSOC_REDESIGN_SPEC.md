# itsoc. — Redesign & Build Spec (for Claude Code)

**How to use this file.** Execute one **phase** at a time, each on its own branch, **additive**,
**tests green before merge**, **stop-and-report** after each. Commit this file as the redesign
north star. Phases 0–5 can start now; Phase 6 (auth) is scoped as demo-polish-with-a-swap-seam.

**Detector note.** `anomaly_detector.py` is no longer frozen at the old `43f0560f…` — the owner
authorized a hardening edit; the current baseline is sha256 **`364577c5…a4a876`**. Treat that as
the reference: **the UI work in this spec must never touch the detector**, and rules still own
every verdict.

---

## 1. Identity & principles (unchanged, and mostly already honored)

**itsoc.** — a local, AI-assisted SOC console. Deterministic rules **own the verdict**; the LLM
**explains, interprets, and recommends** but never decides. The redesign is **"AI-first
experience, rules-first verdict."**

The app already honors the honesty surfaces well — **keep every one of them**: "RULE VERDICT ·
AUTHORITATIVE" vs "EXPLANATION · ADVISORY", verbatim evidence, "observed entities only", "derived
tags — not verdicts", "no sample cases invented", honest "unparsed" runs, honest Logout. These
are the differentiator; the reskin must preserve them verbatim.

**Honest caveat to keep accurate:** Discovery/Vulnerabilities run active nmap scans and
Enrichment/OEM call external providers — so the product is **not** purely read-only/zero-egress
anymore. Don't let any copy claim otherwise (fence these as "Experimental", see Phase 1).

---

## 2. Design system (Grafana × Vercel)

Vercel/Linear restraint (spacious, near-monochrome, thin borders, one accent, tabular numerals)
carrying Grafana data density (time-series, sparklines, dense tables). Layout is the Linear
three-column shape: **nav · content · detail/copilot rail.**

- **Tokens as CSS variables, both themes.** Define `--bg/--pan/--pan2/--bd/--ink/--mut/--acc` +
  the 4 severity colors, with a `[data-theme=light]` override. One accent (violet `#7c6cff`
  dark / `#6d5cf0` light). Theme persists (already does).
- Reference mockups (this session): `itsoc_overview_redesign_mockup` and
  `itsoc_incident_rca_view_mockup` — build the token system to match those.
- Flat, no gradients; motion subtle; empty/loading states first-class.

---

## 3. Phase plan (one branch each, stop-and-report)

**Phase 0 — Brand + design system.**
Rename to `itsoc.` everywhere: sidebar wordmark (with the accent dot), page titles, tab title,
`web/package.json`, and the GitHub repo (`log-anomaly-detector` → `itsoc`, update remote). Build
the token/theme system from §2 as the single source of truth every component imports. No layout
changes yet — just tokens + brand.

**Phase 1 — App shell.**
New sidebar/nav grouped as **Overview · Findings · Incidents · Sources · Settings**, with an
**Experimental** group (off by default via a flag) housing Discovery, Vulnerabilities,
Enrichment, OEM Engine, History. Top bar: **⌘K command palette** (jump-to-anything + ask), the
**searchable/grouped run switcher** (replaces the 25-item flat dropdown; group by source/date,
show findings + parsed/unparsed inline), theme toggle. Chrome only.

**Phase 2 — Core screens.**
Reskin **Overview** (honest metrics: findings-over-time, severity mix, top tactics, MTTD/MTTR =
n/a until lifecycle data, deltas only with a prior run), **Findings** (master-detail: table left,
detail right with the verdict/advisory split + verbatim evidence + rule predicate + timeline),
**Incidents** (master-detail + the RCA panel from `soc.derive_rca`) to the new system.

**Phase 3 — AI copilot.**
A right-rail analyst that **interprets the current view on a relevant prompt** (grounded, cited)
and surfaces recommendations ("start here → X, because…"). Wire to existing `api.ask`/`askStream`
and `soc.derive_rca`; every answer advisory-labeled and passed through `explanation_guard` where
it names findings. It reads verdicts, never sets them.

**Phase 4 — Quality fixes** (all real, from the live screens):
- **Incident dedup/rollup** — the Incidents list shows 121 incidents with literal duplicates
  (same entity + identical timestamp 2–3×) and heavy single-finding LOW noise. De-duplicate by
  incident id and roll single-finding low-value clusters into a collapsed group.
- **Collectors `undefined:undefined`** — the listener shows State "Running" with Bind/port
  "undefined:undefined". Populate real bind/port, or don't claim "Running" (honesty rule).
- **Run-switcher dots vs findings** — a run reads "23 findings" beside dots `1 · 67 · 1322`.
  Reconcile: label what the dots actually count (events? severities?) or fix the mismatch. No
  number next to another number should be unexplained.
- **Explanation latency** — findings sit on "Explanation pending" with a stuck `explain 0/2`.
  Confirm the qwen3:8b advisory pass completes or degrades honestly; don't leave it hanging.
- **"At-risk" nuance** — every observed asset trips "at risk" (≥1 finding). Keep it honest but
  consider a severity-weighted risk so the signal isn't diluted (optional).

**Phase 5 — Remaining screens.**
Reskin Assets, Threat Intel, Reports, Cases, Collectors, Settings, plus the Experimental group,
to the new system. Trim Reports exports to the used set if desired.

**Phase 6 — Auth (demo polish + swap-seam).** See §5.

Every phase: own branch, additive, `anomaly_detector.py` untouched (sha `364577c5…`), and green
`console/test_console.py` + `web` vitest before merge.

---

## 4. AI copilot — capability detail

Five grounded roles, all advisory: (1) **interpret the current view** on prompt ("why is this
critical?", "what's the root cause?") reading that screen's real data; (2) **trend digest**
("what's rising"); (3) **honest forecast** — extrapolate real counts, labeled `forecast · based
on N runs`, never a conjured attack, "not enough runs" when thin; (4) **prioritize** ("look here
first, because…"); (5) **cited resolution** via the runbook engine. Never sets severity.

---

## 5. Auth — Phase 6 (demo polish now, real later)

**Goal:** a real-looking sign-up/log-in for demos, built so future real auth is a backend swap,
not a UI rewrite. It must stay honest and not claim security it doesn't have.

**Frontend (build now):**
- A `/login` + `/signup` screen in the design system (see the login mockup).
- An `AuthProvider` / `useAuth()` context + a `<RequireAuth>` route guard wrapping the app.
- All auth calls go through **one** client module (`web/src/lib/auth.ts`) — the only place that
  talks to the auth backend. This is the swap-seam: today it calls the local stub; later it
  points at real identity, and no screen changes.

**Backend (build now — a local stub):**
- A small `/api/auth/*` contract: `POST /signup`, `POST /login`, `POST /logout`, `GET /me`.
- Implementation now = **local single-profile stub**: store one profile locally with the
  passphrase **hashed** (stdlib `hashlib.scrypt`/`pbkdf2` — never plaintext, never returned),
  issue a short-lived local session token kept client-side. This is a *gate*, not multi-user
  identity — and it's labeled as such.
- Put it behind an `AuthProvider` interface on the backend too (one `LocalDemoAuth` class), so a
  future `OIDC`/`passkey`/`token` provider drops in against the same interface.

**Honesty + your own principle:**
- The login screen carries a subtle honest line (e.g. "Local demo — a single profile on this
  machine"). Don't fake SSO/enterprise.
- Update the **Logout** page: it currently says "there is no account, no login" — that becomes
  "sign out of this local demo session" so the copy stays true.
- Your stated principle is **token/passkey auth, not username/password**. The demo can use a
  passphrase for familiarity, but document that the *real* future provider should be token/passkey
  — so Phase 6's seam is built to accept that, not to entrench passwords.

**What NOT to build now:** real multi-user accounts, RBAC, password reset emails, OAuth — those
are the future swap, gated on the actual hosted/multi-user decision. Building them now would be
security theater on a local tool.

---

## 6. Reuse — do NOT rebuild

The engine and honest backend already exist and work: the detector + rules, `soc.derive_rca`
(RCA), `explanation_guard`, structured output, `redact.py`, `store.py` (sqlite), `export.py`,
`api.askStream` (SSE), the live tail, the verdict/advisory finding detail, the run history. The
redesign **reskins and rewires** these — it does not recreate them.

---

## 7. Reality checks (honest)

- **Metrics/forecast need history**; you now have 25 runs / 263 findings — enough to *show* real
  trends. Keep `n/a` where a metric genuinely has no basis.
- **The real differentiator is still the log-generator → efficacy harness** (generate a known
  attack chain → detect → precision/recall vs ground truth). That's separate from this reskin and
  worth doing after Phase 2, once the screens can show it well.
- **The detector is no longer frozen** — set `364577c5…` as the documented new baseline and
  update `CLAUDE.md`/`PROJECT_HANDOFF.md`/the MCP provenance so nothing still asserts the old sha.
