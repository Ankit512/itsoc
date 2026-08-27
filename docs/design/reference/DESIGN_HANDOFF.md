# itsoc. — Design Handoff (Figma-level, for Claude Code)

A complete page-by-page design spec. Pairs with two files that ARE the implementation:
- **`itsoc-design-system.css`** — tokens + every component class (`is-*`). The single style source.
- **`itsoc_prototype.html`** — the clickable, all-pages reference (the "Figma frames", live). What
  you click there is what to build. Mirror its markup per page; swap dummy data for real endpoints.

**Golden rule:** never invent styles or colors. Every element gets an `is-*` class; every color
comes from a token. If a page looks different from the prototype, it's wrong.

---

## 1. Design language

**Grafana density × Vercel/Linear restraint.** Calm, near-monochrome surfaces; one violet accent
used sparingly; thin 1px borders; generous spacing; tabular numerals; flat (no gradients/shadows
except overlays). Charts are real and dense; chrome is quiet. Dark is default; light is a token
swap via `data-theme`. **Honesty surfaces are part of the design** — keep every "derived · not a
verdict", "verbatim", "observed only", "n/a", and honest empty state verbatim.

**Palette (tokens):** bg/pan/pan2 surfaces · bd borders · ink/mut text · **acc `#7c6cff`** (light
`#6d5cf0`) · severity crit `#f0616d` / high `#f2a33c` / med `#d6b02e` / low `#33c895`.
**Type:** system sans; `ui-monospace` for ids, evidence, timestamps, rule names.
**Wordmark (consistent everywhere):** always `itsoc.` — lowercase, one word, weight ~750, with the
trailing **dot in `--acc`**. Never "ITSOC", "Itsoc", "itSOC", "iTSOC", or without the dot. Identical
treatment on the login brand panel, the sidebar, and any header/title/favicon.

---

## 2. Global frame (the shell you liked)

Applies to every authed page.

- **Sidebar** `.is-side` (220px): brand wordmark `itsoc.` (dot in accent) → ⌘K search pill →
  primary nav `.is-nav` (Overview · Findings · Incidents · Sources · Settings) → **Experimental**
  group `.is-nav-group` with an ON/OFF badge that reveals Assets/Threat Intel/Discovery/
  Vulnerabilities/History → footer: user + role, Logout, `rules · model · local` meta.
  Active item = `.active` (accent-weak bg). This exact structure is in the prototype.
- **Top bar** `.is-top`: page title + accent subtitle · centered ⌘K search `.is-top-search` ·
  actions `.is-top-actions` (Upload Logs primary, run switcher, Runs, Refresh, theme toggle).
- **Run switcher** `.is-runs`: searchable dropdown grouped **Today / Previous runs**; each row =
  filename (mono) + timestamp + findings count; current row accent-weak with ✓; unparsed runs
  flagged in `--high`.
- **Command palette** `.is-palette` (⌘K): filter input → list of pages/actions → footer hints.
- **AI copilot** `.is-rail` — slide-in drawer + floating `.is-cop-fab`. See §4.

---

## 3. Page frames

Each page = `.is-content` inside `.is-main`. Layouts reference the prototype's `#p-*` sections.

**Login** — split `.is-auth`: left `.is-auth__brand` (wordmark, tagline, 3 checks, honest note);
right `.is-auth__card` with `.is-tabs` (Log in / Sign up), username + passphrase fields, primary
button, and the "local demo · scrypt-hashed · swap-seam" honesty note. Sign up adds a Name field.

**Overview** — run-provenance mono strip (file · hosts · lines parsed/unparsed · ruleset · model ·
detector sha). Then `.is-kpis` (Total/Critical/High/Medium/Low; deltas ONLY with a prior run,
else "no prior run — no delta"). Then `.is-grid-3`: **Alerts by severity** (SVG donut, center
total), **Alerts over time** (SVG stacked bars by severity — a real time-series, never a solid
block), **Top ATT&CK tactics** (`.is-hbar` rows + "derived · not a verdict" chip). Then **Latest
alerts** table (`.is-panel` + `.is-table`), rows drill to Findings.

**Findings** — filter row (input + severity select + "N of M findings · lines parsed · unparsed").
`.is-md` master-detail: left `.is-table` (Sev/Time/Rule/Host/ATT&CK); right `.is-md__detail` =
header (severity tag + rule) → title → `.is-vgrid` two blocks: **RULE VERDICT · AUTHORITATIVE**
(`.is-block.<sev>`, colored verdict + why) and **PLAIN-LANGUAGE EXPLANATION · ADVISORY** → **Evidence**
`.is-evidence` (verbatim, mono, matched span in `<mark>`) → `.is-vgrid`: **Rule predicate that
fired** (`.is-predicate`, mono) + **Event sequence**. Row click selects; keep the honesty caption
"verbatim from the source log — nothing generated".

**Incidents** — count strip + state filter. `.is-md`: left `.is-table` (Sev/State/Entity/Findings);
right detail = header (severity + state chip + `inc-…` id) → title "Entity — N correlated finding(s)"
→ meta with "severity is rule-owned" → **Lifecycle** `.is-lifecycle` (New→Acknowledged→Investigating
→Resolved, clickable, stamps real) → `.is-vgrid`: **Timestamps · from the log, not wall-clock**
(`.is-facts`, `n/a` where absent) + **MITRE techniques · derived tags, not verdicts** (tids, or
honest "No techniques mapped") → **Root cause** `.is-rca` (advisory chip; hypothesis + runbook
citation w/ score, OR honest "no runbook match"). Attack timeline `.is-chart` when data exists.

**Sources** — honest banner. `.is-grid-2`: **Syslog collector** card (listen port, Loopback/All-
interfaces radios w/ the "exposes to network" warning, Start/Stop) + **Listener status** facts
(State, real Bind/port — never `undefined`, Protocols, Messages received, Last message). Recent
received events panel (honest empty).

**Settings** — honest banner. Cards (max ~560px): **Compute location** (Local/Remote radios;
Remote reveals Base URL/Model/API-key; "detection ALWAYS local") → **Outbound redaction** note →
**Analyst model** (qwen3:8b, "explains only, never sets severity") → **Appearance** (theme).

**Assets** (experimental) — "observed entities only" banner → `.is-table` (Asset/Kind/Events/
Findings/Risk/Last seen) → Users-at-risk table (at-risk vs clean tags).

**Threat Intel** (experimental) — "surfaced, not generated" banner → `.is-grid-2`: IOC table
(offline STIX) + Rule→MITRE map (rule mono + tids).

**Reports** (experimental) — "real files only" note → download row (HTML + JSON as primary; CSV/
XML/MD secondary) → Saved reports table (name/size/created), honest empty.

**Cases** (experimental) — "analyst-entered, no sample invented" note → New case button → list or
honest empty state.

**Discovery / Vulnerabilities** (experimental) — honest **active-scan** banner (private targets
only, user-initiated, NOT read-only) → scan form + status facts / NSE findings table (severity =
CVSS band or honest "unknown").

**History** (experimental) — persistent-store banner → `.is-kpis` (Events/Critical/High/Assets/
OpenVulns/IOCHits, "source-reported") → EVTX ingest + retention/purge + events table.

**Logout** — honest card: "local, single-user tool — nothing to sign out of; this clears local UI
state" → Clear / Cancel. (In demo-auth mode this becomes "sign out of this local demo session".)

---

## 4. AI Analyst — now a first-class surface (the deeper feature)

The copilot does two jobs: **interpret** the current view, and **showcase** — render real incidents,
findings, or dashboard summaries inline on request. It is always advisory; rules own the verdict.

**Interpret (existing):** ask a relevant question on any screen ("why is this critical?", "what's
the root cause?") → grounded answer from that screen's data, citing findings/runbook, advisory-
labeled, passed through `explanation_guard`.

**Showcase (new):** the copilot can pull a view into the rail as a compact, real result card.
- Trigger by chip or free text: "show me the critical incidents", "summarize the dashboard",
  "what's on server-01?", "top 5 findings".
- The response is a **structured directive**, not just prose. Backend `/api/ask` returns either
  `{answer}` (prose) or `{view}` where `view` = `{type, title, filter, items|kpis, deeplink}`.
  Types: `incidents` · `findings` · `dashboard` · `entity`.
- The rail renders that directive as a card built from the SAME `is-*` classes: a mini
  `.is-table` (e.g. top incidents: sev tag + entity + findings), or a KPI strip (`.is-kpi`
  compact), or an entity summary — each row/card links to the full page (`deeplink` → `go(page)`).
- **Honesty:** the card shows REAL data the backend selected — the AI chooses *what to surface*,
  never a *verdict*. Card carries an `advisory` chip and a "cited: N findings" line. Empty →
  honest "nothing matches", never invented rows.
- Optional: the copilot can also **navigate + highlight** ("take me to the C2 incident" → routes to
  Incidents and selects it).

**Component:** `.is-rec` for the recommendation, `.is-msg-q`/`.is-msg-a` for the exchange, and a
new **result card** (a `.is-panel` variant inside the rail) for showcased views. The prototype
demonstrates this — the suggestion chips render live incident/dashboard cards.

---

## 5. Plug-in workflow (Claude Code)

1. Import `itsoc-design-system.css` globally; put `data-theme` on the app root; wire the toggle.
2. **Per page, one branch, stop-and-report:** open the matching `#p-*` frame in the prototype,
   mirror its structure with the `is-*` classes, and bind the real endpoints (findings, incidents,
   `soc.derive_rca`, metrics, sources, settings). Delete ad-hoc/Tailwind styling that conflicts.
3. **AI showcase:** extend `/api/ask` to optionally return a `view` directive; render it in the
   rail per §4; keep every response advisory + grounded (reuse `askStream` for prose,
   `explanation_guard` for finding-naming). Never let a showcased card imply a verdict.
4. Detector untouched (sha `364577c5…`); honesty copy verbatim; tests + build green each phase.

**Definition of done for a page:** side-by-side with the prototype frame, it's indistinguishable
in layout, spacing, and color — and every value on it is real or an honest `n/a`.
